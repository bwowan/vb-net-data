// The net_listener directly accesses the network card, so it needs privileges:
// You can run it with sudo, or assign sudo setcap 'cap_net_raw,cap_net_admin=eip'
// For debugging, it is easiest to use a debug server: sudo lldb-server platform --listen "*:1234" --server
// and connect to it as done in the launch.json file

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio;
use flume;
use anyhow::Result;
mod capture;
mod console;
mod device;
mod ipc_sender;
mod parser;


#[allow(dead_code)]
mod statistic;
use tracing_subscriber;

//use statistic::run_stats_aggregator;

const POOL_COUNT: usize = 1024;

static SOCKET_PATH: &str = "/tmpu/net_listener_stats2.sock";

#[tokio::main]
async fn main() -> Result<()> {
    let log_file = match std::fs::File::create("/tmpu/net_listener.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Failed to create /tmpu/net_listener.log: {e}");
            return Err(e.into());
        }
    };
    if let Err(e) = tracing_subscriber::fmt()
        .with_writer(log_file)
        .with_ansi(false)
        .try_init()
    {
        println!("Failed to init tracing subscriber: {e}");
        return Err(anyhow::anyhow!(e));
    }

    // 1. Выбираем сетевое устройство.
    let net_device = match device::select_network_device() {
        Ok(Some(device)) => device,
        Ok(None) => return Ok(()),
        Err(e) => {
            println!("Failed to select network device: {e:?}");
            return Err(e);
        }
    };

    let own_mac = parser::get_mac_address(&net_device.name).unwrap_or_default();
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let num_parsers = (cores / 3).min(1);
    println!("Logical cores: {cores}; parser tasks: {num_parsers}");

    let shutdown_flag: Arc<_> = Arc::new(AtomicBool::new(false));
    let cap_pool = mempool::MemPool::<common::NetData, POOL_COUNT>::new();
    let pool: &'static mempool::MemPool<common::NetData, POOL_COUNT> = unsafe { &*(&cap_pool as *const _) };

    //create pipes capture->parser->client
    let (capture_2_parser_sender, capture_2_parser_receiver) =
        flume::bounded::<mempool::PoolSlot<common::NetData>>(POOL_COUNT / 2);
    let (parser_2_client_sender, parser_2_client_receiver) =
        tokio::sync::broadcast::channel::<mempool::PoolSlot<common::NetData>>(POOL_COUNT);

    let mut client_handles: Vec<std::thread::JoinHandle<()>> = Vec::with_capacity(2usize);
    client_handles.push(std::thread::spawn({
        let shutdown_flag = shutdown_flag.clone();
        || console::run(parser_2_client_receiver, shutdown_flag)
    }));
    client_handles.push(std::thread::spawn({
        let shutdown_flag = shutdown_flag.clone();
        let rx = parser_2_client_sender.subscribe();
        || ipc_sender::run(SOCKET_PATH, rx, shutdown_flag)
    }));


    let mut parsers_handles: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(num_parsers); 
    for _ in 0..num_parsers {
        let rx = capture_2_parser_receiver.clone();
        let tx = parser_2_client_sender.clone();
        let shutdown_flag = shutdown_flag.clone();
        parsers_handles.push(tokio::spawn(
            parser::run(own_mac, rx, tx, shutdown_flag)
        ));   
    }

    {   let shutdown_flag_clone = shutdown_flag.clone();
        // oneshot-канал для оповещения, что capture-поток завершён — требуется,
        // чтобы корректно дождаться завершения цикла захвата и не перепутать его с обычным флагом остановки.
        // shutdown_flag сигнализирует о необходимости выйти (Ctrl+C), но не гарантирует, что поток уже завершился —
        // capture_done_rx ждёт именно завершения capture::run (и используется в select).
        let (capture_done_tx, capture_done_rx) = tokio::sync::oneshot::channel();
        // Отдельный поток: next_packet блокируется до таймаута pcap и не занимает worker Tokio.
        // JoinHandle не кладётся в select — проигравшая ветка отменяется, поток нет.
        let mut capture_thread = Some(std::thread::spawn(move || {
            capture::run(
                net_device,
                capture_2_parser_sender,
                shutdown_flag_clone,
                pool,
            );
            let _ = capture_done_tx.send(());
        }));
        tokio::select! {
            _ = capture_done_rx => {
                println!("Capture loop finished");
            }
            _ = tokio::signal::ctrl_c() => {
                println!("Ctrl+C received, shutting down...");
                shutdown_flag.store(true, Ordering::SeqCst);
                println!("Waiting for capture loop to finish...");
                if let Some(handle) = capture_thread.take() {
                    let _ = handle.join();
                }
                println!("Capture loop finished");
            }
        }
    }
    shutdown_flag.store(true, Ordering::SeqCst);

    println!("Waiting for tasks to finish...");
    // parsers_handles содержит JoinHandle<()>, создаваемый с помощью tokio::spawn, для них необходимо await внутри async-функции.
    for handle in parsers_handles {
        let _ = handle.await;
    }
    // client_handles — это обычные OS-потоки с std::thread::spawn и здесь нужен .join(), потому что потоки "выходят" только через join.
    for handle in client_handles {
        let _ = handle.join();
    }

    Ok(()) 
}
