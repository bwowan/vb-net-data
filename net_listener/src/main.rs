// The net_listener directly accesses the network card, so it needs privileges:
// You can run it with sudo, or assign sudo setcap 'cap_net_raw,cap_net_admin=eip'
// For debugging, it is easiest to use a debug server: sudo lldb-server platform --listen "*:1234" --server
// and connect to it as done in the launch.json file

use std::os::unix::net::UnixDatagram;
use tokio;
use flume;
use anyhow::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
mod capture;
mod console;
mod device;
mod parser;


#[allow(dead_code)]
mod statistic;
use tracing_subscriber;

//use statistic::run_stats_aggregator;

const POOL_COUNT: usize = 1024;

static SOCKET_PATH: &str = "/tmpu/net_listener_stats2.sock";
/// Unix-сокет для отдачи статистики наружу. При Drop файл сокета удаляется.
struct MainChannels {
    uds           : UnixDatagram,
}
impl MainChannels {
    fn new() -> Option<MainChannels> {
        let _ = std::fs::remove_file(SOCKET_PATH);
        let uds = match UnixDatagram::bind(SOCKET_PATH) {
            Ok(s) => s,
            Err(e) => {
                println!("Failed to create UnixDatagram socket: {:?}", e);
                return Option::None;
            }
        };
        if let Err(e) = uds.set_nonblocking(true) {
            println!("Failed to set UnixDatagram socket to non-blocking: {:?}", e);
            return Option::None;
        }
        Option::Some(Self {uds})
    } 
}
impl Drop for MainChannels {
    fn drop(&mut self) {
        let _ = self.uds.shutdown(std::net::Shutdown::Both);
        let _ = std::fs::remove_file(SOCKET_PATH);
    }
}


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

    let channels = MainChannels::new();
    if channels.is_none() {
        println!("Failed to initialize channels.");
        return Err(anyhow::anyhow!("Failed to initialize channels."));
    }

    let shutdown_flag: Arc<_> = Arc::new(AtomicBool::new(false));

    //create pipes capture->parser->client
    let (from_capture_to_parser_sender, from_capture_to_parser_receiver) =
        flume::bounded::<(common::CapData, mempool::PoolSlot<common::NetData>)>(POOL_COUNT / 2);
    let (from_parser_to_client_sender, from_parser_to_client_receiver) =
        flume::bounded::<mempool::PoolSlot<common::NetData>>(POOL_COUNT);

    let pool_clients_number = 1u8;
    let mut client_handles: Vec<std::thread::JoinHandle<()>> = Vec::with_capacity(pool_clients_number as usize);
    client_handles.push(std::thread::spawn( { let shutdown_flag = shutdown_flag.clone();
                                              move || console::run(from_parser_to_client_receiver, shutdown_flag)
                                            } )
                        );

    let cap_pool = mempool::MemPool::<common::NetData, POOL_COUNT>::new();

    let mut parsers_handles: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(num_parsers);
    for _ in 0..num_parsers {
        let rx = from_capture_to_parser_receiver.clone();
        let tx = from_parser_to_client_sender.clone();
        parsers_handles.push(tokio::spawn(async move { parser::parse_loop(own_mac, rx, tx).await }));
    }

    tokio::select! {
        _ = capture::capture_loop(
            net_device,
            from_capture_to_parser_sender,
            shutdown_flag.clone(),
            &cap_pool,
            pool_clients_number,
        ) => shutdown_flag.store(true, Ordering::Relaxed),
        _ = tokio::signal::ctrl_c()
          => shutdown_flag.store(true, Ordering::Relaxed),
    }

    println!("Waiting for tasks to finish...");
    for handle in parsers_handles {
        let _ = handle.await;
    }
    for handle in client_handles {
        let _ = handle.join();
    }

    Ok(()) 
}
