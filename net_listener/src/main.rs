// The net_listener directly accesses the network card, so it needs privileges:
// You can run it with sudo, or assign sudo setcap 'cap_net_raw,cap_net_admin=eip'
// For debugging, it is easiest to use a debug server: sudo lldb-server platform --listen "*:1234" --server
// and connect to it as done in the launch.json file

use std::os::unix::net::UnixDatagram;
use tokio;
use flume;
use anyhow::Result;
use pcap;
//use scopeguard::defer;
//use std::sync::{Arc, AtomicBool}
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
mod capture;
mod console;
mod parser;
#[allow(dead_code)]
mod pool;
#[allow(dead_code)]
mod statistic;
use tracing_subscriber;

//use statistic::run_stats_aggregator;

static SOCKET_PATH: &str = "/tmp/net_listener_stats2.sock";
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

/*fn finalizator()
{
    let _ = std::fs::remove_file(SOCKET_PATH);
}*/

fn prefix_len(mask: std::net::IpAddr) -> u32 {
    let bits: u128 = match mask {
        std::net::IpAddr::V4(ip) => u32::from(ip) as u128,
        std::net::IpAddr::V6(ip) => u128::from(ip),
    };
    bits.count_ones()
}

/// Имя, флаги pcap, MAC и адреса — одной строкой для меню выбора.
fn format_device_line(dev: &pcap::Device, mac: Option<pnet_datalink::MacAddr>) -> String {
    let mut flags = heapless::Vec::<&str, 5>::new();
    if dev.flags.is_up() {
        let _ = flags.push("up");
    }
    if dev.flags.is_running() {
        let _ = flags.push("running");
    }
    if dev.flags.is_wireless() {
        let _ = flags.push("wireless");
    }
    if dev.flags.is_loopback() {
        let _ = flags.push("loopback");
    }
    match dev.flags.connection_status {
        pcap::ConnectionStatus::Connected    => { let _ = flags.push("connected"); }
        pcap::ConnectionStatus::Disconnected => { let _ = flags.push("disconnected"); }
        pcap::ConnectionStatus::Unknown | pcap::ConnectionStatus::NotApplicable => {}
    }

    let mut parts: Vec<String> = Vec::new();
    if let Some(desc) = dev.desc.as_deref().filter(|d| !d.is_empty() && *d != dev.name) {
        parts.push(desc.to_string());
    }
    if !flags.is_empty() {
        parts.push(format!("[{}]", flags.join(" ")));
    }
    if let Some(mac) = mac {
        parts.push(mac.to_string());
    }
    for addr in &dev.addresses {
        match addr.netmask {
            Some(mask) => parts.push(format!("{}/{}", addr.addr, prefix_len(mask))),
            None               => parts.push(addr.addr.to_string()),
        }
    }
    if parts.is_empty() {
        dev.name.clone()
    } else {
        format!("{}  {}", dev.name, parts.join("  "))
    }
}

/// Спрашивает интерфейс, пока не введён номер из списка. `0` и `q` — выход без запуска.
fn select_network_device() -> Result<Option<pcap::Device>> {
    let devices = pcap::Device::list().map_err(|e| anyhow::anyhow!(e))?;
    if devices.is_empty() {
        return Err(anyhow::anyhow!("No network interfaces found"));
    }

    let mac_by_name: std::collections::HashMap<String, pnet_datalink::MacAddr> =
        pnet_datalink::interfaces()
            .into_iter()
            .filter_map(|iface| iface.mac.map(|mac| (iface.name, mac)))
            .collect();

    loop {
        println!("Available interfaces:");
        for (i, dev) in devices.iter().enumerate() {
            let mac = mac_by_name.get(&dev.name).copied();
            println!("{}: {}", i + 1, format_device_line(dev, mac));
        }
        println!("Enter interface number (0 or q to quit):");

        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            return Ok(None);
        }
        let choice = input.trim();
        if choice == "0" || choice.eq_ignore_ascii_case("q") {
            return Ok(None);
        }
        if let Ok(n) = choice.parse::<usize>() {
            if (1..=devices.len()).contains(&n) {
                let net_device = devices[n - 1].clone();
                println!("Selected interface: {}", net_device.name);
                return Ok(Some(net_device));
            }
        }
        println!("Enter a number from 1 to {}, or 0 / q to quit.", devices.len());
    }
}

/// Половина логических ядер под задачи парсера. На одном ядре и при ошибке ОС — одна задача.
fn parser_thread_count() -> usize {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    (cores / 2).max(1)
}

#[tokio::main]
async fn main() -> Result<()> {
    let log_file = std::fs::File::create("/tmp/net_listener.log")?;
    tracing_subscriber::fmt()
        .with_writer(log_file)
        .with_ansi(false)
        .init();

    // 1. Выбираем сетевое устройство.
    let net_device = match select_network_device() {
        Ok(Some(device)) => device,
        Ok(None) => return Ok(()),
        Err(e) => {
            println!("Failed to select network device: {e:?}");
            return Err(e);
        }
    };

    let own_mac = parser::get_mac_address(&net_device.name).unwrap_or_default();
    let num_parsers = parser_thread_count();
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    println!("Logical cores: {cores}; parser tasks: {num_parsers}");

    // .ok_or_else() - более идиоматичный способ преобразовать Option в Result
    let channels = MainChannels::new();
    if channels.is_none() {
        println!("Failed to initialize channels.");
        return Err(anyhow::anyhow!("Failed to initialize channels."));
    }

    let shutdown_flag: Arc<_> = Arc::new(AtomicBool::new(false));

    // Вектор для хранения JoinHandle всех запущенных задач
    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(num_parsers+2);
    let (cap2parse_tx, cap2parse_rx) = flume::bounded::<common::CapData>(1024);
    // Кольцо на 1024 — окно отставания. send не блокирует парсер.
    let (broadcaster, stats_rx) = tokio::sync::broadcast::channel::<Arc<common::NetData>>(1024);

    {   //here we made isolation of chanells, so it lives only in these threads

        //start single capture task
        handles.push(   {   let dev = net_device.clone();
                            //let tx = cap2parse_tx;
                            let sh = shutdown_flag.clone();
                            tokio::task::spawn_blocking(move || {
                                capture::capture_loop(dev, cap2parse_tx, sh)
                            })
                        }
        );  

        //start a few parsers tasks
        for _ in 0..num_parsers {
            let rx = cap2parse_rx.clone();
            let tx = broadcaster.clone();
            handles.push(tokio::spawn(async move {
                parser::parse_loop(own_mac, rx, tx).await;
            }));
        }

    }

    let console_shutdown = shutdown_flag.clone();
    let console_handle = std::thread::spawn(move || console::run(stats_rx, console_shutdown));

    loop {
        if console_handle.is_finished() {
            break;
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                shutdown_flag.store(true, Ordering::Relaxed);
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(80)) => {}
        }
    }
    shutdown_flag.store(true, Ordering::Relaxed);
    let _ = tokio::task::spawn_blocking(move || console_handle.join()).await;

    // Ожидаем, пока все задачи завершатся самостоятельно, получив сигнал
    // о закрытии каналов.
    println!("Waiting for tasks to finish...");
    for handle in handles {
        handle.await?;
    }

    Ok(())
}
