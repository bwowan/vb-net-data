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
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
mod capture;
mod parser;
mod statistic;
use tracing_subscriber;

//use statistic::run_stats_aggregator;

/*fn select_network_device() -> Result<(pcap::Device, usize)> {
    let devices = pcap::Device::list();
    if devices.is_err() {
        let pcap_err = devices.err().unwrap();
        Err(anyhow::anyhow!(pcap_err))
    } else {
        let devices = devices.unwrap();
        if devices.is_empty() {
            Err(anyhow::anyhow!("No network interfaces found"))
        } else {
            println!("Available interfaces:");
            for (i, dev) in devices.iter().enumerate() {
                println!("{i}: {}", dev.name);
            }
            println!("Enter interface number:");
            let mut input = String::new();
            let read_result = io::stdin().read_line(&mut input);
            let idx: usize = if read_result.is_ok() {input.trim().parse().unwrap_or(0) } else { 0 };
            let iface_id = idx.min(devices.len().saturating_sub(1));
            let iface_names: Vec<String> = devices.iter().map(|dev| dev.name.clone()).collect();
            let net_device = devices.get(iface_id).unwrap_or(&devices[0]).clone();

            println!("Selected interface: {}", iface_names.get(iface_id).map(String::as_str).unwrap_or(&net_device.name));
            Ok((net_device, iface_id))
        }
    }
}*/

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

fn select_network_device() -> Result<pcap::Device> {
    let iface_id = 0usize; // TODO: make it configurable
    let device = pcap::Device::list().unwrap()[iface_id].clone();
    println!("Selected interface: {}", device.name);
    Ok(device)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // 1. Выбираем сетевое устройство.
    let net_device = match select_network_device() {
        Ok(device) => device,
        Err(e) => {
            println!("Failed to select network device: {e:?}");
            return Err(e);
        }
    };

    let own_mac = parser::get_mac_address(&net_device.name).unwrap_or_default();

    // .ok_or_else() - более идиоматичный способ преобразовать Option в Result
    let channels = MainChannels::new();
    if channels.is_none() {
        println!("Failed to initialize channels.");
        return Err(anyhow::anyhow!("Failed to initialize channels."));
    }

    let shutdown_flag: Arc<_> = Arc::new(AtomicBool::new(false));

    // Вектор для хранения JoinHandle всех запущенных задач
    let num_parsers = 1;
    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(num_parsers+2);
    let (cap2parse_tx, cap2parse_rx) = flume::bounded::<common::CapData>(1024);
    let (parse2stats_tx, parse2stats_rx) = flume::bounded::<common::NetData>(1024);

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
        //for _ in 0..num_parsers {
            //let rx = cap2parse_rx;
            let tx = parse2stats_tx.clone();
            handles.push( tokio::spawn(async move {parser::parse_loop(own_mac, cap2parse_rx, tx).await;} ) );
        //}

        //start statistic task
        {   let rx = parse2stats_rx;
            handles.push( tokio::spawn(async move {statistic::console_statistic(rx).await}) );
        }
    }
    

    // Ожидаем сигнала Ctrl-C для грациозного завершения
    println!("Packet listener started. Press Ctrl-C to stop.");
    tokio::signal::ctrl_c().await?;
    println!("\nCtrl-C received, initiating graceful shutdown...");

    // Ожидаем, пока все задачи завершатся самостоятельно, получив сигнал
    // о закрытии каналов.
    println!("Waiting for tasks to finish...");
    for handle in handles {
        handle.await?;
    }

    Ok(())
}
