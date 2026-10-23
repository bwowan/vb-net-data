use pcap;
use flume::Sender;
use std::sync;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;
use common;
use tracing::{info, error, warn};

/// Сколько кадров выбросить за одну паузу, если очередь или пул заняты.
/// Дальше один sleep, чтобы парсер успел освободить очередь.
const DISCARD_BATCH: usize = 64;

fn open_capture(device: &pcap::Device) -> Option<pcap::Capture<pcap::Active>> {
    let device_name = device.name.as_str();

    let cap = match pcap::Capture::from_device(device_name) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create capture from device {}: {:?}", device_name, e);
            return None;
        }
    };

    info!("CAP: getting device {}; {:?}", device.name, device.desc);

    // immediate_mode выключен: кадры копятся в кольце libpcap.
    // timeout 1 мс — верхняя задержка кадра и шаг, с которым виден shutdown.
    match cap
        .promisc(true)
        .immediate_mode(false)
        .timeout(1)
        .snaplen(65535)
        .buffer_size(16 * 1024 * 1024)
        .open()
    {
        Ok(c) => Some(c),
        Err(e) => {
            error!("Capture device {}: {:?}", device_name, e);
            None
        }
    }
}


/// Захват пакетов. Блокирующий `next_packet`, вызывать с отдельного потока.
pub fn run(
    device: pcap::Device,
    sender: Sender<(common::CapData, mempool::PoolSlot<common::NetData>)>,
    shutdown_flag: sync::Arc<sync::atomic::AtomicBool>,
    pool_acquire: &'static (dyn mempool::PoolAcquire<common::NetData> + Sync),
) {
    info!("CAP: enter capture");

    let device_name = device.name.clone();
    let mut lost_packets: u64 = 0;

    let Some(mut cap) = open_capture(&device) else {
        error!("CAP: failed to open capture on device {}", device.name);
        return;
    };

    while !shutdown_flag.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                if !sender.is_full() {
                    if let Some(slot) = pool_acquire.acquire() {
                        let cap_data = copy_packet(&packet);
                        drop(packet);
                        match sender.try_send((cap_data, slot)) {
                            Ok(()) => {}
                            Err(flume::TrySendError::Full((cap_data, _slot))) => {
                                mempool::recycle_packet_buf(cap_data.data);
                                lost_packets += 1;
                                if !pause_for_consumers(&mut cap, &mut lost_packets, &device_name) {
                                    break;
                                }
                            }
                            Err(flume::TrySendError::Disconnected((cap_data, _slot))) => {
                                mempool::recycle_packet_buf(cap_data.data);
                                info!("Receivers dropped, stopping capture loop on device {}", device_name);
                                break;
                            }
                        }
                        continue;
                    }
                }
                drop(packet);
                lost_packets += 1;
                if !pause_for_consumers(&mut cap, &mut lost_packets, &device_name) {
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => {
                error!("Capture error on device {}: {:?}", device_name, e);
                break;
            }
        }
    }

    if lost_packets > 0 {
        warn!("CAP: dropped {lost_packets} packets on {device_name}");
    }
    info!("CAP: leave capture");
}

fn copy_packet(packet: &pcap::Packet) -> common::CapData {
    let mut data = mempool::take_packet_buf(packet.data.len());
    data.extend_from_slice(packet.data);
    common::CapData {
        cap_len : packet.header.caplen as usize,
        orig_len: packet.header.len as usize,
        data,
    }
}

/// Выбрасывает ещё до [`DISCARD_BATCH`] кадров без копии.
/// `Ok(true)` — буфер pcap пуст, ядро уже подождало таймаут.
/// `Ok(false)` — пачка заполнена, в кольце ещё могут быть кадры.
fn discard_batch(
    cap: &mut pcap::Capture<pcap::Active>,
    lost: &mut u64,
) -> Result<bool, pcap::Error> {
    for _ in 0..DISCARD_BATCH {
        match cap.next_packet() {
            Ok(_) => *lost += 1,
            Err(pcap::Error::TimeoutExpired) => return Ok(true),
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

fn pause_for_consumers(
    cap: &mut pcap::Capture<pcap::Active>,
    lost: &mut u64,
    device_name: &str,
) -> bool {
    match discard_batch(cap, lost) {
        Ok(idle) => {
            if !idle {
                thread::sleep(Duration::from_millis(1));
            }
            true
        }
        Err(e) => {
            error!("Capture error on device {}: {:?}", device_name, e);
            false
        }
    }
}
