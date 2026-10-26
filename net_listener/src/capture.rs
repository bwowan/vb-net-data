use pcap;
use flume::Sender;
use std::sync;
use std::sync::atomic::Ordering;
use common;
use tracing::{info, error, warn};

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
    sender: Sender<mempool::PoolSlot<common::NetData>>,
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

    let mut rest_slot: Option<mempool::PoolSlot<common::NetData>> = None;
    let mut do_break = false;
    while !(shutdown_flag.load(Ordering::Relaxed) || do_break) {
        match cap.next_packet() {
            Ok(packet) => {
                let slot = rest_slot.take().or_else(|| pool_acquire.acquire());
                if sender.is_full()  ||  slot.is_none() {
                    lost_packets += 1;
                    rest_slot = slot;
                } else {
                    let mut slot = slot.unwrap();
                    {   let n = packet.data.len().min(mempool::PACKET_BUF_KEEP);
                        unsafe { std::ptr::copy_nonoverlapping(packet.data.as_ptr(), slot.bin.cast::<u8>(), n); }
                        slot.cap_len = n;
                        slot.orig_len = packet.header.len as usize;
                    }
                    match sender.try_send(slot) {
                        Ok(()) => { }
                        Err(flume::TrySendError::Full(_slot)) => {
                            lost_packets += 1;
                        }
                        Err(flume::TrySendError::Disconnected(_slot)) => {
                            info!("Receivers dropped, stopping capture loop on device {}", device_name);
                            do_break = true;
                        }
                    }
                    rest_slot = None;
                }
                drop(packet);
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => {
                error!("Capture error on device {}: {:?}", device_name, e);
                do_break = true;
            }
        }
    }

    if lost_packets > 0 {
        warn!("CAP: dropped {lost_packets} packets on {device_name}");
    }
    info!("CAP: leave capture");
}
