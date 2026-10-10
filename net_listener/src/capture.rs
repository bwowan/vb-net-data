use pcap;
use flume::Sender;
use std::sync;
use common;
use crate::pool;
use tracing::{info, error, warn};


/// Packet capture loop using `pcap`.
pub fn capture_loop(
    device: pcap::Device, 
    sender: Sender<(common::CapData, pool::PoolSlot<common::NetData>)>,
    shutdown_flag: sync::Arc<sync::atomic::AtomicBool>,
    pool_acqure: &dyn pool::PoolAcquire<common::NetData>,
    pool_release: &dyn pool::PoolReleaseMandatory,
    pool_clients_number: u8,
) {
    info!("CAP: enter capture");

    let device_name = device.name.clone();

    let cap = match pcap::Capture::from_device(device.name.as_str()) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create capture from devicre {}: {:?}", device_name, e);
            return;
        }
    };

    info!("CAP: getting device {}; {:?}", device_name, device.desc);

    let mut cap = match cap
        .promisc(true) // listen all traffic, not only that which is destined for this host
        .immediate_mode(true) // not sure, but it seems to reduce latency
        .snaplen(65535)
        .buffer_size(16 * 1024 * 1024)
        .timeout(3000)
        .open()
    {
        Ok(c) => c,
        Err(e) => {
            error!("Capture device {}: {:?}", device_name, e);
            return;
        }
    };

    info!("CAP: start loop");

    let mut lost_packets:u64 = 0;
    while !shutdown_flag.load(sync::atomic::Ordering::Relaxed) {        
        match cap.next_packet() {
            Ok(packet) => {
                if sender.is_full() || pool_acqure.is_full() { //drop packet
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    lost_packets += 1;
                } else {
                    if let Some(slot) = pool_acqure.acquire(pool_clients_number) {
                        let handle = slot.handle;
                        let cap_data = common::CapData {
                            cap_len: packet.header.caplen as usize,
                            orig_len: packet.header.len as usize,
                            data: packet.data.to_vec(),
                        };
                        match sender.try_send((cap_data, slot)) {
                            Ok(_) => {}
                            Err(flume::TrySendError::Full(_)) => {
                                //warn!("CAP: buffer full, dropping packet");
                                pool_release.release_mandatory(handle);
                                lost_packets += 1;
                                
                            }
                            Err(flume::TrySendError::Disconnected(_)) => {
                                pool_release.release_mandatory(handle);
                                shutdown_flag.store(true, sync::atomic::Ordering::Relaxed);
                                info!("Receivers dropped, stopping capture loop on device {}", device_name);
                            }
                        }
                    } else {
                        lost_packets += 1;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                //info!("Timeout on device {}, continue", device_name);
            }
            Err(e) => {
                error!("Capture error on device {}: {:?}", device_name, e);
                shutdown_flag.store(true, sync::atomic::Ordering::Relaxed);
            }
        }
    }
    info!("CAP: leave capture");
}