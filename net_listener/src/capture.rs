use pcap;
use flume::Sender;
use std::sync;
use common;
use tracing::{info, error, warn};


/// Packet capture loop using `pcap`.
pub fn capture_loop(
    device: pcap::Device, 
    sender: Sender<common::CapData>,
    shutdown_flag: sync::Arc<sync::atomic::AtomicBool>,
) {
    info!("CAP: enter capture");

    let device_name = device.name.clone();

    let cap = match pcap::Capture::from_device(device.name.as_str()) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create capture from device {}: {:?}", device_name, e);
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

    while !shutdown_flag.load(sync::atomic::Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                let cap_data = common::CapData {
                    cap_len: packet.header.caplen as usize,
                    orig_len: packet.header.len as usize,
                    data: packet.data.to_vec(),
                };
                
                match sender.try_send(cap_data) {
                    Ok(_) => {}
                    Err(flume::TrySendError::Full(_)) => {
                        warn!("CAP: buffer full, dropping packet");
                    }
                    Err(flume::TrySendError::Disconnected(_)) => {
                        info!("Receivers dropped, stopping capture loop on device {}", device_name);
                        break;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                //info!("Timeout on device {}, continue", device_name);
                continue; // Timeout, continue the loop to check shutdown_flag
            }
            Err(e) => {
                error!("Capture error on device {}: {:?}", device_name, e);
                break;
            }
        }
    }
    
    info!("CAP: leave capture");
}