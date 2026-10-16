use pcap;
use flume::Sender;
use std::io;
use std::sync;
use std::sync::atomic::Ordering;
use std::time::Duration;
use common;
use tokio::io::unix::AsyncFd;
use tracing::{info, error, warn};


fn open_capture(device: &pcap::Device) -> Option<AsyncFd<pcap::Capture<pcap::Active>>> {
    let device_name = device.name.as_str();

    let cap = match pcap::Capture::from_device(device_name) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create capture from devicre {}: {:?}", device_name, e);
            return None;
        }
    };

    info!("CAP: getting device {}; {:?}", device.name, device.desc);

    let cap = match cap
        .promisc(true) // listen all traffic, not only that which is destined for this host
        .immediate_mode(true) // not sure, but it seems to reduce latency
        .snaplen(65535)
        .buffer_size(16 * 1024 * 1024)
        .open()
    {
        Ok(c) => c,
        Err(e) => {
            error!("Capture device {}: {:?}", device_name, e);
            return None;
        }
    };

    let cap = match cap.setnonblock() {
        Ok(c) => c,
        Err(e) => {
            error!("Set nonblock on device {}: {:?}", device_name, e);
            return None;
        }
    };

    match AsyncFd::new(cap) {
        Ok(c) => Some(c),
        Err(e) => {
            error!("AsyncFd for device {}: {:?}", device_name, e);
            None
        }
    }
}


/// Packet capture loop using a nonblocking `pcap` fd waited on by Tokio.
pub async fn capture_loop(
    device: pcap::Device,
    sender: Sender<(common::CapData, mempool::PoolSlot<common::NetData>)>,
    shutdown_flag: sync::Arc<sync::atomic::AtomicBool>,
    pool_acqure: &(dyn mempool::PoolAcquire<common::NetData> + Sync),
    pool_clients_number: u8,
) {
    info!("CAP: enter capture");

    let device_name = device.name.clone();
    let Some(mut cap) = open_capture(&device) else {
        shutdown_flag.store(true, Ordering::Relaxed);
        return;
    };

    info!("CAP: start loop");

    let mut lost_packets: u64 = 0;
    let mut pending_slot: Option<mempool::PoolSlot<common::NetData>> = None;

    let mut do_break = false;
    while !do_break {
        let guard = cap.readable_mut().await;
        if let Err(e) = guard {
            error!("Capture wait on device {}: {:?}", device_name, e);
            do_break = true;
            continue;
        }
        
        let mut guard = guard.unwrap();
        let mut do_sleep = false;
        while !do_break {
            if do_sleep {
                tokio::time::sleep(Duration::from_millis(1)).await;
                do_sleep = false;
            }
            if sender.is_full() { // Полная очередь: пакет всё равно забираем из pcap, иначе fd останется готовым.
                match guard.try_io (|fd| discard_packet(fd))
                {
                    Ok(Ok(())) => {
                        lost_packets += 1;
                        do_sleep = true;
                    }
                    Ok(Err(e)) => {
                        error!("Capture error on device {}: {:?}", device_name, e);
                        do_break = true;
                    }
                    Err(_) => break,
                }
                continue;
            }
            match guard.try_io(read_packet) {
                Ok(Ok(cap_data)) => {
                    let slot = pending_slot.take().or_else(|| pool_acqure.acquire(pool_clients_number));
                    if let Some(slot) = slot {
                        match sender.try_send((cap_data, slot)) {
                            Ok(_) => { 
                                pending_slot = None;
                            }
                            Err(flume::TrySendError::Full((_, slot))) => {
                                pending_slot = Some(slot);
                                lost_packets += 1;
                                do_sleep = true;
                            }
                            Err(flume::TrySendError::Disconnected(_)) => {
                                do_break = true;
                                info!("Receivers dropped, stopping capture loop on device {}", device_name);
                            }
                        }
                    } else {
                        lost_packets += 1;
                        do_sleep = true;
                    }                    
                }
                Ok(Err(e)) => {
                    error!("Capture error on device {}: {:?}", device_name, e);
                    do_break = true;
                }
                Err(_) => break,
            }
        }
    }
    
    shutdown_flag.store(true, Ordering::Relaxed);
    if lost_packets > 0 {
        warn!("CAP: dropped {lost_packets} packets on {device_name}");
    }
    info!("CAP: leave capture");
}


fn read_packet(fd: &mut AsyncFd<pcap::Capture<pcap::Active>>) -> io::Result<common::CapData> {
    match fd.get_mut().next_packet() {
        Ok(packet)           => Ok(common::CapData {
                                                cap_len : packet.header.caplen as usize,
                                                orig_len: packet.header.len as usize,
                                                data    : packet.data.to_vec(),
                                            }),
        Err(pcap::Error::TimeoutExpired) => Err(io::Error::new(io::ErrorKind::WouldBlock, "timeout expired to read packet")),
        Err(e)                    => Err(io::Error::other(format!("{e:?}"))),
    }
}

fn discard_packet(fd: &mut AsyncFd<pcap::Capture<pcap::Active>>) -> io::Result<()> {
    match fd.get_mut().next_packet() {
        Ok(_)                            => Ok(()),
        Err(pcap::Error::TimeoutExpired) => Err(io::Error::new(io::ErrorKind::WouldBlock, "timeout expired to discard packet")),
        Err(e)                    => Err(io::Error::other(format!("{e:?}"))),
    }
}

