//! Отдаёт разобранные кадры в Unix-датаграмму.
//! Сокет биндится здесь. Получатель присылает любую датаграмму,
//! после этого кадры `NetData` уходят на его адрес.

use std::io::{ErrorKind, Result as IoResult};
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tokio::sync::broadcast::{self, error::TryRecvError};

const IDLE_SLEEP: Duration = Duration::from_millis(2);

struct BoundSocket {
    uds: UnixDatagram,
    path: String,
}

impl BoundSocket {
    fn bind(path: &str) -> IoResult<Self> {
        let _ = std::fs::remove_file(path);
        let uds = UnixDatagram::bind(path)?;
        uds.set_nonblocking(true)?;
        Ok(Self { uds, path: path.to_owned() })
    }
}

impl Drop for BoundSocket {
    fn drop(&mut self) {
        let _ = self.uds.shutdown(std::net::Shutdown::Both);
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn run(socket_path: &str,
           mut rx: broadcast::Receiver<mempool::PoolSlot<common::NetData>>,
           shutdown: Arc<AtomicBool>)
{
    let sock = match BoundSocket::bind(socket_path) {
        Ok(sock) => sock,
        Err(e) => {
            tracing::error!("IPC: failed to bind {}: {}", socket_path, e);
            return;
        }
    };

    let mut peer: Option<SocketAddr> = None;
    let mut frame = Vec::with_capacity(common::net_serde::SER_MAX_FRAME_LEN);
    let mut hello = [0u8; 64];

    while !shutdown.load(Ordering::Relaxed) {
        match sock.uds.recv_from(&mut hello) {
            Ok((_, addr)) => peer = Some(addr),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted => {}
            Err(e) => tracing::warn!("IPC: recv_from: {}", e),
        }

        match rx.try_recv() {
            Ok(slot) => send_frame(&sock, &mut peer, &slot, &mut frame),
            Err(TryRecvError::Empty) => thread::sleep(IDLE_SLEEP),
            Err(TryRecvError::Lagged(_)) => continue,
            Err(TryRecvError::Closed) => break,
        }
    }
}

fn send_frame(sock: &BoundSocket,
              peer: &mut Option<SocketAddr>,
              slot: &mempool::PoolSlot<common::NetData>,
              frame: &mut Vec<u8>)
{
    let Some(addr) = peer.as_ref() else {
        return;
    };
    let data = unsafe { &*slot.body };
    if let Err(e) = common::net_serde::encode(data, frame) {
        tracing::warn!("IPC: encode: {}", e);
        return;
    }
    match sock.uds.send_to_addr(frame, addr) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        Err(e) if e.kind() == ErrorKind::ConnectionRefused || e.kind() == ErrorKind::NotFound => {
            *peer = None;
        }
        Err(e) => tracing::warn!("IPC: send_to: {}", e),
    }
}
