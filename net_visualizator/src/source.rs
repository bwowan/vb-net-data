//! Откуда берутся кадры `NetData`. `poll` ничего не ждёт: вызвал — забрал то, что уже пришло.
//! Так его можно звать и из потока, и из кадра UI.

use common::NetData;
use web_time::Instant;

/// Есть ли живой поток кадров.
#[derive(Clone, Copy, Debug)]
pub enum LinkState {
    Waiting,                        // Hello уходит, ответа ещё не было или он давно затих.
    Connected { last_rx: Instant }, // Хотя бы один кадр разобран. `last_rx` — когда пришёл последний.
}

/// Неблокирующий источник кадров.
pub trait DataSource {
    /// Забирает всё, что уже пришло; ничего не ждёт.
    fn poll(&mut self, out: &mut Vec<NetData>);
    fn state(&self) -> LinkState;
    /// Сколько датаграмм не разобралось как кадр `net_serde`.
    fn decode_errors(&self) -> u64;
}

#[cfg(unix)]
mod uds {
    use std::io::{ErrorKind, Result as IoResult};
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    use super::{DataSource, LinkState};
    use common::NetData;
    use web_time::Instant;

    const HELLO_EVERY: Duration = Duration::from_secs(1);
    const HELLO: &[u8] = b"hi";

    /// Клиент Unix-датаграмм. Сам биндится: у `ipc_sender` нет адреса, пока
    /// получатель не пришлёт любую датаграмму, и отвечать он будет на этот адрес.
    pub struct UdsSource {
        sock: UnixDatagram,         // Сокет для приема/передачи.
        path: String,               // Путь нашего сокета; при `Drop` файл удаляется.
        listener_path: String,      // Куда слать hello.
        buf: Vec<u8>,               // Буфер под один кадр; размер = `SER_MAX_FRAME_LEN`, не растёт.
        last_hello: Instant,        // Когда слали hello.
        last_rx: Option<Instant>,   // Когда пришёл последний кадр.
        decode_errors: u64,         // Сколько датаграмм не разобралось как кадр `net_serde`.
    }

    impl UdsSource {
        /// Биндит `socket_path`, сразу шлёт hello на `listener_path`.
        pub fn open(socket_path: &str, listener_path: &str) -> IoResult<Self> {
            let _ = std::fs::remove_file(socket_path);
            let sock = UnixDatagram::bind(socket_path)?;
            sock.set_nonblocking(true)?;
            let mut src = Self {
                sock,
                path: socket_path.to_owned(),
                listener_path: listener_path.to_owned(),
                buf: vec![0u8; common::net_serde::SER_MAX_FRAME_LEN],
                last_hello: Instant::now(),
                last_rx: None,
                decode_errors: 0,
            };
            src.send_hello();
            tracing::info!("UDS {} -> {}", src.path, src.listener_path);
            Ok(src)
        }

        /// Любая датаграмма годится: `ipc_sender` запоминает адрес отправителя.
        fn send_hello(&mut self) {
            self.last_hello = Instant::now();
            match self.sock.send_to(HELLO, &self.listener_path) {
                Ok(_) => {}
                // Listener ещё не запущен или сокет временно недоступен — не шуметь.
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::NotFound
                            | ErrorKind::ConnectionRefused
                            | ErrorKind::WouldBlock
                            | ErrorKind::Interrupted
                    ) => {}
                Err(e) => tracing::warn!("IPC hello: {e}"),
            }
        }

        /// Нет свежих кадров — пора снова стучаться hello.
        fn silent(&self) -> bool {
            match self.last_rx {
                Some(t) => t.elapsed() >= HELLO_EVERY,
                None => true,
            }
        }
    }

    impl Drop for UdsSource {
        fn drop(&mut self) {
            let _ = self.sock.shutdown(std::net::Shutdown::Both);
            let _ = std::fs::remove_file(&self.path);
        }
    }

    impl DataSource for UdsSource {
        fn poll(&mut self, out: &mut Vec<NetData>) {
            // Пока кадров нет — hello раз в секунду. Так мы дожидаемся listener
            // и возвращаемся после его рестарта: он забывает peer.
            if self.silent() && self.last_hello.elapsed() >= HELLO_EVERY {
                self.send_hello();
            }
            loop {
                match self.sock.recv(&mut self.buf) {
                    Ok(0) => {}
                    Ok(n) => match common::net_serde::decode(&self.buf[..n]) {
                        Ok(data) => {
                            self.last_rx = Some(Instant::now());
                            out.push(data);
                        }
                        Err(e) => {
                            self.decode_errors += 1;
                            tracing::warn!("IPC decode: {e}");
                        }
                    },
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => {
                        tracing::warn!("IPC recv: {e}");
                        break;
                    }
                }
            }
        }

        fn state(&self) -> LinkState {
            match self.last_rx {
                Some(last_rx) => LinkState::Connected { last_rx },
                None => LinkState::Waiting,
            }
        }

        fn decode_errors(&self) -> u64 {
            self.decode_errors
        }
    }
}

#[cfg(unix)]
pub use uds::UdsSource;

#[cfg(all(test, unix))]
mod tests {
    use std::io::ErrorKind;
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    use super::{DataSource, LinkState, UdsSource};
    use common::{EthData, EthType, IpData, IpL4, MacAddr6, NetData, NetPayload};
    use std::net::{IpAddr, Ipv4Addr};

    struct Tmp(&'static str);

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.0);
        }
    }

    fn sample() -> NetData {
        NetData {
            eth: EthData {
                src: MacAddr6([1, 2, 3, 4, 5, 6]),
                dst: MacAddr6([6, 5, 4, 3, 2, 1]),
                dir: common::EDirection::Incoming,
                prot: EthType::Ipv4,
            },
            payload: NetPayload::Ip(IpData {
                src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                len: 100,
                l4: IpL4::Tcp {
                    src_port: 40000,
                    dst_port: 443,
                },
            }),
        }
    }

    fn recv_hello(server: &UnixDatagram) -> Vec<u8> {
        let mut buf = [0u8; 64];
        for _ in 0..50 {
            match server.recv(&mut buf) {
                Ok(n) => return buf[..n].to_vec(),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("recv hello: {e}"),
            }
        }
        panic!("no hello");
    }

    /// Listener получает hello, отвечает кадром, `poll` возвращает тот же `NetData`.
    /// После тишины hello уходит ещё раз — иначе рестарт listener нас не найдёт.
    #[test]
    fn hello_roundtrip_and_repeat_after_silence() {
        let dir = format!("/tmp/netviz-{}-rt", std::process::id());
        let _tmp = Tmp(Box::leak(dir.clone().into_boxed_str()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = format!("{dir}/listener.sock");
        let client = format!("{dir}/client.sock");
        let server = UnixDatagram::bind(&listener).unwrap();
        server.set_nonblocking(true).unwrap();

        let mut src = UdsSource::open(&client, &listener).unwrap();
        assert!(matches!(src.state(), LinkState::Waiting));
        assert_eq!(recv_hello(&server), b"hi");

        let mut frame = Vec::new();
        common::net_serde::encode(&sample(), &mut frame).unwrap();
        server.send_to(&frame, &client).unwrap();

        let mut out = Vec::new();
        for _ in 0..20 {
            src.poll(&mut out);
            if !out.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(out.len(), 1, "frame was not delivered");
        let mut again = Vec::new();
        common::net_serde::encode(&out[0], &mut again).unwrap();
        assert_eq!(again, frame);
        assert!(matches!(src.state(), LinkState::Connected { .. }));

        std::thread::sleep(Duration::from_millis(1200));
        src.poll(&mut Vec::new());
        assert_eq!(recv_hello(&server), b"hi");

        drop(src);
        assert!(!std::path::Path::new(&client).exists());
    }

    /// Короткий мусор не роняет приём: ошибка считается, в выход ничего не кладётся.
    #[test]
    fn short_datagram_is_a_decode_error() {
        let dir = format!("/tmp/netviz-{}-bad", std::process::id());
        let _tmp = Tmp(Box::leak(dir.clone().into_boxed_str()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = format!("{dir}/listener.sock");
        let client = format!("{dir}/client.sock");
        let server = UnixDatagram::bind(&listener).unwrap();
        server.set_nonblocking(true).unwrap();
        let mut src = UdsSource::open(&client, &listener).unwrap();
        let _ = recv_hello(&server);

        server.send_to(&[1, 2, 3, 4], &client).unwrap();
        let mut out = Vec::new();
        for _ in 0..20 {
            src.poll(&mut out);
            if src.decode_errors() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(out.is_empty());
        assert_eq!(src.decode_errors(), 1);
    }
}
