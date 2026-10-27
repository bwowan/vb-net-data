//! Кольцо последних кадров, суммарная статистика и таблица соединений.
//! Статистика и соединения обновляются до кольца: пауза прячет строки, но не счётчики.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use common::{EthType, IpL4, NetData, NetPayload, UdpApp};
use web_time::{Duration, Instant};

use crate::row::{self, Row};
use crate::source::LinkState;

/// Сколько последних кадров держит таблица пакетов.
pub(crate) const RING_CAP: usize = 2000;
/// Верхняя граница карты соединений; сверх — вытесняем самое старое.
pub(crate) const CONN_CAP: usize = 4096;
/// Соединение без пакетов дольше этого забывается.
const CONN_IDLE: Duration = Duration::from_secs(60);

/// Счётчик одной корзины (направление / L4 / …).
#[derive(Clone, Copy, Default)]
pub(crate) struct Tot {
    pub(crate) pkts: u64,
    // По корзинам байты копятся вместе с пакетами; строка статуса показывает общую сумму.
    #[allow(dead_code)]
    pub(crate) bytes: u64,
}

/// Онлайн-агрегация: всё время + скорость за последнюю закрытую секунду.
pub(crate) struct Stats {
    pub(crate) packets: u64,
    pub(crate) bytes: u64,
    /// Накопленное с прошлого `tick`.
    pub(crate) interval_packets: u64,
    pub(crate) interval_bytes: u64,
    /// Что показать как pkt/s и B/s до следующего `tick`.
    pub(crate) last_packets: u64,
    pub(crate) last_bytes: u64,
    rate_at: Instant,
    pub(crate) dir: [Tot; 5],
    pub(crate) l4: [Tot; 6],
    pub(crate) ip: [Tot; 3],
    pub(crate) eth: [Tot; 8],
}

impl Stats {
    fn new() -> Self {
        Self {
            packets: 0,
            bytes: 0,
            interval_packets: 0,
            interval_bytes: 0,
            last_packets: 0,
            last_bytes: 0,
            rate_at: Instant::now(),
            dir: [Tot::default(); 5],
            l4: [Tot::default(); 6],
            ip: [Tot::default(); 3],
            eth: [Tot::default(); 8],
        }
    }

    /// Учитывает кадр в суммах и во всех корзинах.
    fn add(&mut self, data: &NetData) {
        let bytes = row::packet_len(data);
        self.packets += 1;
        self.bytes += bytes;
        self.interval_packets += 1;
        self.interval_bytes += bytes;
        add_tot(&mut self.dir[row::dir_index(data.eth.dir)], bytes);
        add_tot(&mut self.eth[eth_index(data.eth.prot)], bytes);
        match &data.payload {
            NetPayload::Ip(ip) => {
                let ip_i = match ip.src {
                    IpAddr::V4(_) => 0,
                    IpAddr::V6(_) => 1,
                };
                add_tot(&mut self.ip[ip_i], bytes);
                add_tot(&mut self.l4[l4_index(&ip.l4)], bytes);
            }
            _ => add_tot(&mut self.ip[2], bytes),
        }
    }
}

fn add_tot(tot: &mut Tot, bytes: u64) {
    tot.pkts += 1;
    tot.bytes += bytes;
}

/// Индекс в `Stats::l4` / `L4_NAMES`.
fn l4_index(l4: &IpL4) -> usize {
    match l4 {
        IpL4::Tcp { .. }                => 0,
        IpL4::Udp { .. }                => 1,
        IpL4::Icmp4(_) | IpL4::Icmp6(_) => 2,
        IpL4::Igmp(_)                   => 3,
        IpL4::Esp(_)                    => 4,
        IpL4::Other(_)                  => 5,
    }
}

/// Индекс в `Stats::eth` / `ETH_NAMES`.
fn eth_index(prot: EthType) -> usize {
    match prot {
        EthType::Ipv4                      => 0, // Internet Protocol version 4 (IPv4).
        EthType::Ipv6                      => 1, // Internet Protocol version 6 (IPv6).
        EthType::Arp                       => 2, // Address Resolution Protocol (ARP).
        EthType::Rarp                      => 3, // Reverse Address Resolution Protocol.
        EthType::Mpls | EthType::MplsMcast => 4, // Multi-Protocol Label Switching.
        EthType::Lldp                      => 5, // Link Layer Discovery Protocol.
        EthType::Ectp                      => 6, // Ethernet Control and Transport Protocol.
        EthType::Unsupported               => 7, // Unsupported Ethernet Type.
    }
}

pub(crate) const DIR_NAMES: [&str; 5] = ["unknown", "in", "out", "bcast", "mcast"];
pub(crate) const L4_NAMES: [&str; 6] = ["tcp", "udp", "icmp", "igmp", "esp", "other"];
pub(crate) const IP_NAMES: [&str; 3] = ["ipv4", "ipv6", "non-ip"];
pub(crate) const ETH_NAMES: [&str; 8] = [
    "IPv4", "IPv6", "ARP", "RARP", "MPLS", "LLDP", "ECTP", "other",
];

/// Транспорт, по которому склеиваем поток (TCP и UDP раздельно).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum ConnProto {
    Tcp,
    Udp,
}

/// Нормализованный ключ: `(a, pa) <= (b, pb)`, чтобы оба направления совпали.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) struct ConnKey {
    pub(crate) proto: ConnProto, // Protocol.
    pub(crate) a    : IpAddr,    // Source IP address.
    pub(crate) pa   : u16,       // Source port.
    pub(crate) b    : IpAddr,    // Destination IP address.
    pub(crate) pb   : u16,       // Destination port.
}

/// Счётчики одного потока; `ab` — от меньшего конца ключа к большему.
pub(crate) struct ConnRec {
    pub(crate) pkts_ab: u64,
    pub(crate) bytes_ab: u64,
    pub(crate) pkts_ba: u64,
    pub(crate) bytes_ba: u64,
    // Начало потока. Таблица показывает простой от `last`, не отсюда.
    #[allow(dead_code)]
    pub(crate) first: Instant,
    pub(crate) last: Instant,
    pub(crate) udp_app: UdpApp,
    /// Какие направления `EDirection` уже видели у этого потока.
    pub(crate) saw: [bool; 5],
}

/// Общее состояние: кольцо строк, статистика, соединения, линк.
pub struct Store {
    pub(crate) ring: VecDeque<Row>,
    /// Монотонный номер кадра для колонки `#` и раскрытия строки.
    next_seq: u64,
    pub(crate) stats: Stats,
    pub(crate) conns: HashMap<ConnKey, ConnRec>,
    pub(crate) link: LinkState,
    pub(crate) decode_errors: u64,
}

impl Store {
    pub fn new() -> Self {
        Self {
            ring: VecDeque::new(),
            next_seq: 1,
            stats: Stats::new(),
            conns: HashMap::new(),
            link: LinkState::Waiting,
            decode_errors: 0,
        }
    }

    /// `keep_row == false` — пауза: кадр учитывается, в кольцо не пишется.
    pub fn ingest(&mut self, data: NetData, keep_row: bool) {
        self.tick();
        self.stats.add(&data);
        self.note_conn(&data);
        if self.conns.len() > CONN_CAP {
            self.evict_conns();
        }
        if keep_row {
            if self.ring.len() >= RING_CAP {
                self.ring.pop_front();
            }
            let seq = self.next_seq;
            self.next_seq += 1;
            self.ring.push_back(Row::from_owned(seq, data));
        }
    }

    /// Копия состояния источника для строки статуса в UI.
    pub fn set_link(&mut self, link: LinkState) {
        self.link = link;
    }

    /// Счётчик ошибок разбора с источника (не сбрасываем при паузе).
    pub fn set_decode_errors(&mut self, n: u64) {
        self.decode_errors = n;
    }

    /// Раз в секунду интервал становится скоростью. Если секунд прошло больше двух,
    /// показывать старый всплеск уже нечего — скорость ноль.
    pub fn tick(&mut self) {
        let elapsed = self.stats.rate_at.elapsed();
        if elapsed < Duration::from_secs(1) {
            return;
        }
        if elapsed >= Duration::from_secs(2) {
            self.stats.last_packets = 0;
            self.stats.last_bytes = 0;
        } else {
            self.stats.last_packets = self.stats.interval_packets;
            self.stats.last_bytes = self.stats.interval_bytes;
        }
        self.stats.interval_packets = 0;
        self.stats.interval_bytes = 0;
        self.stats.rate_at = Instant::now();
    }

    /// Сначала idle, потом самые старые по `last`, пока не уложимся в кап.
    pub fn evict_conns(&mut self) {
        let now = Instant::now();
        self.conns
            .retain(|_, rec| now.saturating_duration_since(rec.last) < CONN_IDLE);
        while self.conns.len() > CONN_CAP {
            let old = self
                .conns
                .iter()
                .min_by_key(|(_, rec)| rec.last)
                .map(|(key, _)| key.clone());
            let Some(old) = old else { break };
            self.conns.remove(&old);
        }
    }

    /// TCP/UDP → одно соединение на пару адресов:портов; ICMP и прочее не считаем.
    fn note_conn(&mut self, data: &NetData) {
        let NetPayload::Ip(ip) = &data.payload else {
            return;
        };
        let (proto, sport, dport, app) = match &ip.l4 {
            IpL4::Tcp { src_port, dst_port } => {
                (ConnProto::Tcp, *src_port, *dst_port, UdpApp::Other)
            }
            IpL4::Udp {
                src_port,
                dst_port,
                app,
                ..
            } => (ConnProto::Udp, *src_port, *dst_port, *app),
            _ => return,
        };
        let (key, forward) = flow_key(proto, ip.src, sport, ip.dst, dport);
        let bytes = row::packet_len(data);
        let now = Instant::now();
        let di = row::dir_index(data.eth.dir);
        if let Some(rec) = self.conns.get_mut(&key) {
            add_side(rec, forward, bytes);
            rec.last = now;
            rec.saw[di] = true;
            if app != UdpApp::Other {
                rec.udp_app = app;
            }
            return;
        }
        let mut rec = ConnRec {
            pkts_ab: 0,
            bytes_ab: 0,
            pkts_ba: 0,
            bytes_ba: 0,
            first: now,
            last: now,
            udp_app: app,
            saw: [false; 5],
        };
        add_side(&mut rec, forward, bytes);
        rec.saw[di] = true;
        self.conns.insert(key, rec);
    }
}

/// `forward` — пакет шёл от `a` к `b` в ключе, иначе наоборот.
fn add_side(rec: &mut ConnRec, forward: bool, bytes: u64) {
    if forward {
        rec.pkts_ab += 1;
        rec.bytes_ab += bytes;
    } else {
        rec.pkts_ba += 1;
        rec.bytes_ba += bytes;
    }
}

/// Как `flow_key` в `console.rs`: меньший конец — `a`, больший — `b`.
/// Второй элемент — шёл ли пакет в сторону a→b.
fn flow_key(proto: ConnProto, src: IpAddr, sport: u16, dst: IpAddr, dport: u16) -> (ConnKey, bool) {
    if (src, sport) <= (dst, dport) {
        (
            ConnKey {
                proto,
                a: src,
                pa: sport,
                b: dst,
                pb: dport,
            },
            true,
        )
    } else {
        (
            ConnKey {
                proto,
                a: dst,
                pa: dport,
                b: src,
                pb: sport,
            },
            false,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::row::tcp_packet;
    use common::EDirection;

    /// Кольцо держит 2000 последних кадров. Первый вытесняется, номера не переиспользуются.
    #[test]
    fn ring_keeps_the_last_2000() {
        let mut store = Store::new();
        for n in 0..2001 {
            store.ingest(
                tcp_packet(
                    [10, 0, 0, 1],
                    10,
                    [10, 0, 0, 2],
                    80,
                    60,
                    EDirection::Incoming,
                ),
                true,
            );
            let _ = n;
        }
        assert_eq!(store.ring.len(), RING_CAP);
        assert_eq!(store.ring.front().unwrap().seq, 2);
        assert_eq!(store.ring.back().unwrap().seq, 2001);
    }

    /// Оба направления TCP — одно соединение, байты не смешиваются.
    #[test]
    fn both_directions_share_one_connection() {
        let mut store = Store::new();
        store.ingest(
            tcp_packet(
                [10, 0, 0, 1],
                10,
                [10, 0, 0, 2],
                80,
                100,
                EDirection::Outgoing,
            ),
            true,
        );
        store.ingest(
            tcp_packet(
                [10, 0, 0, 2],
                80,
                [10, 0, 0, 1],
                10,
                40,
                EDirection::Incoming,
            ),
            true,
        );
        assert_eq!(store.conns.len(), 1);
        let rec = store.conns.values().next().unwrap();
        assert_eq!(rec.pkts_ab, 1);
        assert_eq!(rec.bytes_ab, 100);
        assert_eq!(rec.pkts_ba, 1);
        assert_eq!(rec.bytes_ba, 40);
        assert_eq!(store.stats.packets, 2);
        assert_eq!(store.stats.bytes, 140);
        assert_eq!(store.stats.l4[0].pkts, 2);
    }

    /// Молчащее соединение уходит через минуту. Свежее остаётся.
    #[test]
    fn idle_connection_is_evicted() {
        let mut store = Store::new();
        store.ingest(
            tcp_packet(
                [10, 0, 0, 1],
                1,
                [10, 0, 0, 2],
                80,
                10,
                EDirection::Incoming,
            ),
            false,
        );
        store.ingest(
            tcp_packet(
                [10, 0, 0, 1],
                2,
                [10, 0, 0, 2],
                80,
                10,
                EDirection::Incoming,
            ),
            false,
        );
        let stale = flow_key(
            ConnProto::Tcp,
            IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            1,
            IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
            80,
        )
        .0;
        store.conns.get_mut(&stale).unwrap().last = Instant::now() - Duration::from_secs(61);
        store.evict_conns();
        assert!(!store.conns.contains_key(&stale));
        assert_eq!(store.conns.len(), 1);
    }

    /// Сверх лимита вытесняется соединение с самым старым `last`.
    #[test]
    fn connection_cap_evicts_the_oldest() {
        let mut store = Store::new();
        for port in 0..CONN_CAP as u16 {
            store.ingest(
                tcp_packet(
                    [10, 0, 0, 1],
                    port,
                    [10, 0, 0, 2],
                    1,
                    10,
                    EDirection::Incoming,
                ),
                false,
            );
        }
        assert_eq!(store.conns.len(), CONN_CAP);
        let oldest = flow_key(
            ConnProto::Tcp,
            IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            0,
            IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
            1,
        )
        .0;
        store.conns.get_mut(&oldest).unwrap().last = Instant::now() - Duration::from_secs(5);
        store.ingest(
            tcp_packet([10, 1, 0, 1], 9, [10, 1, 0, 2], 9, 10, EDirection::Incoming),
            false,
        );
        assert_eq!(store.conns.len(), CONN_CAP);
        assert!(!store.conns.contains_key(&oldest));
    }

    /// Пауза не пишет строку, статистика и соединение при этом растут.
    #[test]
    fn pause_skips_the_ring() {
        let mut store = Store::new();
        store.ingest(
            tcp_packet(
                [10, 0, 0, 1],
                10,
                [10, 0, 0, 2],
                80,
                50,
                EDirection::Incoming,
            ),
            false,
        );
        assert!(store.ring.is_empty());
        assert_eq!(store.stats.packets, 1);
        assert_eq!(store.conns.len(), 1);
    }
}
