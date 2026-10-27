//! Одна строка таблицы. Колонки собираются при приёме, чтобы кадр UI их не разбирал заново.

use std::net::IpAddr;

use common::{
    CiscoData, EDirection, EthType, IpL4, NetData, NetPayload, ParseError, UdpApp, UdpMsg,
};
use web_time::{SystemTime, UNIX_EPOCH};

/// Индекс совпадает с `Filter::dir` и `ConnRec::saw`.
pub(crate) fn dir_index(dir: EDirection) -> usize {
    match dir {
        EDirection::Unknown => 0,
        EDirection::Incoming => 1,
        EDirection::Outgoing => 2,
        EDirection::Broadcast => 3,
        EDirection::Multicast => 4,
    }
}

/// Байты IP-payload; для не-IP в статистике пишем 0.
pub(crate) fn packet_len(data: &NetData) -> u64 {
    match &data.payload {
        NetPayload::Ip(ip) => ip.len as u64,
        _ => 0,
    }
}

/// Готовая строка таблицы + исходный `NetData` для раскрытия.
pub(crate) struct Row {
    pub(crate) seq: u64,
    /// Местное время приёма (`HH:MM:SS.mmm`).
    pub(crate) time: String,
    pub(crate) dir: String,
    pub(crate) l2: String,
    pub(crate) src: String,
    pub(crate) dst: String,
    pub(crate) proto: String,
    pub(crate) len: u64,
    /// Краткая сводка (DNS-имя, ICMP, ARP…); полный разбор — в `data`.
    pub(crate) info: String,
    pub(crate) data: NetData,
}

impl Row {
    /// Собирает колонки один раз при приёме кадра.
    pub(crate) fn from_owned(seq: u64, data: NetData) -> Self {
        let (l2, src, dst, proto, info) = columns(&data);
        let len = packet_len(&data);
        let dir = data.eth.dir.to_string();
        Self {
            seq,
            time: format_local(SystemTime::now()),
            dir,
            l2,
            src,
            dst,
            proto,
            len,
            info,
            data,
        }
    }
}

/// `(l2, src, dst, proto, info)`.
fn columns(data: &NetData) -> (String, String, String, String, String) {
    let l2 = l2_label(data).to_string();
    let (src, dst) = endpoints(data);
    (l2, src, dst, proto_label(data), info_label(data))
}

/// Колонка L2: по payload, не только по EtherType.
fn l2_label(data: &NetData) -> &'static str {
    match &data.payload {
        NetPayload::Ip(_) => match data.eth.prot {
            EthType::Ipv6 => "IPv6",
            _ => "IPv4",
        },
        NetPayload::Arp(_) => match data.eth.prot {
            EthType::Rarp => "RARP",
            _ => "ARP",
        },
        NetPayload::Mpls(_) => "MPLS",
        NetPayload::Lldp(_) => "LLDP",
        NetPayload::Ectp(_) => "ECTP",
        NetPayload::DEC(_) => "DEC",
        NetPayload::Cisco(_) => "Cisco",
        NetPayload::Err(_) => "ERR",
    }
}

/// IP:порт для TCP/UDP, иначе IP или MAC.
fn endpoints(data: &NetData) -> (String, String) {
    match &data.payload {
        NetPayload::Ip(ip) => match &ip.l4 {
            IpL4::Tcp { src_port, dst_port }
            | IpL4::Udp {
                src_port, dst_port, ..
            } => (
                format!("{}:{src_port}", ip.src),
                format!("{}:{dst_port}", ip.dst),
            ),
            _ => (ip.src.to_string(), ip.dst.to_string()),
        },
        NetPayload::Err(err) => error_ips(err).unwrap_or_else(|| macs(data)),
        _ => macs(data),
    }
}

fn macs(data: &NetData) -> (String, String) {
    (data.eth.src.to_string(), data.eth.dst.to_string())
}

/// У части `ParseError` адреса уже есть — показываем их вместо MAC.
fn error_ips(err: &ParseError) -> Option<(String, String)> {
    let (src, dst): (&IpAddr, &IpAddr) = match err {
        ParseError::Tcp_Broken { src, dst, .. }
        | ParseError::Udp_Broken { src, dst, .. }
        | ParseError::Icmp4_Broken { src, dst, .. }
        | ParseError::Icmp6_Broken { src, dst, .. }
        | ParseError::Igmp_Broken { src, dst, .. }
        | ParseError::Esp_Broken { src, dst, .. }
        | ParseError::Ip4_Fragment { src, dst }
        | ParseError::Ip6_Fragment { src, dst } => (src, dst),
        _ => return None,
    };
    Some((src.to_string(), dst.to_string()))
}

/// Колонка Proto: TCP, UDP/DNS, ICMPv6, CDP…
fn proto_label(data: &NetData) -> String {
    match &data.payload {
        NetPayload::Ip(ip) => match &ip.l4 {
            IpL4::Tcp { .. } => "TCP".to_string(),
            IpL4::Udp { app, .. } => {
                if *app == UdpApp::Other {
                    "UDP".to_string()
                } else {
                    format!("UDP/{app}")
                }
            }
            IpL4::Icmp4(_) => "ICMPv4".to_string(),
            IpL4::Icmp6(_) => "ICMPv6".to_string(),
            IpL4::Igmp(_) => "IGMP".to_string(),
            IpL4::Esp(_) => "ESP".to_string(),
            IpL4::Other(t) => t.to_string(),
        },
        NetPayload::Arp(_) => "ARP".to_string(),
        NetPayload::Mpls(_) => "MPLS".to_string(),
        NetPayload::Lldp(_) => "LLDP".to_string(),
        NetPayload::Ectp(_) => "ECTP".to_string(),
        NetPayload::DEC(_) => "DEC".to_string(),
        NetPayload::Cisco(c) => cisco_name(c).to_string(),
        NetPayload::Err(_) => "ERR".to_string(),
    }
}

fn cisco_name(c: &CiscoData) -> &'static str {
    match c {
        CiscoData::CDP(_) => "CDP",
        CiscoData::CGMP => "CGMP",
        CiscoData::VTP => "VTP",
        CiscoData::DTP => "DTP",
        CiscoData::PAGP => "PAGP",
        CiscoData::PVSTP => "PVSTP",
        CiscoData::UDLD => "UDLD",
    }
}

/// Краткая сводка из `Display` подтипов common; многострочное режем до первой строки.
fn info_label(data: &NetData) -> String {
    match &data.payload {
        NetPayload::Ip(ip) => match &ip.l4 {
            IpL4::Udp { msg, .. } => udp_info(msg),
            IpL4::Icmp4(m) => m.to_string(),
            IpL4::Icmp6(m) => m.to_string(),
            IpL4::Igmp(m) => m.to_string(),
            IpL4::Esp(m) => m.to_string(),
            IpL4::Tcp { .. } | IpL4::Other(_) => String::new(),
        },
        NetPayload::Arp(a) => a.to_string(),
        NetPayload::Mpls(m) => m.to_string(),
        NetPayload::Lldp(d) => first_line(&d.to_string()),
        NetPayload::Ectp(d) => d.to_string(),
        NetPayload::DEC(d) => format!("prot=0x{:04X}", d.protocol_id),
        NetPayload::Cisco(c) => first_line(&c.to_string()),
        NetPayload::Err(e) => e.to_string(),
    }
}

fn udp_info(msg: &Option<UdpMsg>) -> String {
    match msg {
        Some(UdpMsg::Query(q)) => q.to_string(),
        Some(UdpMsg::Dhcp6 { msg, addr, dns }) => {
            let mut s = msg.to_string();
            if let Some(ip) = addr {
                s.push(' ');
                s.push_str(&ip.to_string());
            }
            for ip in dns {
                s.push(' ');
                s.push_str(&ip.to_string());
            }
            s
        }
        Some(UdpMsg::Dhcp4 {
            msg,
            host,
            requested,
            router,
            dns,
            server,
            lease,
            domain,
        }) => {
            let mut s = String::new();
            let mut push = |part: &str| {
                if !s.is_empty() {
                    s.push(' ');
                }
                s.push_str(part);
            };
            if let Some(m) = msg {
                push(&m.to_string());
            }
            if let Some(h) = host {
                push(h);
            }
            if let Some(ip) = requested {
                push(&ip.to_string());
            }
            if let Some(ip) = router {
                push(&ip.to_string());
            }
            for ip in dns {
                push(&ip.to_string());
            }
            if let Some(ip) = server {
                push(&ip.to_string());
            }
            if let Some(sec) = lease {
                push(&sec.to_string());
            }
            if let Some(name) = domain {
                push(name);
            }
            s
        }
        Some(UdpMsg::Ssdp(s)) => {
            let mut out = s.start.to_string();
            if let Some(nt) = &s.nt {
                out.push_str(" NT=");
                out.push_str(nt);
            }
            out
        }
        Some(UdpMsg::Nbns(n)) => n.to_string(),
        None => String::new(),
    }
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("").to_string()
}

/// Местное время суток. Смещение кэшируется: `localtime_r` на каждый кадр не нужен.
fn format_local(t: SystemTime) -> String {
    let ms = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
    let secs = (ms / 1000) as i64 + local_offset_secs();
    let millis = (ms % 1000) as u64;
    let tod = secs.rem_euclid(86_400) as u64;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60,
        millis
    )
}

/// Смещение локальной зоны от UTC в секундах (на не-Linux — 0).
fn local_offset_secs() -> i64 {
    #[cfg(target_os = "linux")]
    {
        linux_offset()
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// `AtomicU64` на wasm32 нет, а смещение нужно только здесь.
#[cfg(target_os = "linux")]
fn linux_offset() -> i64 {
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
    static OFF: AtomicI64 = AtomicI64::new(0);
    static AT: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let at = AT.load(Ordering::Relaxed);
    if at != 0 && now.saturating_sub(at) < 60 {
        return OFF.load(Ordering::Relaxed);
    }
    let off = read_offset();
    OFF.store(off, Ordering::Relaxed);
    AT.store(now, Ordering::Relaxed);
    off
}

#[cfg(target_os = "linux")]
fn read_offset() -> i64 {
    // SAFETY: `tm` жив на время вызова, `localtime_r` пишет только в него.
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            0
        } else {
            tm.tm_gmtoff as i64
        }
    }
}

/// Минимальный TCP IPv4 для тестов Store/Filter.
#[cfg(test)]
pub(crate) fn tcp_packet(
    src: [u8; 4],
    sport: u16,
    dst: [u8; 4],
    dport: u16,
    len: usize,
    dir: EDirection,
) -> NetData {
    use std::net::Ipv4Addr;
    NetData {
        eth: common::EthData {
            src: common::MacAddr6([1, 0, 0, 0, 0, 1]),
            dst: common::MacAddr6([2, 0, 0, 0, 0, 2]),
            dir,
            prot: EthType::Ipv4,
        },
        payload: NetPayload::Ip(common::IpData {
            src: IpAddr::V4(Ipv4Addr::from(src)),
            dst: IpAddr::V4(Ipv4Addr::from(dst)),
            len,
            l4: IpL4::Tcp {
                src_port: sport,
                dst_port: dport,
            },
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Порты TCP стоят в src/dst, протокол и длина — в своих колонках.
    #[test]
    fn tcp_columns_show_ports() {
        let row = Row::from_owned(
            7,
            tcp_packet(
                [10, 0, 0, 1],
                40000,
                [1, 2, 3, 4],
                443,
                100,
                EDirection::Incoming,
            ),
        );
        assert_eq!(row.seq, 7);
        assert_eq!(row.src, "10.0.0.1:40000");
        assert_eq!(row.dst, "1.2.3.4:443");
        assert_eq!(row.proto, "TCP");
        assert_eq!(row.l2, "IPv4");
        assert_eq!(row.len, 100);
        assert_eq!(row.dir, "-->");
        assert_eq!(row.time.len(), 12);
    }
}
