//! Один и тот же фильтр стоит глобально и на каждой вкладке.
//! Строка видна, только если её пропускают оба: см. [`visible_row`].

use common::{IpL4, NetPayload, UdpApp};

use crate::row::{self, Row};
use crate::store::{ConnKey, ConnProto, ConnRec};

const DIR_NAMES: [&str; 5] = ["Unknown", "In", "Out", "Bcast", "Mcast"];

const UDP_APPS: [(UdpApp, &str); 12] = [
    (UdpApp::Dhcp4      , "DHCP"),
    (UdpApp::Dhcp6      , "DHCPv6"),
    (UdpApp::Dns        , "DNS"),
    (UdpApp::Mdns       , "mDNS"),
    (UdpApp::Ssdp       , "SSDP"),
    (UdpApp::Llmnr      , "LLMNR"),
    (UdpApp::Nbns       , "NBNS"),
    (UdpApp::Ntp        , "NTP"),
    (UdpApp::Quic       , "QUIC"),
    (UdpApp::Wireguard  , "WireGuard"),
    (UdpApp::EspOverUdp , "ESP-UDP"),
    (UdpApp::Other      , "Other"),
];

/// Чекбоксы + текстовый поиск. По умолчанию всё включено.
#[derive(Clone)]
pub(crate) struct Filter {
    /// Индекс — `row::dir_index`.
    dir      : [bool; 5],
    tcp      : bool,
    udp      : bool,
    icmp     : bool,
    igmp     : bool,
    esp      : bool,
    other_l4 : bool,
    ipv4     : bool,
    ipv6     : bool,
    /// ARP, LLDP и прочий не-IP.
    non_ip   : bool,
    /// Порядок как в `UDP_APPS` / `udp_index`.
    udp_app  : [bool; 12],
    arp      : bool,
    lldp     : bool,
    cdp      : bool,
    mpls     : bool,
    dec      : bool,
    ectp     : bool,
    err      : bool,
    /// Подстрока по src/dst/info без учёта регистра; пустая — не режет.
    text     : String,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            dir      : [true; 5],
            tcp      : true,
            udp      : true,
            icmp     : true,
            igmp     : true,
            esp      : true,
            other_l4 : true,
            ipv4     : true,
            ipv6     : true,
            non_ip   : true,
            udp_app  : [true; 12],
            arp      : true,
            lldp     : true,
            cdp      : true,
            mpls     : true,
            dec      : true,
            ectp     : true,
            err      : true,
            text     : String::new(),
        }
    }
}

impl Filter {
    /// Рисует все галочки и поле поиска (глобальный и локальный — один виджет).
    pub(crate) fn ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Direction");
            for (flag, name) in self.dir.iter_mut().zip(DIR_NAMES) {
                ui.checkbox(flag, name);
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("L4");
            ui.checkbox(&mut self.tcp, "TCP");
            ui.checkbox(&mut self.udp, "UDP");
            ui.checkbox(&mut self.icmp, "ICMP");
            ui.checkbox(&mut self.igmp, "IGMP");
            ui.checkbox(&mut self.esp, "ESP");
            ui.checkbox(&mut self.other_l4, "Other");
            ui.separator();
            ui.label("IP");
            ui.checkbox(&mut self.ipv4, "IPv4");
            ui.checkbox(&mut self.ipv6, "IPv6");
            ui.checkbox(&mut self.non_ip, "non-IP");
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("L2");
            ui.checkbox(&mut self.arp, "ARP");
            ui.checkbox(&mut self.lldp, "LLDP");
            ui.checkbox(&mut self.cdp, "Cisco");
            ui.checkbox(&mut self.mpls, "MPLS");
            ui.checkbox(&mut self.dec, "DEC");
            ui.checkbox(&mut self.ectp, "ECTP");
            ui.checkbox(&mut self.err, "Errors");
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("UDP");
            for (flag, (_, name)) in self.udp_app.iter_mut().zip(UDP_APPS) {
                ui.checkbox(flag, name);
            }
        });
        ui.horizontal(|ui| {
            ui.label("Search");
            ui.add(
                egui::TextEdit::singleline(&mut self.text)
                    .desired_width(280.0)
                    .hint_text("ip, mac, text"),
            );
        });
    }

    /// Строка таблицы пакетов: направление, L2/IP/L4 и текстовый поиск.
    pub(crate) fn passes_row(&self, row: &Row) -> bool {
        if !self.dir[row::dir_index(row.data.eth.dir)] {
            return false;
        }
        if !self.l2_ok(&row.data.payload)
            || !self.ip_ok(&row.data.payload)
            || !self.l4_ok(&row.data.payload)
        {
            return false;
        }
        contains_ci(&row.src, &self.text)
            || contains_ci(&row.dst, &self.text)
            || contains_ci(&row.info, &self.text)
    }

    /// L2-галочки на соединение не действуют: это уже поток IP.
    /// Направление проходит, если хотя бы одна виденная сторона включена.
    pub(crate) fn passes_conn(&self, key: &ConnKey, rec: &ConnRec) -> bool {
        if !self.dir_seen(&rec.saw) {
            return false;
        }
        let ip_ok = match key.a {
            std::net::IpAddr::V4(_) => self.ipv4,
            std::net::IpAddr::V6(_) => self.ipv6,
        };
        if !ip_ok {
            return false;
        }
        let l4_ok = match key.proto {
            ConnProto::Tcp => self.tcp,
            ConnProto::Udp => self.udp && self.udp_on(rec.udp_app),
        };
        if !l4_ok {
            return false;
        }
        let a = format!("{}:{}", key.a, key.pa);
        let b = format!("{}:{}", key.b, key.pb);
        self.text.is_empty() || contains_ci(&a, &self.text) || contains_ci(&b, &self.text)
    }

    /// Если направление ещё не видели — не режем; иначе нужна включённая галочка.
    fn dir_seen(&self, saw: &[bool; 5]) -> bool {
        let mut any = false;
        for (on, seen) in self.dir.iter().zip(saw.iter()) {
            if *seen {
                any = true;
                if *on {
                    return true;
                }
            }
        }
        !any
    }

    fn l2_ok(&self, payload: &NetPayload) -> bool {
        match payload {
            NetPayload::Ip(_)    => true,
            NetPayload::Arp(_)   => self.arp,
            NetPayload::Lldp(_)  => self.lldp,
            NetPayload::Cisco(_) => self.cdp,
            NetPayload::Mpls(_)  => self.mpls,
            NetPayload::DEC(_)   => self.dec,
            NetPayload::Ectp(_)  => self.ectp,
            NetPayload::Err(_)   => self.err,
        }
    }

    fn ip_ok(&self, payload: &NetPayload) -> bool {
        match payload {
            NetPayload::Ip(ip) => match ip.src {
                std::net::IpAddr::V4(_) => self.ipv4,
                std::net::IpAddr::V6(_) => self.ipv6,
            },
            _ => self.non_ip,
        }
    }

    fn l4_ok(&self, payload: &NetPayload) -> bool {
        let NetPayload::Ip(ip) = payload else {
            return true;
        };
        match &ip.l4 {
            IpL4::Tcp { .. } => self.tcp,
            IpL4::Udp { app, .. }  => self.udp && self.udp_on(*app),
            IpL4::Icmp4(_) | IpL4::Icmp6(_) => self.icmp,
            IpL4::Igmp(_)                   => self.igmp,
            IpL4::Esp(_)                    => self.esp,
            IpL4::Other(_)                  => self.other_l4,
        }
    }

    fn udp_on(&self, app: UdpApp) -> bool {
        self.udp_app[udp_index(app)]
    }
}

/// Итог для таблицы: Global AND Local.
pub(crate) fn visible_row(global: &Filter, local: &Filter, row: &Row) -> bool {
    global.passes_row(row) && local.passes_row(row)
}

/// То же для соединений.
pub(crate) fn visible_conn(global: &Filter, local: &Filter, key: &ConnKey, rec: &ConnRec) -> bool {
    global.passes_conn(key, rec) && local.passes_conn(key, rec)
}

/// Позиция в `udp_app` / `UDP_APPS`.
fn udp_index(app: UdpApp) -> usize {
    match app {
        UdpApp::Dhcp4      => 0,
        UdpApp::Dhcp6      => 1,
        UdpApp::Dns        => 2,
        UdpApp::Mdns       => 3,
        UdpApp::Ssdp       => 4,
        UdpApp::Llmnr      => 5,
        UdpApp::Nbns       => 6,
        UdpApp::Ntp        => 7,
        UdpApp::Quic       => 8,
        UdpApp::Wireguard  => 9,
        UdpApp::EspOverUdp => 10,
        UdpApp::Other      => 11,
    }
}

/// Пустой `needle` всегда проходит. Сравнение по байтам ASCII, без аллокаций.
fn contains_ci(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let needle = needle.as_bytes();
    hay.as_bytes()
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::row::{Row, tcp_packet};
    use crate::store::{ConnProto, ConnRec};
    use common::{
        ArpData, EDirection, EthData, EthType, IpData, IpL4, MacAddr6, NetData, NetPayload, UdpApp,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use web_time::Instant;

    fn row_of(data: NetData) -> Row {
        Row::from_owned(1, data)
    }

    /// Пакет виден только когда его пропускают оба фильтра.
    #[test]
    fn row_needs_global_and_local() {
        let row = row_of(tcp_packet(
            [10, 0, 0, 1],
            10,
            [10, 0, 0, 2],
            80,
            100,
            EDirection::Incoming,
        ));
        let global = Filter::default();
        let mut local = Filter::default();
        assert!(visible_row(&global, &local, &row));
        local.tcp = false;
        assert!(!visible_row(&global, &local, &row));
        local.tcp = true;
        let mut global = Filter::default();
        global.dir[crate::row::dir_index(EDirection::Incoming)] = false;
        assert!(!visible_row(&global, &local, &row));
    }

    /// Поиск идёт по src/dst/info и не смотрит на регистр.
    #[test]
    fn text_search_is_case_insensitive() {
        let data = NetData {
            eth: EthData {
                src: MacAddr6([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
                dst: MacAddr6([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
                dir: EDirection::Broadcast,
                prot: EthType::Arp,
            },
            payload: NetPayload::Arp(ArpData::default()),
        };
        let row = row_of(data);
        let mut global = Filter::default();
        let local = Filter::default();
        global.text = "aa:bb:cc".into();
        assert!(visible_row(&global, &local, &row));
        global.text = "AA:BB:CC".into();
        assert!(visible_row(&global, &local, &row));
        global.text = "10.0.0.1".into();
        let local_hit = Filter::default();
        assert!(!visible_row(&global, &local_hit, &row));
        global.text.clear();
        let mut local = Filter::default();
        local.text = "no-such".into();
        assert!(!visible_row(&global, &local, &row));
    }

    /// Снятие DNS прячет UDP/DNS, даже если UDP в целом включён.
    #[test]
    fn udp_app_checkbox_hides_dns() {
        let data = NetData {
            eth: EthData {
                src: MacAddr6([1, 0, 0, 0, 0, 1]),
                dst: MacAddr6([2, 0, 0, 0, 0, 2]),
                dir: EDirection::Outgoing,
                prot: EthType::Ipv4,
            },
            payload: NetPayload::Ip(IpData {
                src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                dst: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                len: 60,
                l4: IpL4::Udp {
                    src_port: 12345,
                    dst_port: 53,
                    app: UdpApp::Dns,
                    msg: None,
                },
            }),
        };
        let row = row_of(data);
        let mut filter = Filter::default();
        assert!(filter.passes_row(&row));
        filter.udp_app[udp_index(UdpApp::Dns)] = false;
        assert!(!filter.passes_row(&row));
    }

    /// Соединение тоже подчиняется обоим фильтрам.
    #[test]
    fn connection_needs_both_filters() {
        let key = ConnKey {
            proto: ConnProto::Tcp,
            a    : IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            pa   : 10,
            b    : IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            pb   : 80,
        };
        let now = Instant::now();
        let rec = ConnRec {
            pkts_ab : 1,
            bytes_ab: 100,
            pkts_ba : 0,
            bytes_ba: 0,
            first   : now,
            last    : now,
            udp_app : UdpApp::Other,
            saw: [false, true, false, false, false],
        };
        let global = Filter::default();
        let mut local = Filter::default();
        assert!(visible_conn(&global, &local, &key, &rec));
        local.tcp = false;
        assert!(!visible_conn(&global, &local, &key, &rec));
        local.tcp = true;
        local.text = "10.0.0.2:80".into();
        assert!(visible_conn(&global, &local, &key, &rec));
        local.text = "192.168.9.9".into();
        assert!(!visible_conn(&global, &local, &key, &rec));
    }

    /// Индекс UDP-приложения совпадает с подписью в UI.
    #[test]
    fn udp_index_matches_labels() {
        for (i, (app, _)) in UDP_APPS.iter().enumerate() {
            assert_eq!(udp_index(*app), i);
        }
    }
}
