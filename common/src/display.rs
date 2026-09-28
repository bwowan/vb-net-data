#![allow(non_snake_case)]
use std::cmp::min;
use std::fmt;
use core::fmt::Write;
use crate::{EDirection::Multicast, net_common::*};
use heapless;

impl fmt::Display for TrafficStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RX: {} packets / {} bytes; TX: {} packets / {} bytes; Total: {} packets / {} bytes",
            self.rx_packets,
            self.rx_bytes,
            self.tx_packets,
            self.tx_bytes,
            self.total_packets(),
            self.total_bytes()
        )
    }
}

impl fmt::Display for EthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EthType::Ipv4             => write!(f, "IPv4"),
            EthType::Ipv6             => write!(f, "IPv6"),
            EthType::Arp              => write!(f, "ARP (0x0806)"),
            EthType::Rarp             => write!(f, "RARP (0x8035)"),
            EthType::Mpls             => write!(f, "MPLS (0x8847)"),
            EthType::MplsMcast        => write!(f, "MPLS Multicast (0x8848)"), 
            EthType::Lldp             => write!(f, "LLDP (0x88cc)"),
            EthType::Ectp             => write!(f, "ECTP (0x9003)"),
            EthType::Unsupported      => write!(f, "Unsupported"),
        }
    }
}

impl fmt::Display for IpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpType::Tcp              => write!(f, "TCP"),
            IpType::Udp              => write!(f, "UDP"),
            IpType::Icmp4            => write!(f, "ICMPv4"),
            IpType::Icmp6            => write!(f, "ICMPv6"),
            IpType::Unsupported      => write!(f, "Unsupported"),
        }
    }
}

fn dir_2_str(d: EDirection) -> &'static str {
    match d {
        EDirection::Incoming  => "-->",
        EDirection::Outgoing  => "<--",
        EDirection::Broadcast => ">>>",
        EDirection::Multicast => "->>",
        EDirection::Unknown   => "???",
    }
}


impl fmt::Display for EDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", dir_2_str(*self))
    }
}
    
impl fmt::Display for MacAddr6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let u = self.0;
        write!(f, "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", u[0], u[1], u[2], u[3], u[4], u[5])
    }
}

impl fmt::Display for MacAddr8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let u = self.0;
        write!(f, "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7])
    }
}

impl fmt::Display for EthData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s_dir = if self.dir == Multicast {
            let last_section = self.dst.0[MAC_ADDRESS_LEN6 - 1];
            if last_section == LLDP_BROADCAST_ADDRESS6.0[MAC_ADDRESS_LEN6 - 1] {
                "LLDP BROADCAST"
            } else if last_section >= BRIDGE_BROADCAST_START_ADDRESS6.0[MAC_ADDRESS_LEN6 - 1] &&
                      last_section <= BRIDGE_BROADCAST_END_ADDRESS6.0[MAC_ADDRESS_LEN6 - 1] {
                "BRIDGE BROADCAST"
            } else if self.dst == CISCO_BROADCAST_ADDRESS6 {
                "CISCO BROADCAST"
            } else {
                "Multicast"
            }
        } else {
            dir_2_str(self.dir)
        };

        let mut s_prot: heapless::String<32> = heapless::String::new();
        if self.prot == EthType::Unsupported {
            write!(s_prot, "len={}", self.prot as u16)?;
        } else {
            write!(s_prot, "{}", self.prot)?;
        }
        write!(f, "Eth[{}, {}-{}{}-{}]", 
               s_prot, self.src, self.dir, s_dir,  self.dst,
        )
    }
}


impl fmt::Display for ArpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArpOp::Request     => write!(f, "Request"),
            ArpOp::Reply       => write!(f, "Reply"),
            ArpOp::RarpRequest => write!(f, "RARP Request"),
            ArpOp::RarpReply   => write!(f, "RARP Reply"),
            ArpOp::Unknown(id) => write!(f, "Unknown({})", id),
        }
    }
}


impl fmt::Display for ArpData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.op {
            ArpOp::RarpRequest | ArpOp::RarpReply => "RarpData",
            _ => "ArpData",
        };
        write!(f, "{} {}, sender:{}/{}, target:{}/{}",
            kind,
            self.op,
            self.sender_mac, self.sender_ip,
            self.target_mac, self.target_ip)
    }
}

impl fmt::Display for IpData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IP[{}({}bytes), src:{}:{} --> dst:{}:{}]",
            self.protocol, self.len, self.src, self.src_port, self.dst, self.dst_port)
    }
}
impl fmt::Display for MplsData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mpls (label:{}, tc:{}, bos:{}, ttl:{})", self.label, self.tc, self.bos, self.ttl)
    }
}

fn bytes_to_string_or_hex(data: &[u8; LLDP_TLV_MAX_LEN]) -> String {
    // Пытаемся интерпретировать как UTF-8
    if let Ok(s) = std::str::from_utf8(data) {
        // Проверяем, что это "печатный" текст (нет управляющих символов, кроме пробельных)
        // is_control() отсекает 0x00-0x1F, но is_whitespace() возвращает true для \n, \r, \t
        if !data.is_empty() && s.chars().all(|c| !c.is_control() || c.is_whitespace()) {
            return s.to_string();
            //format!("\"{}\"", s)
        }
    }
    let hex: Vec<String> = data.iter().map(|b| format!("{:02X}", b)).collect();
    format!("[{}]", hex.join(" "))
}
    
fn TLV_DATA_2_str(tlv: &TLV_DATA, prefix:&str) -> String {
    if tlv.tlv_len == 0 {
        "".to_string()
    } else {
        let mut s = String::with_capacity(tlv.tlv_len as usize + prefix.len());
        s.push_str(prefix);
        for i in 0..std::cmp::min(tlv.tlv_len as usize, LLDP_TLV_MAX_LEN) {
            let byte = tlv.tlv_data[i];
            if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {
                s.push(byte as char);
            } /*else {
                s.push(' ');
            }*/
        }
        s
    }
}

impl fmt::Display for CISCO_CDP_ADDRESS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.addr_len {
             4 => write!(f, "{}.{}.{}.{}", self.addr[0], self.addr[1], self.addr[2], self.addr[3]),
            16 => write!(f, "{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}",
                    (self.addr[ 0] as u16) << 8 | (self.addr[ 1] as u16), 
                    (self.addr[ 2] as u16) << 8 | (self.addr[ 3] as u16), 
                    (self.addr[ 4] as u16) << 8 | (self.addr[ 5] as u16), 
                    (self.addr[ 6] as u16) << 8 | (self.addr[ 7] as u16), 
                    (self.addr[ 8] as u16) << 8 | (self.addr[ 9] as u16), 
                    (self.addr[10] as u16) << 8 | (self.addr[11] as u16), 
                    (self.addr[12] as u16) << 8 | (self.addr[13] as u16), 
                    (self.addr[14] as u16) << 8 | (self.addr[15] as u16)),
            _  => write!(f, "(prot_type={}, prot_len={}, prot={}, addr_len={})", self.prot_type, self.prot_len, self.prot, self.addr_len)
        }
    }
}

impl fmt::Display for TLV_DATA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Берем срез данных реальной длины
        //let valid_len = std::cmp::min(self.tlv_len as usize, self.tlv_data.len());
        //let data_slice = &self.tlv_data[0..valid_len];
        if self.tlv_len > 0 {
            write!(f, "TLV[0x{:04X} l({}) {}]",
                self.tlv_type as u16,
                self.tlv_len as u16,
                bytes_to_string_or_hex(&self.tlv_data))
        } else {
            write!(f, "")
        }
    }
}

const CISCO_CAPABILITIES:[(u8,&str); 7] = [
        (0x01, "Router"),              // Выполняет L3-маршрутизацию
        (0x02, "Trans Bridge"),        // L2 transparent bridging
        (0x04, "Source Route Bridge"), // L2 source-route bridging
        (0x08, "SwitchL2 switching"),  // (без STP в старых определениях)
        (0x10, "Host"),                // Отправляет/принимает пакеты сетевого уровня, но не маршрутизирует
        (0x20, "IGMP snooping"),       // Не форвардит IGMP reports (IGMP filtering/snooping)
        (0x40, "Level 1"),             // Устаревший бит (level 1 functionality)
];
fn CDP_CISCO_DATA_2_Str(cap:u32) -> String {
    if cap == 0 {
        "".to_string()
    } else {
        let mut s = String::with_capacity(100);
        for i in CISCO_CAPABILITIES.iter() {
            if 0 != cap & i.0 as u32 {
                s.push_str(i.1);
            }
        }
        s
    }
}

impl fmt::Display for CDP_CISCO_DATA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CDP_CISCO_DATA[ver:{} ttl:{}sec checksum:{:04X}\n\t {}",
               self.Header.ver as u8, self.Header.ttl as u8, self.Header.chksm as u16,
               CDP_CISCO_DATA_2_Str(self.Capabilities)
        )?;

        for tlv in &self.tlvs {
            match tlv.tlv_type {
                0x000a if tlv.tlv_len >= 2 => {
                    let vlan = u16::from_be_bytes([tlv.tlv_data[0], tlv.tlv_data[1]]);
                    write!(f, "; NativeVLAN:{}", vlan)?;
                }
                0x000b if tlv.tlv_len >= 1 => {
                    match tlv.tlv_data[0] {
                        0x01 => write!(f, "; Duplex:1(half)")?,
                        0x02 => write!(f, "; Duplex:2(full)")?,
                        other => write!(f, "; Duplex:{}", other)?,
                    }
                }
                _ => {
                    let prefix = match tlv.tlv_type {
                        0x0001 => " DevID:",
                        0x0003 => "; PortId:",
                        0x0005 => "; SwVer:",
                        0x0006 => "; Platform:",
                        0x000a => "; NativeVLAN:",
                        0x000b => "; Duplex:",
                        _ => "; UnknownTLV:",
                    };
                    write!(f, "{}", TLV_DATA_2_str(tlv, prefix))?;
                }
            }
        }

        write!(f, "\n\t Addresses:")?;
        if !self.addresses.is_empty() {
            for i in 0..self.addresses.len() {
                write!(f, "\n\t  [{}] {}", i, self.addresses[i])?;
            }
        } else {
            write!(f, " (none)")?;
        }
        write!(f, "]")
    }
}

impl fmt::Display for CiscoData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CiscoData::CDP(data) => write!(f, "{}", data),
            _ => write!(f, "(unsuppoorted cisco)"),
        }
    }
}

impl fmt::Display for NetPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetPayload::Ip   (data)         => write!(f, "{}", data),
            NetPayload::Arp  (data)        => write!(f, "{}", data),
            NetPayload::Mpls (data)       => write!(f, "{}", data),
            NetPayload::Lldp (data)      => write!(f, "{}", data),
            NetPayload::Ectp (data)   => write!(f, "{}", data),
            NetPayload::DEC  (data)  => write!(f, "{}", data),
            NetPayload::Cisco(data)      => write!(f, "{}", data),
            NetPayload::Err  (data)     => write!(f, "{}", data),
        }
    }
}


impl fmt::Display for NetData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{} + {}]", self.eth, self.payload)
    }
}


fn Cisco_Broken_String(sub_type: &u16) -> &'static str {
    match sub_type {
        0x2000 => "CDP (Discovery)",        // 0x2000	CDP (Discovery)	Поиск соседей и обмен информацией о железе.
        0x2001 => "CGMP (Group Mgmt)",      // 0x2001	CGMP (Group Mgmt)	Управление Multicast-группами (устаревший).
        0x2003 => "VTP (VLAN Trunking)",    // 0x2003	VTP (VLAN Trunking)	Синхронизация базы VLAN между коммутаторами.
        0x2004 => "DTP (Dynamic Trunking)", // 0x2004	DTP (Dynamic Trunking)	Согласование режима работы порта (Trunk или Access).
        0x200E => "PAGP (Aggregation)",     // 0x200E	PAGP (Aggregation)	Протокол объединения каналов (EtherChannel).
        0x010B => "PVSTP+ (Spanning Tree)", // 0x010B	PVSTP+ (Spanning Tree)	Работа дерева STP отдельно для каждого VLAN.
        0x010C => "UDLD (Link Detection)",  // 0x010C	UDLD (Link Detection)	Проверка того, что связь по кабелю идет в обе стороны.
        _      => "Unknown"
    }
}


impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Unknown_Error                                            => write!(f, "unknown error"),
            ParseError::Unsupported_Eth          { id    }                 => write!(f, "unsupported EtherType: 0x{:04x}", id),
            ParseError::LLC_SNAP_TooShort_Broken { id, len }       => write!(f, "LLC/SNAP header({:04x}) too short: {} bytes (need at least 8)", id, len),
            ParseError::LLC_SNAP_Header_Broken   { id, header }  => write!(f, "invalid LLC/SNAP header({:04x}): [{}]", id, header.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")),
            ParseError::Unsupported_Eth_SNAP_OUI { oui, prot_id} => write!(f, "unsupported SNAP OUI:[{:02x}:{:02x}:{:02x}] Protocol ID:0x{:04x}", oui[0], oui[1], oui[2], prot_id),
            ParseError::Unsupported_L4           { id     }                 => write!(f, "unsupported L4 protocol: {:04x}", id),
            ParseError::Eth_Broken               { len }                 => write!(f, "Ethernet frame too short: {} bytes", len),
            ParseError::Ip4_Broken               { len }                 => write!(f, "IPv4 payload too short: {} bytes (need at least 20)", len),
            ParseError::Ip6_Broken               { len }                 => write!(f, "IPv6 payload too short: {} bytes (need at least 40)", len),
            ParseError::Tcp_Broken               { len, src, dst } => write!(
                f, "TCP payload too short or invalid: {} bytes (src={}, dst={})",   len, src, dst
            ),
            ParseError::Udp_Broken   { len, src, dst } => write!(
                f, "UDP payload too short or invalid: {} bytes (src={}, dst={})",   len, src, dst
            ),
            ParseError::Icmp4_Broken { len, src, dst } => write!(
                f, "ICMP payload too short or invalid: {} bytes (src={}, dst={})",  len, src, dst
            ),
            ParseError::Icmp6_Broken { len, src, dst } => write!(
                f, "ICMPv6 payload too short or invalid: {} bytes (src={}, dst={})",len, src, dst
            ),
            ParseError::Ip4_Fragment { src, dst } => {
                write!(f, "IPv4 fragment (non-first), L4 unknown (src={}, dst={})", src, dst)
            }
            ParseError::Ip6_Fragment { src, dst } => {
                write!(f, "IPv6 fragment (non-first), L4 unknown (src={}, dst={})", src, dst)
            }
            ParseError::Arp_Broken       { len } => write!(f, "ARP payload too short: {} bytes (need at least 28)", len),
            ParseError::Arp_Unsupported  { hw_type, proto_type, hw_len, proto_len } => write!(
                f,
                "unsupported ARP/RARP: hw_type=0x{:04x}, proto_type=0x{:04x}, hw_len={}, proto_len={} (need Ethernet+IPv4: 1/0x0800, 6/4)",
                hw_type, proto_type, hw_len, proto_len
            ),
            ParseError::Mpls_Broken      { len } => write!(f, "MPLS payload too short: {} bytes (need at least 4)",  len),
            ParseError::Lldp_Broken      { len } => write!(f, "LLDP payload too short: {} bytes (need at least 4)",  len),
            ParseError::Ectp            { len } => write!(f, "ECTP payload too short: {} bytes (need at least 4)", len),
            ParseError::DEC_Broken       { len, sub_type } => write!(f, "DEC Loopback payload too short: {} bytes (need at least 4), type:0x{:04x}", len, sub_type),
            ParseError::Cisco_Broken     { len, sub_type } => write!(f, "Cisco Broken payload {} bytes {}", len, Cisco_Broken_String(sub_type)),
        }
    }
}

fn LLDP_MgmtAddr_2_str(m: &LLDP_MgmtAddr) -> String {
    let if_name = match m.if_subtype {
        1 => "unknown",
        2 => "ifIndex",
        3 => "sysPort",
        _ => "if",
    };
    match (m.family, m.addr_len) {
        (1, 4) => format!(
            "\n\t MngmntADDR:{} ({}/{})",
            Ipv4Addr::new(m.addr[0], m.addr[1], m.addr[2], m.addr[3]),
            if_name, m.if_number
        ),
        (2, 16) => {
            let a = m.addr;
            let ip = Ipv6Addr::from(a);
            format!("\n\t MngmntADDR:{} ({}/{})", ip, if_name, m.if_number)
        }
        _ => format!(
            "\n\t MngmntADDR:family={} len={} ({}/{})",
            m.family, m.addr_len, if_name, m.if_number
        ),
    }
}

fn LLDP_OrgSpecific_2_str(tlv: &TLV_DATA) -> String {
    // Value: OUI(3) + subtype(1) + information string
    if tlv.tlv_len < 4 {
        return "\n\t OrgSpecific:(too short)".to_string();
    }
    let len = min(tlv.tlv_len as usize, LLDP_TLV_MAX_LEN);
    let oui = &tlv.tlv_data[0..3];
    let subtype = tlv.tlv_data[3];
    let oui_name = match oui {
        [0x00, 0x80, 0xC2] => "IEEE802.1",
        [0x00, 0x12, 0xBB] => "TIA-TR41(MED)",
        [0x00, 0x00, 0x0C] => "Cisco",
        _ => "",
    };
    let mut s = String::with_capacity(64 + len);
    if oui_name.is_empty() {
        write!(
            &mut s,
            "\n\t OrgSpecific:OUI[{:02X}:{:02X}:{:02X}] sub={} ",
            oui[0], oui[1], oui[2], subtype
        ).ok();
    } else {
        write!(
            &mut s,
            "\n\t OrgSpecific:{}({:02X}:{:02X}:{:02X}) sub={} ",
            oui_name, oui[0], oui[1], oui[2], subtype
        ).ok();
    }
    for i in 4..len {
        let byte = tlv.tlv_data[i];
        if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {
            s.push(byte as char);
        } else {
            write!(&mut s, "{:02X}", byte).ok();
        }
    }
    s
}

impl fmt::Display for LLDP_Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LLDP[TTL({}) Sys_CAP({})\n\t", self.TTL, self.Sys_CAP_supported)?;

        for tlv in &self.tlvs {
            if tlv.tlv_type == 127 {
                write!(f, "{}", LLDP_OrgSpecific_2_str(tlv))?;
                continue;
            }
            let prefix = match tlv.tlv_type {
                1 => " Chassis:",
                2 => " Port:",
                4 => "\n\t Port_DESC:",
                5 => "\n\t Sys_NAME:",
                6 => "\n\t Sys_DESC:",
                _ => "\n\t UnknownTLV:",
            };
            write!(f, "{}", TLV_DATA_2_str(tlv, prefix))?;
        }
        for m in &self.mgmt_addrs {
            write!(f, "{}", LLDP_MgmtAddr_2_str(m))?;
        }
        write!(f, "]")
    }
}

impl fmt::Display for LoopbackData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s_func = match self.function {
            0x0000 => "(One way test)",
            0x0001 => "(Replay)", // Loopback function for replaying packets
            0x0002 => "(Forward)",   // Loopback function for testing
            _      => ""
        };
        write!(f, "LoopbackData[skip_cnt:{}, func:{}{}, receipt:{}]",
               self.skip_count,
               self.function, s_func,
               self.receipt_mac
        )
    }
}


impl fmt::Display for DECSnapHeader {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s_oui = match self.oui {
                                [0x00, 0x00, 0x0C] => "Cisco",                  //00:00:0C + 0x2000 → CDP (самый классический Cisco SNAP)
                                [0x00, 0x80, 0xC2] => "Some ext:LLDP или QinQ", //00:80:C2 + разные подтипы → расширения 802.1 (чаще всего в контексте LLDP или QinQ/bridge)
                                _ => ""
                            };
        let s_control = match self.control {
                                0x03 => "Unnumbered Information (UI)", //Unnumbered Information (UI
                                0xF3 => "UI Poll/Final", // Unnumbered Information with Poll/Final bit set
                                0xAF => "Asynchronous Balanced Mode Extended (SABME)", // Установка асинхронного сбалансированного режима (расширенный)
                                0xEF => "Asynchronous Balanced Mode (SABM)", // Установка асинхронного сбалансированного режима
                                0x8F => "Asynchronous Balanced Mode Extended (SABME) with Poll/Final bit set", //XID, TEST (очень редко, в основном при отладке/инициализации)
                                _ => ""
                            };
        let s_dsap_ssap = match (self.dsap, self.ssap) {
                                (0xAA, 0xAA) => "DECSNAP (Subnetwork Access Protocol)", //Почти все Cisco-протоколы + старый IP/ARP (очень часто)
                                (0x42, 0x42) => "STP/RSTP/MSTP (Spanning Tree)(Cisco)", //Все Cisco / почти все managed-коммутаторы (очень часто)
                                (0xE0, 0xE0) => "Novell IPX, NetWare (old)", //Очень старые сети, редко (редко)
                                (0xFE, 0xFE) => "ISO CLNP, routed OSI", //-протоколыСтарые правительственные/телеком сети (редко)
                                (0x06, 0x06) => "IP(old RFC 948)", //Почти не встречается ★☆☆☆☆ (почти исчез)
                                (0x04, 0x04) => "IBM SNA (old mainframes)", // др.IBM SNA / старые мейнфреймыLegacy-системы (очень редко)
                                _ => "",
                            };
        let s_protocol = match self.protocol_id {
                            0x2000 => "Cisco Discovery Protocol",             //обнаружение соседних устройств.
                            0x010B => "PVST+	Per-VLAN Spanning Tree Plus", //Используется для управления топологией без петель в отдельных VLAN.  
                            0x2003 => "VTP VLAN Trunking Protocol",           //Синхронизирует базу данных VLAN между коммутаторами.
                            0x2004 => "DTP Dynamic Trunking Protocol",        //Согласовывает тип транка (trunk) между портами.
                            0x8021 => "PAGP Port Aggregation Protocol",       //Протокол для объединения каналов (EtherChannel).
                            0x0800 => "IPv4 old(802.3)",
                            0x86DD => "IPv6 SNAP",
                            _ => "",
                        };

        write!(f, "DECSnapHeader[dsap/ssap:0x{:02X}/0x{:02X} {}, control:0x{:02x}({}), oui:{:02x}:{:02x}:{:02x}{}, prot:{:02X} {}]",
               self.dsap, self.ssap, s_dsap_ssap,
               self.control, s_control,
               self.oui[0], self.oui[1], self.oui[2], s_oui,
               self.protocol_id, s_protocol
        )
    }
}
