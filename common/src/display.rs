#![allow(non_snake_case)]
use std::fmt;
use crate::net_common::*;

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


impl fmt::Display for EDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EDirection::Incoming  => write!(f, "---->"),
            EDirection::Outgoing  => write!(f, "<----"),
            EDirection::Broadcast => write!(f, "<<->>"),
            EDirection::Multicast => write!(f, "<-->>"),
            EDirection::Unknown   => write!(f, "?????"),
        }
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
        let s  = match self.dst {
            CISCO_BROADCAST_ADDRESS6 => "(brdcst_cisco)",
            BROADCAST_ADDRESS6       => "(brdcst_all)",
            _                        => "",
        };
        write!(f, "Eth[{}:{}{}{} {}]", 
               self.prot, self.src, self.dir,s,  self.dst,
        )
    }
}


impl fmt::Display for ArpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArpOp::Request => write!(f, "Request"),
            ArpOp::Reply   => write!(f, "Reply"),
            ArpOp::Unknown(id) => write!(f, "Unknown({})", id),
        }
    }
}


impl fmt::Display for ArpData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArpData {}, sender:{}/{}, target:{}/{}",
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

impl fmt::Display for CISCO_CDP_ADDRESSES {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.count > 0 {
            for i in 0..self.count as usize {
                if let Err(e) = write!(f, "\t[{}]\n", self.addresses[i]) {
                    return Err(e);
                }
            }
            Ok(())
        } else {
            write!(f, "(no addresses)")
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
        write!(f, "CDP_CISCO_DATA[ver:{} ttl:{}sec checksum:{:04X}\n\t {} {} {} {} {}; Addr:{}]",
               self.Header.ver as u8, self.Header.ttl as u8, self.Header.chksm as u16,
               CDP_CISCO_DATA_2_Str(self.Capabilities),
               TLV_DATA_2_str(&self.DeviceId       , ""     ),
               TLV_DATA_2_str(&self.PortId         , "; PortId:"  ), 
               TLV_DATA_2_str(&self.SoftwareVersion, "; SwVer:"   ),
               TLV_DATA_2_str(&self.Platform       , "; Platform:"),
               self.Address,
        )
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
            NetPayload::Ip  (data)          => write!(f, "{}", data),
            NetPayload::Arp (data)          => write!(f, "{}", data),
            NetPayload::Mpls(data)          => write!(f, "{}", data),
            NetPayload::Lldp(data)          => write!(f, "{}", data),
            NetPayload::Ectp(data)          => write!(f, "{}", data),
            NetPayload::DEC(data)           => write!(f, "{}", data),
            NetPayload::Cisco(data)         => write!(f, "{}", data),
            NetPayload::Err (data)          => write!(f, "{}", data),
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
            ParseError::Unknown_Error                    => write!(f, "unknown error"),
            ParseError::Unsupported_Eth { id    }  => write!(f, "unsupported EtherType: 0x{:04x}", id),
            ParseError::Unsupported_Eth_SNAP_OUI {oui, prot_id} => write!(f, "unsupported SNAP OUI:[{:02x}:{:02x}:{:02x}] Protocol ID:0x{:04x}", oui[0], oui[1], oui[2], prot_id),
            ParseError::Unsupported_L4  { id     }  => write!(f, "unsupported L4 protocol: {}", id),
            ParseError::Eth_Broken      { len }  => write!(f, "Ethernet frame too short: {} bytes", len),
            ParseError::Ip4_Broken      { len }  => write!(f, "IPv4 payload too short: {} bytes (need at least 20)", len),
            ParseError::Ip6_Broken      { len }  => write!(f, "IPv6 payload too short: {} bytes (need at least 40)", len),
            ParseError::Tcp_Broken      { len, src, dst } => write!(
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
            ParseError::Arp_Broken       { len } => write!(f, "ARP payload too short: {} bytes (need at least 28)", len),
            ParseError::Mpls_Broken      { len } => write!(f, "MPLS payload too short: {} bytes (need at least 4)",  len),
            ParseError::Lldp_Broken      { len } => write!(f, "LLDP payload too short: {} bytes (need at least 4)",  len),
            ParseError::Ectp            { len } => write!(f, "ECTP payload too short: {} bytes (need at least 4)", len),
            ParseError::DEC_Broken       { len, sub_type } => write!(f, "DEC Loopback payload too short: {} bytes (need at least 4), type:0x{:04x}", len, sub_type),
            ParseError::Cisco_Broken     { len, sub_type } => write!(f, "Cisco Broken payload {} bytes {}", len, Cisco_Broken_String(sub_type)),
        }
    }
}

impl fmt::Display for LLDP_Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LLDP[{} {} TTL({}) {}\n\t {} {}\n\t Sys_CAP({}) {}]",
               TLV_DATA_2_str(&self.Chassis_ID     , "Chassis:"),
               TLV_DATA_2_str(&self.Port_ID        , "Port:"),
               self.TTL,
               TLV_DATA_2_str(&self.Port_DESC      , "\n\t Port_DESC:"),
               TLV_DATA_2_str(&self.Sys_NAME       , "\n\t Sys_NAME:"),
               TLV_DATA_2_str(&self.Sys_DESC       , "\n\t Sys_DESC:"),
                self.Sys_CAP_supported,
               TLV_DATA_2_str(&self.Management_Addr, "\n\t MngmntADDR:"),
        )
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
