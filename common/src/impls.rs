use crate::net_common::*;
use std::fmt::Debug;

impl TrafficStats {
    pub fn new() -> Self { Self::default() }
    pub fn total_packets(&self) -> u64 { self.rx_packets + self.tx_packets }
    pub fn total_bytes(&self)   -> u64 { self.rx_bytes + self.tx_bytes     }
}
impl MacAddr6 {
    pub fn empty()              -> Self { Self([0; 6]) }
    pub fn new(addr: [u8; 6])   -> Self { Self(addr)   }
    pub fn from_slice(s: &[u8]) -> Self { Self([s[0], s[1], s[2], s[3], s[4], s[5]]) }
}
impl MacAddr8 {
    pub fn empty()              -> Self { Self([0; 8]) }
    pub fn new(addr: [u8; 8])   -> Self { Self(addr) }
    pub fn from_slice(s: &[u8]) -> Self { Self([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]) }
}

impl Default for ArpData {
    fn default() -> Self {
        Self {
            op: ArpOp::default(),
            sender_mac: MacAddr6::default(),
            sender_ip: std::net::Ipv4Addr::UNSPECIFIED,
            target_mac: MacAddr6::default(),
            target_ip: std::net::Ipv4Addr::UNSPECIFIED,
        }
    }
}

impl IpData {
    pub fn new_icmp4(src: &IpAddr, dst: &IpAddr, payload_len: usize) -> Self {
        Self { protocol: IpType::Icmp4, src: *src, dst: *dst, len: payload_len, src_port: 0, dst_port: 0 }
    }
    pub fn new_icmp6(src: &IpAddr, dst: &IpAddr, payload_len: usize) -> Self {
        Self { protocol: IpType::Icmp6, src: *src, dst: *dst, len: payload_len, src_port: 0, dst_port: 0 }
    }
    pub fn new_tcp_udp(protocol: IpType, src: &IpAddr, dst: &IpAddr, payload_len: usize, src_port:u16, dst_port:u16) -> Self {
        Self { protocol, src: *src, dst: *dst, len: payload_len, src_port, dst_port }
    }
    pub fn new(protocol: IpType, src: &IpAddr, dst: &IpAddr, payload_len: usize, src_port:u16, dst_port:u16) -> Self {
        Self { protocol, src: *src, dst: *dst, len: payload_len, src_port, dst_port }
    }
}
impl ArpData {
    pub fn new(op: ArpOp,
               sender_mac: MacAddr6, sender_ip: Ipv4Addr,
               target_mac: MacAddr6, target_ip: Ipv4Addr) -> Self {
        Self { op, sender_mac, sender_ip, target_mac, target_ip }
    }
}

impl MplsData {
    pub fn new(label: u32, tc: u8, bos: bool, ttl: u8) -> Self {
        Self { label, tc, bos, ttl }
    }
}

impl Default for ArpOp {
    fn default() -> Self {
        ArpOp::Unknown(0)
    }
}

impl Default for EDirection {
    fn default() -> Self {
        EDirection::Unknown
    }
}

impl Default for ParseError {
    fn default() -> Self {
        ParseError::Unknown_Error
    }
}

impl Default for IpData {
    fn default() -> Self {
        Self {
            protocol: IpType::Unsupported,
            src: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            dst: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            len: 0,
            src_port: 0,
            dst_port: 0,
        }
    }
}

impl Default for NetPayload {
    fn default() -> Self {
        NetPayload::Err(ParseError::default())
    }
}

impl Debug for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let ParseError::Arp_Unsupported { hw_type, proto_type, hw_len, proto_len } = self {
            return write!(
                f,
                "Arp_Unsupported {{ hw_type: 0x{:04x}, proto_type: 0x{:04x}, hw_len: {}, proto_len: {} }}",
                hw_type, proto_type, hw_len, proto_len
            );
        }
        let variant_name = match self {
            ParseError::Unknown_Error                   => "Unknown_Error",
            ParseError::Unsupported_Eth { .. }          => "Unsupported_Eth",
            ParseError::LLC_SNAP_TooShort_Broken { .. } => "LLC_SNAP_TooShort",
            ParseError::LLC_SNAP_Header_Broken   { .. } => "LLC_SNAP_Header_Broken",
            ParseError::Unsupported_Eth_SNAP_OUI { .. } => "Unsupported_Eth_SNAP_OUI",
            ParseError::Unsupported_L4 { .. }           => "Unsupported_L4",
            ParseError::Eth_Broken { .. }               => "Eth_Broken",
            ParseError::Ip4_Broken { .. }               => "Ip4_Broken",
            ParseError::Ip6_Broken { .. }               => "Ip6_Broken",
            ParseError::Tcp_Broken { .. }               => "Tcp_Broken",
            ParseError::Udp_Broken { .. }               => "Udp_Broken",
            ParseError::Icmp4_Broken { .. }             => "Icmp4_Broken",
            ParseError::Icmp6_Broken { .. }             => "Icmp6_Broken",
            ParseError::Ip4_Fragment { .. }             => "Ip4_Fragment",
            ParseError::Ip6_Fragment { .. }             => "Ip6_Fragment",
            ParseError::Arp_Broken { .. }               => "Arp_Broken",
            ParseError::Arp_Unsupported { .. }          => "Arp_Unsupported",
            ParseError::Mpls_Broken { .. }              => "Mpls_Broken",
            ParseError::Lldp_Broken { .. }              => "Lldp_Broken",
            ParseError::Ectp { .. }                     => "Ectp",
            ParseError::DEC_Broken { .. }               => "DEC_Broken",
            ParseError::Cisco_Broken { .. }             => "Cisco_Broken",
        };
        write!(f, "{}", variant_name)
    }
}