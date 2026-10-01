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

impl IpL4 {
    pub fn ip_type(&self) -> IpType {
        match self {
            IpL4::Tcp { .. } => IpType::Tcp,
            IpL4::Udp { .. } => IpType::Udp,
            IpL4::Igmp(_)    => IpType::Igmp,
            IpL4::Icmp4(_)   => IpType::Icmp4,
            IpL4::Icmp6(_)   => IpType::Icmp6,
            IpL4::Esp(_)     => IpType::Esp,
            IpL4::Other(t)   => *t,
        }
    }
}

impl IpData {
    pub fn new_tcp(src: &IpAddr, dst: &IpAddr, payload_len: usize, src_port: u16, dst_port: u16) -> Self {
        Self { src: *src, dst: *dst, len: payload_len, l4: IpL4::Tcp { src_port, dst_port } }
    }
    pub fn new_udp(src: &IpAddr, dst: &IpAddr, payload_len: usize, src_port: u16, dst_port: u16) -> Self {
        Self {
            src: *src, dst: *dst, len: payload_len,
            l4: IpL4::Udp { src_port, dst_port, app: UdpApp::from_ports(src_port, dst_port), msg: None },
        }
    }
    pub fn new_icmp4(src: &IpAddr, dst: &IpAddr, payload_len: usize, msg: Icmp4Data) -> Self {
        Self { src: *src, dst: *dst, len: payload_len, l4: IpL4::Icmp4(msg) }
    }
    pub fn new_icmp6(src: &IpAddr, dst: &IpAddr, payload_len: usize, msg: Icmp6Data) -> Self {
        Self { src: *src, dst: *dst, len: payload_len, l4: IpL4::Icmp6(msg) }
    }
    pub fn new_igmp(src: &IpAddr, dst: &IpAddr, payload_len: usize, msg: IgmpData) -> Self {
        Self { src: *src, dst: *dst, len: payload_len, l4: IpL4::Igmp(msg) }
    }
    pub fn new_esp(src: &IpAddr, dst: &IpAddr, payload_len: usize, msg: EspData) -> Self {
        Self { src: *src, dst: *dst, len: payload_len, l4: IpL4::Esp(msg) }
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
            src: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            dst: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            len: 0,
            l4: IpL4::Other(IpType::Unsupported),
        }
    }
}

impl Default for NetPayload {
    fn default() -> Self {
        NetPayload::Err(ParseError::default())
    }
}

impl Default for IgmpType {
    fn default() -> Self {
        IgmpType::Unknown(0)
    }
}

impl Default for Icmp4Type {
    fn default() -> Self {
        Icmp4Type::Unknown(0)
    }
}

impl Default for Icmp6Type {
    fn default() -> Self {
        Icmp6Type::Unknown(0)
    }
}

impl Dhcp4Msg {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Dhcp4Msg::Discover,
            2 => Dhcp4Msg::Offer,
            3 => Dhcp4Msg::Request,
            4 => Dhcp4Msg::Decline,
            5 => Dhcp4Msg::Ack,
            6 => Dhcp4Msg::Nak,
            7 => Dhcp4Msg::Release,
            8 => Dhcp4Msg::Inform,
            other => Dhcp4Msg::Other(other),
        }
    }
}

impl UdpApp {
    /// Ярлык по src или dst. Более специфичный выигрывает (DHCP/mDNS раньше QUIC).
    pub fn from_ports(src: u16, dst: u16) -> Self {
        let a = Self::from_port(src);
        let b = Self::from_port(dst);
        if a.rank() <= b.rank() { a } else { b }
    }

    fn from_port(port: u16) -> Self {
        match port {
            67 | 68   => UdpApp::Dhcp4,
            546 | 547 => UdpApp::Dhcp6,
            5353      => UdpApp::Mdns,
            1900      => UdpApp::Ssdp,
            53        => UdpApp::Dns,
            5355      => UdpApp::Llmnr,
            123       => UdpApp::Ntp,
            443       => UdpApp::Quic,
            51820     => UdpApp::Wireguard,
            4500      => UdpApp::EspOverUdp,
            _         => UdpApp::Other,
        }
    }

    fn rank(self) -> u8 {
        match self {
            UdpApp::Dhcp4 | UdpApp::Dhcp6 | UdpApp::Mdns | UdpApp::Ssdp => 0,
            UdpApp::Dns | UdpApp::Llmnr | UdpApp::Ntp => 1,
            UdpApp::Quic | UdpApp::Wireguard | UdpApp::EspOverUdp => 2,
            UdpApp::Other => 3,
        }
    }
}

impl Icmp4Type {
    pub fn from_payload(payload: &[u8]) -> Self {
        let Some(&ty) = payload.first() else {
            return Icmp4Type::Unknown(0);
        };
        Self::from_u8(ty)
    }

    pub fn from_u8(ty: u8) -> Self {
        match ty {
            ICMP4_TYPE_ECHO_REPLY      => Icmp4Type::EchoReply,
            ICMP4_TYPE_DST_UNREACH     => Icmp4Type::DestUnreach,
            ICMP4_TYPE_REDIRECT        => Icmp4Type::Redirect,
            ICMP4_TYPE_ECHO_REQUEST    => Icmp4Type::EchoRequest,
            ICMP4_TYPE_RA              => Icmp4Type::RouterAdvertisement,
            ICMP4_TYPE_RS              => Icmp4Type::RouterSolicitation,
            ICMP4_TYPE_TIME_EXCEEDED   => Icmp4Type::TimeExceeded,
            ICMP4_TYPE_PARAM_PROBLEM   => Icmp4Type::ParamProblem,
            ICMP4_TYPE_TIMESTAMP       => Icmp4Type::Timestamp,
            ICMP4_TYPE_TIMESTAMP_REPLY => Icmp4Type::TimestampReply,
            other                      => Icmp4Type::Unknown(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Icmp4Type::EchoReply           => ICMP4_TYPE_ECHO_REPLY,
            Icmp4Type::DestUnreach         => ICMP4_TYPE_DST_UNREACH,
            Icmp4Type::Redirect            => ICMP4_TYPE_REDIRECT,
            Icmp4Type::EchoRequest         => ICMP4_TYPE_ECHO_REQUEST,
            Icmp4Type::RouterAdvertisement => ICMP4_TYPE_RA,
            Icmp4Type::RouterSolicitation  => ICMP4_TYPE_RS,
            Icmp4Type::TimeExceeded        => ICMP4_TYPE_TIME_EXCEEDED,
            Icmp4Type::ParamProblem        => ICMP4_TYPE_PARAM_PROBLEM,
            Icmp4Type::Timestamp           => ICMP4_TYPE_TIMESTAMP,
            Icmp4Type::TimestampReply      => ICMP4_TYPE_TIMESTAMP_REPLY,
            Icmp4Type::Unknown(t)          => t,
        }
    }
}

impl Icmp4Data {
    pub fn icmp4_type(&self) -> Icmp4Type {
        match self {
            Icmp4Data::EchoRequest { .. }         => Icmp4Type::EchoRequest,
            Icmp4Data::EchoReply { .. }           => Icmp4Type::EchoReply,
            Icmp4Data::DestUnreach { .. }         => Icmp4Type::DestUnreach,
            Icmp4Data::TimeExceeded { .. }        => Icmp4Type::TimeExceeded,
            Icmp4Data::ParamProblem { .. }        => Icmp4Type::ParamProblem,
            Icmp4Data::Redirect { .. }            => Icmp4Type::Redirect,
            Icmp4Data::Timestamp { .. }           => Icmp4Type::Timestamp,
            Icmp4Data::TimestampReply { .. }      => Icmp4Type::TimestampReply,
            Icmp4Data::RouterAdvertisement { .. } => Icmp4Type::RouterAdvertisement,
            Icmp4Data::RouterSolicitation        => Icmp4Type::RouterSolicitation,
            Icmp4Data::Unknown { type_u8, .. }    => Icmp4Type::Unknown(*type_u8),
        }
    }
}

impl Icmp6Type {
    pub fn from_payload(payload: &[u8]) -> Self {
        let Some(&ty) = payload.first() else {
            return Icmp6Type::Unknown(0);
        };
        Self::from_u8(ty)
    }

    pub fn from_u8(ty: u8) -> Self {
        match ty {
            ICMP6_TYPE_DST_UNREACH    => Icmp6Type::DestUnreach,
            ICMP6_TYPE_PACKET_TOO_BIG => Icmp6Type::PacketTooBig,
            ICMP6_TYPE_TIME_EXCEEDED  => Icmp6Type::TimeExceeded,
            ICMP6_TYPE_PARAM_PROBLEM  => Icmp6Type::ParamProblem,
            ICMP6_TYPE_ECHO_REQUEST   => Icmp6Type::EchoRequest,
            ICMP6_TYPE_ECHO_REPLY     => Icmp6Type::EchoReply,
            ICMP6_TYPE_MLD_QUERY      => Icmp6Type::MldQuery,
            ICMP6_TYPE_MLD_REPORT     => Icmp6Type::MldReport,
            ICMP6_TYPE_MLD_DONE       => Icmp6Type::MldDone,
            ICMP6_TYPE_RS             => Icmp6Type::RouterSolicitation,
            ICMP6_TYPE_RA             => Icmp6Type::RouterAdvertisement,
            ICMP6_TYPE_NS             => Icmp6Type::NeighborSolicitation,
            ICMP6_TYPE_NA             => Icmp6Type::NeighborAdvertisement,
            ICMP6_TYPE_REDIRECT       => Icmp6Type::Redirect,
            ICMP6_TYPE_MLDV2_REPORT   => Icmp6Type::MldV2Report,
            other                     => Icmp6Type::Unknown(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Icmp6Type::DestUnreach          => ICMP6_TYPE_DST_UNREACH,
            Icmp6Type::PacketTooBig         => ICMP6_TYPE_PACKET_TOO_BIG,
            Icmp6Type::TimeExceeded         => ICMP6_TYPE_TIME_EXCEEDED,
            Icmp6Type::ParamProblem         => ICMP6_TYPE_PARAM_PROBLEM,
            Icmp6Type::EchoRequest          => ICMP6_TYPE_ECHO_REQUEST,
            Icmp6Type::EchoReply            => ICMP6_TYPE_ECHO_REPLY,
            Icmp6Type::MldQuery             => ICMP6_TYPE_MLD_QUERY,
            Icmp6Type::MldReport            => ICMP6_TYPE_MLD_REPORT,
            Icmp6Type::MldDone              => ICMP6_TYPE_MLD_DONE,
            Icmp6Type::RouterSolicitation   => ICMP6_TYPE_RS,
            Icmp6Type::RouterAdvertisement  => ICMP6_TYPE_RA,
            Icmp6Type::NeighborSolicitation => ICMP6_TYPE_NS,
            Icmp6Type::NeighborAdvertisement=> ICMP6_TYPE_NA,
            Icmp6Type::Redirect             => ICMP6_TYPE_REDIRECT,
            Icmp6Type::MldV2Report          => ICMP6_TYPE_MLDV2_REPORT,
            Icmp6Type::Unknown(t)           => t,
        }
    }
}

impl Icmp6Data {
    pub fn icmp6_type(&self) -> Icmp6Type {
        match self {
            Icmp6Data::EchoRequest { .. }            => Icmp6Type::EchoRequest,
            Icmp6Data::EchoReply { .. }              => Icmp6Type::EchoReply,
            Icmp6Data::DestUnreach { .. }            => Icmp6Type::DestUnreach,
            Icmp6Data::PacketTooBig { .. }           => Icmp6Type::PacketTooBig,
            Icmp6Data::TimeExceeded { .. }           => Icmp6Type::TimeExceeded,
            Icmp6Data::ParamProblem { .. }           => Icmp6Type::ParamProblem,
            Icmp6Data::RouterSolicitation            => Icmp6Type::RouterSolicitation,
            Icmp6Data::RouterAdvertisement { .. }    => Icmp6Type::RouterAdvertisement,
            Icmp6Data::NeighborSolicitation { .. }   => Icmp6Type::NeighborSolicitation,
            Icmp6Data::NeighborAdvertisement { .. }  => Icmp6Type::NeighborAdvertisement,
            Icmp6Data::Redirect { .. }               => Icmp6Type::Redirect,
            Icmp6Data::MldQuery { .. }               => Icmp6Type::MldQuery,
            Icmp6Data::MldReport { .. }              => Icmp6Type::MldReport,
            Icmp6Data::MldDone { .. }                => Icmp6Type::MldDone,
            Icmp6Data::MldV2Report                   => Icmp6Type::MldV2Report,
            Icmp6Data::Unknown { type_u8, .. }       => Icmp6Type::Unknown(*type_u8),
        }
    }
}

impl IgmpType {
    /// Тип IGMP-сообщения по первому байту и длине среза.
    /// Версия Query (0x11) определяется длиной и Max Resp Time.
    pub fn from_payload(payload: &[u8]) -> Self {
        let Some(&ty) = payload.first() else {
            return IgmpType::Unknown(0);
        };
        match ty {
            IGMP_TYPE_QUERY => {
                if payload.len() > IGMP_V1V2_LEN {
                    // Длиннее 8 байт — IGMPv3 Query, даже если хвост обрезан.
                    IgmpType::V3Query
                } else if payload.len() == IGMP_V1V2_LEN {
                    if payload[1] == 0 { IgmpType::V1Query } else { IgmpType::V2Query }
                } else {
                    IgmpType::Query
                }
            }
            IGMP_TYPE_V1_REPORT => IgmpType::V1Report,
            IGMP_TYPE_V2_REPORT => IgmpType::V2Report,
            IGMP_TYPE_V2_LEAVE  => IgmpType::V2Leave,
            IGMP_TYPE_V3_REPORT => IgmpType::V3Report,
            other               => IgmpType::Unknown(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            IgmpType::Query | IgmpType::V1Query | IgmpType::V2Query | IgmpType::V3Query => IGMP_TYPE_QUERY,
            IgmpType::V1Report => IGMP_TYPE_V1_REPORT,
            IgmpType::V2Report => IGMP_TYPE_V2_REPORT,
            IgmpType::V2Leave  => IGMP_TYPE_V2_LEAVE,
            IgmpType::V3Report => IGMP_TYPE_V3_REPORT,
            IgmpType::Unknown(t) => t,
        }
    }
}

impl IgmpV3RecordType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => IgmpV3RecordType::ModeIsInclude,
            2 => IgmpV3RecordType::ModeIsExclude,
            3 => IgmpV3RecordType::ChangeToInclude,
            4 => IgmpV3RecordType::ChangeToExclude,
            5 => IgmpV3RecordType::AllowNewSources,
            6 => IgmpV3RecordType::BlockOldSources,
            other => IgmpV3RecordType::Unknown(other),
        }
    }
}

impl IgmpData {
    pub fn igmp_type(&self) -> IgmpType {
        match self {
            IgmpData::V1Query (_) => IgmpType::V1Query,
            IgmpData::V1Report(_) => IgmpType::V1Report,
            IgmpData::V2Query (_) => IgmpType::V2Query,
            IgmpData::V2Report(_) => IgmpType::V2Report,
            IgmpData::V2Leave (_) => IgmpType::V2Leave,
            IgmpData::V3Query (_) => IgmpType::V3Query,
            IgmpData::V3Report(_) => IgmpType::V3Report,
        }
    }
}


impl Default for TLV_DATA {
    fn default() -> Self {
        Self {
            tlv_len: 0,
            tlv_type: 0,
            tlv_data: [0u8; LLDP_TLV_MAX_LEN],
        }
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
            ParseError::Igmp_Broken { .. }              => "Igmp_Broken",
            ParseError::Esp_Broken { .. }               => "Esp_Broken",
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