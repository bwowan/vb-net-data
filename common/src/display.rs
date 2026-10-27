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
            IpType::Igmp             => write!(f, "IGMP"),
            IpType::Esp              => write!(f, "ESP"),
            IpType::Unsupported      => write!(f, "Unsupported"),
        }
    }
}

impl fmt::Display for IgmpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IgmpType::Query           => write!(f, "IGMP Query"),
            IgmpType::V1Query         => write!(f, "IGMPv1 Query"),
            IgmpType::V1Report        => write!(f, "IGMPv1 Report"),
            IgmpType::V2Query         => write!(f, "IGMPv2 Query"),
            IgmpType::V2Report        => write!(f, "IGMPv2 Report"),
            IgmpType::V2Leave         => write!(f, "IGMPv2 Leave"),
            IgmpType::V3Query         => write!(f, "IGMPv3 Query"),
            IgmpType::V3Report        => write!(f, "IGMPv3 Report"),
            IgmpType::Unknown(t) => write!(f, "IGMP type 0x{:02x}", t),
        }
    }
}

impl fmt::Display for IgmpV3RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IgmpV3RecordType::ModeIsInclude   => write!(f, "MODE_IS_INCLUDE"),
            IgmpV3RecordType::ModeIsExclude   => write!(f, "MODE_IS_EXCLUDE"),
            IgmpV3RecordType::ChangeToInclude => write!(f, "CHANGE_TO_INCLUDE"),
            IgmpV3RecordType::ChangeToExclude => write!(f, "CHANGE_TO_EXCLUDE"),
            IgmpV3RecordType::AllowNewSources => write!(f, "ALLOW_NEW_SOURCES"),
            IgmpV3RecordType::BlockOldSources => write!(f, "BLOCK_OLD_SOURCES"),
            IgmpV3RecordType::Unknown(t) => write!(f, "record 0x{:02x}", t),
        }
    }
}

impl fmt::Display for IgmpData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IgmpData::V1Query(v)        => write!(f, "IGMPv1 Query group={}", v.group),
            IgmpData::V1Report(v)       => write!(f, "IGMPv1 Report group={}", v.group),
            IgmpData::V2Query(v)        => write!(f, "IGMPv2 Query group={} max_resp={}", v.group, v.max_resp_time),
            IgmpData::V2Report(v)       => write!(f, "IGMPv2 Report group={}", v.group),
            IgmpData::V2Leave(v)        => write!(f, "IGMPv2 Leave group={}", v.group),
            IgmpData::V3Query(v)   => write!(
                f, "IGMPv3 Query group={} sources={} S={} QRV={} QQIC={}",
                v.group, v.sources.len(), v.suppress_router_processing, v.qrv, v.qqic
            ),
            IgmpData::V3Report(v) => write!(f, "IGMPv3 Report records={}", v.records.len()),
        }
    }
}

impl fmt::Display for EspData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SPI=0x{:08X}", self.spi)
    }
}

impl fmt::Display for Dhcp4Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dhcp4Msg::Discover => write!(f, "Discover"),
            Dhcp4Msg::Offer    => write!(f, "Offer"),
            Dhcp4Msg::Request  => write!(f, "Request"),
            Dhcp4Msg::Decline  => write!(f, "Decline"),
            Dhcp4Msg::Ack      => write!(f, "Ack"),
            Dhcp4Msg::Nak      => write!(f, "Nak"),
            Dhcp4Msg::Release  => write!(f, "Release"),
            Dhcp4Msg::Inform   => write!(f, "Inform"),
            Dhcp4Msg::Other(c) => write!(f, "type {}", c),
        }
    }
}

impl fmt::Display for Dhcp6Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dhcp6Msg::Solicit            => write!(f, "Solicit"),
            Dhcp6Msg::Advertise          => write!(f, "Advertise"),
            Dhcp6Msg::Request            => write!(f, "Request"),
            Dhcp6Msg::Confirm            => write!(f, "Confirm"),
            Dhcp6Msg::Renew              => write!(f, "Renew"),
            Dhcp6Msg::Rebind             => write!(f, "Rebind"),
            Dhcp6Msg::Reply              => write!(f, "Reply"),
            Dhcp6Msg::Release            => write!(f, "Release"),
            Dhcp6Msg::Decline            => write!(f, "Decline"),
            Dhcp6Msg::Reconfigure        => write!(f, "Reconfigure"),
            Dhcp6Msg::InformationRequest => write!(f, "Information-Request"),
            Dhcp6Msg::RelayForw          => write!(f, "Relay-forward"),
            Dhcp6Msg::RelayRepl          => write!(f, "Relay-reply"),
        }
    }
}

impl fmt::Display for NbnsOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NbnsOp::Query         => write!(f, "Query"),
            NbnsOp::Registration  => write!(f, "Registration"),
            NbnsOp::Release       => write!(f, "Release"),
            NbnsOp::Wack          => write!(f, "WACK"),
            NbnsOp::Refresh       => write!(f, "Refresh"),
            NbnsOp::Other(c) => write!(f, "op {}", c),
        }
    }
}

impl fmt::Display for NbnsMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.response {
            write!(f, "Response")?;
        } else {
            write!(f, "{}", self.op)?;
        }
        write!(f, " ")?;
        if !self.name.is_empty() {
            write!(f, "{} ", self.name)?;
        }
        write!(f, "<{:02X}>", self.suffix)?;
        if self.kind == NbnsKind::NbStat {
            write!(f, " NBSTAT")?;
        }
        if let Some(addr) = self.addr {
            write!(f, " {}", addr)?;
        }
        if self.response && self.rcode != 0 {
            write!(f, " rcode={}", self.rcode)?;
        }
        Ok(())
    }
}

fn write_addr_list<T: fmt::Display>(f: &mut fmt::Formatter<'_>, label: &str, addrs: &[T]) -> fmt::Result {
    if addrs.is_empty() {
        return Ok(());
    }
    write!(f, " {}=", label)?;
    for (i, addr) in addrs.iter().enumerate() {
        if i > 0 {
            write!(f, ",")?;
        }
        write!(f, "{}", addr)?;
    }
    Ok(())
}

impl fmt::Display for DnsQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut wrote = false;
        if let Some(name) = &self.name {
            write!(f, "q={}", name)?;
            wrote = true;
        }
        if let Some(service) = &self.service {
            if wrote {
                write!(f, " ")?;
            }
            write!(f, "service={}", service)?;
            wrote = true;
        }
        if let Some(ptr) = &self.ptr {
            if wrote {
                write!(f, " ")?;
            }
            write!(f, "PTR={}", ptr)?;
            wrote = true;
        }
        if let Some(srv) = &self.srv {
            if wrote {
                write!(f, " ")?;
            }
            write!(f, "SRV port={} host={}", srv.port, srv.host)?;
            wrote = true;
        }
        if let Some(a) = self.a {
            if wrote {
                write!(f, " ")?;
            }
            write!(f, "A={}", a)?;
            wrote = true;
        }
        if let Some(aaaa) = self.aaaa {
            if wrote {
                write!(f, " ")?;
            }
            write!(f, "AAAA={}", aaaa)?;
            wrote = true;
        }
        if let Some(txt) = &self.txt {
            if wrote {
                write!(f, " ")?;
            }
            write!(f, "TXT={}", txt)?;
        }
        Ok(())
    }
}

impl fmt::Display for UdpApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UdpApp::Dhcp4      => write!(f, "DHCP"),
            UdpApp::Dhcp6      => write!(f, "DHCPv6"),
            UdpApp::Dns        => write!(f, "DNS"),
            UdpApp::Mdns       => write!(f, "mDNS"),
            UdpApp::Ssdp       => write!(f, "SSDP"),
            UdpApp::Llmnr      => write!(f, "LLMNR"),
            UdpApp::Nbns       => write!(f, "NBNS"),
            UdpApp::Ntp        => write!(f, "NTP"),
            UdpApp::Quic       => write!(f, "QUIC"),
            UdpApp::Wireguard  => write!(f, "WireGuard"),
            UdpApp::EspOverUdp => write!(f, "ESP-UDP"),
            UdpApp::Other      => write!(f, "UDP"),
        }
    }
}

impl fmt::Display for Icmp4Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Icmp4Type::EchoReply           => write!(f, "ICMPv4 Echo Reply"),
            Icmp4Type::DestUnreach         => write!(f, "ICMPv4 Dest Unreach"),
            Icmp4Type::Redirect            => write!(f, "ICMPv4 Redirect"),
            Icmp4Type::EchoRequest         => write!(f, "ICMPv4 Echo Request"),
            Icmp4Type::RouterAdvertisement => write!(f, "ICMPv4 Router Advertisement"),
            Icmp4Type::RouterSolicitation  => write!(f, "ICMPv4 Router Solicitation"),
            Icmp4Type::TimeExceeded        => write!(f, "ICMPv4 Time Exceeded"),
            Icmp4Type::ParamProblem        => write!(f, "ICMPv4 Param Problem"),
            Icmp4Type::Timestamp           => write!(f, "ICMPv4 Timestamp"),
            Icmp4Type::TimestampReply      => write!(f, "ICMPv4 Timestamp Reply"),
            Icmp4Type::Unknown(t)          => write!(f, "ICMPv4 type {}", t),
        }
    }
}

impl fmt::Display for Icmp4Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Icmp4Data::EchoRequest { id, seq } => write!(f, "Echo Request id={} seq={}", id, seq),
            Icmp4Data::EchoReply { id, seq }   => write!(f, "Echo Reply id={} seq={}", id, seq),
            Icmp4Data::DestUnreach { code, mtu: Some(mtu) } => write!(f, "Dest Unreach code={} mtu={}", code, mtu),
            Icmp4Data::DestUnreach { code, mtu: None } => write!(f, "Dest Unreach code={}", code),
            Icmp4Data::TimeExceeded { code } => write!(f, "Time Exceeded code={}", code),
            Icmp4Data::ParamProblem { code, pointer } => write!(f, "Param Problem code={} pointer={}", code, pointer),
            Icmp4Data::Redirect { code, gateway } => write!(f, "Redirect code={} gateway={}", code, gateway),
            Icmp4Data::Timestamp { id, seq, originate, receive, transmit } => write!(
                f, "Timestamp id={} seq={} originate={} receive={} transmit={}", id, seq, originate, receive, transmit
            ),
            Icmp4Data::TimestampReply { id, seq, originate, receive, transmit } => write!(
                f, "Timestamp Reply id={} seq={} originate={} receive={} transmit={}", id, seq, originate, receive, transmit
            ),
            Icmp4Data::RouterAdvertisement { num_addrs, addr_entry_size, lifetime } => write!(
                f, "Router Advertisement addrs={} entry={} lifetime={}", num_addrs, addr_entry_size, lifetime
            ),
            Icmp4Data::RouterSolicitation => write!(f, "Router Solicitation"),
            Icmp4Data::Unknown { type_u8, code } => write!(f, "ICMPv4 type={} code={}", type_u8, code),
        }
    }
}

impl fmt::Display for Icmp6Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Icmp6Type::DestUnreach           => write!(f, "ICMPv6 Dest Unreach"),
            Icmp6Type::PacketTooBig          => write!(f, "ICMPv6 Packet Too Big"),
            Icmp6Type::TimeExceeded          => write!(f, "ICMPv6 Time Exceeded"),
            Icmp6Type::ParamProblem          => write!(f, "ICMPv6 Param Problem"),
            Icmp6Type::EchoRequest           => write!(f, "ICMPv6 Echo Request"),
            Icmp6Type::EchoReply             => write!(f, "ICMPv6 Echo Reply"),
            Icmp6Type::MldQuery              => write!(f, "MLD Query"),
            Icmp6Type::MldReport             => write!(f, "MLD Report"),
            Icmp6Type::MldDone               => write!(f, "MLD Done"),
            Icmp6Type::MldV2Report           => write!(f, "MLDv2 Report"),
            Icmp6Type::RouterSolicitation    => write!(f, "Router Solicitation"),
            Icmp6Type::RouterAdvertisement   => write!(f, "Router Advertisement"),
            Icmp6Type::NeighborSolicitation  => write!(f, "Neighbor Solicitation"),
            Icmp6Type::NeighborAdvertisement => write!(f, "Neighbor Advertisement"),
            Icmp6Type::Redirect              => write!(f, "Redirect"),
            Icmp6Type::Unknown(t)            => write!(f, "ICMPv6 type {}", t),
        }
    }
}

impl fmt::Display for Icmp6Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Icmp6Data::EchoRequest { id, seq } => write!(f, "Echo Request id={} seq={}", id, seq),
            Icmp6Data::EchoReply { id, seq }   => write!(f, "Echo Reply id={} seq={}", id, seq),
            Icmp6Data::DestUnreach { code }    => write!(f, "Dest Unreach code={}", code),
            Icmp6Data::PacketTooBig { mtu }    => write!(f, "Packet Too Big mtu={}", mtu),
            Icmp6Data::TimeExceeded { code }   => write!(f, "Time Exceeded code={}", code),
            Icmp6Data::ParamProblem { code }   => write!(f, "Param Problem code={}", code),
            Icmp6Data::RouterSolicitation     => write!(f, "Router Solicitation"),
            Icmp6Data::RouterAdvertisement { hop_limit, managed, other_config, lifetime, mtu, prefixes, dns, domain } => {
                write!(f, "Router Advertisement hop={} M={} O={} lifetime={}", hop_limit, managed, other_config, lifetime)?;
                for p in prefixes {
                    write!(f, " prefix={}/{}", p.prefix, p.len)?;
                }
                write_addr_list(f, "dns", dns)?;
                if let Some(domain) = domain {
                    write!(f, " domain={}", domain)?;
                }
                if let Some(mtu) = mtu {
                    write!(f, " mtu={}", mtu)?;
                }
                Ok(())
            }
            Icmp6Data::NeighborSolicitation { target, lladdr } => match lladdr {
                Some(mac) => write!(f, "Neighbor Solicitation target={} lladdr={}", target, mac),
                None => write!(f, "Neighbor Solicitation target={}", target),
            },
            Icmp6Data::NeighborAdvertisement { router, solicited, override_flag, target, lladdr } => match lladdr {
                Some(mac) => write!(
                    f, "Neighbor Advertisement target={} R={} S={} O={} lladdr={}",
                    target, router, solicited, override_flag, mac
                ),
                None => write!(
                    f, "Neighbor Advertisement target={} R={} S={} O={}",
                    target, router, solicited, override_flag
                ),
            },
            Icmp6Data::Redirect { target, destination } => write!(
                f, "Redirect target={} dest={}", target, destination
            ),
            Icmp6Data::MldQuery { max_resp_delay, group } => write!(
                f, "MLD Query group={} max_resp={}", group, max_resp_delay
            ),
            Icmp6Data::MldReport { group } => write!(f, "MLD Report group={}", group),
            Icmp6Data::MldDone { group }   => write!(f, "MLD Done group={}", group),
            Icmp6Data::MldV2Report         => write!(f, "MLDv2 Report"),
            Icmp6Data::Unknown { type_u8, code } => write!(f, "ICMPv6 type={} code={}", type_u8, code),
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
            ArpOp::Request           => write!(f, "Request"),
            ArpOp::Reply             => write!(f, "Reply"),
            ArpOp::RarpRequest       => write!(f, "RARP Request"),
            ArpOp::RarpReply         => write!(f, "RARP Reply"),
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
        match &self.l4 {
            IpL4::Igmp(igmp) => write!(f, "IP[{}({}bytes), src:{} --> dst:{}, {}]",
                IpType::Igmp, self.len, self.src, self.dst, igmp),
            IpL4::Icmp6(msg) => write!(f, "IP[{}({}bytes), src:{} --> dst:{}, {}]",
                IpType::Icmp6, self.len, self.src, self.dst, msg),
            IpL4::Icmp4(msg) => write!(f, "IP[{}({}bytes), src:{} --> dst:{}, {}]",
                IpType::Icmp4, self.len, self.src, self.dst, msg),
            IpL4::Esp(esp) => write!(f, "IP[{}({}bytes), src:{} --> dst:{}, {}]",
                IpType::Esp, self.len, self.src, self.dst, esp),
            IpL4::Udp { src_port, dst_port, app, msg } if *app != UdpApp::Other => match msg {
                Some(UdpMsg::Query(q)) => write!(
                    f, "IP[UDP/{} {}({}bytes), src:{}:{} --> dst:{}:{}]",
                    app, q, self.len, self.src, src_port, self.dst, dst_port
                ),
                Some(UdpMsg::Dhcp4 { msg, host, requested, router, dns, server, lease, domain }) => {
                    write!(f, "IP[UDP/{}", app)?;
                    if let Some(m) = msg {
                        write!(f, " {}", m)?;
                    }
                    if let Some(h) = host {
                        write!(f, " host={}", h)?;
                    }
                    if let Some(ip) = requested {
                        write!(f, " req={}", ip)?;
                    }
                    if let Some(ip) = router {
                        write!(f, " router={}", ip)?;
                    }
                    write_addr_list(f, "dns", dns)?;
                    if let Some(ip) = server {
                        write!(f, " server={}", ip)?;
                    }
                    if let Some(sec) = lease {
                        write!(f, " lease={}", sec)?;
                    }
                    if let Some(name) = domain {
                        write!(f, " domain={}", name)?;
                    }
                    write!(
                        f, "({}bytes), src:{}:{} --> dst:{}:{}",
                        self.len, self.src, src_port, self.dst, dst_port
                    )
                }
                Some(UdpMsg::Nbns(n)) => write!(
                    f, "IP[UDP/{} {}({}bytes), src:{}:{} --> dst:{}:{}]",
                    app, n, self.len, self.src, src_port, self.dst, dst_port
                ),
                Some(UdpMsg::Dhcp6 { msg, addr, dns }) => {
                    write!(f, "IP[UDP/{} {}", app, msg)?;
                    if let Some(ip) = addr {
                        write!(f, " addr={}", ip)?;
                    }
                    write_addr_list(f, "dns", dns)?;
                    write!(
                        f, "({}bytes), src:{}:{} --> dst:{}:{}",
                        self.len, self.src, src_port, self.dst, dst_port
                    )
                }
                Some(UdpMsg::Ssdp(s)) => {
                    write!(f, "IP[UDP/{} {}", app, s.start)?;
                    if let Some(nt) = &s.nt {
                        write!(f, " NT={}", nt)?;
                    }
                    if let Some(usn) = &s.usn {
                        write!(f, " USN={}", usn)?;
                    }
                    if let Some(loc) = &s.location {
                        write!(f, " LOCATION={}", loc)?;
                    }
                    write!(
                        f, "({}bytes), src:{}:{} --> dst:{}:{}",
                        self.len, self.src, src_port, self.dst, dst_port
                    )
                }
                _ => write!(f, "IP[UDP/{}({}bytes), src:{}:{} --> dst:{}:{}]",
                    app, self.len, self.src, src_port, self.dst, dst_port),
            },
            IpL4::Tcp { src_port, dst_port } => write!(
                f, "IP[{}({}bytes), src:{}:{} --> dst:{}:{}]",
                IpType::Tcp, self.len, self.src, src_port, self.dst, dst_port
            ),
            IpL4::Udp { src_port, dst_port, .. } => write!(
                f, "IP[{}({}bytes), src:{}:{} --> dst:{}:{}]",
                IpType::Udp, self.len, self.src, src_port, self.dst, dst_port
            ),
            IpL4::Other(t) => write!(f, "IP[{}({}bytes), src:{} --> dst:{}]",
                t, self.len, self.src, self.dst),
        }
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
            ParseError::Icmp4_Broken { len, src, dst, icmp4_type } => write!(
                f, "{} payload too short or invalid: {} bytes (src={}, dst={})", icmp4_type, len, src, dst
            ),
            ParseError::Icmp6_Broken { len, src, dst, icmp6_type } => write!(
                f, "{} payload too short or invalid: {} bytes (src={}, dst={})", icmp6_type, len, src, dst
            ),
            ParseError::Igmp_Broken { len, src, dst, igmp_type } => write!(
                f, "{} payload too short or invalid: {} bytes (src={}, dst={})", igmp_type, len, src, dst
            ),
            ParseError::Esp_Broken { len, src, dst } => write!(
                f, "ESP payload too short: {} bytes (need at least 8, src={}, dst={})", len, src, dst
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
