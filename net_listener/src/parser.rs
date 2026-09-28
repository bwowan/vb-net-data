#![allow(non_snake_case)]
use flume;
use common::{self};
use pnet_datalink;
use etherparse;
use std::cmp::min;
use tokio::time::{self, Duration};
//use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn get_mac_address(device_name: &str) -> Option<common::MacAddr6> {
    pnet_datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == device_name)
        .and_then(|iface| iface.mac)
        .map(|mac| common::MacAddr6::new(mac.octets()))
}


pub async fn parse_loop(own_mac : common::MacAddr6,
                        receiver: flume::Receiver<common::CapData>,
                        _sender : flume::Sender<common::NetData>)
{
    let mut interval = time::interval(Duration::from_secs(2));
    interval.tick().await;

    // Цикл будет работать, пока канал-приемник открыт и поставляет данные.
    // recv_async().await вернет Err, когда все отправители будут уничтожены.
    println!("PARSER: enter parsing");
    loop {
        //println!("PARSER: start loop");
        //println!(" Receiver --> disConnected_{} empty_{} full_{}, len:{}, cap:{}, s_cnt:{}, r_cnt:{}",
        //        receiver.is_disconnected(), receiver.is_empty(), receiver.is_full(), 
        //         receiver.len(), receiver.capacity().unwrap_or(9999), receiver.sender_count(), receiver.receiver_count());
        match receiver.recv_async().await {
            Err(e) => {
                println!("PARSER: error read from receiver - {:?}", e);
                break;
            }
            Ok(data) => {
                match parse_ethernet_packet(data, own_mac) {
                    Ok(_net_data) => {
                        //println!("[parser] {}", net_data);
                        /*match sender.send_async(net_data).await {
                            Ok(_) => {},
                            Err(e) => {
                                println!("[parser] Downstream receiver gone, stopping {:?}.", e);
                                break;
                            }
                        }*/
                    }
                    Err(e) => {
                        println!("[parser] {:?}", e);
                        continue;
                    }
                }
            }
        }
    }
    println!("PARSER: leave parsing");
}


// ── EtherType lookup ────────────────────────────────────────────────────────
const ETH_TYPES_PAIRS: [(pnet_packet::ethernet::EtherType, common::EthType); 8] = [
    (pnet_packet::ethernet::EtherTypes::Ipv4     , common::EthType::Ipv4     ),
    (pnet_packet::ethernet::EtherTypes::Ipv6     , common::EthType::Ipv6     ),
    (pnet_packet::ethernet::EtherTypes::Arp      , common::EthType::Arp      ),
    (pnet_packet::ethernet::EtherTypes::Rarp     , common::EthType::Rarp     ),
    (pnet_packet::ethernet::EtherTypes::Mpls     , common::EthType::Mpls     ),
    (pnet_packet::ethernet::EtherTypes::MplsMcast, common::EthType::MplsMcast),
    (pnet_packet::ethernet::EtherTypes::Lldp     , common::EthType::Lldp     ),
    (pnet_packet::ethernet::EtherType(0x9003)    , common::EthType::Ectp     ), //ECTP \[IEEE 802.3\]
];


fn find_eth_type(protocol: pnet_packet::ethernet::EtherType) -> common::EthType {
    if let Some(p) = ETH_TYPES_PAIRS.iter().find(|&&p| p.0 == protocol) {
        p.1
    } else {
        common::EthType::Unsupported
    }
}

fn get_direction(src: &common::MacAddr6, dst: &common::MacAddr6, own_mac: &common::MacAddr6) -> common::EDirection {
    if dst.0[0] & 1 == 1 {
        if *dst == common::BROADCAST_ADDRESS6 {
            common::EDirection::Broadcast
        } else {
            common::EDirection::Multicast
        }
    } else if src == own_mac {
        common::EDirection::Outgoing
    } else if dst == own_mac {
        common::EDirection::Incoming
    } else {
        common::EDirection::Unknown
    }
}


// ── Ethernet ────────────────────────────────────────────────────────────────
fn parse_ethernet_packet(data: common::CapData, own_mac: common::MacAddr6) -> Result<common::NetData, common::ParseError> {
    let (eth_header, eth_payload) = etherparse::Ethernet2Header::from_slice(&data.data).map_err(|e| {
            println!("{:?}", e);
            common::ParseError::Eth_Broken { len: data.data.len() }
        })?;
    
    let (src, dst) = (common::MacAddr6::new(eth_header.source), common::MacAddr6::new(eth_header.destination));
    let dir = get_direction(&src, &dst, &own_mac);
    let prot = find_eth_type(pnet_packet::ethernet::EtherType::new(eth_header.ether_type.0));

    let result: Result<common::NetPayload, common::ParseError> = match eth_header.ether_type.0 {
                0x0000..=0x0007 | 0x05DC..=0x05FF => // Зарезервированные/недопустимые диапазоны
                    Err(common::ParseError::Unsupported_Eth { id: eth_header.ether_type.0 }),
                
                0x0008..=0x05DB  =>                  //LLC + SNAP headers → ожидаем IEEE 802.3 + LLC
                    parse_LLC_SNAP(eth_payload, eth_header.ether_type.0),
                
                0x0600..=0xFFFF =>                   // 1536 - type is type
                    parse_RegularEthernet(eth_payload, prot),

    };
    match result {
        Ok(r) => {
                let eth_data = common::EthData { src, dst, dir, prot};
                let result  = common::NetData { eth: eth_data, payload: r };
                if prot != common::EthType::Ipv4  &&  prot != common::EthType::Ipv6 {
                    println!("{}", result);
                }
                Ok(result)
            },
        Err(e) => return Err(e),
    }    
}

// ── Etehernet LLC+SNAP ──────────────────────────────────────────────────────────
fn parse_LLC_SNAP(pl: &[u8], prot:u16) -> Result<common::NetPayload, common::ParseError> {
    if pl.len() < (8usize+4usize) {
        Err(common::ParseError::LLC_SNAP_TooShort_Broken { id: prot, len: prot as usize})
    } else {
        let llc_header = &pl[0..3];
        if llc_header != [0xAA, 0xAA, 0x03] { //there is SNAP Header (IEEE 802.2 LLC SNAP)
            Err(common::ParseError::LLC_SNAP_Header_Broken { id: prot, header: pl[0..8].try_into().unwrap() })
        } else {
            let oui = u32::from_be_bytes([0, pl[3], pl[4], pl[5]]);
            let snap_prot = u16::from_be_bytes([pl[6], pl[7]]);
            let snap_payload = &pl[8..];
            match oui { //OUI (Organizationally Unique Identifier) - 3 bytes, Protocol ID - 2 bytes (total 5 bytes)
                0x00000C => { // Cisco
                    parse_Cisco(snap_payload, snap_prot).map(common::NetPayload::Cisco)
                }
                0x08002B => { // DEC
                    parse_DECSnapHeader(snap_payload).map(common::NetPayload::DEC)
                }
                _ => Err(common::ParseError::Unsupported_Eth_SNAP_OUI { oui: [pl[3], pl[4], pl[5]], prot_id: snap_prot }),
            }
        }
    }
}



// ── Etehernet packet ──────────────────────────────────────────────────────────
fn parse_RegularEthernet(pl: &[u8], prot:common::EthType) -> Result<common::NetPayload, common::ParseError> {
    match prot {
        common::EthType::Ipv4                => parse_ipv4    (pl),
        common::EthType::Ipv6                => parse_ipv6    (pl),
        common::EthType::Arp              |
        common::EthType::Rarp                => parse_arp     (pl).map(|r     | common::NetPayload::Arp (r)),
        common::EthType::Mpls             | 
        common::EthType::MplsMcast           => parse_mpls    (pl).map(|r    | common::NetPayload::Mpls(r)),
        common::EthType::Ectp                => parse_Loopback(pl).map(|r| common::NetPayload::Ectp(r)),
        common::EthType::Lldp                => parse_LLDP    (pl).map(|r   | common::NetPayload::Lldp(r)),

        _ => Err(common::ParseError::Unsupported_Eth { id: prot as u16})
    }
}

// ── Etyhernet Cisco SNAP ─────────────────────────────────────────────────────
fn parse_Cisco(pl: &[u8], protocol_id: u16) -> Result<common::CiscoData, common::ParseError> {
    //to do another Cisco protocols: 0x2001, 0x2003, 0x2004, 0x200E, 0x010B, 0x010C
    if protocol_id == 0x2000 {
        return parse_CISCO_CDP(pl).map(|r|common::CiscoData::CDP(r));
    }
    Err(common::ParseError::Cisco_Broken { len: pl.len(), sub_type: protocol_id })
}

// ── IP ───────────────────────────────────────────────────────────────────────
// from_slice у IPv4/IPv6 отдаёт весь хвост кадра, вместе с Ethernet-padding.
// До parse_l4 длина берётся из заголовка, у IPv6 ещё пропускаются extension
// headers. Непервый фрагмент сюда не доходит: L4-заголовка в его начале нет.

fn parse_ipv4(pl: &[u8]) -> Result<common::NetPayload, common::ParseError> {
    let (ip, rest) = etherparse::Ipv4Header::from_slice(pl)
        .map_err(|_| common::ParseError::Ip4_Broken { len: pl.len() })?;

    let src = common::IpAddr::from(ip.source);
    let dst = common::IpAddr::from(ip.destination);

    // Смещение в блоках по 8 байт. Ненулевое — этот фрагмент начинается
    // в середине исходной дейтаграммы, а не с заголовка TCP/UDP/ICMP.
    if ip.fragment_offset.value() != 0 {
        return Err(common::ParseError::Ip4_Fragment { src, dst });
    }

    let ip_payload = ipv4_payload_slice(&ip, rest);
    let ip_data = parse_l4(ip_payload, &src, &dst, ip.protocol)?;
    Ok(common::NetPayload::Ip(ip_data))
}

fn parse_ipv6(pl: &[u8]) -> Result<common::NetPayload, common::ParseError> {
    let (ip, rest) = etherparse::Ipv6Header::from_slice(pl)
        .map_err(|_| common::ParseError::Ip6_Broken { len: pl.len() })?;

    let src = common::IpAddr::from(ip.source);
    let dst = common::IpAddr::from(ip.destination);

    let ip_payload = ipv6_payload_slice(&ip, rest);
    let (l4, l4_proto) = ipv6_l4_slice(ip.next_header, ip_payload, &src, &dst)?;
    let ip_data = parse_l4(l4, &src, &dst, l4_proto)?;
    Ok(common::NetPayload::Ip(ip_data))
}

/// Обрезает хвост до объявленной длины, если она помещается в срез.
/// Иначе (обрезанный захват или длина больше буфера) возвращает хвост целиком.
/// `None` — длина в заголовке бессмысленна, хвост тоже не трогаем.
fn clamp_declared_payload<'a>(declared: Option<usize>, rest: &'a [u8]) -> &'a [u8] {
    match declared {
        Some(len) if len <= rest.len() => &rest[..len],
        _ => rest,
    }
}

/// Payload IPv4: `total_len` минус длина заголовка, включая опции.
fn ipv4_payload_slice<'a>(ip: &etherparse::Ipv4Header, rest: &'a [u8]) -> &'a [u8] {
    let declared = ip.payload_len().ok().map(usize::from);
    clamp_declared_payload(declared, rest)
}

/// Payload IPv6 вместе с extension headers.
/// `payload_length == 0` — jumbogram или пустой пакет, срез не обрезается.
fn ipv6_payload_slice<'a>(ip: &etherparse::Ipv6Header, rest: &'a [u8]) -> &'a [u8] {
    if ip.payload_length == 0 {
        return rest;
    }
    clamp_declared_payload(Some(usize::from(ip.payload_length)), rest)
}

/// Пропускает Hop-by-Hop, Routing, Destination Options, Fragment и AH.
/// Возвращает номер протокола L4 и срез, который с него начинается.
/// Непервый фрагмент не разбирается: его тело — продолжение предыдущего.
fn ipv6_l4_slice<'a>(
    next_header: etherparse::IpNumber,
    payload: &'a [u8],
    src: &common::IpAddr,
    dst: &common::IpAddr,
) -> Result<(&'a [u8], etherparse::IpNumber), common::ParseError> {
    let (exts, l4_proto, l4) = etherparse::Ipv6Extensions::from_slice(next_header, payload)
        .map_err(|_| common::ParseError::Ip6_Broken { len: payload.len() })?;

    if exts.fragment.as_ref().is_some_and(|frag| frag.fragment_offset.value() != 0) {
        return Err(common::ParseError::Ip6_Fragment { src: *src, dst: *dst });
    }
    Ok((l4, l4_proto))
}


// ── L4 ───────────────────────────────────────────────────────────────────────
// `payload` уже начинается с заголовка L4 и обрезан до длины дейтаграммы
// (без Ethernet-padding и без IPv6 extension headers). IpData.len — эта длина.
fn parse_l4(
    payload : &[u8],
    src     : &common::IpAddr,
    dst     : &common::IpAddr,
    protocol: etherparse::IpNumber,
) -> Result<common::IpData, common::ParseError> {
    match protocol {
        etherparse::IpNumber::TCP => {
            let (tcp, _) = etherparse::TcpHeader::from_slice(payload)
                .map_err(|_| common::ParseError::Tcp_Broken { len: payload.len(), src: *src, dst: *dst })?;
            Ok(common::IpData::new_tcp_udp(common::IpType::Tcp, src, dst, payload.len(),
                                         tcp.source_port, tcp.destination_port))
        }
        etherparse::IpNumber::UDP => {
            let (udp, _) = etherparse::UdpHeader::from_slice(payload)
                .map_err(|_| common::ParseError::Udp_Broken { len: payload.len(), src: *src, dst: *dst })?;
            Ok(common::IpData::new_tcp_udp(common::IpType::Udp, src, dst, payload.len(),
                                         udp.source_port, udp.destination_port))
        }
        etherparse::IpNumber::ICMP => {
            etherparse::Icmpv4Header::from_slice(payload)
                .map_err(|_| common::ParseError::Icmp4_Broken { len: payload.len(), src: *src, dst: *dst })?;
            Ok(common::IpData::new_icmp4(src, dst, payload.len()))
        }
        etherparse::IpNumber::IPV6_ICMP => {
            etherparse::Icmpv6Header::from_slice(payload)
                .map_err(|_| common::ParseError::Icmp6_Broken { len: payload.len(), src: *src, dst: *dst })?;
            Ok(common::IpData::new_icmp6(src, dst, payload.len()))
        }
        other => Err(common::ParseError::Unsupported_L4 { id: other.0 }),
    }
}


// ── ARP / RARP ───────────────────────────────────────────────────────────────
// ARP packet (IPv4 over Ethernet, 28 bytes):
//   0-1  : hardware type  (1 = Ethernet)
//   2-3  : protocol type  (0x0800 = IPv4)
//   4    : hw addr length (6)
//   5    : proto addr len (4)
//   6-7  : operation (1=request, 2=reply, 3=RARP request, 4=RARP reply)
//   8-13 : sender MAC
//   14-17: sender IP
//   18-23: target MAC
//   24-27: target IP
fn parse_arp(pl: &[u8]) -> Result<common::ArpData, common::ParseError> {
    let arp = etherparse::ArpPacketSlice::from_slice(pl)
        .map_err(|_| common::ParseError::Arp_Broken { len: pl.len() })?;
    let packet = arp.to_packet();
    let ipv4 = packet.try_eth_ipv4().map_err(|_| common::ParseError::Arp_Unsupported {
        hw_type: packet.hw_addr_type.0,
        proto_type: packet.proto_addr_type.0,
        hw_len: packet.hw_addr_size(),
        proto_len: packet.protocol_addr_size(),
    })?;

    let op = match ipv4.operation.0 {
        1 => common::ArpOp::Request,
        2 => common::ArpOp::Reply,
        3 => common::ArpOp::RarpRequest,
        4 => common::ArpOp::RarpReply,
        other => common::ArpOp::Unknown(other),
    };

    Ok(common::ArpData::new(
        op,
        common::MacAddr6::new(ipv4.sender_mac),
        ipv4.sender_ipv4_addr(),
        common::MacAddr6::new(ipv4.target_mac),
        ipv4.target_ipv4_addr(),
    ))
}

// ── MPLS ─────────────────────────────────────────────────────────────────────
//
// MPLS label stack entry (4 bytes):
//   bits 31-12 (20 bits): label
//   bits 11-9  ( 3 bits): TC (traffic class)
//   bit  8     ( 1 bit ): S  (bottom of stack)
//   bits 7-0   ( 8 bits): TTL

fn parse_mpls(pl: &[u8]) -> Result<common::MplsData, common::ParseError> {
    if pl.len() < 4 {
        Err(common::ParseError::Mpls_Broken { len: pl.len() })
    } else {
        let word = u32::from_be_bytes([pl[0], pl[1], pl[2], pl[3]]);
        let r = common::MplsData::new((word >> 12) & 0x000F_FFFF, ((word >> 9) & 0x7) as u8,  (word & 0x100) != 0, (word & 0xFF) as u8);
        Ok(r)
    }
}

fn parse_Loopback(pl : &[u8]) -> Result<common::LoopbackData, common::ParseError> {
    if pl.len() < 4 {
        Err(common::ParseError::Lldp_Broken { len: pl.len() })
    } else {
        let skip_count = u16::from_be_bytes([pl[0], pl[1]]);
        let function   = u16::from_be_bytes([pl[2], pl[3]]);
        let receipt_mac = if pl.len() < 10 {common::MacAddr6::empty()} else {common::MacAddr6::from_slice(&pl[4..10])};
        let r = common::LoopbackData { skip_count, function, receipt_mac };
        Ok(r)
    }
}

fn parse_DECSnapHeader(pl : &[u8]) -> Result<common::DECSnapHeader, common::ParseError> {
    if pl.len() < 8 {
        Err(common::ParseError::DEC_Broken { len: pl.len(), sub_type: 0 })
    } else {
        let r = common::DECSnapHeader { dsap:pl[0], ssap:pl[1], control:pl[2], oui:[pl[3], pl[4], pl[5]], protocol_id:u16::from_be_bytes([pl[6], pl[7]]) };
        Ok(r)
    }
}

fn parse_CISCO_TLV(pl: &[u8], tlv_type: u16, value_len: usize) -> common::TLV_DATA {
    // value_len — длина value (без type+len); tlv_data хранит только value
    let copy_len = min(common::LLDP_TLV_MAX_LEN, value_len);
    let mut tlv_data = [0u8; common::LLDP_TLV_MAX_LEN];
    tlv_data[..copy_len].copy_from_slice(&pl[..copy_len]);
    common::TLV_DATA {
        tlv_type,
        tlv_len: value_len as u16,
        tlv_data,
    }
}

fn parse_CISCO_CDP_ADDRESSES(pl: &[u8]) -> heapless::Vec<common::CISCO_CDP_ADDRESS, { common::CISCO_CDP_MAX_ADDRESSES }> {
    let mut result = heapless::Vec::new();
    let len = pl.len();
    if len == 0 {
        return result;
    }
    let count = pl[0];
    let mut n: usize = 1;
    let n_addresses = std::cmp::min(common::CISCO_CDP_MAX_ADDRESSES, count as usize);
    for _i_address in 0..n_addresses {
        // Protocol type (1) + protocol length (1) + protocol + address length (2)
        if n + 2 > len {
            break;
        }
        let prot_type = pl[n];
        let prot_len = pl[n + 1] as usize;
        n += 2;
        if prot_len == 0 || n + prot_len > len {
            break;
        }
        // CDP обычно prot_len=1 (NLPID); >2 — читаем до 2 байт BE, список не обрываем
        let prot: u16 = match prot_len {
            1 => pl[n] as u16,
            2 => u16::from_be_bytes([pl[n], pl[n + 1]]),
            _ => {
                let hi = pl[n] as u16;
                let lo = if prot_len > 1 { pl[n + 1] as u16 } else { 0 };
                (hi << 8) | lo
            }
        };
        n += prot_len;
        if n + 2 > len {
            break;
        }
        let addr_len = u16::from_be_bytes([pl[n], pl[n + 1]]) as usize;
        n += 2;
        if n + addr_len > len {
            break;
        }
        let copy_len = std::cmp::min(common::CISCO_CDP_MAX_ADDRESS_LEN, addr_len);
        let mut address = common::CISCO_CDP_ADDRESS {
            prot_type,
            prot_len: prot_len as u8,
            prot,
            addr_len: addr_len as u16,
            ..Default::default()
        };
        address.addr[..copy_len].copy_from_slice(&pl[n..n + copy_len]);
        let _ = result.push(address);
        n += addr_len;
    }
    result
}

fn parse_CISCO_CDP(pl: &[u8]) -> Result<common::CDP_CISCO_DATA, common::ParseError> {
    let data_len = pl.len();
    // минимум: header(4) + один TLV header(4)
    if data_len < 8 {
        return Err(common::ParseError::Cisco_Broken { len: data_len, sub_type: 0 });
    }

    let ver = pl[0];
    if ver != 1 && ver != 2 {
        return Err(common::ParseError::Cisco_Broken { len: data_len, sub_type: 0x2000 });
    }

    let chksm = u16::from_be_bytes([pl[2], pl[3]]);
    let cdp_header = common::CISCO_CDP_HEADER { ver, ttl: pl[1], chksm };
    let mut data = common::CDP_CISCO_DATA { Header: cdp_header, ..Default::default() };

    let mut n: usize = 4;
    // Sniffer-политика: битый/обрезанный TLV → break; если Device-ID уже есть → Ok(partial)
    while n + 4 <= data_len {
        let tlv_type = u16::from_be_bytes([pl[n], pl[n + 1]]);
        let tlv_len = u16::from_be_bytes([pl[n + 2], pl[n + 3]]) as usize;
        if tlv_len < 4 || n + tlv_len > data_len {
            break;
        }
        let value = &pl[n + 4..n + tlv_len];
        let value_len = tlv_len - 4;
        match tlv_type {
            0x0002 => {
                let parsed = parse_CISCO_CDP_ADDRESSES(value);
                for addr in parsed {
                    if data.addresses.push(addr).is_err() {
                        break;
                    }
                }
            }
            0x0004 => {
                if value.len() >= 4 {
                    data.Capabilities = u32::from_be_bytes(value[..4].try_into().unwrap_or_default());
                }
            }
            // 0x0001 Device-ID, 0x0003 Port-ID, 0x0005 Version, 0x0006 Platform,
            // 0x000a Native VLAN, 0x000b Duplex, прочие — в tlvs (value_len)
            _ => {
                let _ = data.tlvs.push(parse_CISCO_TLV(value, tlv_type, value_len));
            }
        }
        n += tlv_len;
    }

    let has_device_id = data.tlvs.iter().any(|t| t.tlv_type == 0x0001 && t.tlv_len > 0);
    if has_device_id {
        Ok(data)
    } else {
        Err(common::ParseError::Cisco_Broken {
            len: data_len,
            sub_type: 0x2000,
        })
    }
}


fn parse_LLDP_TLV(pl : &[u8], n: usize) -> common::TLV_DATA {
    let tlv_header = u16::from_be_bytes([pl[n], pl[n+1]]);
    let mut tlv = common::TLV_DATA {tlv_type: tlv_header >> 9,  tlv_len: tlv_header & 0x01FF,  ..Default::default() };
    if tlv.tlv_len > 0 {
        let copy_len = min(pl.len() - n - 2,  min(common::LLDP_TLV_MAX_LEN, tlv.tlv_len as usize));
        //let mut tlv_data = [0u8; common::LLDP_TLV_MAX_LEN];
        tlv.tlv_data[..copy_len].copy_from_slice(&pl[n+2..n+2+copy_len]);
    }
    tlv
}

/// Management Address TLV (type 8), IEEE 802.1AB:
///   addr_str_len(1) | family(1) | addr[N] | if_subtype(1) | if_number(4) | oid_len(1) [| oid]
fn parse_LLDP_MgmtAddr(value: &[u8]) -> Option<common::LLDP_MgmtAddr> {
    if value.is_empty() {
        return None;
    }
    let addr_str_len = value[0] as usize;
    // family(1) + addr must fit in addr_str_len; then if_subtype+if_number+oid_len
    if addr_str_len < 2 || value.len() < 1 + addr_str_len + 1 + 4 + 1 {
        return None;
    }
    let family = value[1];
    let addr_len = addr_str_len - 1;
    if addr_len > 16 || 2 + addr_len > 1 + addr_str_len {
        return None;
    }
    let mut addr = [0u8; 16];
    addr[..addr_len].copy_from_slice(&value[2..2 + addr_len]);
    let base = 1 + addr_str_len;
    let if_subtype = value[base];
    let if_number = u32::from_be_bytes([
        value[base + 1],
        value[base + 2],
        value[base + 3],
        value[base + 4],
    ]);
    // oid_len = value[base + 5]; oid ignored
    Some(common::LLDP_MgmtAddr {
        family,
        addr_len: addr_len as u8,
        addr,
        if_subtype,
        if_number,
    })
}


pub fn parse_LLDP(pl: &[u8]) ->  Result<common::LLDP_Data, common::ParseError> {
    // LLDP TLV types (IEEE 802.1AB), type в старших 7 битах заголовка:
    //   0   — End of LLDPDU
    //   1   — Chassis ID          (обязательный)
    //   2   — Port ID             (обязательный)
    //   3   — Time To Live        (обязательный)
    //   4   — Port Description
    //   5   — System Name
    //   6   — System Description
    //   7   — System Capabilities
    //   8   — Management Address
    //   9–126 — reserved
    //   127 — Organizationally Specific (OUI + subtype + info)
    let mut n: usize = 0;
    let mut lldp = common::LLDP_Data::default();
    let data_len = pl.len();
    let mut complete: u8 = 0;
    while n + 2 <= data_len {
        let tlv = parse_LLDP_TLV(pl, n);
        if tlv.tlv_type != 0 {
            match tlv.tlv_type {
                // 1 Chassis ID, 2 Port ID — обязательные, кладём в tlvs
                1 | 2 => {
                    complete |= 1 << (tlv.tlv_type - 1); // 1->bit0, 2->bit1
                    let _ = lldp.tlvs.push(tlv);
                },
                // 3 Time To Live — обязательный, TTL в секундах (2 байта)
                3 => {
                    lldp.TTL = u16::from_be_bytes([tlv.tlv_data[0], tlv.tlv_data[1]]);
                    complete |= 4;
                },
                // 7 System Capabilities — supported (2) + enabled (2)
                7 => if tlv.tlv_len >= 4 {
                        lldp.Sys_CAP_supported = u16::from_be_bytes([tlv.tlv_data[0], tlv.tlv_data[1]]);
                        lldp.Sys_CAP_enabled   = u16::from_be_bytes([tlv.tlv_data[2], tlv.tlv_data[3]]);
                        complete |= 8;
                    },
                // 8 Management Address — IPv4/IPv6 + interface number
                8 => {
                    let len = min(tlv.tlv_len as usize, common::LLDP_TLV_MAX_LEN);
                    if let Some(m) = parse_LLDP_MgmtAddr(&tlv.tlv_data[..len]) {
                        let _ = lldp.mgmt_addrs.push(m);
                    }
                },
                // 127 Organizationally Specific: OUI(3) + subtype(1) + info
                127 => if tlv.tlv_len >= 4 {
                        let _ = lldp.tlvs.push(tlv);
                    },
                // 4 Port Description, 5 System Name, 6 System Description,
                // 9–126 reserved — сырые TLV в tlvs
                _ => {
                    let _ = lldp.tlvs.push(tlv);
                }
            }
            n += 2 + tlv.tlv_len as usize;  // 2 байта заголовка TLV (тип+длина) + данные
        } else {
            // 0 End of LLDPDU — конец списка TLV
            n = data_len
        }
    }
    if complete >= 7 {
        Ok(lldp)
    } else {
        Err( common::ParseError::Lldp_Broken{ len: data_len } )
    }
}

/*
Ethernet Header: Вы уже его прочли. Видите поле Length (например, 60).

LLC Header (3 байта): Обычно это 0xAA 0xAA 0x03. Это метка того, что дальше идет SNAP.

SNAP Header (5 байт):

    3 байта — OUI (Organizationally Unique Identifier). Для протоколов DEC это обычно 08 00 2B.

    2 байта — Protocol ID. Вот здесь и лежат ваши 0x0060 или 0x005A.

Protocol Data: И только после этих 8 байт (3 LLC + 5 SNAP) начинаются данные самой структуры (например, DecLoopback).
// Допустим, packet — это SlicedPacket от etherparse
if let Some(eth) = packet.ethernet {
    let ether_type_or_len = eth.ether_type(); // Это наше значение < 0x0600
    
    if ether_type_or_len < 0x0600 {
        let payload = packet.payload;
        
        // 1. Проверяем, достаточно ли данных для LLC + SNAP (минимум 8 байт)
        if payload.len() >= 8 {
            // 2. Проверяем заголовок SNAP (LLC: AA AA 03 + OUI: 08 00 2B)
            let is_dec = payload[0] == 0xAA && payload[1] == 0xAA && payload[2] == 0x03 
                         && &payload[3..6] == &[0x08, 0x00, 0x2B];
            
            if is_dec {
                // 3. Читаем Protocol ID (байты 6 и 7)
                let protocol_id = u16::from_be_bytes([payload[6], payload[7]]);
                
                // 4. Смещаемся к фактическим данным протокола
                let actual_data = &payload[8..];
                
                match protocol_id {
                    0x0060 => parse_dec_loopback(actual_data),
                    0x005A => parse_mop_console(actual_data),
                    _ => println!("Другой протокол DEC: {:#06x}", protocol_id),
                }
            }
        }
    }
} */

#[cfg(test)]
mod tests {
    use super::*;

    fn lldp_tlv(tlv_type: u16, value: &[u8]) -> Vec<u8> {
        let header = (tlv_type << 9) | (value.len() as u16 & 0x01FF);
        let mut out = Vec::with_capacity(2 + value.len());
        out.extend_from_slice(&header.to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    fn lldp_mandatory() -> Vec<u8> {
        let mut packet = Vec::new();
        // Chassis ID (type 1): subtype MAC + 6 bytes
        packet.extend(lldp_tlv(1, &[0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
        // Port ID (type 2): subtype interface name "eth0"
        packet.extend(lldp_tlv(2, &[0x05, b'e', b't', b'h', b'0']));
        // TTL (type 3): 120 sec
        packet.extend(lldp_tlv(3, &120u16.to_be_bytes()));
        packet
    }

    /// Обязательные TLV Chassis ID, Port ID и TTL разбираются, TTL сохраняется.
    #[test]
    fn lldp_minimal_ok() {
        let packet = lldp_mandatory();
        let data = parse_LLDP(&packet).expect("valid minimal LLDP");
        assert_eq!(data.TTL, 120);
        assert!(data.tlvs.iter().any(|t| t.tlv_type == 1));
        assert!(data.tlvs.iter().any(|t| t.tlv_type == 2));
    }

    /// Без обязательного TTL кадр отвергается как Lldp_Broken.
    #[test]
    fn lldp_missing_mandatory_err() {
        // only Chassis + Port, no TTL
        let mut packet = Vec::new();
        packet.extend(lldp_tlv(1, &[0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
        packet.extend(lldp_tlv(2, &[0x05, b'e', b't', b'h', b'0']));
        assert!(matches!(
            parse_LLDP(&packet),
            Err(common::ParseError::Lldp_Broken { .. })
        ));
    }

    /// Organizationally Specific TLV (тип 127) сохраняет OUI, subtype и значение.
    #[test]
    fn lldp_org_specific_127() {
        let mut packet = lldp_mandatory();
        // type 127: OUI 00:12:BB (TIA MED), subtype 1 (Port VLAN ID), value 0x0001
        packet.extend(lldp_tlv(127, &[0x00, 0x12, 0xBB, 0x01, 0x00, 0x01]));
        // End of LLDPDU
        packet.extend(lldp_tlv(0, &[]));

        let data = parse_LLDP(&packet).expect("LLDP with org-specific");
        let org = data
            .tlvs
            .iter()
            .find(|t| t.tlv_type == 127)
            .expect("org-specific TLV present");
        let org_len = org.tlv_len;
        let org_data = org.tlv_data;
        assert_eq!(org_len, 6);
        assert_eq!(&org_data[0..3], &[0x00, 0x12, 0xBB]);
        assert_eq!(org_data[3], 0x01);
        assert_eq!(&org_data[4..6], &[0x00, 0x01]);
    }

    /// Слишком короткий TLV 127 пропускается, остальные TLV кадра остаются.
    #[test]
    fn lldp_org_specific_127_too_short_skipped() {
        let mut packet = lldp_mandatory();
        // type 127 with only 3 bytes — слишком коротко для OUI+subtype
        packet.extend(lldp_tlv(127, &[0x00, 0x12, 0xBB]));

        let data = parse_LLDP(&packet).expect("still valid without short org TLV");
        assert!(!data.tlvs.iter().any(|t| t.tlv_type == 127));
    }

    /// System Name и System Capabilities читаются, End of LLDPDU останавливает разбор.
    #[test]
    fn lldp_optional_tlvs_and_end() {
        let mut packet = lldp_mandatory();
        packet.extend(lldp_tlv(5, b"MySwitch")); // System Name
        packet.extend(lldp_tlv(7, &[0x00, 0x14, 0x00, 0x14])); // Sys Cap: bridge+router
        packet.extend(lldp_tlv(0, &[])); // End

        let data = parse_LLDP(&packet).expect("LLDP with optionals");
        assert_eq!(data.Sys_CAP_supported, 0x0014);
        assert_eq!(data.Sys_CAP_enabled, 0x0014);
        let name = data.tlvs.iter().find(|t| t.tlv_type == 5).expect("Sys_NAME");
        assert_eq!(&name.tlv_data[..8], b"MySwitch");
    }

    /// Management Address с IPv4 сохраняет адрес, ifIndex и попадает в Display.
    #[test]
    fn lldp_mgmt_addr_ipv4() {
        let mut packet = lldp_mandatory();
        // type 8: addr_str_len=5, family=1(IPv4), 192.168.87.1, ifIndex=4, oid_len=0
        packet.extend(lldp_tlv(8, &[
            0x05, 0x01, 192, 168, 87, 1,
            0x02, 0x00, 0x00, 0x00, 0x04,
            0x00,
        ]));
        packet.extend(lldp_tlv(0, &[]));

        let data = parse_LLDP(&packet).expect("LLDP with mgmt addr");
        assert_eq!(data.mgmt_addrs.len(), 1);
        let m = data.mgmt_addrs[0];
        assert_eq!(m.family, 1);
        assert_eq!(m.addr_len, 4);
        assert_eq!(&m.addr[..4], &[192, 168, 87, 1]);
        assert_eq!(m.if_subtype, 2);
        assert_eq!(m.if_number, 4);
        let s = format!("{}", data);
        assert!(s.contains("192.168.87.1"));
        assert!(s.contains("ifIndex/4"));
    }

    /// Management Address с IPv6 сохраняет 16 байт адреса и печатает его в Display.
    #[test]
    fn lldp_mgmt_addr_ipv6() {
        let mut packet = lldp_mandatory();
        let ipv6 = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0,
            0xe6, 0x8d, 0x8c, 0xff, 0xfe, 0x66, 0x01, 0x91,
        ];
        let mut value = Vec::new();
        value.push(17); // addr_str_len = 1 family + 16 addr
        value.push(2);  // IPv6
        value.extend_from_slice(&ipv6);
        value.push(2); // ifIndex
        value.extend_from_slice(&0u32.to_be_bytes());
        value.push(0); // oid_len
        packet.extend(lldp_tlv(8, &value));

        let data = parse_LLDP(&packet).expect("LLDP IPv6 mgmt");
        assert_eq!(data.mgmt_addrs.len(), 1);
        let m = data.mgmt_addrs[0];
        assert_eq!(m.family, 2);
        assert_eq!(m.addr_len, 16);
        assert_eq!(&m.addr[..], &ipv6);
        let s = format!("{}", data);
        assert!(s.contains("fe80:"));
    }

    /// Management Address без if/oid пропускается, кадр остаётся валидным.
    #[test]
    fn lldp_mgmt_addr_too_short_skipped() {
        let mut packet = lldp_mandatory();
        packet.extend(lldp_tlv(8, &[0x05, 0x01, 10, 0, 0, 1])); // нет if/oid
        let data = parse_LLDP(&packet).expect("still valid");
        assert!(data.mgmt_addrs.is_empty());
    }

    /// Один IPv4-адрес в TLV Addresses: тип NLPID, протокол 0xCC, 4 байта адреса.
    #[test]
    fn cdp_addresses_ipv4() {
        let value = [
            0x01, // count
            0x01, // prot_type = NLPID
            0x01, // prot_len
            0xCC, // prot = IPv4
            0x00, 0x04, // addr_len = 4 (big-endian, 2 bytes)
            192, 168, 1, 1,
        ];
        let result = parse_CISCO_CDP_ADDRESSES(&value);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].prot_type, 1);
        assert_eq!(result[0].prot_len, 1);
        assert_eq!(result[0].prot, 0xCC);
        assert_eq!(result[0].addr_len, 4);
        assert_eq!(&result[0].addr[..4], &[192, 168, 1, 1]);
    }

    /// Пустой буфер Addresses не даёт адресов и не падает.
    #[test]
    fn cdp_addresses_empty_buffer() {
        let result = parse_CISCO_CDP_ADDRESSES(&[]);
        assert!(result.is_empty());
    }

    /// prot_len больше 1 не обрывает разбор: адрес читается после байт протокола.
    #[test]
    fn cdp_addresses_exotic_prot_len_continues() {
        // prot_len=3: не break, читаем адрес после 3 байт протокола
        let value = [
            0x01, // count
            0x01, // prot_type
            0x03, // prot_len = 3
            0xAB, 0xCD, 0xEF, // protocol bytes
            0x00, 0x04, // addr_len
            10, 1, 2, 3,
        ];
        let result = parse_CISCO_CDP_ADDRESSES(&value);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].prot, 0xABCD);
        assert_eq!(&result[0].addr[..4], &[10, 1, 2, 3]);
    }

    fn cdp_header(ver: u8) -> Vec<u8> {
        vec![ver, 0xB4, 0x00, 0x00]
    }

    fn cdp_device_id(name: &[u8]) -> Vec<u8> {
        let mut tlv = Vec::new();
        tlv.extend_from_slice(&0x0001u16.to_be_bytes());
        tlv.extend_from_slice(&((4 + name.len()) as u16).to_be_bytes());
        tlv.extend_from_slice(name);
        tlv
    }

    /// Полный CDP: версия, TTL, Device-ID, один адрес и Capabilities.
    #[test]
    fn cdp_packet_round_trip() {
        let mut packet = cdp_header(2);
        packet.extend(cdp_device_id(b"R1"));

        packet.extend_from_slice(&0x0002u16.to_be_bytes());
        packet.extend_from_slice(&0x000Eu16.to_be_bytes());
        packet.push(0x01);
        packet.push(0x01);
        packet.push(0x01);
        packet.push(0xCC);
        packet.extend_from_slice(&0x0004u16.to_be_bytes());
        packet.extend_from_slice(&[10, 0, 0, 1]);

        packet.extend_from_slice(&0x0004u16.to_be_bytes());
        packet.extend_from_slice(&0x0008u16.to_be_bytes());
        packet.extend_from_slice(&0x00000001u32.to_be_bytes());

        let data = parse_CISCO_CDP(&packet).expect("valid CDP packet");
        assert_eq!(data.Header.ver, 2);
        assert_eq!(data.Header.ttl, 180);
        assert_eq!(data.addresses.len(), 1);
        assert_eq!(data.addresses[0].addr_len, 4);
        assert_eq!(&data.addresses[0].addr[..4], &[10, 0, 0, 1]);
        assert_eq!(data.Capabilities, 1);
        let dev = data.tlvs.iter().find(|t| t.tlv_type == 0x0001).unwrap();
        let dev_len = dev.tlv_len;
        let dev_data = dev.tlv_data;
        assert_eq!(dev_len, 2); // value length, not full TLV
        assert_eq!(&dev_data[..2], b"R1");
    }

    /// Пакет без обязательного Device-ID отвергается.
    #[test]
    fn cdp_packet_requires_device_id() {
        let mut packet = cdp_header(2);
        packet.extend_from_slice(&0x0002u16.to_be_bytes());
        packet.extend_from_slice(&0x0005u16.to_be_bytes());
        packet.push(0x00);
        assert!(parse_CISCO_CDP(&packet).is_err());
    }

    /// Версия CDP не 1 и не 2 даёт Cisco_Broken.
    #[test]
    fn cdp_bad_version_err() {
        let mut packet = cdp_header(3);
        packet.extend(cdp_device_id(b"X"));
        assert!(matches!(
            parse_CISCO_CDP(&packet),
            Err(common::ParseError::Cisco_Broken { .. })
        ));
    }

    /// Два TLV Addresses сливаются в один список адресов.
    #[test]
    fn cdp_merge_two_address_tlvs() {
        let mut packet = cdp_header(1);
        packet.extend(cdp_device_id(b"sw1"));

        packet.extend_from_slice(&0x0002u16.to_be_bytes());
        packet.extend_from_slice(&0x000Eu16.to_be_bytes());
        packet.push(0x01);
        packet.push(0x01);
        packet.push(0x01);
        packet.push(0xCC);
        packet.extend_from_slice(&0x0004u16.to_be_bytes());
        packet.extend_from_slice(&[10, 0, 0, 1]);

        packet.extend_from_slice(&0x0002u16.to_be_bytes());
        packet.extend_from_slice(&0x000Eu16.to_be_bytes());
        packet.push(0x01);
        packet.push(0x01);
        packet.push(0x01);
        packet.push(0xCC);
        packet.extend_from_slice(&0x0004u16.to_be_bytes());
        packet.extend_from_slice(&[10, 0, 0, 2]);

        let data = parse_CISCO_CDP(&packet).expect("two address TLVs");
        assert_eq!(data.addresses.len(), 2);
        assert_eq!(&data.addresses[0].addr[..4], &[10, 0, 0, 1]);
        assert_eq!(&data.addresses[1].addr[..4], &[10, 0, 0, 2]);
    }

    /// Обрезанный TLV отбрасывается, пакет с Device-ID остаётся успешным.
    #[test]
    fn cdp_truncated_tlv_still_ok_with_device_id() {
        let mut packet = cdp_header(2);
        packet.extend(cdp_device_id(b"ok"));
        // битый TLV: заявленная длина больше остатка буфера
        packet.extend_from_slice(&0x0005u16.to_be_bytes());
        packet.extend_from_slice(&0x00FFu16.to_be_bytes());
        packet.extend_from_slice(b"xx");

        let data = parse_CISCO_CDP(&packet).expect("partial CDP with Device-ID");
        assert!(data.tlvs.iter().any(|t| t.tlv_type == 0x0001));
        assert!(!data.tlvs.iter().any(|t| t.tlv_type == 0x0005));
    }

    /// Native VLAN и Duplex попадают в строку Display.
    #[test]
    fn cdp_native_vlan_and_duplex_display() {
        let mut packet = cdp_header(2);
        packet.extend(cdp_device_id(b"ap"));
        packet.extend_from_slice(&0x000au16.to_be_bytes());
        packet.extend_from_slice(&0x0006u16.to_be_bytes());
        packet.extend_from_slice(&100u16.to_be_bytes());
        packet.extend_from_slice(&0x000bu16.to_be_bytes());
        packet.extend_from_slice(&0x0005u16.to_be_bytes());
        packet.push(0x02);

        let data = parse_CISCO_CDP(&packet).expect("vlan+duplex");
        let s = format!("{}", data);
        assert!(s.contains("NativeVLAN:100"));
        assert!(s.contains("Duplex:2(full)"));
    }

    fn expect_ip(result: Result<common::NetPayload, common::ParseError>) -> common::IpData {
        match result.expect("ip packet") {
            common::NetPayload::Ip(ip) => ip,
            _ => panic!("expected IP payload"),
        }
    }

    fn tcp_header(src_port: u16, dst_port: u16) -> etherparse::TcpHeader {
        etherparse::TcpHeader::new(src_port, dst_port, 1, 1024)
    }

    /// Короткий UDP: длина берётся из total_len, Ethernet-padding в len не входит.
    #[test]
    fn ipv4_udp_ignores_ethernet_padding() {
        let ip = etherparse::Ipv4Header::new(
            8, 64, etherparse::IpNumber::UDP, [10, 0, 0, 1], [10, 0, 0, 2],
        ).unwrap();
        let udp = etherparse::UdpHeader {
            source_port: 12345,
            destination_port: 53,
            length: 8,
            checksum: 0,
        };
        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&udp.to_bytes());
        // Минимум Ethernet — 46 байт payload; короткий UDP добивается padding.
        packet.extend_from_slice(&[0xAA; 18]);

        let data = expect_ip(parse_ipv4(&packet));
        assert!(data.protocol == common::IpType::Udp);
        assert_eq!(data.src_port, 12345);
        assert_eq!(data.dst_port, 53);
        assert_eq!(data.len, 8);
    }

    /// Непервый IPv4-фрагмент не читается как TCP, даже если байты похожи на заголовок.
    #[test]
    fn ipv4_non_first_fragment_is_not_parsed_as_l4() {
        let mut ip = etherparse::Ipv4Header::new(
            20, 64, etherparse::IpNumber::TCP, [10, 0, 0, 1], [10, 0, 0, 2],
        ).unwrap();
        ip.fragment_offset = 1u16.try_into().unwrap();
        ip.dont_fragment = false;
        let tcp = tcp_header(40000, 443);

        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&tcp.to_bytes());

        match parse_ipv4(&packet) {
            Err(common::ParseError::Ip4_Fragment { .. }) => {}
            Err(e) => panic!("expected Ip4_Fragment, got {e:?}"),
            Ok(_) => panic!("expected Ip4_Fragment"),
        }
    }

    /// Первый IPv4-фрагмент (offset 0, MF=1) сохраняет порты TCP.
    #[test]
    fn ipv4_first_fragment_keeps_tcp_ports() {
        let mut ip = etherparse::Ipv4Header::new(
            20, 64, etherparse::IpNumber::TCP, [10, 0, 0, 1], [10, 0, 0, 2],
        ).unwrap();
        ip.more_fragments = true;
        ip.dont_fragment = false;
        let tcp = tcp_header(40000, 443);

        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&tcp.to_bytes());

        let data = expect_ip(parse_ipv4(&packet));
        assert!(data.protocol == common::IpType::Tcp);
        assert_eq!(data.src_port, 40000);
        assert_eq!(data.dst_port, 443);
        assert_eq!(data.len, 20);
    }

    /// Если захват короче total_len, len равен фактически захваченному хвосту.
    #[test]
    fn ipv4_truncated_capture_uses_captured_tail() {
        // total_len обещает 120 байт payload, в срезе только TCP-заголовок.
        let ip = etherparse::Ipv4Header::new(
            120, 64, etherparse::IpNumber::TCP, [10, 0, 0, 1], [10, 0, 0, 2],
        ).unwrap();
        let tcp = tcp_header(1234, 80);

        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&tcp.to_bytes());

        let data = expect_ip(parse_ipv4(&packet));
        assert_eq!(data.src_port, 1234);
        assert_eq!(data.dst_port, 80);
        assert_eq!(data.len, 20);
    }

    /// TCP за IPv6 Destination Options читается как TCP, а не как Unsupported_L4.
    #[test]
    fn ipv6_tcp_after_destination_options() {
        let src = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        // Destination Options: next = TCP, hdr ext len = 0 (всего 8 байт).
        let dest_opt = [
            etherparse::IpNumber::TCP.0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let ip = etherparse::Ipv6Header {
            payload_length: (dest_opt.len() + 20) as u16,
            next_header: etherparse::IpNumber::IPV6_DESTINATION_OPTIONS,
            hop_limit: 64,
            source: src,
            destination: dst,
            ..etherparse::Ipv6Header::default()
        };
        let tcp = tcp_header(50000, 443);

        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&dest_opt);
        packet.extend_from_slice(&tcp.to_bytes());

        let data = expect_ip(parse_ipv6(&packet));
        assert!(data.protocol == common::IpType::Tcp);
        assert_eq!(data.src_port, 50000);
        assert_eq!(data.dst_port, 443);
        assert_eq!(data.len, 20);
        assert_eq!(data.src, common::IpAddr::from(src));
        assert_eq!(data.dst, common::IpAddr::from(dst));
    }

    /// Непервый IPv6-фрагмент даёт Ip6_Fragment и не разбирает хвост как TCP.
    #[test]
    fn ipv6_non_first_fragment_is_not_parsed_as_l4() {
        let src = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let frag = etherparse::Ipv6FragmentHeader::new(
            etherparse::IpNumber::TCP,
            1u16.try_into().unwrap(),
            false,
            0xABC,
        );
        let ip = etherparse::Ipv6Header {
            payload_length: (etherparse::Ipv6FragmentHeader::LEN + 20) as u16,
            next_header: etherparse::IpNumber::IPV6_FRAGMENTATION_HEADER,
            hop_limit: 64,
            source: src,
            destination: dst,
            ..etherparse::Ipv6Header::default()
        };
        let tcp = tcp_header(50000, 443);

        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&frag.to_bytes());
        packet.extend_from_slice(&tcp.to_bytes());

        match parse_ipv6(&packet) {
            Err(common::ParseError::Ip6_Fragment { .. }) => {}
            Err(e) => panic!("expected Ip6_Fragment, got {e:?}"),
            Ok(_) => panic!("expected Ip6_Fragment"),
        }
    }
}
