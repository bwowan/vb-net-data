#![allow(non_snake_case)]
use flume;
use common;
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
    if let Some((LLC_Header, snap_payload)) = pl.split_first_chunk::<3>() {
        if *LLC_Header == [0xAA_u8, 0xAA_u8, 0x03_u8] {//there is SNAP Header (IEEE 802.2 LLC SNAP)
            if let Some((SNAP_Header, snap_payload)) = snap_payload.split_first_chunk::<5>() {
                let snap_oui = [SNAP_Header[0], SNAP_Header[1], SNAP_Header[2]];
                let snap_prot = u16::from_be_bytes([SNAP_Header[3], SNAP_Header[4]]);
                if snap_oui == [0x00, 0x00, 0x0C] {//OUI (Organizationally Unique Identifier) - 3 bytes, Protocol ID - 2 bytes (total 5 bytes)
                    if let Ok(Cisco) = parse_Cisco(snap_payload, snap_prot) {
                       return Ok(common::NetPayload::Cisco(Cisco));
                    }
                } else if snap_oui == [0x08, 0x00, 0x2B] { // DEC OUI
                    return parse_DECSnapHeader(pl).map(common::NetPayload::DEC);
                }
            }
        }
    }
    Err(common::ParseError::Unsupported_Eth { id: prot })
}



// ── Etehernet packet ──────────────────────────────────────────────────────────
fn parse_RegularEthernet(pl: &[u8], prot:common::EthType) -> Result<common::NetPayload, common::ParseError> {
    match prot {
        common::EthType::Ipv4                => parse_ipv4    (pl   ),
        common::EthType::Ipv6                => parse_ipv6    (pl   ),
        common::EthType::Arp              |
        common::EthType::Rarp                => parse_arp     (pl   ).map(|r     | common::NetPayload::Arp (r)),
        common::EthType::Mpls             | 
        common::EthType::MplsMcast           => parse_mpls    (pl   ).map(|r    | common::NetPayload::Mpls(r)),
        common::EthType::Ectp                => parse_Loopback(pl   ).map(|r| common::NetPayload::Ectp(r)),
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
fn parse_ipv4(pl: &[u8]) -> Result<common::NetPayload, common::ParseError> {
    let (ip, ip_payload) = etherparse::Ipv4Header::from_slice(pl)
        .map_err(|_| common::ParseError::Ip4_Broken { len: pl.len() })?;

    let src = common::IpAddr::from(ip.source);
    let dst = common::IpAddr::from(ip.destination);
    let ip_data = parse_l4(ip_payload, &src, &dst, ip.protocol)?;
    Ok(common::NetPayload::Ip(ip_data))
}

fn parse_ipv6(pl: &[u8]) -> Result<common::NetPayload, common::ParseError> {
    let (ip, ip_payload) = etherparse::Ipv6Header::from_slice(pl)
        .map_err(|_| common::ParseError::Ip6_Broken { len: pl.len() })?;

    let src = common::IpAddr::from(ip.source);
    let dst = common::IpAddr::from(ip.destination);
    let ip_data = parse_l4(ip_payload, &src, &dst, ip.next_header)?;
    Ok(common::NetPayload::Ip(ip_data))
}


// ── L4 ───────────────────────────────────────────────────────────────────────
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
//   6-7  : operation
//   8-13 : sender MAC
//   14-17: sender IP
//   18-23: target MAC
//   24-27: target IP
fn parse_arp(pl: &[u8]) -> Result<common::ArpData, common::ParseError> {
    let arp = etherparse::ArpPacketSlice::from_slice(pl)
        .map_err(|_| common::ParseError::Arp_Broken { len: pl.len() })?;
    
    let op = match arp.operation() {
        etherparse::ArpOperation::REQUEST => common::ArpOp::Request,
        etherparse::ArpOperation::REPLY   => common::ArpOp::Reply,
        other => common::ArpOp::Unknown(other.0),
    };

    if arp.hw_addr_size() != 6 || arp.proto_addr_size() != 4 {
        Err(common::ParseError::Arp_Broken { len: pl.len() })
    } else {
        let r = common::ArpData::new(  op,
                                                common::MacAddr6::new(arp.sender_hw_addr()[0..6].try_into().unwrap()),
                                                common::Ipv4Addr::from(TryInto::<[u8; 4]>::try_into(&arp.sender_protocol_addr()[0..4]).unwrap_or_default()),
                                                common::MacAddr6::new(arp.target_hw_addr()[0..6].try_into().unwrap()),
                                                common::Ipv4Addr::from(TryInto::<[u8; 4]>::try_into(&arp.target_protocol_addr()[0..4]).unwrap_or_default()),
                                            );
        Ok(r)
    }
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

fn parse_CISCO_TLV(pl : &[u8], tlv_type:u16, tlv_len:usize) -> common::TLV_DATA {
    let copy_len = min(common::LLDP_TLV_MAX_LEN, tlv_len-4);
    let mut tlv_data = [0u8; common::LLDP_TLV_MAX_LEN];
    tlv_data[..copy_len].copy_from_slice(&pl[..copy_len]);
    common::TLV_DATA {tlv_type, tlv_len:tlv_len as u16, tlv_data}
}

fn parse_CISCO_CDP_ADDRESSES(pl: &[u8]) -> common::CISCO_CDP_ADDRESSES {
    let mut result = common::CISCO_CDP_ADDRESSES{count:pl[0], ..Default::default() };
    let len = pl.len();
    let mut n:usize = 1;
    let n_Adresses = min (common::CISCO_CDP_MAX_ADDRESSES, result.count as usize);
    for iAddress in 0usize..n_Adresses {
        if n + 8 > len {
            break;
        }
        let prot_type = pl[n];
        let prot_len = pl[n+1];
        let prot: u16  = match prot_len {
            1 => { pl[n+2] as u16 },
            2 => { u16::from_be_bytes([pl[n+2], pl[n+3]]) },
            _ => { 0 }
        };
        if prot == 0 {
            break;
        }
        n += prot_len as usize;
        let addr_len = pl[n];
        if n + addr_len as usize > len {
            break;
        }
        n += 1;
        let copy_len = min(common::CISCO_CDP_MAX_ADDRESS_LEN, addr_len as usize);
        result.addresses[iAddress] = common::CISCO_CDP_ADDRESS{ prot_type, prot_len, prot, addr_len, ..Default::default() };
        result.addresses[iAddress].addr[..copy_len].copy_from_slice(&pl[n..n+copy_len]);
        n += addr_len as usize;
    }   
    result
}

fn parse_CISCO_CDP(pl: &[u8]) ->  Result<common::CDP_CISCO_DATA, common::ParseError> {
    let data_len = pl.len();
    if data_len < 9 {
        return Err(common::ParseError::Cisco_Broken { len: data_len, sub_type: 0 }); //no TLV field -  only headers. 
    }

    let chksm = u16::from_be_bytes([pl[2], pl[3]]);
    let cdp_header = common::CISCO_CDP_HEADER{ver:pl[0], ttl:pl[1], chksm};
    let mut data = common::CDP_CISCO_DATA{Header:cdp_header, ..Default::default()};

    let mut n: usize = 4;
    while n + 4 < data_len {
        let tlv_type = u16::from_be_bytes([pl[n], pl[n+1]]);
        let tlv_len  = u16::from_be_bytes([pl[n+2], pl[n+3]]) as usize;
        //n += 4;
        if tlv_len < 8  ||  n + tlv_len >= data_len {
            break;
        } else {
            let buf = &pl[n+4..n+tlv_len];
            match tlv_type {
                0x0001 => data.DeviceId        = parse_CISCO_TLV(buf, tlv_type, tlv_len),
                0x0002 => data.Address         = parse_CISCO_CDP_ADDRESSES(buf),
                0x0003 => data.PortId          = parse_CISCO_TLV(buf, tlv_type, tlv_len),
                0x0004 => data.Capabilities    = u32::from_be_bytes(buf[..4].try_into().unwrap_or_default()),
                0x0005 => data.SoftwareVersion = parse_CISCO_TLV(buf, tlv_type, tlv_len),
                0x0006 => data.Platform        = parse_CISCO_TLV(buf, tlv_type, tlv_len),
                _ => (),
            }
            n += tlv_len;
        }
    }
    if data.DeviceId.tlv_len > 4 {
        Ok(data)
    } else {
        Err( common::ParseError::Cisco_Broken{ len: data_len, sub_type:0x2000 } )
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


pub fn parse_LLDP(pl: &[u8]) ->  Result<common::LLDP_Data, common::ParseError> {
    let mut n: usize = 0;
    let mut lldp = common::LLDP_Data::default();
    let data_len = pl.len();
    let mut complete: u8 = 0;
    while n + 2 < data_len {
        let tlv = parse_LLDP_TLV(pl, n);
        if tlv.tlv_len != 0 {
            match tlv.tlv_type {
                1 => { lldp.Chassis_ID      = tlv;                                        complete |= 1; },
                2 => { lldp.Port_ID         = tlv;                                        complete |= 2; },
                3 => { lldp.TTL = u16::from_be_bytes([tlv.tlv_data[0], tlv.tlv_data[1]]); complete |= 4; },
                4 =>   lldp.Port_DESC       = tlv,
                5 =>   lldp.Sys_NAME        = tlv,
                6 =>   lldp.Sys_DESC        = tlv,
                7 =>   if tlv.tlv_len >= 4 {
                            lldp.Sys_CAP_supported = u16::from_be_bytes([tlv.tlv_data[0], tlv.tlv_data[1]]);
                            lldp.Sys_CAP_enabled   = u16::from_be_bytes([tlv.tlv_data[2], tlv.tlv_data[3]]);
                            complete |= 8;
                       },
                8 =>   lldp.Management_Addr = tlv,
                _ => (),
            }
            n = n + tlv.tlv_len as usize;
        } else {
            n = data_len
        }
    }
    if complete == 7 {
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