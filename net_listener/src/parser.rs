#![allow(non_snake_case)]
use flume;
use common::{self};
use pnet_datalink;
use etherparse;
use std::cmp::min;
use tokio::time::{self, Duration};
use tracing::info;
//use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn get_mac_address(device_name: &str) -> Option<common::MacAddr6> {
    pnet_datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == device_name)
        .and_then(|iface| iface.mac)
        .map(|mac| common::MacAddr6::new(mac.octets()))
}


pub async fn parse_loop(own_mac : common::MacAddr6,
                        receiver: flume::Receiver<(common::CapData, mempool::PoolSlot<common::NetData>)>,
                        sender  : flume::Sender<mempool::PoolSlot<common::NetData>>)
{
    let mut interval = time::interval(Duration::from_secs(2));
    interval.tick().await;

    // Цикл будет работать, пока канал-приемник открыт и поставляет данные.
    // recv_async().await вернет Err, когда все отправители будут уничтожены.
    info!("PARSER: enter parsing");
    loop {
        match receiver.recv_async().await {
            Err(e) => {
                eprintln!("PARSER: error read from receiver - {e:?}");
                break;
            }
            Ok((data, slot)) => {
                if sender.is_disconnected() {
                    info!("PARSER: clients dropped, stop parsing");
                    break;
                }
                match parse_ethernet_packet(data, own_mac) {
                    Ok(net_data) => {
                        unsafe { std::ptr::write(slot.body, net_data); }
                        let _ = sender.try_send(slot);
                    }
                    Err(e) => {
                        eprintln!("[parser] {e:?}");
                        continue;
                    }
                }
            }
        }
    }
    info!("PARSER: leave parsing");
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
            eprintln!("{e:?}");
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
            let eth_data = common::EthData { src, dst, dir, prot };
            Ok(common::NetData { eth: eth_data, payload: r })
        }
        Err(e) => {
            let dump_len = min(128, data.data.len());
            eprintln!("PARSER: packet {} bytes, first {}:", data.data.len(), dump_len);
            for (i, b) in data.data[..dump_len].iter().enumerate() {
                if i % 16 == 0 {
                    eprint!("  {i:04x}: ");
                }
                eprint!("{:02x}{}", b, if i % 16 == 15 || i + 1 == dump_len { "\n" } else { " " });
            }
            Err(e)
        }
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
            Ok(common::IpData::new_tcp(src, dst, payload.len(),
                                         tcp.source_port, tcp.destination_port))
        }
        etherparse::IpNumber::UDP => {
            let (udp, rest) = etherparse::UdpHeader::from_slice(payload)
                .map_err(|_| common::ParseError::Udp_Broken { len: payload.len(), src: *src, dst: *dst })?;
            let mut data = common::IpData::new_udp(src, dst, payload.len(),
                                         udp.source_port, udp.destination_port);
            confirm_udp_body(&mut data, udp_payload_slice(udp.length, rest));
            Ok(data)
        }
        etherparse::IpNumber::ICMP => parse_icmp4(payload, src, dst),
        etherparse::IpNumber::IPV6_ICMP => parse_icmp6(payload, src, dst),
        etherparse::IpNumber::IGMP => parse_igmp(payload, src, dst),
        etherparse::IpNumber::ENCAPSULATING_SECURITY_PAYLOAD => parse_esp(payload, src, dst),
        other => Err(common::ParseError::Unsupported_L4 { id: other.0 }),
    }
}

/// Тело UDP по полю length. Если захват короче заявленного, берётся весь хвост.
fn udp_payload_slice(length: u16, rest: &[u8]) -> &[u8] {
    let declared = (length as usize).saturating_sub(etherparse::UdpHeader::LEN);
    if declared <= rest.len() { &rest[..declared] } else { rest }
}

/// DNS/mDNS/LLMNR: первое имя вопроса и первая SRV в ответах.
/// mDNS ещё: метки `_service._proto` и первая PTR. DHCP: magic cookie, опции 53, 12 и 50.
/// DHCPv6: первый байт — тип. NBNS: имя из 32 символов A–P. SSDP: первая строка и заголовки NT, USN, LOCATION.
/// Тело не сошлось — ярлык по порту снимается, пакет остаётся обычным UDP.
fn confirm_udp_body(data: &mut common::IpData, body: &[u8]) {
    let common::IpL4::Udp { app, msg, .. } = &mut data.l4 else { return };
    match *app {
        common::UdpApp::Dhcp4 => match parse_dhcp4(body) {
            Some(parsed) => *msg = Some(parsed),
            None => *app = common::UdpApp::Other,
        },
        common::UdpApp::Dhcp6 => match parse_dhcp6(body) {
            Some(parsed) => *msg = Some(parsed),
            None => *app = common::UdpApp::Other,
        },
        common::UdpApp::Ssdp => match parse_ssdp(body) {
            Some(parsed) => *msg = Some(parsed),
            None => *app = common::UdpApp::Other,
        },
        common::UdpApp::Nbns => match parse_nbns(body) {
            Some(parsed) => *msg = Some(parsed),
            None => *app = common::UdpApp::Other,
        },
        common::UdpApp::Dns | common::UdpApp::Mdns | common::UdpApp::Llmnr => match parse_dns_msg(body) {
            Ok(Some(mut q)) => {
                if *app != common::UdpApp::Mdns {
                    q.service = None;
                    q.ptr = None;
                }
                *msg = Some(common::UdpMsg::Query(q));
            }
            Ok(None) => {}
            Err(()) => *app = common::UdpApp::Other,
        },
        _ => {}
    }
}

const DNS_HEADER_LEN: usize = 12;
const DNS_PTR_HOPS: usize = 8;
const DNS_TYPE_PTR: u16 = 12;
const DNS_TYPE_SRV: u16 = 33;
const DNS_SRV_FIXED: usize = 6; // priority, weight, port
const NBNS_TYPE_NB: u16 = 0x0020;
const NBNS_LABEL_LEN: usize = 32;
const NBNS_RDATA_MIN: usize = 6; // flags + IPv4
const DHCP4_COOKIE_AT: usize = 236;
const DHCP4_OPTIONS_AT: usize = 240;
const DHCP4_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const DHCP4_OPT_HOST: u8 = 12;
const DHCP4_OPT_REQ_ADDR: u8 = 50;
const DHCP4_OPT_MSG_TYPE: u8 = 53;
const DHCP4_OPT_END: u8 = 255;
const DHCP4_OPT_PAD: u8 = 0;
const DHCP6_MSG_MIN: usize = 4;   // type + transaction-id
const DHCP6_RELAY_MIN: usize = 34; // type, hop-count, link-address, peer-address

/// `Ok(None)` — заголовок есть, ни вопроса, ни целой SRV, ни целой PTR. `Err` — битое первое имя вопроса.
/// Первая SRV в ответах: порт и целевой хост. Короче 7 байт или имя вне rdata — запись пропускается.
/// Первая PTR: имя из rdata. `service` — первые метки `_service._proto` (вопрос, затем владелец PTR, rdata PTR, владелец SRV).
/// Обрезанный ответ останавливает обход: уже прочитанные вопрос, PTR и SRV сохраняются, недостающее не выдумывается.
fn parse_dns_msg(body: &[u8]) -> Result<Option<common::DnsQuery>, ()> {
    if body.len() < DNS_HEADER_LEN {
        return Err(());
    }
    let qd = u16::from_be_bytes([body[4], body[5]]);
    let an = u16::from_be_bytes([body[6], body[7]]);
    let mut pos = DNS_HEADER_LEN;
    let mut name = None;
    let mut service = None;
    if qd > 0 {
        let (n, end) = read_dns_name(body, pos)?;
        if end + 4 > body.len() {
            return Err(());
        }
        service = mdns_service(&n);
        name = Some(n);
        pos = end + 4;
        for _ in 1..qd {
            let Some(next) = skip_dns_question(body, pos) else {
                return Ok(Some(common::DnsQuery { name, srv: None, service, ptr: None }));
            };
            pos = next;
        }
    }
    let found = dns_answers(body, pos, an);
    if service.is_none() {
        service = found.ptr_owner.as_ref().and_then(|n| mdns_service(n));
    }
    if service.is_none() {
        service = found.ptr.as_ref().and_then(|n| mdns_service(n));
    }
    if service.is_none() {
        service = found.srv_owner.as_ref().and_then(|n| mdns_service(n));
    }
    if name.is_none() && found.srv.is_none() && found.ptr.is_none() {
        Ok(None)
    } else {
        Ok(Some(common::DnsQuery { name, srv: found.srv, service, ptr: found.ptr }))
    }
}

struct DnsAnswers {
    srv: Option<common::SrvHost>,
    ptr: Option<heapless::String<{ common::UDP_QNAME_MAX }>>,
    ptr_owner: Option<heapless::String<{ common::UDP_QNAME_MAX }>>,
    srv_owner: Option<heapless::String<{ common::UDP_QNAME_MAX }>>,
}

fn skip_dns_question(body: &[u8], pos: usize) -> Option<usize> {
    let (_, end) = read_dns_name(body, pos).ok()?;
    let next = end.checked_add(4)?;
    if next > body.len() { None } else { Some(next) }
}

/// Первые целые PTR и SRV среди `an` записей с позиции `pos`. Приоритет и вес SRV не читаются.
/// Обрезанная запись останавливает обход и оставляет уже найденное.
fn dns_answers(body: &[u8], mut pos: usize, an: u16) -> DnsAnswers {
    let mut found = DnsAnswers { srv: None, ptr: None, ptr_owner: None, srv_owner: None };
    for _ in 0..an {
        if found.srv.is_some() && found.ptr.is_some() {
            break;
        }
        let Ok((owner, name_end)) = read_dns_name(body, pos) else {
            break;
        };
        if name_end + 10 > body.len() {
            break;
        }
        let rr_type = u16::from_be_bytes([body[name_end], body[name_end + 1]]);
        let rdlen = u16::from_be_bytes([body[name_end + 8], body[name_end + 9]]) as usize;
        let rdata = name_end + 10;
        if rdata + rdlen > body.len() {
            break;
        }
        if rr_type == DNS_TYPE_SRV && found.srv.is_none() {
            if let Some(srv) = parse_srv_rdata(body, rdata, rdlen) {
                found.srv = Some(srv);
                found.srv_owner = Some(owner);
            }
        } else if rr_type == DNS_TYPE_PTR && found.ptr.is_none() {
            if let Some(target) = parse_ptr_rdata(body, rdata, rdlen) {
                found.ptr = Some(target);
                found.ptr_owner = Some(owner);
            }
        }
        pos = rdata + rdlen;
    }
    found
}

fn parse_ptr_rdata(
    body: &[u8],
    rdata: usize,
    rdlen: usize,
) -> Option<heapless::String<{ common::UDP_QNAME_MAX }>> {
    if rdlen == 0 {
        return None;
    }
    let (name, end) = read_dns_name(body, rdata).ok()?;
    if end > rdata + rdlen {
        return None;
    }
    Some(name)
}

/// Две соседние метки, обе с `_`: `_ipp._tcp` из `_ipp._tcp.local` или `Office._ipp._tcp.local`.
fn mdns_service(name: &str) -> Option<heapless::String<{ common::UDP_QNAME_MAX }>> {
    let labels: Vec<&str> = name.split('.').filter(|label| !label.is_empty()).collect();
    let pair = labels.windows(2).find(|w| w[0].starts_with('_') && w[1].starts_with('_'))?;
    let mut out = heapless::String::new();
    for (i, label) in pair.iter().enumerate() {
        if i > 0 && out.push('.').is_err() {
            return Some(out);
        }
        for c in label.chars() {
            if out.push(c).is_err() {
                return Some(out);
            }
        }
    }
    Some(out)
}

fn parse_srv_rdata(body: &[u8], rdata: usize, rdlen: usize) -> Option<common::SrvHost> {
    if rdlen < DNS_SRV_FIXED + 1 {
        return None;
    }
    let port = u16::from_be_bytes([body[rdata + 4], body[rdata + 5]]);
    let (host, end) = read_dns_name(body, rdata + DNS_SRV_FIXED).ok()?;
    if end > rdata + rdlen {
        return None;
    }
    Some(common::SrvHost { port, host })
}

/// Имя с позиции `pos`. Второе значение — где кончается имя на проводе, без учёта прыжков по указателям.
fn read_dns_name(packet: &[u8], mut pos: usize) -> Result<(heapless::String<{ common::UDP_QNAME_MAX }>, usize), ()> {
    let mut out = heapless::String::new();
    let mut hops = 0usize;
    let mut end = None;
    let mut steps = 0usize;
    loop {
        if pos >= packet.len() || steps > packet.len() {
            return Err(());
        }
        steps += 1;
        let len = packet[pos];
        if len == 0 {
            if end.is_none() {
                end = Some(pos + 1);
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= packet.len() {
                return Err(());
            }
            if end.is_none() {
                end = Some(pos + 2);
            }
            hops += 1;
            if hops > DNS_PTR_HOPS {
                return Err(());
            }
            let off = (((len as usize) & 0x3F) << 8) | packet[pos + 1] as usize;
            if off >= packet.len() {
                return Err(());
            }
            pos = off;
            continue;
        }
        if len & 0xC0 != 0 {
            return Err(());
        }
        let n = len as usize;
        pos += 1;
        if pos + n > packet.len() {
            return Err(());
        }
        push_dns_label(&mut out, &packet[pos..pos + n]);
        pos += n;
    }
    if out.is_empty() {
        let _ = out.push('.');
    }
    Ok((out, end.ok_or(())?))
}

fn push_dns_label(out: &mut heapless::String<{ common::UDP_QNAME_MAX }>, label: &[u8]) {
    if !out.is_empty() && out.push('.').is_err() {
        return;
    }
    for &b in label {
        let c = if b.is_ascii_graphic() { b as char } else { '?' };
        if out.push(c).is_err() {
            return;
        }
    }
}

/// `Some` — cookie есть. `None` — это не DHCP.
/// Опция 12 длиннее 64 символов обрезается. Опция 50 короче или длиннее 4 байт пропускается.
/// Обрезанная опция останавливает обход: уже прочитанные поля сохраняются.
fn parse_dhcp4(body: &[u8]) -> Option<common::UdpMsg> {
    if body.len() < DHCP4_OPTIONS_AT || body[DHCP4_COOKIE_AT..DHCP4_OPTIONS_AT] != DHCP4_COOKIE {
        return None;
    }
    let mut msg = None;
    let mut host = None;
    let mut requested = None;
    let mut i = DHCP4_OPTIONS_AT;
    while i < body.len() {
        let code = body[i];
        if code == DHCP4_OPT_END {
            break;
        }
        if code == DHCP4_OPT_PAD {
            i += 1;
            continue;
        }
        if i + 1 >= body.len() {
            break;
        }
        let len = body[i + 1] as usize;
        if i + 2 + len > body.len() {
            break;
        }
        let value = &body[i + 2..i + 2 + len];
        match code {
            DHCP4_OPT_MSG_TYPE if msg.is_none() && !value.is_empty() => {
                msg = Some(common::Dhcp4Msg::from_u8(value[0]));
            }
            DHCP4_OPT_HOST if host.is_none() && !value.is_empty() => {
                host = Some(dhcp4_hostname(value));
            }
            DHCP4_OPT_REQ_ADDR if requested.is_none() && value.len() == 4 => {
                requested = Some(common::Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            _ => {}
        }
        i += 2 + len;
    }
    Some(common::UdpMsg::Dhcp4 { msg, host, requested })
}

/// `Some` — тип 1–11 и не короче 4 байт, либо relay 12–13 и не короче 34.
/// `None` — это не DHCPv6. Transaction-id и опции не читаются.
fn parse_dhcp6(body: &[u8]) -> Option<common::UdpMsg> {
    let msg = common::Dhcp6Msg::from_u8(*body.first()?)?;
    let min = if msg.is_relay() { DHCP6_RELAY_MIN } else { DHCP6_MSG_MIN };
    if body.len() < min {
        return None;
    }
    Some(common::UdpMsg::Dhcp6 { msg })
}

struct NbnsDecoded {
    name: heapless::String<{ common::NBNS_NAME_MAX }>,
    suffix: u8,
}

/// `Some` — первая метка из 32 символов A–P и тип NB или NBSTAT.
/// `None` — это не NBNS. У ответа без вопросов имя берётся из первой записи.
/// IPv4 — из первой целой NB-записи (6 байт). Короче или обрезанная адреса не даёт.
fn parse_nbns(body: &[u8]) -> Option<common::UdpMsg> {
    if body.len() < DNS_HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([body[2], body[3]]);
    let response = flags & 0x8000 != 0;
    let op = common::NbnsOp::from_u8(((flags >> 11) & 0x0F) as u8);
    let rcode = (flags & 0x0F) as u8;
    let qd = u16::from_be_bytes([body[4], body[5]]);
    let an = u16::from_be_bytes([body[6], body[7]]);

    let mut pos = DNS_HEADER_LEN;
    let mut decoded = None;
    let mut kind = None;
    if qd > 0 {
        let (name, end) = read_nbns_name(body, pos)?;
        if end + 4 > body.len() {
            return None;
        }
        kind = Some(common::NbnsKind::from_u16(u16::from_be_bytes([body[end], body[end + 1]]))?);
        decoded = Some(name);
        pos = end + 4;
        for _ in 1..qd {
            let Some(next) = skip_dns_question(body, pos) else {
                let name = decoded.unwrap();
                let kind = kind.unwrap();
                return Some(nbns_msg(response, op, name, kind, rcode, None));
            };
            pos = next;
        }
    } else if !response {
        return None;
    }

    let addr = if response {
        if decoded.is_none() {
            if an == 0 {
                return None;
            }
            let (name, name_end) = read_nbns_name(body, pos)?;
            if name_end + 2 > body.len() {
                return None;
            }
            kind = Some(common::NbnsKind::from_u16(u16::from_be_bytes([body[name_end], body[name_end + 1]]))?);
            decoded = Some(name);
            nbns_addr_at(body, name_end)
        } else {
            nbns_first_addr(body, pos, an)
        }
    } else {
        None
    };
    Some(nbns_msg(response, op, decoded?, kind?, rcode, addr))
}

fn nbns_msg(
    response: bool,
    op: common::NbnsOp,
    name: NbnsDecoded,
    kind: common::NbnsKind,
    rcode: u8,
    addr: Option<common::Ipv4Addr>,
) -> common::UdpMsg {
    common::UdpMsg::Nbns(common::NbnsMsg {
        response,
        op,
        name: name.name,
        suffix: name.suffix,
        kind,
        rcode,
        addr,
    })
}

fn read_nbns_name(packet: &[u8], mut pos: usize) -> Option<(NbnsDecoded, usize)> {
    let mut hops = 0usize;
    let mut end = None;
    let mut decoded = None;
    let mut steps = 0usize;
    loop {
        if pos >= packet.len() || steps > packet.len() {
            return None;
        }
        steps += 1;
        let len = packet[pos];
        if len == 0 {
            if end.is_none() {
                end = Some(pos + 1);
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= packet.len() {
                return None;
            }
            if end.is_none() {
                end = Some(pos + 2);
            }
            hops += 1;
            if hops > DNS_PTR_HOPS {
                return None;
            }
            let off = (((len as usize) & 0x3F) << 8) | packet[pos + 1] as usize;
            if off >= packet.len() {
                return None;
            }
            pos = off;
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        let n = len as usize;
        if pos + 1 + n > packet.len() {
            return None;
        }
        if decoded.is_none() {
            if n != NBNS_LABEL_LEN {
                return None;
            }
            decoded = Some(decode_nbns_label(&packet[pos + 1..pos + 1 + n])?);
        }
        pos += 1 + n;
    }
    Some((decoded?, end?))
}

fn decode_nbns_label(label: &[u8]) -> Option<NbnsDecoded> {
    let mut raw = [0u8; 16];
    for i in 0..16 {
        let hi = nbns_nibble(label[i * 2])?;
        let lo = nbns_nibble(label[i * 2 + 1])?;
        raw[i] = (hi << 4) | lo;
    }
    let mut end = 15;
    while end > 0 && raw[end - 1] == b' ' {
        end -= 1;
    }
    let mut name = heapless::String::new();
    for &b in &raw[..end] {
        let c = if b == b' ' || b.is_ascii_graphic() { b as char } else { '?' };
        if name.push(c).is_err() {
            break;
        }
    }
    Some(NbnsDecoded { name, suffix: raw[15] })
}

fn nbns_nibble(b: u8) -> Option<u8> {
    if (b'A'..=b'P').contains(&b) { Some(b - b'A') } else { None }
}

fn nbns_first_addr(body: &[u8], mut pos: usize, an: u16) -> Option<common::Ipv4Addr> {
    for _ in 0..an {
        let (_, name_end) = read_nbns_name(body, pos)?;
        if name_end + 10 > body.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([body[name_end], body[name_end + 1]]);
        let rdlen = u16::from_be_bytes([body[name_end + 8], body[name_end + 9]]) as usize;
        let rdata = name_end + 10;
        if rdata + rdlen > body.len() {
            return None;
        }
        if rr_type == NBNS_TYPE_NB && rdlen >= NBNS_RDATA_MIN {
            return Some(common::Ipv4Addr::new(body[rdata + 2], body[rdata + 3], body[rdata + 4], body[rdata + 5]));
        }
        pos = rdata + rdlen;
    }
    None
}

fn nbns_addr_at(body: &[u8], name_end: usize) -> Option<common::Ipv4Addr> {
    if name_end + 10 > body.len() {
        return None;
    }
    let rr_type = u16::from_be_bytes([body[name_end], body[name_end + 1]]);
    let rdlen = u16::from_be_bytes([body[name_end + 8], body[name_end + 9]]) as usize;
    let rdata = name_end + 10;
    if rr_type != NBNS_TYPE_NB || rdlen < NBNS_RDATA_MIN || rdata + rdlen > body.len() {
        return None;
    }
    Some(common::Ipv4Addr::new(body[rdata + 2], body[rdata + 3], body[rdata + 4], body[rdata + 5]))
}

fn dhcp4_hostname(value: &[u8]) -> heapless::String<{ common::UDP_QNAME_MAX }> {
    let mut out = heapless::String::new();
    for &b in value {
        let c = if b.is_ascii_graphic() { b as char } else { '?' };
        if out.push(c).is_err() {
            break;
        }
    }
    out
}

/// `Some` — первая строка M-SEARCH, NOTIFY или HTTP/1.x. `None` — это не SSDP.
/// Заголовки NT, USN и LOCATION: первое вхождение, длиннее 128 символов обрезается.
/// Пустая строка заканчивает заголовки. NTS не считается NT.
fn parse_ssdp(body: &[u8]) -> Option<common::UdpMsg> {
    let (first, mut rest) = split_ssdp_line(body);
    if !ssdp_start_line(first) {
        return None;
    }
    let start = ssdp_text(first);
    if start.is_empty() {
        return None;
    }
    let mut nt = None;
    let mut usn = None;
    let mut location = None;
    while !rest.is_empty() {
        let (line, next) = split_ssdp_line(rest);
        rest = next;
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = split_ssdp_header(line) else { continue };
        if ssdp_name_is(name, b"NT") && nt.is_none() {
            nt = Some(ssdp_text(value));
        } else if ssdp_name_is(name, b"USN") && usn.is_none() {
            usn = Some(ssdp_text(value));
        } else if ssdp_name_is(name, b"LOCATION") && location.is_none() {
            location = Some(ssdp_text(value));
        }
    }
    Some(common::UdpMsg::Ssdp(common::SsdpMsg { start, nt, usn, location }))
}

fn ssdp_start_line(line: &[u8]) -> bool {
    starts_with_ignore_ascii_case(line, b"M-SEARCH ")
        || starts_with_ignore_ascii_case(line, b"NOTIFY ")
        || starts_with_ignore_ascii_case(line, b"HTTP/1.")
}

fn split_ssdp_line(buf: &[u8]) -> (&[u8], &[u8]) {
    if let Some(i) = buf.iter().position(|&b| b == b'\n') {
        (trim_cr(&buf[..i]), &buf[i + 1..])
    } else {
        (trim_cr(buf), &[])
    }
}

fn trim_cr(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((b'\r', head)) => head,
        _ => line,
    }
}

fn split_ssdp_header(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = line.iter().position(|&b| b == b':')?;
    let name = trim_sp(&line[..colon]);
    let value = trim_sp(&line[colon + 1..]);
    if name.is_empty() || value.is_empty() {
        None
    } else {
        Some((name, value))
    }
}

fn trim_sp(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|b| *b != b' ' && *b != b'\t').unwrap_or(s.len());
    let end = s.iter().rposition(|b| *b != b' ' && *b != b'\t').map(|i| i + 1).unwrap_or(start);
    &s[start..end]
}

fn ssdp_name_is(name: &[u8], want: &[u8]) -> bool {
    name.len() == want.len() && name.iter().zip(want).all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn starts_with_ignore_ascii_case(buf: &[u8], prefix: &[u8]) -> bool {
    buf.len() >= prefix.len()
        && buf[..prefix.len()].iter().zip(prefix).all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn ssdp_text(raw: &[u8]) -> heapless::String<{ common::UDP_SSDP_MAX }> {
    let mut out = heapless::String::new();
    for &b in raw {
        let c = if b == b' ' || b.is_ascii_graphic() { b as char } else { '?' };
        if out.push(c).is_err() {
            break;
        }
    }
    out
}

/// ESP: SPI из первых 4 байт. Sequence и ciphertext не читаются.
/// Короче 8 байт — заголовок неполный, SPI не сохраняется.
fn parse_esp(
    payload: &[u8],
    src: &common::IpAddr,
    dst: &common::IpAddr,
) -> Result<common::IpData, common::ParseError> {
    if payload.len() < common::ESP_MIN_LEN {
        return Err(common::ParseError::Esp_Broken {
            len: payload.len(),
            src: *src,
            dst: *dst,
        });
    }
    let spi = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    Ok(common::IpData::new_esp(src, dst, payload.len(), common::EspData { spi }))
}

/// ICMPv4: etherparse читает фиксированный заголовок. Вложенный IP и адреса RA не разбираются.
/// Timestamp (тип 13/14, code 0) etherparse принимает только при длине ровно 20 байт.
fn parse_icmp4(
    payload: &[u8],
    src: &common::IpAddr,
    dst: &common::IpAddr,
) -> Result<common::IpData, common::ParseError> {
    let (hdr, _) = etherparse::Icmpv4Header::from_slice(payload)
        .map_err(|_| icmp4_broken(payload, src, dst))?;
    Ok(common::IpData::new_icmp4(src, dst, payload.len(), parse_icmp4_msg(&hdr.icmp_type)))
}

fn icmp4_broken(
    payload: &[u8],
    src: &common::IpAddr,
    dst: &common::IpAddr,
) -> common::ParseError {
    common::ParseError::Icmp4_Broken {
        len: payload.len(),
        src: *src,
        dst: *dst,
        icmp4_type: common::Icmp4Type::from_payload(payload),
    }
}

fn parse_icmp4_msg(icmp_type: &etherparse::Icmpv4Type) -> common::Icmp4Data {
    use etherparse::Icmpv4Type;
    match icmp_type {
        Icmpv4Type::EchoRequest(e) => common::Icmp4Data::EchoRequest { id: e.id, seq: e.seq },
        Icmpv4Type::EchoReply(e)   => common::Icmp4Data::EchoReply { id: e.id, seq: e.seq },
        Icmpv4Type::DestinationUnreachable(h) => {
            let mtu = match h {
                etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded { next_hop_mtu } => Some(*next_hop_mtu),
                _ => None,
            };
            common::Icmp4Data::DestUnreach { code: h.code_u8(), mtu }
        }
        Icmpv4Type::TimeExceeded(code) => common::Icmp4Data::TimeExceeded { code: code.code_u8() },
        Icmpv4Type::ParameterProblem(h) => {
            // RFC 792 / 4884: 0 — pointer, 1 — missing option, 2 — bad length.
            use etherparse::icmpv4::ParameterProblemHeader::*;
            let (code, pointer) = match h {
                PointerIndicatesError(p) => (0, *p),
                MissingRequiredOption    => (1, 0),
                BadLength                => (2, 0),
            };
            common::Icmp4Data::ParamProblem { code, pointer }
        }
        Icmpv4Type::Redirect(h) => common::Icmp4Data::Redirect {
            code: h.code.code_u8(),
            gateway: common::Ipv4Addr::from(h.gateway_internet_address),
        },
        Icmpv4Type::TimestampRequest(m) => common::Icmp4Data::Timestamp {
            id: m.id, seq: m.seq,
            originate: m.originate_timestamp, receive: m.receive_timestamp, transmit: m.transmit_timestamp,
        },
        Icmpv4Type::TimestampReply(m) => common::Icmp4Data::TimestampReply {
            id: m.id, seq: m.seq,
            originate: m.originate_timestamp, receive: m.receive_timestamp, transmit: m.transmit_timestamp,
        },
        // etherparse 0.19 отдаёт RA/RS как Unknown
        Icmpv4Type::Unknown { type_u8, code_u8, bytes5to8 } => match *type_u8 {
            common::ICMP4_TYPE_RA => common::Icmp4Data::RouterAdvertisement {
                num_addrs: bytes5to8[0],
                addr_entry_size: bytes5to8[1],
                lifetime: u16::from_be_bytes([bytes5to8[2], bytes5to8[3]]),
            },
            common::ICMP4_TYPE_RS => common::Icmp4Data::RouterSolicitation,
            _ => common::Icmp4Data::Unknown { type_u8: *type_u8, code: *code_u8 },
        },
    }
}

/// IGMP: тип по первому байту, версия Query — по длине и Max Resp Time.
/// v1/v2 — 8 байт; v3 Query — от 12; v3 Report — от 8 плюс group records.
fn parse_igmp(
    payload: &[u8],
    src: &common::IpAddr,
    dst: &common::IpAddr,
) -> Result<common::IpData, common::ParseError> {
    let igmp_type = common::IgmpType::from_payload(payload);
    match parse_igmp_msg(payload, igmp_type) {
        Some(msg) => Ok(common::IpData::new_igmp(src, dst, payload.len(), msg)),
        None => Err(common::ParseError::Igmp_Broken {
            len: payload.len(),
            src: *src,
            dst: *dst,
            igmp_type,
        }),
    }
}

fn igmp_checksum_group(payload: &[u8]) -> (u16, common::Ipv4Addr) {
    let checksum = u16::from_be_bytes([payload[2], payload[3]]);
    let group = common::Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
    (checksum, group)
}

fn igmp_push_sources(
    out: &mut heapless::Vec<common::Ipv4Addr, { common::IGMP_V3_MAX_SOURCES }>,
    bytes: &[u8],
    nsrc: usize,
) -> Option<usize> {
    let need = nsrc.checked_mul(4)?;
    if bytes.len() < need {
        return None;
    }
    let store = min(nsrc, common::IGMP_V3_MAX_SOURCES);
    for i in 0..store {
        let o = i * 4;
        let _ = out.push(common::Ipv4Addr::new(bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]));
    }
    Some(need)
}

fn parse_igmp_v1v2(payload: &[u8]) -> Option<(u8, u16, common::Ipv4Addr)> {
    if payload.len() < common::IGMP_V1V2_LEN {
        return None;
    }
    let (checksum, group) = igmp_checksum_group(payload);
    Some((payload[1], checksum, group))
}

fn parse_igmp_v3_query(payload: &[u8]) -> Option<common::IgmpV3Query> {
    if payload.len() < common::IGMP_V3_QUERY_MIN_LEN {
        return None;
    }
    let (checksum, group) = igmp_checksum_group(payload);
    let flags = payload[8];
    let nsrc = u16::from_be_bytes([payload[10], payload[11]]) as usize;
    let mut sources = heapless::Vec::new();
    igmp_push_sources(&mut sources, &payload[12..], nsrc)?;
    Some(common::IgmpV3Query {
        max_resp_code: payload[1],
        checksum,
        group,
        suppress_router_processing: flags & 0x08 != 0,
        qrv: flags & 0x07,
        qqic: payload[9],
        sources,
    })
}

fn parse_igmp_v3_report(payload: &[u8]) -> Option<common::IgmpV3Report> {
    if payload.len() < common::IGMP_V3_REPORT_MIN_LEN {
        return None;
    }
    let checksum = u16::from_be_bytes([payload[2], payload[3]]);
    let nrecords = u16::from_be_bytes([payload[6], payload[7]]) as usize;
    let mut records = heapless::Vec::new();
    let mut rest = &payload[8..];
    for _ in 0..nrecords {
        if rest.len() < common::IGMP_V3_RECORD_MIN_LEN {
            return None;
        }
        let record_type = common::IgmpV3RecordType::from_u8(rest[0]);
        let aux_len = rest[1] as usize * 4;
        let nsrc = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        let multicast = common::Ipv4Addr::new(rest[4], rest[5], rest[6], rest[7]);
        rest = &rest[8..];
        let mut sources = heapless::Vec::new();
        let src_bytes = igmp_push_sources(&mut sources, rest, nsrc)?;
        rest = &rest[src_bytes..];
        if rest.len() < aux_len {
            return None;
        }
        rest = &rest[aux_len..];
        let _ = records.push(common::IgmpV3GroupRecord { record_type, multicast, sources });
    }
    Some(common::IgmpV3Report { checksum, records })
}

fn parse_igmp_msg(payload: &[u8], igmp_type: common::IgmpType) -> Option<common::IgmpData> {
    match igmp_type {
        common::IgmpType::V1Query => {
            let (_, checksum, group) = parse_igmp_v1v2(payload)?;
            Some(common::IgmpData::V1Query(common::IgmpV1 { checksum, group }))
        }
        common::IgmpType::V1Report => {
            let (_, checksum, group) = parse_igmp_v1v2(payload)?;
            Some(common::IgmpData::V1Report(common::IgmpV1 { checksum, group }))
        }
        common::IgmpType::V2Query => {
            let (max_resp_time, checksum, group) = parse_igmp_v1v2(payload)?;
            Some(common::IgmpData::V2Query(common::IgmpV2 { max_resp_time, checksum, group }))
        }
        common::IgmpType::V2Report => {
            let (max_resp_time, checksum, group) = parse_igmp_v1v2(payload)?;
            Some(common::IgmpData::V2Report(common::IgmpV2 { max_resp_time, checksum, group }))
        }
        common::IgmpType::V2Leave => {
            let (max_resp_time, checksum, group) = parse_igmp_v1v2(payload)?;
            Some(common::IgmpData::V2Leave(common::IgmpV2 { max_resp_time, checksum, group }))
        }
        common::IgmpType::V3Query => parse_igmp_v3_query(payload).map(common::IgmpData::V3Query),
        common::IgmpType::V3Report => parse_igmp_v3_report(payload).map(common::IgmpData::V3Report),
        common::IgmpType::Query | common::IgmpType::Unknown(_) => None,
    }
}

fn icmp6_broken(
    payload: &[u8],
    src: &common::IpAddr,
    dst: &common::IpAddr,
) -> common::ParseError {
    common::ParseError::Icmp6_Broken {
        len: payload.len(),
        src: *src,
        dst: *dst,
        icmp6_type: common::Icmp6Type::from_payload(payload),
    }
}

fn ipv6_addr_from(bytes: &[u8]) -> Option<common::Ipv6Addr> {
    if bytes.len() < 16 {
        return None;
    }
    let mut oct = [0u8; 16];
    oct.copy_from_slice(&bytes[..16]);
    Some(common::Ipv6Addr::from(oct))
}

/// ICMPv6: etherparse разбирает известные типы; MLD (130–132, 143) приходит как Unknown.
/// Target NDP и группа MLD читаются из хвоста после 8-байтного заголовка.
/// У NS после target — Source LLA, у NA — Target LLA.
fn parse_icmp6(
    payload: &[u8],
    src: &common::IpAddr,
    dst: &common::IpAddr,
) -> Result<common::IpData, common::ParseError> {
    let (hdr, rest) = etherparse::Icmpv6Header::from_slice(payload)
        .map_err(|_| icmp6_broken(payload, src, dst))?;
    match parse_icmp6_msg(&hdr, rest) {
        Some(msg) => Ok(common::IpData::new_icmp6(src, dst, payload.len(), msg)),
        None => Err(icmp6_broken(payload, src, dst)),
    }
}

fn parse_mld_group(rest: &[u8]) -> Option<common::Ipv6Addr> {
    ipv6_addr_from(rest)
}

/// MAC соседа из опций NDP после 16-байтного target (RFC 4861 §4.6).
/// `want` — тип 1 для NS, тип 2 для NA. Берётся первая опция этого типа длиной 1
/// (8 байт: заголовок и Ethernet MAC). Длиннее 6 байт — пропускается.
/// Длина 0 или заявка, вылезающая за срез, останавливает обход: уже найденный MAC сохраняется.
fn ndp_neighbor_lladdr(options: &[u8], want: u8) -> Option<common::MacAddr6> {
    let mut i = 0;
    while i + 2 <= options.len() {
        let opt_type = options[i];
        let units = options[i + 1] as usize;
        if units == 0 {
            break;
        }
        let opt_bytes = units * 8;
        if i + opt_bytes > options.len() {
            break;
        }
        if opt_type == want && units == 1 {
            return Some(common::MacAddr6::from_slice(&options[i + 2..i + 8]));
        }
        i += opt_bytes;
    }
    None
}

fn parse_icmp6_msg(
    hdr: &etherparse::Icmpv6Header,
    rest: &[u8],
) -> Option<common::Icmp6Data> {
    use etherparse::Icmpv6Type;
    match hdr.icmp_type {
        Icmpv6Type::EchoRequest(e) => Some(common::Icmp6Data::EchoRequest { id: e.id, seq: e.seq }),
        Icmpv6Type::EchoReply(e)   => Some(common::Icmp6Data::EchoReply { id: e.id, seq: e.seq }),
        Icmpv6Type::DestinationUnreachable(_) => Some(common::Icmp6Data::DestUnreach { code: hdr.icmp_type.code_u8() }),
        Icmpv6Type::PacketTooBig { mtu } => Some(common::Icmp6Data::PacketTooBig { mtu }),
        Icmpv6Type::TimeExceeded(_) => Some(common::Icmp6Data::TimeExceeded { code: hdr.icmp_type.code_u8() }),
        Icmpv6Type::ParameterProblem(_) => Some(common::Icmp6Data::ParamProblem { code: hdr.icmp_type.code_u8() }),
        Icmpv6Type::RouterSolicitation => Some(common::Icmp6Data::RouterSolicitation),
        Icmpv6Type::RouterAdvertisement(ra) => Some(common::Icmp6Data::RouterAdvertisement {
            hop_limit: ra.cur_hop_limit,
            managed: ra.managed_address_config,
            other_config: ra.other_config,
            lifetime: ra.router_lifetime,
        }),
        Icmpv6Type::NeighborSolicitation => {
            let target = ipv6_addr_from(rest)?;
            let lladdr = ndp_neighbor_lladdr(&rest[16..], common::ICMP6_NDP_OPT_SRC_LLADDR);
            Some(common::Icmp6Data::NeighborSolicitation { target, lladdr })
        }
        Icmpv6Type::NeighborAdvertisement(na) => {
            let target = ipv6_addr_from(rest)?;
            let lladdr = ndp_neighbor_lladdr(&rest[16..], common::ICMP6_NDP_OPT_TGT_LLADDR);
            Some(common::Icmp6Data::NeighborAdvertisement {
                router: na.router,
                solicited: na.solicited,
                override_flag: na.r#override,
                target,
                lladdr,
            })
        }
        Icmpv6Type::Redirect => {
            let target = ipv6_addr_from(rest)?;
            let destination = ipv6_addr_from(&rest[16..])?;
            Some(common::Icmp6Data::Redirect { target, destination })
        }
        Icmpv6Type::Unknown { type_u8, code_u8, bytes5to8 } => match type_u8 {
            common::ICMP6_TYPE_MLD_QUERY => {
                let group = parse_mld_group(rest)?;
                Some(common::Icmp6Data::MldQuery {
                    max_resp_delay: u16::from_be_bytes([bytes5to8[0], bytes5to8[1]]),
                    group,
                })
            }
            common::ICMP6_TYPE_MLD_REPORT => {
                let group = parse_mld_group(rest)?;
                Some(common::Icmp6Data::MldReport { group })
            }
            common::ICMP6_TYPE_MLD_DONE => {
                let group = parse_mld_group(rest)?;
                Some(common::Icmp6Data::MldDone { group })
            }
            common::ICMP6_TYPE_MLDV2_REPORT => Some(common::Icmp6Data::MldV2Report),
            // etherparse 0.19 отдаёт RS/RA/Redirect как Unknown
            common::ICMP6_TYPE_RS => Some(common::Icmp6Data::RouterSolicitation),
            common::ICMP6_TYPE_RA => Some(common::Icmp6Data::RouterAdvertisement {
                hop_limit: bytes5to8[0],
                managed: bytes5to8[1] & 0x80 != 0,
                other_config: bytes5to8[1] & 0x40 != 0,
                lifetime: u16::from_be_bytes([bytes5to8[2], bytes5to8[3]]),
            }),
            common::ICMP6_TYPE_REDIRECT => {
                let target = ipv6_addr_from(rest)?;
                let destination = ipv6_addr_from(&rest[16..])?;
                Some(common::Icmp6Data::Redirect { target, destination })
            }
            _ => Some(common::Icmp6Data::Unknown { type_u8, code: code_u8 }),
        },
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
    let ipv4 = packet.try_eth_ipv4()
            .map_err(|_| common::ParseError::Arp_Unsupported
                {
                    hw_type: packet.hw_addr_type.0,
                    proto_type: packet.proto_addr_type.0,
                    hw_len: packet.hw_addr_size(),
                    proto_len: packet.protocol_addr_size(),
                }
            )?;

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
        match data.l4 {
            common::IpL4::Udp { src_port: 12345, dst_port: 53, .. } => {}
            other => panic!("expected UDP ports, got {other:?}"),
        }
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
        match data.l4 {
            common::IpL4::Tcp { src_port: 40000, dst_port: 443 } => {}
            other => panic!("expected TCP ports, got {other:?}"),
        }
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
        match data.l4 {
            common::IpL4::Tcp { src_port: 1234, dst_port: 80 } => {}
            other => panic!("expected TCP ports, got {other:?}"),
        }
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
        match data.l4 {
            common::IpL4::Tcp { src_port: 50000, dst_port: 443 } => {}
            other => panic!("expected TCP ports, got {other:?}"),
        }
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

    /// `payload_length == 0` не обрезает хвост: len включает байты после TCP.
    #[test]
    fn ipv6_zero_payload_length_keeps_tail() {
        let src = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let tcp = tcp_header(50000, 443);
        let ip = etherparse::Ipv6Header {
            payload_length: 0,
            next_header: etherparse::IpNumber::TCP,
            hop_limit: 64,
            source: src,
            destination: dst,
            ..etherparse::Ipv6Header::default()
        };

        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&tcp.to_bytes());
        packet.extend_from_slice(&[0xBB; 10]);

        let data = expect_ip(parse_ipv6(&packet));
        match data.l4 {
            common::IpL4::Tcp { src_port: 50000, dst_port: 443 } => {}
            other => panic!("expected TCP ports, got {other:?}"),
        }
        assert_eq!(data.len, 30);
    }

    /// Первый IPv6-фрагмент (offset 0, MF=1) сохраняет порты TCP.
    #[test]
    fn ipv6_first_fragment_keeps_tcp_ports() {
        let src = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let frag = etherparse::Ipv6FragmentHeader::new(
            etherparse::IpNumber::TCP,
            0u16.try_into().unwrap(),
            true,
            0xABC,
        );
        let tcp = tcp_header(50000, 443);
        let ip = etherparse::Ipv6Header {
            payload_length: (etherparse::Ipv6FragmentHeader::LEN + 20) as u16,
            next_header: etherparse::IpNumber::IPV6_FRAGMENTATION_HEADER,
            hop_limit: 64,
            source: src,
            destination: dst,
            ..etherparse::Ipv6Header::default()
        };

        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&frag.to_bytes());
        packet.extend_from_slice(&tcp.to_bytes());

        let data = expect_ip(parse_ipv6(&packet));
        match data.l4 {
            common::IpL4::Tcp { src_port: 50000, dst_port: 443 } => {}
            other => panic!("expected TCP ports, got {other:?}"),
        }
        assert_eq!(data.len, 20);
    }

    /// IGMPv2 Membership Report: 8 байт, тип 0x16, групповой адрес в payload.
    #[test]
    fn ipv4_igmp_v2_report() {
        let ip = etherparse::Ipv4Header::new(
            8, 1, etherparse::IpNumber::IGMP, [10, 0, 0, 1], [224, 0, 0, 22],
        ).unwrap();
        // type=0x16 (v2 report), max resp=0, checksum=0, group=239.1.1.1
        let igmp = [0x16, 0x00, 0x00, 0x00, 239, 1, 1, 1];

        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&igmp);

        let data = expect_ip(parse_ipv4(&packet));
        assert_eq!(data.len, 8);
        match data.l4 {
            common::IpL4::Igmp(common::IgmpData::V2Report(v)) => {
                assert_eq!(v.group, common::Ipv4Addr::new(239, 1, 1, 1));
            }
            other => panic!("expected V2Report, got {other:?}"),
        }
    }

    /// IGMPv1 Query: тип 0x11, Max Resp Time = 0, 8 байт.
    #[test]
    fn ipv4_igmp_v1_query() {
        let ip = etherparse::Ipv4Header::new(
            8, 1, etherparse::IpNumber::IGMP, [10, 0, 0, 1], [224, 0, 0, 1],
        ).unwrap();
        let igmp = [0x11, 0x00, 0x00, 0x00, 0, 0, 0, 0];

        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&igmp);

        let data = expect_ip(parse_ipv4(&packet));
        assert!(matches!(data.l4, common::IpL4::Igmp(common::IgmpData::V1Query(_))));
    }

    /// IGMPv3 Query без источников: 12 байт.
    #[test]
    fn ipv4_igmp_v3_query_no_sources() {
        let ip = etherparse::Ipv4Header::new(
            12, 1, etherparse::IpNumber::IGMP, [10, 0, 0, 1], [224, 0, 0, 1],
        ).unwrap();
        let igmp = [
            0x11, 0x64, 0x00, 0x00,
            0, 0, 0, 0,
            0x02, // S=0, QRV=2
            0x7D, // QQIC
            0x00, 0x00, // nsrc=0
        ];

        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&igmp);

        let data = expect_ip(parse_ipv4(&packet));
        match data.l4 {
            common::IpL4::Igmp(common::IgmpData::V3Query(q)) => {
                assert_eq!(q.max_resp_code, 0x64);
                assert_eq!(q.qrv, 2);
                assert!(q.sources.is_empty());
            }
            other => panic!("expected V3Query, got {other:?}"),
        }
    }

    /// Обрезанный Query (тип 0x11, 4 байта) — Igmp_Broken с типом Query.
    #[test]
    fn ipv4_igmp_too_short() {
        let ip = etherparse::Ipv4Header::new(
            4, 1, etherparse::IpNumber::IGMP, [10, 0, 0, 1], [224, 0, 0, 1],
        ).unwrap();
        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&[0x11, 0x00, 0x00, 0x00]);

        match parse_ipv4(&packet) {
            Err(common::ParseError::Igmp_Broken { igmp_type: common::IgmpType::Query, .. }) => {}
            Err(e) => panic!("expected Igmp_Broken Query, got {e:?}"),
            Ok(_) => panic!("expected Igmp_Broken"),
        }
    }

    /// Обрезанный IGMPv3 Query (10 байт вместо 12) — Igmp_Broken с типом V3Query.
    #[test]
    fn ipv4_igmp_v3_query_truncated() {
        let ip = etherparse::Ipv4Header::new(
            10, 1, etherparse::IpNumber::IGMP, [10, 0, 0, 1], [224, 0, 0, 1],
        ).unwrap();
        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&[0x11, 0x64, 0, 0, 0, 0, 0, 0, 0x02, 0x7D]);

        match parse_ipv4(&packet) {
            Err(common::ParseError::Igmp_Broken { igmp_type: common::IgmpType::V3Query, .. }) => {}
            Err(e) => panic!("expected Igmp_Broken V3Query, got {e:?}"),
            Ok(_) => panic!("expected Igmp_Broken"),
        }
    }

    /// IGMPv2 Query: ровно 8 байт и Max Resp Time ≠ 0.
    #[test]
    fn ipv4_igmp_v2_query() {
        let ip = etherparse::Ipv4Header::new(
            8, 1, etherparse::IpNumber::IGMP, [10, 0, 0, 1], [224, 0, 0, 1],
        ).unwrap();
        let igmp = [0x11, 0x0A, 0x12, 0x34, 224, 0, 0, 1];

        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&igmp);

        let data = expect_ip(parse_ipv4(&packet));
        match data.l4 {
            common::IpL4::Igmp(common::IgmpData::V2Query(q)) => {
                assert_eq!(q.max_resp_time, 0x0A);
                assert_eq!(q.checksum, 0x1234);
                assert_eq!(q.group, common::Ipv4Addr::new(224, 0, 0, 1));
            }
            other => panic!("expected V2Query, got {other:?}"),
        }
    }

    /// IGMPv2 Leave Group: тип 0x17, 8 байт, адрес группы.
    #[test]
    fn ipv4_igmp_v2_leave() {
        let ip = etherparse::Ipv4Header::new(
            8, 1, etherparse::IpNumber::IGMP, [10, 0, 0, 1], [224, 0, 0, 2],
        ).unwrap();
        let igmp = [0x17, 0x00, 0x00, 0x00, 239, 1, 1, 2];

        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&igmp);

        let data = expect_ip(parse_ipv4(&packet));
        match data.l4 {
            common::IpL4::Igmp(common::IgmpData::V2Leave(v)) => {
                assert_eq!(v.group, common::Ipv4Addr::new(239, 1, 1, 2));
            }
            other => panic!("expected V2Leave, got {other:?}"),
        }
    }

    /// IGMPv3 Report: одна запись INCLUDE и один источник.
    #[test]
    fn ipv4_igmp_v3_report_one_source() {
        let igmp = [
            0x22, 0x00, 0x12, 0x34, 0x00, 0x00, 0x00, 0x01,
            0x01, 0x00, 0x00, 0x01, 239, 1, 1, 1,
            10, 0, 0, 5,
        ];
        let ip = etherparse::Ipv4Header::new(
            igmp.len() as u16, 1, etherparse::IpNumber::IGMP, [10, 0, 0, 1], [224, 0, 0, 22],
        ).unwrap();

        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&igmp);

        let data = expect_ip(parse_ipv4(&packet));
        match data.l4 {
            common::IpL4::Igmp(common::IgmpData::V3Report(r)) => {
                assert_eq!(r.checksum, 0x1234);
                assert_eq!(r.records.len(), 1);
                assert_eq!(r.records[0].record_type, common::IgmpV3RecordType::ModeIsInclude);
                assert_eq!(r.records[0].multicast, common::Ipv4Addr::new(239, 1, 1, 1));
                assert_eq!(r.records[0].sources.as_slice(), &[common::Ipv4Addr::new(10, 0, 0, 5)]);
            }
            other => panic!("expected V3Report, got {other:?}"),
        }
    }

    fn ipv4_udp_ports(src_port: u16, dst_port: u16) -> common::IpData {
        let ip = etherparse::Ipv4Header::new(
            8, 64, etherparse::IpNumber::UDP, [10, 0, 0, 1], [10, 0, 0, 2],
        ).unwrap();
        let udp = etherparse::UdpHeader {
            source_port: src_port,
            destination_port: dst_port,
            length: 8,
            checksum: 0,
        };
        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&udp.to_bytes());
        expect_ip(parse_ipv4(&packet))
    }

    fn ipv4_udp(src_port: u16, dst_port: u16, body: &[u8]) -> common::IpData {
        let udp_len = (8 + body.len()) as u16;
        let ip = etherparse::Ipv4Header::new(
            udp_len, 64, etherparse::IpNumber::UDP, [10, 0, 0, 1], [10, 0, 0, 2],
        ).unwrap();
        let udp = etherparse::UdpHeader {
            source_port: src_port,
            destination_port: dst_port,
            length: udp_len,
            checksum: 0,
        };
        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&udp.to_bytes());
        packet.extend_from_slice(body);
        expect_ip(parse_ipv4(&packet))
    }

    fn dns_query(name: &str) -> Vec<u8> {
        let mut body = vec![0u8; 12];
        body[5] = 1;
        for label in name.split('.') {
            body.push(label.len() as u8);
            body.extend_from_slice(label.as_bytes());
        }
        body.push(0);
        body.extend_from_slice(&[0, 1, 0, 1]);
        body
    }

    fn dhcp4_with_options(options: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 240];
        body[0] = 1;
        body[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        body.extend_from_slice(options);
        body
    }

    fn ipv6_l4(next: etherparse::IpNumber, l4: &[u8]) -> Result<common::NetPayload, common::ParseError> {
        let src = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let ip = etherparse::Ipv6Header {
            payload_length: l4.len() as u16,
            next_header: next,
            hop_limit: 64,
            source: src,
            destination: dst,
            ..etherparse::Ipv6Header::default()
        };
        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(l4);
        parse_ipv6(&packet)
    }

    /// DHCP Discover: cookie и опция 53 подтверждают ярлык, в строке есть тип.
    #[test]
    fn udp_dhcp4_discover() {
        let data = ipv4_udp(68, 67, &dhcp4_with_options(&[53, 1, 1, 255]));
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Dhcp4, msg: Some(common::UdpMsg::Dhcp4 { msg: Some(common::Dhcp4Msg::Discover), host: None, requested: None }), .. } => {}
            other => panic!("expected DHCP Discover, got {other:?}"),
        }
        assert!(format!("{}", data).contains("UDP/DHCP Discover"));
    }

    /// Порты 68/67 без magic cookie — не DHCP.
    #[test]
    fn udp_dhcp4_without_cookie_is_other() {
        let data = ipv4_udp(68, 67, &[0u8; 240]);
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Other, msg: None, .. } => {}
            other => panic!("expected plain UDP, got {other:?}"),
        }
    }

    /// Cookie есть, опции 53 нет: ярлык DHCP остаётся, тип не выдумывается.
    #[test]
    fn udp_dhcp4_cookie_without_msg_type() {
        let data = ipv4_udp(67, 68, &dhcp4_with_options(&[]));
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Dhcp4, msg: Some(common::UdpMsg::Dhcp4 { msg: None, host: None, requested: None }), .. } => {}
            other => panic!("expected DHCP without type, got {other:?}"),
        }
    }

    /// Опция 53 находится после pad и другой опции.
    #[test]
    fn udp_dhcp4_request_after_other_option() {
        let data = ipv4_udp(68, 67, &dhcp4_with_options(&[
            0, 12, 5, b'h', b'o', b's', b't', b'1', 53, 1, 3, 255,
        ]));
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Dhcp4 {
                msg: Some(common::Dhcp4Msg::Request), host: Some(name), requested: None,
            }), .. } => assert_eq!(name.as_str(), "host1"),
            other => panic!("expected DHCP Request, got {other:?}"),
        }
    }

    /// Опция 12 — имя хоста, опция 50 — запрошенный адрес. Обе читаются и после типа.
    #[test]
    fn udp_dhcp4_hostname_and_requested() {
        let data = ipv4_udp(68, 67, &dhcp4_with_options(&[
            53, 1, 3,
            50, 4, 192, 168, 1, 50,
            12, 7, b'p', b'r', b'i', b'n', b't', b'e', b'r',
            255,
        ]));
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Dhcp4 {
                msg: Some(common::Dhcp4Msg::Request), host: Some(name), requested: Some(ip),
            }), .. } => {
                assert_eq!(name.as_str(), "printer");
                assert_eq!(ip, common::Ipv4Addr::new(192, 168, 1, 50));
            }
            other => panic!("expected DHCP host and requested address, got {other:?}"),
        }
        let s = format!("{}", data);
        assert!(s.contains("host=printer"));
        assert!(s.contains("req=192.168.1.50"));
    }

    /// Имя длиннее 64 символов обрезается, пакет остаётся DHCP.
    #[test]
    fn udp_dhcp4_hostname_truncated_to_64() {
        let mut options = vec![12, 70];
        options.extend(std::iter::repeat(b'a').take(70));
        options.push(255);
        let data = ipv4_udp(68, 67, &dhcp4_with_options(&options));
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Dhcp4 { host: Some(name), .. }), .. } => {
                assert_eq!(name.len(), common::UDP_QNAME_MAX);
                assert!(name.chars().all(|c| c == 'a'));
            }
            other => panic!("expected truncated hostname, got {other:?}"),
        }
    }

    /// Опция 50 не из 4 байт не становится адресом. Имя из соседней опции сохраняется.
    #[test]
    fn udp_dhcp4_requested_wrong_length_skipped() {
        let data = ipv4_udp(68, 67, &dhcp4_with_options(&[
            50, 2, 10, 0, 12, 1, b'a', 255,
        ]));
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Dhcp4 {
                host: Some(name), requested: None, ..
            }), .. } => assert_eq!(name.as_str(), "a"),
            other => panic!("expected hostname without requested address, got {other:?}"),
        }
    }

    /// Обрезанная опция 50 не даёт частичный адрес. Уже прочитанное имя остаётся.
    #[test]
    fn udp_dhcp4_truncated_requested_keeps_hostname() {
        let data = ipv4_udp(68, 67, &dhcp4_with_options(&[
            12, 1, b'a', 50, 4, 192, 168,
        ]));
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Dhcp4 {
                host: Some(name), requested: None, ..
            }), .. } => assert_eq!(name.as_str(), "a"),
            other => panic!("expected hostname, truncated requested dropped, got {other:?}"),
        }
    }

    /// DHCPv6 Solicit: 4 байта, тип в первом. В строке есть тип.
    #[test]
    fn udp_dhcp6_solicit() {
        let data = ipv4_udp(546, 547, &[1, 0x11, 0x22, 0x33]);
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Dhcp6, msg: Some(common::UdpMsg::Dhcp6 { msg: common::Dhcp6Msg::Solicit }), .. } => {}
            other => panic!("expected DHCPv6 Solicit, got {other:?}"),
        }
        assert!(format!("{}", data).contains("UDP/DHCPv6 Solicit"));
    }

    /// Reply — клиентское сообщение, хватает 4 байт.
    #[test]
    fn udp_dhcp6_reply() {
        let data = ipv4_udp(547, 546, &[7, 0, 0, 1]);
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Dhcp6 { msg: common::Dhcp6Msg::Reply }), .. } => {}
            other => panic!("expected DHCPv6 Reply, got {other:?}"),
        }
    }

    /// Relay-forward подтверждается только с заголовком в 34 байта.
    #[test]
    fn udp_dhcp6_relay_forward() {
        let mut body = vec![12u8, 0];
        body.extend_from_slice(&[0u8; 32]);
        let data = ipv4_udp(547, 547, &body);
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Dhcp6 { msg: common::Dhcp6Msg::RelayForw }), .. } => {}
            other => panic!("expected DHCPv6 Relay-forward, got {other:?}"),
        }
        assert!(format!("{}", data).contains("UDP/DHCPv6 Relay-forward"));
    }

    /// Relay короче 34 байт снимает ярлык.
    #[test]
    fn udp_dhcp6_relay_too_short_is_other() {
        let data = ipv4_udp(547, 547, &[12u8, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Other, msg: None, .. } => {}
            other => panic!("expected plain UDP, got {other:?}"),
        }
    }

    /// Solicit короче заголовка и нулевой тип не подтверждают DHCPv6.
    #[test]
    fn udp_dhcp6_bad_header_is_other() {
        for body in [&[1u8, 0, 0][..], &[0, 0, 0, 0][..], &[99, 0, 0, 0][..]] {
            let data = ipv4_udp(546, 547, body);
            match data.l4.clone() {
                common::IpL4::Udp { app: common::UdpApp::Other, msg: None, .. } => {}
                other => panic!("expected plain UDP for {body:?}, got {other:?}"),
            }
        }
    }

    fn push_nbns_name(buf: &mut Vec<u8>, name: &str, suffix: u8) {
        buf.push(32);
        let mut raw = [b' '; 16];
        let bytes = name.as_bytes();
        let n = bytes.len().min(15);
        raw[..n].copy_from_slice(&bytes[..n]);
        raw[15] = suffix;
        for b in raw {
            buf.push(b'A' + (b >> 4));
            buf.push(b'A' + (b & 0x0F));
        }
        buf.push(0);
    }

    fn nbns_packet(flags: u16, qd: u16, an: u16, rest: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 12];
        body[2..4].copy_from_slice(&flags.to_be_bytes());
        body[4..6].copy_from_slice(&qd.to_be_bytes());
        body[6..8].copy_from_slice(&an.to_be_bytes());
        body.extend_from_slice(rest);
        body
    }

    /// Запрос NBNS: имя и суффикс. Код результата в строку не попадает.
    #[test]
    fn udp_nbns_query() {
        let mut rest = Vec::new();
        push_nbns_name(&mut rest, "WORKSTATION", 0x00);
        rest.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]);
        let data = ipv4_udp(137, 137, &nbns_packet(0x0110, 1, 0, &rest));
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Nbns, msg: Some(common::UdpMsg::Nbns(n)), .. } => {
                assert!(!n.response);
                assert_eq!(n.op, common::NbnsOp::Query);
                assert_eq!(n.name.as_str(), "WORKSTATION");
                assert_eq!(n.suffix, 0x00);
                assert_eq!(n.kind, common::NbnsKind::Nb);
                assert!(n.addr.is_none());
            }
            other => panic!("expected NBNS query, got {other:?}"),
        }
        let shown = format!("{}", data);
        assert!(shown.contains("UDP/NBNS Query WORKSTATION <00>"));
        assert!(shown.contains("src:"));
        assert!(shown.contains("dst:"));
        assert!(!shown.contains("rcode="));
    }

    /// Регистрация — код операции 5, это не ответ.
    #[test]
    fn udp_nbns_registration() {
        let mut rest = Vec::new();
        push_nbns_name(&mut rest, "WORKSTATION", 0x00);
        rest.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]);
        let data = ipv4_udp(137, 137, &nbns_packet(0x2910, 1, 0, &rest));
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Nbns(n)), .. } => {
                assert!(!n.response);
                assert_eq!(n.op, common::NbnsOp::Registration);
            }
            other => panic!("expected NBNS registration, got {other:?}"),
        }
        assert!(format!("{}", data).contains("UDP/NBNS Registration WORKSTATION <00>"));
    }

    /// Ответ: имя вопроса сжатым указателем и IPv4 из NB-записи.
    #[test]
    fn udp_nbns_response_address() {
        let mut rest = Vec::new();
        push_nbns_name(&mut rest, "WORKSTATION", 0x20);
        rest.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]);
        rest.extend_from_slice(&[0xC0, 0x0C]);
        rest.extend_from_slice(&[0x00, 0x20, 0x00, 0x01, 0, 0, 0, 0, 0, 6, 0, 0, 192, 168, 1, 20]);
        let data = ipv4_udp(137, 137, &nbns_packet(0x8500, 1, 1, &rest));
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Nbns(n)), .. } => {
                assert!(n.response);
                assert_eq!(n.name.as_str(), "WORKSTATION");
                assert_eq!(n.suffix, 0x20);
                assert_eq!(n.addr, Some(common::Ipv4Addr::new(192, 168, 1, 20)));
                assert_eq!(n.rcode, 0);
            }
            other => panic!("expected NBNS response, got {other:?}"),
        }
        assert!(format!("{}", data).contains("UDP/NBNS Response WORKSTATION <20> 192.168.1.20"));
    }

    /// Отрицательный ответ хранит код и не выдумывает адрес.
    #[test]
    fn udp_nbns_response_rcode() {
        let mut rest = Vec::new();
        push_nbns_name(&mut rest, "WORKSTATION", 0x00);
        rest.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]);
        let data = ipv4_udp(137, 137, &nbns_packet(0x8003, 1, 0, &rest));
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Nbns(n)), .. } => {
                assert!(n.response);
                assert_eq!(n.rcode, 3);
                assert!(n.addr.is_none());
            }
            other => panic!("expected NBNS error response, got {other:?}"),
        }
        assert!(format!("{}", data).contains("UDP/NBNS Response WORKSTATION <00> rcode=3"));
    }

    /// Ответ без вопросов: имя и адрес из первой записи.
    #[test]
    fn udp_nbns_response_without_question() {
        let mut rest = Vec::new();
        push_nbns_name(&mut rest, "SERVER", 0x20);
        rest.extend_from_slice(&[0x00, 0x20, 0x00, 0x01, 0, 0, 0, 0, 0, 6, 0, 0, 10, 0, 0, 5]);
        let data = ipv4_udp(137, 137, &nbns_packet(0x8400, 0, 1, &rest));
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Nbns(n)), .. } => {
                assert_eq!(n.name.as_str(), "SERVER");
                assert_eq!(n.addr, Some(common::Ipv4Addr::new(10, 0, 0, 5)));
            }
            other => panic!("expected NBNS answer without question, got {other:?}"),
        }
    }

    /// NBSTAT виден в строке. Короткая NB-запись не даёт адрес, имя остаётся.
    #[test]
    fn udp_nbns_nbstat_and_short_rdata() {
        let mut rest = Vec::new();
        push_nbns_name(&mut rest, "WORKSTATION", 0x00);
        rest.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]);
        let data = ipv4_udp(137, 137, &nbns_packet(0x0110, 1, 0, &rest));
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Nbns(n)), .. } => {
                assert_eq!(n.kind, common::NbnsKind::NbStat);
            }
            other => panic!("expected NBSTAT, got {other:?}"),
        }
        assert!(format!("{}", data).contains("NBSTAT"));

        let mut rest = Vec::new();
        push_nbns_name(&mut rest, "WORKSTATION", 0x00);
        rest.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]);
        rest.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x20, 0x00, 0x01, 0, 0, 0, 0, 0, 4, 1, 2, 3, 4]);
        let data = ipv4_udp(137, 137, &nbns_packet(0x8500, 1, 1, &rest));
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Nbns(n)), .. } => {
                assert_eq!(n.name.as_str(), "WORKSTATION");
                assert!(n.addr.is_none());
            }
            other => panic!("expected name without address, got {other:?}"),
        }
    }

    /// Метка не из A–P снимает ярлык порта.
    #[test]
    fn udp_nbns_bad_label_is_other() {
        let mut rest = vec![32u8];
        rest.extend(std::iter::repeat(b'A').take(31));
        rest.push(b'Z');
        rest.push(0);
        rest.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]);
        let data = ipv4_udp(137, 137, &nbns_packet(0x0110, 1, 0, &rest));
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Other, msg: None, .. } => {}
            other => panic!("expected plain UDP, got {other:?}"),
        }
    }

    /// NOTIFY: первая строка и заголовки NT, USN, LOCATION. NTS не попадает в NT.
    #[test]
    fn udp_ssdp_notify_headers() {
        let body = b"\
NOTIFY * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
NTS: ssdp:alive\r\n\
nt: urn:device:1\r\n\
USN: uuid:abc\r\n\
Location: http://192.168.0.2/desc.xml\r\n\
\r\n";
        let data = ipv4_udp(1900, 1900, body);
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Ssdp, msg: Some(common::UdpMsg::Ssdp(s)), .. } => {
                assert_eq!(s.start.as_str(), "NOTIFY * HTTP/1.1");
                assert_eq!(s.nt.unwrap().as_str(), "urn:device:1");
                assert_eq!(s.usn.unwrap().as_str(), "uuid:abc");
                assert_eq!(s.location.unwrap().as_str(), "http://192.168.0.2/desc.xml");
            }
            other => panic!("expected SSDP NOTIFY, got {other:?}"),
        }
        let shown = format!("{}", data);
        assert!(shown.contains("UDP/SSDP NOTIFY * HTTP/1.1"));
        assert!(shown.contains("NT=urn:device:1"));
        assert!(shown.contains("USN=uuid:abc"));
        assert!(shown.contains("LOCATION=http://192.168.0.2/desc.xml"));
    }

    /// M-SEARCH без NT/USN/LOCATION остаётся SSDP, поля пустые.
    #[test]
    fn udp_ssdp_msearch_start_only() {
        let body = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n\r\n";
        let data = ipv4_udp(45000, 1900, body);
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Ssdp, msg: Some(common::UdpMsg::Ssdp(s)), .. } => {
                assert_eq!(s.start.as_str(), "M-SEARCH * HTTP/1.1");
                assert!(s.nt.is_none());
                assert!(s.usn.is_none());
                assert!(s.location.is_none());
            }
            other => panic!("expected SSDP M-SEARCH, got {other:?}"),
        }
    }

    /// Ответ HTTP/1.1: LOCATION и USN, NT нет.
    #[test]
    fn udp_ssdp_http_response() {
        let body = b"HTTP/1.1 200 OK\nUSN: uuid:dev\nLOCATION: http://10.0.0.1/\n\n";
        let data = ipv4_udp(1900, 50000, body);
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Ssdp(s)), .. } => {
                assert_eq!(s.start.as_str(), "HTTP/1.1 200 OK");
                assert!(s.nt.is_none());
                assert_eq!(s.usn.unwrap().as_str(), "uuid:dev");
                assert_eq!(s.location.unwrap().as_str(), "http://10.0.0.1/");
            }
            other => panic!("expected SSDP response, got {other:?}"),
        }
    }

    /// Повтор NT: берётся первое. Длинный LOCATION обрезается до 128.
    #[test]
    fn udp_ssdp_first_nt_and_truncated_location() {
        let mut body = b"NOTIFY * HTTP/1.1\r\nNT: urn:first\r\nNT: urn:second\r\nLOCATION: ".to_vec();
        body.extend(std::iter::repeat(b'u').take(140));
        body.extend_from_slice(b"\r\n\r\n");
        let data = ipv4_udp(1900, 1900, &body);
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Ssdp(s)), .. } => {
                assert_eq!(s.nt.unwrap().as_str(), "urn:first");
                let loc = s.location.unwrap();
                assert_eq!(loc.len(), common::UDP_SSDP_MAX);
                assert!(loc.chars().all(|c| c == 'u'));
            }
            other => panic!("expected first NT and truncated LOCATION, got {other:?}"),
        }
    }

    /// Тело без стартовой строки SSDP снимает ярлык порта.
    #[test]
    fn udp_ssdp_garbage_is_other() {
        let data = ipv4_udp(1900, 1900, b"not a search");
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Other, msg: None, .. } => {}
            other => panic!("expected plain UDP, got {other:?}"),
        }
    }

    /// DNS: первое имя вопроса попадает в строку.
    #[test]
    fn udp_dns() {
        let data = ipv4_udp(12345, 53, &dns_query("example.com"));
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Dns, msg: Some(common::UdpMsg::Query(q)), .. } => {
                assert_eq!(q.name.unwrap().as_str(), "example.com");
                assert!(q.srv.is_none());
            }
            other => panic!("expected query name, got {other:?}"),
        }
        assert!(format!("{}", data).contains("UDP/DNS q=example.com"));
    }

    /// Короткий хвост на порту 53 — не DNS.
    #[test]
    fn udp_dns_too_short_is_other() {
        let data = ipv4_udp(12345, 53, &[0, 1, 2, 3]);
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Other, .. } => {}
            other => panic!("expected plain UDP, got {other:?}"),
        }
    }

    /// Указатель в имени вопроса собирается в одно имя.
    #[test]
    fn udp_dns_compressed_qname() {
        let mut body = vec![0u8; 12];
        body[5] = 1;
        body.extend_from_slice(&[3, b'w', b'w', b'w', 0xC0, 22]);
        body.extend_from_slice(&[0, 1, 0, 1]);
        body.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        let data = ipv4_udp(5355, 5355, &body);
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Llmnr, msg: Some(common::UdpMsg::Query(q)), .. } => {
                assert_eq!(q.name.unwrap().as_str(), "www.example.com");
                assert!(q.srv.is_none());
            }
            other => panic!("expected compressed name, got {other:?}"),
        }
    }

    /// Цикл указателя снимает ярлык DNS.
    #[test]
    fn udp_dns_pointer_loop_is_other() {
        let mut body = dns_query("example.com");
        body[12] = 0xC0;
        body[13] = 12;
        let data = ipv4_udp(53, 53, &body);
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Other, .. } => {}
            other => panic!("expected plain UDP, got {other:?}"),
        }
    }

    /// mDNS 5353 важнее DNS 53, имя вопроса при этом читается.
    #[test]
    fn udp_mdns_beats_dns() {
        let data = ipv4_udp(53, 5353, &dns_query("printer.local"));
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Mdns, msg: Some(common::UdpMsg::Query(q)), .. } => {
                assert_eq!(q.name.unwrap().as_str(), "printer.local");
                assert!(q.srv.is_none());
            }
            other => panic!("expected mDNS name, got {other:?}"),
        }
    }

    fn append_dns_name(buf: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
    }

    /// Вопрос `_service._proto` даёт метки сервиса. PTR в таком пакете нет.
    #[test]
    fn udp_mdns_service_from_question() {
        let data = ipv4_udp(5353, 5353, &dns_query("_googlecast._tcp.local"));
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Mdns, msg: Some(common::UdpMsg::Query(q)), .. } => {
                assert_eq!(q.name.unwrap().as_str(), "_googlecast._tcp.local");
                assert_eq!(q.service.unwrap().as_str(), "_googlecast._tcp");
                assert!(q.ptr.is_none());
            }
            other => panic!("expected mDNS service from question, got {other:?}"),
        }
        assert!(format!("{}", data).contains("service=_googlecast._tcp"));
    }

    /// Ответ PTR: имя экземпляра и метки сервиса. Rdata сжата указателем на владельца.
    #[test]
    fn udp_mdns_ptr_compressed() {
        let mut body = vec![0u8; 12];
        body[7] = 1;
        let owner_at = body.len();
        append_dns_name(&mut body, "_ipp._tcp.local");
        body.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 0]);
        let mut rdata = b"\x06Office".to_vec();
        rdata.extend_from_slice(&[0xC0, owner_at as u8]);
        body.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        body.extend_from_slice(&rdata);

        let data = ipv4_udp(5353, 5353, &body);
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Mdns, msg: Some(common::UdpMsg::Query(q)), .. } => {
                assert!(q.name.is_none());
                assert_eq!(q.ptr.unwrap().as_str(), "Office._ipp._tcp.local");
                assert_eq!(q.service.unwrap().as_str(), "_ipp._tcp");
            }
            other => panic!("expected compressed mDNS PTR, got {other:?}"),
        }
        let shown = format!("{}", data);
        assert!(shown.contains("PTR=Office._ipp._tcp.local"));
        assert!(shown.contains("service=_ipp._tcp"));
    }

    /// Битая PTR пропускается. Вопрос остаётся, следующая целая PTR читается.
    #[test]
    fn udp_mdns_broken_ptr_skipped() {
        let mut body = vec![0u8; 12];
        body[5] = 1;
        body[7] = 2;
        append_dns_name(&mut body, "printer.local");
        body.extend_from_slice(&[0, 12, 0, 1]);
        body.extend_from_slice(&[0xC0, 12]);
        body.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 0, 0, 1, 0x04]);
        append_dns_name(&mut body, "_ipp._tcp.local");
        body.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 0]);
        let mut rdata = Vec::new();
        append_dns_name(&mut rdata, "Office._ipp._tcp.local");
        body.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        body.extend_from_slice(&rdata);

        let data = ipv4_udp(5353, 5353, &body);
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Query(q)), .. } => {
                assert_eq!(q.name.unwrap().as_str(), "printer.local");
                assert_eq!(q.ptr.unwrap().as_str(), "Office._ipp._tcp.local");
                assert_eq!(q.service.unwrap().as_str(), "_ipp._tcp");
            }
            other => panic!("expected question and the next PTR, got {other:?}"),
        }
    }

    /// DNS/53 с PTR не получает метки сервиса и имя PTR.
    #[test]
    fn udp_dns_ptr_stays_without_service() {
        let mut body = dns_query("_ipp._tcp.local");
        body[7] = 1;
        let owner_at = 12u8;
        body.extend_from_slice(&[0xC0, owner_at, 0, 12, 0, 1, 0, 0, 0, 0]);
        let mut rdata = b"\x06Office".to_vec();
        rdata.extend_from_slice(&[0xC0, owner_at]);
        body.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        body.extend_from_slice(&rdata);

        let data = ipv4_udp(53, 53, &body);
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Dns, msg: Some(common::UdpMsg::Query(q)), .. } => {
                assert_eq!(q.name.unwrap().as_str(), "_ipp._tcp.local");
                assert!(q.service.is_none());
                assert!(q.ptr.is_none());
            }
            other => panic!("expected DNS without mDNS fields, got {other:?}"),
        }
        let shown = format!("{}", data);
        assert!(shown.contains("q=_ipp._tcp.local"));
        assert!(!shown.contains("service="));
        assert!(!shown.contains("PTR="));
    }

    /// Ответ mDNS: порт и хост первой SRV. Приоритет и вес не сохраняются.
    #[test]
    fn udp_mdns_srv_port_and_host() {
        let mut body = vec![0u8; 12];
        body[5] = 1;
        body[7] = 1;
        append_dns_name(&mut body, "_ipp._tcp.local");
        body.extend_from_slice(&[0, 33, 0, 1]);
        append_dns_name(&mut body, "Office._ipp._tcp.local");
        body.extend_from_slice(&[0, 33, 0, 1, 0, 0, 0, 120]);
        let mut rdata = vec![0, 10, 0, 20, 0x02, 0x77];
        append_dns_name(&mut rdata, "printer.local");
        body.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        body.extend_from_slice(&rdata);

        let data = ipv4_udp(5353, 5353, &body);
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Query(q)), .. } => {
                assert_eq!(q.name.unwrap().as_str(), "_ipp._tcp.local");
                assert_eq!(q.service.unwrap().as_str(), "_ipp._tcp");
                assert!(q.ptr.is_none());
                let srv = q.srv.unwrap();
                assert_eq!(srv.port, 631);
                assert_eq!(srv.host.as_str(), "printer.local");
            }
            other => panic!("expected SRV port and host, got {other:?}"),
        }
        let shown = format!("{}", data);
        assert!(shown.contains("q=_ipp._tcp.local"));
        assert!(shown.contains("SRV port=631 host=printer.local"));
    }

    /// Объявление без вопросов: остаётся mDNS с портом и хостом SRV.
    #[test]
    fn udp_mdns_srv_without_question() {
        let mut body = vec![0u8; 12];
        body[7] = 1;
        append_dns_name(&mut body, "Office._ipp._tcp.local");
        body.extend_from_slice(&[0, 33, 0, 1, 0, 0, 0, 0]);
        let mut rdata = vec![0, 0, 0, 0, 0x00, 80];
        append_dns_name(&mut rdata, "office.local");
        body.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        body.extend_from_slice(&rdata);

        let data = ipv4_udp(5353, 5353, &body);
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Mdns, msg: Some(common::UdpMsg::Query(q)), .. } => {
                assert!(q.name.is_none());
                assert_eq!(q.service.unwrap().as_str(), "_ipp._tcp");
                let srv = q.srv.unwrap();
                assert_eq!(srv.port, 80);
                assert_eq!(srv.host.as_str(), "office.local");
            }
            other => panic!("expected SRV without question, got {other:?}"),
        }
    }

    /// Хост SRV сжатым указателем на имя вопроса.
    #[test]
    fn udp_mdns_srv_compressed_host() {
        let mut body = vec![0u8; 12];
        body[5] = 1;
        body[7] = 1;
        let name_at = body.len();
        append_dns_name(&mut body, "printer.local");
        body.extend_from_slice(&[0, 33, 0, 1]);
        body.extend_from_slice(&[0xC0, name_at as u8]);
        body.extend_from_slice(&[0, 33, 0, 1, 0, 0, 0, 0]);
        let rdata = [0, 0, 0, 0, 0x02, 0x77, 0xC0, name_at as u8];
        body.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        body.extend_from_slice(&rdata);

        let data = ipv4_udp(5353, 5353, &body);
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Query(q)), .. } => {
                let srv = q.srv.unwrap();
                assert_eq!(srv.port, 631);
                assert_eq!(srv.host.as_str(), "printer.local");
            }
            other => panic!("expected compressed SRV host, got {other:?}"),
        }
    }

    /// Запись A перед SRV пропускается. Из двух SRV берётся первая.
    #[test]
    fn udp_mdns_srv_skips_a_and_keeps_first() {
        let mut body = vec![0u8; 12];
        body[5] = 1;
        body[7] = 3;
        append_dns_name(&mut body, "printer.local");
        body.extend_from_slice(&[0, 33, 0, 1]);
        let owner = [0xC0u8, 12];
        body.extend_from_slice(&owner);
        body.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 10, 0, 0, 2]);
        body.extend_from_slice(&owner);
        body.extend_from_slice(&[0, 33, 0, 1, 0, 0, 0, 0]);
        let mut first = vec![0, 0, 0, 0, 0x02, 0x77];
        append_dns_name(&mut first, "a.local");
        body.extend_from_slice(&(first.len() as u16).to_be_bytes());
        body.extend_from_slice(&first);
        body.extend_from_slice(&owner);
        body.extend_from_slice(&[0, 33, 0, 1, 0, 0, 0, 0]);
        let mut second = vec![0, 0, 0, 0, 0x00, 1];
        append_dns_name(&mut second, "b.local");
        body.extend_from_slice(&(second.len() as u16).to_be_bytes());
        body.extend_from_slice(&second);

        let data = ipv4_udp(5353, 5353, &body);
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Query(q)), .. } => {
                let srv = q.srv.unwrap();
                assert_eq!(srv.port, 631);
                assert_eq!(srv.host.as_str(), "a.local");
            }
            other => panic!("expected first SRV after A, got {other:?}"),
        }
    }

    /// SRV без целевого имени не даёт порт. Имя вопроса сохраняется.
    #[test]
    fn udp_mdns_srv_without_host_keeps_question() {
        let mut body = vec![0u8; 12];
        body[5] = 1;
        body[7] = 1;
        append_dns_name(&mut body, "printer.local");
        body.extend_from_slice(&[0, 33, 0, 1]);
        body.extend_from_slice(&[0xC0, 12]);
        body.extend_from_slice(&[0, 33, 0, 1, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0x02, 0x77]);

        let data = ipv4_udp(5353, 5353, &body);
        match data.l4.clone() {
            common::IpL4::Udp { msg: Some(common::UdpMsg::Query(q)), .. } => {
                assert_eq!(q.name.unwrap().as_str(), "printer.local");
                assert!(q.srv.is_none());
            }
            other => panic!("expected question without SRV, got {other:?}"),
        }
    }

    /// Неизвестный порт остаётся Other, Display без суффикса приложения.
    #[test]
    fn udp_other_keeps_plain_udp() {
        let data = ipv4_udp_ports(3456, 80);
        match data.l4.clone() {
            common::IpL4::Udp { app: common::UdpApp::Other, .. } => {}
            other => panic!("expected plain UDP, got {other:?}"),
        }
        let s = format!("{}", data);
        assert!(!s.contains("UDP/"));
    }

    /// ICMPv6 Echo Request: id и seq из заголовка.
    #[test]
    fn ipv6_icmp_echo_request() {
        let echo = etherparse::Icmpv6Header::new(etherparse::Icmpv6Type::EchoRequest(
            etherparse::IcmpEchoHeader { id: 7, seq: 9 },
        ));
        let data = expect_ip(ipv6_l4(etherparse::IpNumber::IPV6_ICMP, &echo.to_bytes()));
        match data.l4.clone() {
            common::IpL4::Icmp6(common::Icmp6Data::EchoRequest { id, seq }) => {
                assert_eq!(id, 7);
                assert_eq!(seq, 9);
            }
            other => panic!("expected EchoRequest, got {other:?}"),
        }
    }

    /// Neighbor Solicitation: target из 16 байт после заголовка.
    #[test]
    fn ipv6_icmp_neighbor_solicitation() {
        let target = common::Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 2);
        let hdr = etherparse::Icmpv6Header::new(etherparse::Icmpv6Type::NeighborSolicitation);
        let mut icmp = Vec::from(hdr.to_bytes().as_slice());
        icmp.extend_from_slice(&target.octets());
        let data = expect_ip(ipv6_l4(etherparse::IpNumber::IPV6_ICMP, &icmp));
        match data.l4.clone() {
            common::IpL4::Icmp6(common::Icmp6Data::NeighborSolicitation { target: t, lladdr: None }) => assert_eq!(t, target),
            other => panic!("expected NS, got {other:?}"),
        }
    }

    fn ndp_option(opt_type: u8, mac: [u8; 6]) -> [u8; 8] {
        [opt_type, 1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]
    }

    /// NS: Source LLA (тип 1) после target — MAC спрашивающего.
    #[test]
    fn ipv6_icmp_ns_source_lladdr() {
        let target = common::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let hdr = etherparse::Icmpv6Header::new(etherparse::Icmpv6Type::NeighborSolicitation);
        let mut icmp = Vec::from(hdr.to_bytes().as_slice());
        icmp.extend_from_slice(&target.octets());
        icmp.extend_from_slice(&ndp_option(common::ICMP6_NDP_OPT_SRC_LLADDR, mac));
        let data = expect_ip(ipv6_l4(etherparse::IpNumber::IPV6_ICMP, &icmp));
        match data.l4.clone() {
            common::IpL4::Icmp6(common::Icmp6Data::NeighborSolicitation { target: t, lladdr: Some(m) }) => {
                assert_eq!(t, target);
                assert_eq!(m, common::MacAddr6::new(mac));
            }
            other => panic!("expected NS with lladdr, got {other:?}"),
        }
        assert!(format!("{}", data).contains("lladdr=02:11:22:33:44:55"));
    }

    /// NA: Target LLA (тип 2) — MAC объявляемого соседа. Source LLA на NA не читается.
    #[test]
    fn ipv6_icmp_na_target_lladdr() {
        let target = common::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let na = etherparse::icmpv6::NeighborAdvertisementHeader {
            router: false,
            solicited: true,
            r#override: true,
        };
        let hdr = etherparse::Icmpv6Header::new(etherparse::Icmpv6Type::NeighborAdvertisement(na));
        let mut icmp = Vec::from(hdr.to_bytes().as_slice());
        icmp.extend_from_slice(&target.octets());
        icmp.extend_from_slice(&ndp_option(common::ICMP6_NDP_OPT_SRC_LLADDR, [0x02, 0, 0, 0, 0, 1]));
        icmp.extend_from_slice(&ndp_option(common::ICMP6_NDP_OPT_TGT_LLADDR, mac));
        let data = expect_ip(ipv6_l4(etherparse::IpNumber::IPV6_ICMP, &icmp));
        match data.l4.clone() {
            common::IpL4::Icmp6(common::Icmp6Data::NeighborAdvertisement {
                router, solicited, override_flag, target: t, lladdr: Some(m),
            }) => {
                assert!(!router);
                assert!(solicited);
                assert!(override_flag);
                assert_eq!(t, target);
                assert_eq!(m, common::MacAddr6::new(mac));
            }
            other => panic!("expected NA with target lladdr, got {other:?}"),
        }
    }

    /// Неизвестная опция перед Source LLA пропускается, MAC берётся из следующей.
    #[test]
    fn ipv6_icmp_ns_skips_unknown_option() {
        let target = common::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 3);
        let mac = [0x02, 0x10, 0x20, 0x30, 0x40, 0x50];
        let hdr = etherparse::Icmpv6Header::new(etherparse::Icmpv6Type::NeighborSolicitation);
        let mut icmp = Vec::from(hdr.to_bytes().as_slice());
        icmp.extend_from_slice(&target.octets());
        icmp.extend_from_slice(&ndp_option(25, [0xff; 6]));
        icmp.extend_from_slice(&ndp_option(common::ICMP6_NDP_OPT_SRC_LLADDR, mac));
        let data = expect_ip(ipv6_l4(etherparse::IpNumber::IPV6_ICMP, &icmp));
        match data.l4.clone() {
            common::IpL4::Icmp6(common::Icmp6Data::NeighborSolicitation { lladdr: Some(m), .. }) => {
                assert_eq!(m, common::MacAddr6::new(mac));
            }
            other => panic!("expected NS lladdr after unknown option, got {other:?}"),
        }
    }

    /// Опция, заявленная длиннее хвоста, не даёт частичный MAC. Target сохраняется.
    #[test]
    fn ipv6_icmp_ns_truncated_option_has_no_lladdr() {
        let target = common::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 4);
        let hdr = etherparse::Icmpv6Header::new(etherparse::Icmpv6Type::NeighborSolicitation);
        let mut icmp = Vec::from(hdr.to_bytes().as_slice());
        icmp.extend_from_slice(&target.octets());
        icmp.extend_from_slice(&[common::ICMP6_NDP_OPT_SRC_LLADDR, 1, 0x02, 0x11]);
        let data = expect_ip(ipv6_l4(etherparse::IpNumber::IPV6_ICMP, &icmp));
        match data.l4.clone() {
            common::IpL4::Icmp6(common::Icmp6Data::NeighborSolicitation { target: t, lladdr: None }) => {
                assert_eq!(t, target);
            }
            other => panic!("expected NS without lladdr, got {other:?}"),
        }
    }

    /// Router Advertisement без options: hop limit, флаги M/O, lifetime.
    #[test]
    fn ipv6_icmp_router_advertisement() {
        let ra = etherparse::icmpv6::RouterAdvertisementHeader {
            cur_hop_limit: 64,
            managed_address_config: true,
            other_config: false,
            router_lifetime: 1800,
        };
        let hdr = etherparse::Icmpv6Header::new(etherparse::Icmpv6Type::RouterAdvertisement(ra));
        let data = expect_ip(ipv6_l4(etherparse::IpNumber::IPV6_ICMP, &hdr.to_bytes()));
        match data.l4.clone() {
            common::IpL4::Icmp6(common::Icmp6Data::RouterAdvertisement { hop_limit, managed, other_config, lifetime }) => {
                assert_eq!(hop_limit, 64);
                assert!(managed);
                assert!(!other_config);
                assert_eq!(lifetime, 1800);
            }
            other => panic!("expected RA, got {other:?}"),
        }
    }

    /// MLD Query: тип 130, группа в хвосте.
    #[test]
    fn ipv6_icmp_mld_query() {
        let group = common::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        let mut icmp = vec![130, 0, 0, 0, 0x03, 0xe8, 0, 0];
        icmp.extend_from_slice(&group.octets());
        let data = expect_ip(ipv6_l4(etherparse::IpNumber::IPV6_ICMP, &icmp));
        match data.l4.clone() {
            common::IpL4::Icmp6(common::Icmp6Data::MldQuery { max_resp_delay, group: g }) => {
                assert_eq!(max_resp_delay, 1000);
                assert_eq!(g, group);
            }
            other => panic!("expected MLD Query, got {other:?}"),
        }
    }

    /// Packet Too Big: MTU из заголовка.
    #[test]
    fn ipv6_icmp_packet_too_big() {
        let hdr = etherparse::Icmpv6Header::new(etherparse::Icmpv6Type::PacketTooBig { mtu: 1280 });
        let data = expect_ip(ipv6_l4(etherparse::IpNumber::IPV6_ICMP, &hdr.to_bytes()));
        assert_eq!(data.l4, common::IpL4::Icmp6(common::Icmp6Data::PacketTooBig { mtu: 1280 }));
    }

    /// Redirect etherparse отдаёт как Unknown: target и destination из хвоста.
    #[test]
    fn ipv6_icmp_redirect() {
        let target = common::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let destination = common::Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 5);
        let mut icmp = vec![common::ICMP6_TYPE_REDIRECT, 0, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&target.octets());
        icmp.extend_from_slice(&destination.octets());
        let data = expect_ip(ipv6_l4(etherparse::IpNumber::IPV6_ICMP, &icmp));
        match data.l4.clone() {
            common::IpL4::Icmp6(common::Icmp6Data::Redirect { target: t, destination: d }) => {
                assert_eq!(t, target);
                assert_eq!(d, destination);
            }
            other => panic!("expected Redirect, got {other:?}"),
        }
    }

    /// MLD Report: тип 131, группа в хвосте.
    #[test]
    fn ipv6_icmp_mld_report() {
        let group = common::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        let mut icmp = vec![common::ICMP6_TYPE_MLD_REPORT, 0, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&group.octets());
        let data = expect_ip(ipv6_l4(etherparse::IpNumber::IPV6_ICMP, &icmp));
        assert_eq!(data.l4, common::IpL4::Icmp6(common::Icmp6Data::MldReport { group }));
    }

    /// MLD Done: тип 132, группа в хвосте.
    #[test]
    fn ipv6_icmp_mld_done() {
        let group = common::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
        let mut icmp = vec![common::ICMP6_TYPE_MLD_DONE, 0, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&group.octets());
        let data = expect_ip(ipv6_l4(etherparse::IpNumber::IPV6_ICMP, &icmp));
        assert_eq!(data.l4, common::IpL4::Icmp6(common::Icmp6Data::MldDone { group }));
    }

    /// MLDv2 Report: тип 143, записи не разбираются.
    #[test]
    fn ipv6_icmp_mldv2_report_is_empty() {
        let mut icmp = vec![common::ICMP6_TYPE_MLDV2_REPORT, 0, 0, 0, 0, 0, 0, 1];
        icmp.extend_from_slice(&[1, 0, 0, 0, 0xff, 0x02]);
        let data = expect_ip(ipv6_l4(etherparse::IpNumber::IPV6_ICMP, &icmp));
        assert_eq!(data.l4, common::IpL4::Icmp6(common::Icmp6Data::MldV2Report));
    }

    /// Neighbor Solicitation без target — Icmp6_Broken с типом NS.
    #[test]
    fn ipv6_icmp_ns_truncated() {
        let hdr = etherparse::Icmpv6Header::new(etherparse::Icmpv6Type::NeighborSolicitation);
        match ipv6_l4(etherparse::IpNumber::IPV6_ICMP, &hdr.to_bytes()) {
            Err(common::ParseError::Icmp6_Broken { icmp6_type: common::Icmp6Type::NeighborSolicitation, .. }) => {}
            Err(e) => panic!("expected Icmp6_Broken NS, got {e:?}"),
            Ok(_) => panic!("expected Icmp6_Broken"),
        }
    }

    /// ESP (протокол 50): SPI из первых 4 байт, длина всего payload, хвост не читается.
    #[test]
    fn ipv4_esp_keeps_spi_and_length() {
        let ip = etherparse::Ipv4Header::new(
            16, 64, etherparse::IpNumber::ENCAPSULATING_SECURITY_PAYLOAD, [10, 0, 0, 1], [10, 0, 0, 2],
        ).unwrap();
        let mut esp = vec![0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x01];
        esp.extend_from_slice(&[0xAA; 8]);

        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&esp);

        let data = expect_ip(parse_ipv4(&packet));
        assert_eq!(data.len, 16);
        assert_eq!(data.l4, common::IpL4::Esp(common::EspData { spi: 0x0102_0304 }));
        let s = format!("{}", data);
        assert!(s.contains("SPI=0x01020304"));
        assert!(s.contains("ESP"));
    }

    /// ESP короче SPI+sequence — Esp_Broken, SPI не выдумывается.
    #[test]
    fn ipv4_esp_too_short() {
        let ip = etherparse::Ipv4Header::new(
            4, 64, etherparse::IpNumber::ENCAPSULATING_SECURITY_PAYLOAD, [10, 0, 0, 1], [10, 0, 0, 2],
        ).unwrap();
        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        match parse_ipv4(&packet) {
            Err(common::ParseError::Esp_Broken { len: 4, .. }) => {}
            Err(e) => panic!("expected Esp_Broken, got {e:?}"),
            Ok(_) => panic!("expected Esp_Broken"),
        }
    }

    /// UDP/4500 остаётся EspOverUdp, а не протоколом 50.
    #[test]
    fn udp_4500_is_esp_over_udp() {
        let data = ipv4_udp_ports(4500, 40000);
        assert!(matches!(data.l4, common::IpL4::Udp { app: common::UdpApp::EspOverUdp, msg: None, .. }));
    }

    fn ipv4_icmp(icmp: &[u8]) -> Result<common::NetPayload, common::ParseError> {
        let ip = etherparse::Ipv4Header::new(
            icmp.len() as u16, 64, etherparse::IpNumber::ICMP, [10, 0, 0, 1], [10, 0, 0, 2],
        ).unwrap();
        let mut packet = Vec::new();
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(icmp);
        parse_ipv4(&packet)
    }

    /// ICMPv4 Echo Request: id и seq из заголовка.
    #[test]
    fn ipv4_icmp_echo_request() {
        let hdr = etherparse::Icmpv4Header::new(etherparse::Icmpv4Type::EchoRequest(
            etherparse::IcmpEchoHeader { id: 7, seq: 9 },
        ));
        let data = expect_ip(ipv4_icmp(&hdr.to_bytes()));
        match data.l4.clone() {
            common::IpL4::Icmp4(common::Icmp4Data::EchoRequest { id, seq }) => {
                assert_eq!(id, 7);
                assert_eq!(seq, 9);
            }
            other => panic!("expected EchoRequest, got {other:?}"),
        }
        let s = format!("{}", data);
        assert!(s.contains("ICMPv4"));
        assert!(s.contains("Echo Request id=7 seq=9"));
    }

    /// Dest Unreach code 4 несёт next-hop MTU. Вложенный IP не читается.
    #[test]
    fn ipv4_icmp_dest_unreach_mtu() {
        let hdr = etherparse::Icmpv4Header::new(etherparse::Icmpv4Type::DestinationUnreachable(
            etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded { next_hop_mtu: 1500 },
        ));
        let mut icmp = Vec::from(hdr.to_bytes().as_slice());
        icmp.extend_from_slice(&[0x45, 0x00, 0x00, 0x14]);
        let data = expect_ip(ipv4_icmp(&icmp));
        match data.l4.clone() {
            common::IpL4::Icmp4(common::Icmp4Data::DestUnreach { code, mtu }) => {
                assert_eq!(code, 4);
                assert_eq!(mtu, Some(1500));
            }
            other => panic!("expected DestUnreach, got {other:?}"),
        }
    }

    /// Redirect: код и gateway IPv4.
    #[test]
    fn ipv4_icmp_redirect() {
        let hdr = etherparse::Icmpv4Header::new(etherparse::Icmpv4Type::Redirect(
            etherparse::icmpv4::RedirectHeader {
                code: etherparse::icmpv4::RedirectCode::RedirectForHost,
                gateway_internet_address: [192, 168, 1, 1],
            },
        ));
        let data = expect_ip(ipv4_icmp(&hdr.to_bytes()));
        match data.l4.clone() {
            common::IpL4::Icmp4(common::Icmp4Data::Redirect { code, gateway }) => {
                assert_eq!(code, 1);
                assert_eq!(gateway, common::Ipv4Addr::new(192, 168, 1, 1));
            }
            other => panic!("expected Redirect, got {other:?}"),
        }
    }

    /// Timestamp ровно 20 байт: id, seq и три метки.
    #[test]
    fn ipv4_icmp_timestamp() {
        let hdr = etherparse::Icmpv4Header::new(etherparse::Icmpv4Type::TimestampRequest(
            etherparse::icmpv4::TimestampMessage {
                id: 1,
                seq: 2,
                originate_timestamp: 10,
                receive_timestamp: 20,
                transmit_timestamp: 30,
            },
        ));
        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), 20);
        let data = expect_ip(ipv4_icmp(&bytes));
        match data.l4.clone() {
            common::IpL4::Icmp4(common::Icmp4Data::Timestamp { id, seq, originate, receive, transmit }) => {
                assert_eq!(id, 1);
                assert_eq!(seq, 2);
                assert_eq!(originate, 10);
                assert_eq!(receive, 20);
                assert_eq!(transmit, 30);
            }
            other => panic!("expected Timestamp, got {other:?}"),
        }
    }

    /// Router Advertisement: etherparse отдаёт Unknown, поля берутся из bytes5to8.
    #[test]
    fn ipv4_icmp_router_advertisement() {
        let hdr = etherparse::Icmpv4Header::new(etherparse::Icmpv4Type::Unknown {
            type_u8: common::ICMP4_TYPE_RA,
            code_u8: 0,
            bytes5to8: [2, 2, 0x00, 0xB4],
        });
        let data = expect_ip(ipv4_icmp(&hdr.to_bytes()));
        match data.l4.clone() {
            common::IpL4::Icmp4(common::Icmp4Data::RouterAdvertisement { num_addrs, addr_entry_size, lifetime }) => {
                assert_eq!(num_addrs, 2);
                assert_eq!(addr_entry_size, 2);
                assert_eq!(lifetime, 180);
            }
            other => panic!("expected RA, got {other:?}"),
        }
    }

    /// Time Exceeded: код TTL exceeded. Вложенный IP не читается.
    #[test]
    fn ipv4_icmp_time_exceeded() {
        let hdr = etherparse::Icmpv4Header::new(etherparse::Icmpv4Type::TimeExceeded(
            etherparse::icmpv4::TimeExceededCode::TtlExceededInTransit,
        ));
        let mut icmp = Vec::from(hdr.to_bytes().as_slice());
        icmp.extend_from_slice(&[0x45, 0x00, 0x00, 0x14]);
        let data = expect_ip(ipv4_icmp(&icmp));
        assert_eq!(data.l4, common::IpL4::Icmp4(common::Icmp4Data::TimeExceeded { code: 0 }));
    }

    /// Parameter Problem code 0: указатель на байт заголовка.
    #[test]
    fn ipv4_icmp_parameter_problem() {
        let hdr = etherparse::Icmpv4Header::new(etherparse::Icmpv4Type::ParameterProblem(
            etherparse::icmpv4::ParameterProblemHeader::PointerIndicatesError(42),
        ));
        let data = expect_ip(ipv4_icmp(&hdr.to_bytes()));
        assert_eq!(
            data.l4,
            common::IpL4::Icmp4(common::Icmp4Data::ParamProblem { code: 0, pointer: 42 }),
        );
    }

    /// Router Solicitation: etherparse отдаёт Unknown, тип 10.
    #[test]
    fn ipv4_icmp_router_solicitation() {
        let hdr = etherparse::Icmpv4Header::new(etherparse::Icmpv4Type::Unknown {
            type_u8: common::ICMP4_TYPE_RS,
            code_u8: 0,
            bytes5to8: [0, 0, 0, 0],
        });
        let data = expect_ip(ipv4_icmp(&hdr.to_bytes()));
        assert_eq!(data.l4, common::IpL4::Icmp4(common::Icmp4Data::RouterSolicitation));
    }

    /// Echo короче 8 байт — Icmp4_Broken с типом EchoRequest.
    #[test]
    fn ipv4_icmp_echo_truncated() {
        match ipv4_icmp(&[8, 0, 0, 0]) {
            Err(common::ParseError::Icmp4_Broken { icmp4_type: common::Icmp4Type::EchoRequest, len: 4, .. }) => {}
            Err(e) => panic!("expected Icmp4_Broken EchoRequest, got {e:?}"),
            Ok(_) => panic!("expected Icmp4_Broken"),
        }
    }

    /// Timestamp не из 20 байт etherparse не принимает: Icmp4_Broken с типом Timestamp.
    #[test]
    fn ipv4_icmp_timestamp_wrong_length() {
        match ipv4_icmp(&[13, 0, 0, 0, 0, 0, 0, 0]) {
            Err(common::ParseError::Icmp4_Broken { icmp4_type: common::Icmp4Type::Timestamp, .. }) => {}
            Err(e) => panic!("expected Icmp4_Broken Timestamp, got {e:?}"),
            Ok(_) => panic!("expected Icmp4_Broken"),
        }
    }

    /// Неизвестный тип остаётся Unknown, пакет не ошибка.
    #[test]
    fn ipv4_icmp_unknown_type() {
        let hdr = etherparse::Icmpv4Header::new(etherparse::Icmpv4Type::Unknown {
            type_u8: 99,
            code_u8: 1,
            bytes5to8: [0, 0, 0, 0],
        });
        let data = expect_ip(ipv4_icmp(&hdr.to_bytes()));
        assert_eq!(data.l4, common::IpL4::Icmp4(common::Icmp4Data::Unknown { type_u8: 99, code: 1 }));
    }

    fn eth_frame(dst: [u8; 6], src: [u8; 6], ether_type: u16, payload: &[u8]) -> common::CapData {
        let eth = etherparse::Ethernet2Header {
            destination: dst,
            source: src,
            ether_type: etherparse::EtherType(ether_type),
        };
        let mut data = Vec::from(eth.to_bytes());
        data.extend_from_slice(payload);
        common::CapData { cap_len: data.len(), orig_len: data.len(), data }
    }

    fn arp_bytes(op: u16, sender_mac: [u8; 6], sender_ip: [u8; 4], target_mac: [u8; 6], target_ip: [u8; 4]) -> Vec<u8> {
        let mut p = Vec::with_capacity(28);
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&0x0800u16.to_be_bytes());
        p.push(6);
        p.push(4);
        p.extend_from_slice(&op.to_be_bytes());
        p.extend_from_slice(&sender_mac);
        p.extend_from_slice(&sender_ip);
        p.extend_from_slice(&target_mac);
        p.extend_from_slice(&target_ip);
        p
    }

    /// Направление относительно MAC интерфейса: исходящий, входящий, broadcast, multicast, чужой unicast.
    #[test]
    fn ethernet_direction_from_own_mac() {
        let own = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let other = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let arp = arp_bytes(1, other, [10, 0, 0, 2], [0, 0, 0, 0, 0, 0], [10, 0, 0, 1]);
        let cases = [
            (other, own, common::EDirection::Outgoing),
            (own, other, common::EDirection::Incoming),
            ([0xff; 6], other, common::EDirection::Broadcast),
            ([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01], other, common::EDirection::Multicast),
            (other, [0x02, 0x00, 0x00, 0x00, 0x00, 0x03], common::EDirection::Unknown),
        ];
        for (dst, src, dir) in cases {
            let frame = eth_frame(dst, src, 0x0806, &arp);
            let net = parse_ethernet_packet(frame, common::MacAddr6::new(own)).expect("arp frame");
            assert!(net.eth.dir == dir);
            assert!(net.eth.prot == common::EthType::Arp);
        }
    }

    /// ARP Request: Ethernet+IPv4, MAC и адреса отправителя и цели.
    #[test]
    fn arp_request_eth_ipv4() {
        let sender_mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let target_mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let arp = arp_bytes(1, sender_mac, [10, 0, 0, 2], target_mac, [10, 0, 0, 1]);
        let frame = eth_frame([0xff; 6], sender_mac, 0x0806, &arp);
        let net = parse_ethernet_packet(frame, common::MacAddr6::new(sender_mac)).expect("arp");
        match net.payload {
            common::NetPayload::Arp(a) => {
                assert!(a.op == common::ArpOp::Request);
                assert_eq!(a.sender_mac, common::MacAddr6::new(sender_mac));
                assert_eq!(a.sender_ip, common::Ipv4Addr::new(10, 0, 0, 2));
                assert_eq!(a.target_mac, common::MacAddr6::new(target_mac));
                assert_eq!(a.target_ip, common::Ipv4Addr::new(10, 0, 0, 1));
            }
            _ => panic!("expected ARP"),
        }
    }

    /// Верхняя метка MPLS: label, TC, bottom of stack и TTL.
    #[test]
    fn mpls_top_label() {
        let word = (100u32 << 12) | (3 << 9) | (1 << 8) | 64;
        let frame = eth_frame(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            0x8847,
            &word.to_be_bytes(),
        );
        let net = parse_ethernet_packet(frame, common::MacAddr6::empty()).expect("mpls");
        assert!(net.eth.prot == common::EthType::Mpls);
        match net.payload {
            common::NetPayload::Mpls(m) => {
                assert_eq!(m.label, 100);
                assert_eq!(m.tc, 3);
                assert!(m.bos);
                assert_eq!(m.ttl, 64);
            }
            _ => panic!("expected MPLS"),
        }
    }

    /// IEEE 802.3 length + LLC/SNAP Cisco OUI 00:00:0C и protocol id CDP.
    #[test]
    fn llc_snap_cisco_cdp() {
        let mut cdp = cdp_header(2);
        cdp.extend(cdp_device_id(b"R1"));
        let mut snap = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00];
        snap.extend_from_slice(&cdp);
        let frame = eth_frame(
            [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            snap.len() as u16,
            &snap,
        );
        let net = parse_ethernet_packet(frame, common::MacAddr6::empty()).expect("cdp snap");
        match net.payload {
            common::NetPayload::Cisco(common::CiscoData::CDP(data)) => {
                assert_eq!(data.Header.ver, 2);
                let dev = data.tlvs.iter().find(|t| t.tlv_type == 0x0001).expect("device-id");
                assert_eq!(&dev.tlv_data[..2], b"R1");
            }
            _ => panic!("expected Cisco CDP"),
        }
    }
}
