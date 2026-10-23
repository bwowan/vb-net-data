//! Бинарный кадр `NetData` для передачи между процессами.
//!
//! Один кадр — одно значение `NetData`. Длина переменная: тело — bincode 2
//! (serde, целые фиксированной ширины, little-endian), поэтому в hex-дампе
//! порты и длины читаются как есть.
//!
//! ```text
//! offset  size  поле
//! 0       2     version     u16 LE   SER_VERSION
//! 2       2     subversion  u16 LE   SER_SUBVERSION
//! 4       4     body_len    u32 LE   длина тела в байтах
//! 8       8     checksum    u64 LE   CRC-64/XZ от тела
//! 16      N     body        bincode
//! ```
//!
//! `version` при разборе сверяется строго. `subversion` только возвращается
//! в [`FrameHeader`]: задел на добавление полей без разрыва совместимости.

use crate::net_common::{
    CISCO_CDP_MAX_ADDRESSES, CISCO_CDP_MAX_ADDRESS_LEN, CISCO_CDP_MAX_TLVS, LLDP_TLV_MAX_LEN, NetData,
};
use bincode::config::{Configuration, Fixint, LittleEndian, NoLimit};

/// Старшая версия формата. Несовпадение — кадр не разбирается.
pub const SER_VERSION: u16 = 1;
/// Младшая версия формата. Не проверяется, доступна через [`FrameHeader`].
pub const SER_SUBVERSION: u16 = 0;
/// Размер заголовка кадра в байтах.
pub const SER_HEADER_LEN: usize = 16;

/// Верхняя граница кадра целиком (заголовок + тело). `NetData` состоит только из
/// типов фиксированной ёмкости, поэтому максимум точный: его даёт CDP с полными
/// `addresses` и `tlvs`. Буфер такого размера под `encode` и `recv` никогда не растёт.
/// Тест `cdp_full_is_max_frame` следит, чтобы расширение `NetData` не пробило потолок.
pub const SER_MAX_FRAME_LEN: usize = SER_HEADER_LEN
    + 20                                                     // EthData: 6 + 6 + dir + prot
    + 4                                                      // NetPayload tag
    + 4                                                      // CiscoData tag
    + 4                                                      // CISCO_CDP_HEADER
    + 8 + CISCO_CDP_MAX_ADDRESSES * (6 + CISCO_CDP_MAX_ADDRESS_LEN) // addresses
    + 4                                                      // Capabilities
    + 8 + CISCO_CDP_MAX_TLVS * (4 + LLDP_TLV_MAX_LEN);      // tlvs

const OFF_VERSION: usize = 0;
const OFF_SUBVERSION: usize = 2;
const OFF_BODY_LEN: usize = 4;
const OFF_CHECKSUM: usize = 8;

/// Конфигурация bincode. Одна и та же на обеих сторонах, иначе байты не сойдутся.
const CONFIG: Configuration<LittleEndian, Fixint, NoLimit> = bincode::config::standard()
    .with_little_endian()
    .with_fixed_int_encoding()
    .with_no_limit();

/// Что пошло не так при разборе кадра.
#[derive(Debug, PartialEq, Eq)]
pub enum SerError {
    /// Буфер короче заголовка.
    TooShort { len: usize },
    /// `version` в заголовке не равна [`SER_VERSION`].
    Version { got: u16 },
    /// `body_len` не совпал с тем, сколько байт лежит после заголовка.
    Length { declared: u32, actual: usize },
    /// Контрольная сумма тела не сошлась.
    Checksum,
    /// Ошибка bincode при кодировании или разборе тела.
    Codec(String),
}

impl std::fmt::Display for SerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SerError::TooShort { len } => write!(f, "frame too short: {len} bytes, header is {SER_HEADER_LEN}"),
            SerError::Version { got } => write!(f, "unsupported frame version {got}, expected {SER_VERSION}"),
            SerError::Length { declared, actual } => write!(f, "body length mismatch: header says {declared}, buffer has {actual}"),
            SerError::Checksum => write!(f, "body checksum mismatch"),
            SerError::Codec(msg) => write!(f, "codec error: {msg}"),
        }
    }
}

impl std::error::Error for SerError {}

/// Заголовок кадра, прочитанный из буфера. Тело ещё не проверено.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u16,
    pub subversion: u16,
    pub body_len: u32,
    pub checksum: u64,
}

/// CRC-64/XZ: полином ECMA-182 в отражённом виде, init и xorout — все единицы.
/// Тот же вариант, что в `xz` и Go `crc64.ECMA`. Check("123456789") = 0x995DC9BBDF1939FA.
/// Не криптография: ловит обрезку и порчу байт, этого для локального канала достаточно.
pub fn body_checksum(body: &[u8]) -> u64 {
    body.iter().fold(!0u64, |crc, &b| {
        CRC64_TABLE[((crc ^ u64::from(b)) & 0xFF) as usize] ^ (crc >> 8)
    }) ^ !0u64
}

/// Отражённый полином ECMA-182 (0x42F0E1EBA9EA3693).
const CRC64_POLY_REFLECTED: u64 = 0xC96C_5795_D787_0F42;

/// Таблица на 256 записей, считается на этапе компиляции.
const CRC64_TABLE: [u64; 256] = {
    let mut table = [0u64; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u64;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ CRC64_POLY_REFLECTED } else { crc >> 1 };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Кодирует `data` в `buf` целиком: заголовок и тело. `buf` очищается,
/// ёмкость сохраняется — вызывающий переиспользует один `Vec` на все кадры.
pub fn encode(data: &NetData, buf: &mut Vec<u8>) -> Result<(), SerError> {
    buf.clear();
    buf.resize(SER_HEADER_LEN, 0);

    bincode::serde::encode_into_std_write(data, buf, CONFIG)
        .map_err(|e| SerError::Codec(e.to_string()))?;

    let body = &buf[SER_HEADER_LEN..];
    let body_len = u32::try_from(body.len())
        .map_err(|_| SerError::Codec(format!("body of {} bytes does not fit u32", body.len())))?;
    let checksum = body_checksum(body);

    buf[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&SER_VERSION.to_le_bytes());
    buf[OFF_SUBVERSION..OFF_SUBVERSION + 2].copy_from_slice(&SER_SUBVERSION.to_le_bytes());
    buf[OFF_BODY_LEN..OFF_BODY_LEN + 4].copy_from_slice(&body_len.to_le_bytes());
    buf[OFF_CHECKSUM..OFF_CHECKSUM + 8].copy_from_slice(&checksum.to_le_bytes());
    Ok(())
}

/// Читает заголовок без проверки тела. Ошибка только если буфер короче заголовка.
pub fn read_header(bytes: &[u8]) -> Result<FrameHeader, SerError> {
    if bytes.len() < SER_HEADER_LEN {
        return Err(SerError::TooShort { len: bytes.len() });
    }
    let u16_at = |off: usize| u16::from_le_bytes([bytes[off], bytes[off + 1]]);
    let u32_at = |off: usize| u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    let u64_at = |off: usize| u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
    Ok(FrameHeader {
        version: u16_at(OFF_VERSION),
        subversion: u16_at(OFF_SUBVERSION),
        body_len: u32_at(OFF_BODY_LEN),
        checksum: u64_at(OFF_CHECKSUM),
    })
}

/// Разбирает кадр: заголовок, версия, длина, контрольная сумма, затем тело.
/// `bytes` — ровно один кадр (например, одна датаграмма).
pub fn decode(bytes: &[u8]) -> Result<NetData, SerError> {
    let header = read_header(bytes)?;
    if header.version != SER_VERSION {
        return Err(SerError::Version { got: header.version });
    }
    let body = &bytes[SER_HEADER_LEN..];
    if header.body_len as usize != body.len() {
        return Err(SerError::Length { declared: header.body_len, actual: body.len() });
    }
    if body_checksum(body) != header.checksum {
        return Err(SerError::Checksum);
    }
    let (data, _consumed) = bincode::serde::decode_from_slice::<NetData, _>(body, CONFIG)
        .map_err(|e| SerError::Codec(e.to_string()))?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_common::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn hs<const N: usize>(s: &str) -> heapless::String<N> {
        heapless::String::try_from(s).expect("fits")
    }

    fn eth(prot: EthType) -> EthData {
        EthData {
            src: MacAddr6([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            dst: MacAddr6([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]),
            dir: EDirection::Incoming,
            prot,
        }
    }

    fn ip4(l4: IpL4, len: usize) -> NetPayload {
        NetPayload::Ip(IpData {
            src: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            len,
            l4,
        })
    }

    fn ip6(l4: IpL4, len: usize) -> NetPayload {
        NetPayload::Ip(IpData {
            src: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4)),
            dst: IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
            len,
            l4,
        })
    }

    /// `heapless::Vec::push` возвращает элемент в `Err`; типы без `Debug` так не `unwrap`-нуть.
    fn push<T, const N: usize>(v: &mut heapless::Vec<T, N>, item: T) {
        assert!(v.push(item).is_ok(), "heapless::Vec is full");
    }

    fn tlv(t: u16, value: &[u8]) -> TLV_DATA {
        let mut d = [0u8; LLDP_TLV_MAX_LEN];
        d[..value.len()].copy_from_slice(value);
        TLV_DATA { tlv_len: value.len() as u16, tlv_type: t, tlv_data: d }
    }

    /// Ошибка разбора. `NetData` не `Debug`/`PartialEq`, поэтому `Result` целиком не сравнивается.
    fn decode_err(bytes: &[u8]) -> SerError {
        match decode(bytes) {
            Ok(_) => panic!("decode unexpectedly succeeded"),
            Err(e) => e,
        }
    }

    /// Кодирует, разбирает, кодирует снова: у `NetData` нет `PartialEq`,
    /// поэтому сравниваются байты второго кадра с первым.
    fn roundtrip(data: &NetData) -> Vec<u8> {
        let mut first = Vec::new();
        encode(data, &mut first).expect("encode");
        let back = decode(&first).expect("decode");
        let mut second = Vec::new();
        encode(&back, &mut second).expect("encode again");
        assert_eq!(first, second, "second encode differs from first");
        first
    }

    fn tcp_frame() -> NetData {
        NetData {
            eth: eth(EthType::Ipv4),
            payload: ip4(IpL4::Tcp { src_port: 51234, dst_port: 443 }, 1460),
        }
    }

    /// TCP: заголовок, версия и длина тела в кадре совпадают с ожидаемыми.
    #[test]
    fn header_fields_match_body() {
        let bytes = roundtrip(&tcp_frame());
        let h = read_header(&bytes).unwrap();
        assert_eq!(h.version, SER_VERSION);
        assert_eq!(h.subversion, SER_SUBVERSION);
        assert_eq!(h.body_len as usize, bytes.len() - SER_HEADER_LEN);
        assert_eq!(h.checksum, body_checksum(&bytes[SER_HEADER_LEN..]));
    }

    /// Fixint LE: порты TCP видны в теле как есть, без varint-упаковки.
    #[test]
    fn tcp_ports_readable_in_dump() {
        let bytes = roundtrip(&tcp_frame());
        let body = &bytes[SER_HEADER_LEN..];
        let has = |needle: &[u8]| body.windows(needle.len()).any(|w| w == needle);
        assert!(has(&51234u16.to_le_bytes()), "src_port not found");
        assert!(has(&443u16.to_le_bytes()), "dst_port not found");
    }

    /// TCP-кадр компактный: укладывается в 80 байт вместе с заголовком.
    #[test]
    fn tcp_frame_is_small() {
        let bytes = roundtrip(&tcp_frame());
        assert!(bytes.len() <= 80, "tcp frame is {} bytes", bytes.len());
    }

    /// `encode` переиспользует буфер: старое содержимое стирается, ёмкость остаётся.
    #[test]
    fn encode_reuses_buffer() {
        let mut buf = vec![0xAAu8; 4096];
        let cap = buf.capacity();
        encode(&tcp_frame(), &mut buf).unwrap();
        assert!(buf.len() < 4096);
        assert_eq!(buf.capacity(), cap);
        assert!(decode(&buf).is_ok());
    }

    /// UDP mDNS с именем, SRV, service и PTR — все Option заполнены.
    #[test]
    fn roundtrip_udp_mdns_query() {
        let data = NetData {
            eth: eth(EthType::Ipv4),
            payload: ip4(
                IpL4::Udp {
                    src_port: 5353,
                    dst_port: 5353,
                    app: UdpApp::Mdns,
                    msg: Some(UdpMsg::Query(DnsQuery {
                        name: Some(hs("_airplay._tcp.local")),
                        srv: Some(SrvHost { port: 7000, host: hs("living-room.local") }),
                        service: Some(hs("_airplay._tcp")),
                        ptr: Some(hs("Living Room._airplay._tcp.local")),
                    })),
                },
                312,
            ),
        };
        roundtrip(&data);
    }

    /// UDP с ярлыком по порту и без тела: `msg == None`.
    #[test]
    fn roundtrip_udp_no_msg() {
        let data = NetData {
            eth: eth(EthType::Ipv4),
            payload: ip4(IpL4::Udp { src_port: 123, dst_port: 123, app: UdpApp::Ntp, msg: None }, 48),
        };
        roundtrip(&data);
    }

    /// DHCPv4 Request с hostname и запрошенным адресом.
    #[test]
    fn roundtrip_udp_dhcp4() {
        let data = NetData {
            eth: eth(EthType::Ipv4),
            payload: ip4(
                IpL4::Udp {
                    src_port: 68,
                    dst_port: 67,
                    app: UdpApp::Dhcp4,
                    msg: Some(UdpMsg::Dhcp4 {
                        msg: Some(Dhcp4Msg::Request),
                        host: Some(hs("laptop-01")),
                        requested: Some(Ipv4Addr::new(192, 168, 1, 77)),
                    }),
                },
                300,
            ),
        };
        roundtrip(&data);
    }

    /// SSDP NOTIFY с заголовками NT, USN, LOCATION.
    #[test]
    fn roundtrip_udp_ssdp() {
        let data = NetData {
            eth: eth(EthType::Ipv4),
            payload: ip4(
                IpL4::Udp {
                    src_port: 1900,
                    dst_port: 1900,
                    app: UdpApp::Ssdp,
                    msg: Some(UdpMsg::Ssdp(SsdpMsg {
                        start: hs("NOTIFY * HTTP/1.1"),
                        nt: Some(hs("upnp:rootdevice")),
                        usn: Some(hs("uuid:0a1b2c3d-4e5f::upnp:rootdevice")),
                        location: Some(hs("http://192.168.1.1:1900/desc.xml")),
                    })),
                },
                420,
            ),
        };
        roundtrip(&data);
    }

    /// NBNS-ответ с адресом первой NB-записи.
    #[test]
    fn roundtrip_udp_nbns() {
        let data = NetData {
            eth: eth(EthType::Ipv4),
            payload: ip4(
                IpL4::Udp {
                    src_port: 137,
                    dst_port: 137,
                    app: UdpApp::Nbns,
                    msg: Some(UdpMsg::Nbns(NbnsMsg {
                        response: true,
                        op: NbnsOp::Query,
                        name: hs("WORKGROUP"),
                        suffix: 0x1d,
                        kind: NbnsKind::Nb,
                        rcode: 0,
                        addr: Some(Ipv4Addr::new(192, 168, 1, 5)),
                    })),
                },
                62,
            ),
        };
        roundtrip(&data);
    }

    /// DHCPv6 Solicit.
    #[test]
    fn roundtrip_udp_dhcp6() {
        let data = NetData {
            eth: eth(EthType::Ipv6),
            payload: ip6(
                IpL4::Udp {
                    src_port: 546,
                    dst_port: 547,
                    app: UdpApp::Dhcp6,
                    msg: Some(UdpMsg::Dhcp6 { msg: Dhcp6Msg::Solicit }),
                },
                96,
            ),
        };
        roundtrip(&data);
    }

    /// ICMPv6 Neighbor Advertisement с флагами и Target LLA.
    #[test]
    fn roundtrip_icmp6_na() {
        let data = NetData {
            eth: eth(EthType::Ipv6),
            payload: ip6(
                IpL4::Icmp6(Icmp6Data::NeighborAdvertisement {
                    router: true,
                    solicited: true,
                    override_flag: false,
                    target: Ipv6Addr::new(0xfe80, 0, 0, 0, 0xdead, 0xbeef, 0, 1),
                    lladdr: Some(MacAddr6([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])),
                }),
                32,
            ),
        };
        roundtrip(&data);
    }

    /// ICMPv4 Dest Unreachable code 4 с MTU.
    #[test]
    fn roundtrip_icmp4_dest_unreach_mtu() {
        let data = NetData {
            eth: eth(EthType::Ipv4),
            payload: ip4(IpL4::Icmp4(Icmp4Data::DestUnreach { code: 4, mtu: Some(1400) }), 56),
        };
        roundtrip(&data);
    }

    /// IGMPv3 Report с двумя записями групп и источниками.
    #[test]
    fn roundtrip_igmp_v3_report() {
        let mut records = heapless::Vec::<IgmpV3GroupRecord, IGMP_V3_MAX_RECORDS>::new();
        records
            .push(IgmpV3GroupRecord {
                record_type: IgmpV3RecordType::ChangeToExclude,
                multicast: Ipv4Addr::new(239, 255, 255, 250),
                sources: heapless::Vec::new(),
            })
            .unwrap();
        records
            .push(IgmpV3GroupRecord {
                record_type: IgmpV3RecordType::AllowNewSources,
                multicast: Ipv4Addr::new(224, 0, 0, 251),
                sources: heapless::Vec::from_slice(&[Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]).unwrap(),
            })
            .unwrap();
        let data = NetData {
            eth: eth(EthType::Ipv4),
            payload: ip4(IpL4::Igmp(IgmpData::V3Report(IgmpV3Report { checksum: 0x1234, records })), 40),
        };
        roundtrip(&data);
    }

    /// ESP: только SPI.
    #[test]
    fn roundtrip_esp() {
        let data = NetData {
            eth: eth(EthType::Ipv4),
            payload: ip4(IpL4::Esp(EspData { spi: 0xdead_beef }), 1200),
        };
        roundtrip(&data);
    }

    /// Неизвестный L4: `IpL4::Other` с номером протокола.
    #[test]
    fn roundtrip_l4_other() {
        let data = NetData {
            eth: eth(EthType::Ipv4),
            payload: ip4(IpL4::Other(IpType::Unsupported), 100),
        };
        roundtrip(&data);
    }

    /// ARP Request.
    #[test]
    fn roundtrip_arp() {
        let data = NetData {
            eth: eth(EthType::Arp),
            payload: NetPayload::Arp(ArpData {
                op: ArpOp::Request,
                sender_mac: MacAddr6([1, 2, 3, 4, 5, 6]),
                sender_ip: Ipv4Addr::new(192, 168, 1, 10),
                target_mac: MacAddr6([0; 6]),
                target_ip: Ipv4Addr::new(192, 168, 1, 1),
            }),
        };
        roundtrip(&data);
    }

    /// MPLS, ECTP, DEC — простые Copy-варианты `NetPayload`.
    #[test]
    fn roundtrip_mpls_ectp_dec() {
        for payload in [
            NetPayload::Mpls(MplsData { label: 0xABCDE, tc: 5, bos: true, ttl: 64 }),
            NetPayload::Ectp(LoopbackData { skip_count: 0, function: 2, receipt_mac: MacAddr6([9; 6]) }),
            NetPayload::DEC(DECSnapHeader { dsap: 0xAA, ssap: 0xAA, control: 3, oui: [0x08, 0x00, 0x2B], protocol_id: 0x6002 }),
        ] {
            roundtrip(&NetData { eth: eth(EthType::Unsupported), payload });
        }
    }

    /// LLDP с management-адресами и TLV (включая `[u8; 64]` через BigArray).
    #[test]
    fn roundtrip_lldp() {
        let mut mgmt = heapless::Vec::<LLDP_MgmtAddr, LLDP_MAX_MGMT_ADDRS>::new();
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&[192, 168, 1, 1]);
        push(&mut mgmt, LLDP_MgmtAddr { family: 1, addr_len: 4, addr, if_subtype: 2, if_number: 7 });
        let mut tlvs = heapless::Vec::<TLV_DATA, LLDP_MAX_TLVS>::new();
        push(&mut tlvs, tlv(5, b"switch-01"));
        push(&mut tlvs, tlv(6, b"Core switch, rack 3"));
        let data = NetData {
            eth: eth(EthType::Lldp),
            payload: NetPayload::Lldp(LLDP_Data {
                TTL: 120,
                Sys_CAP_supported: 0x0014,
                Sys_CAP_enabled: 0x0004,
                mgmt_addrs: mgmt,
                tlvs,
            }),
        };
        roundtrip(&data);
    }

    /// CDP с полными `addresses` и `tlvs` — самый большой возможный кадр.
    fn cdp_full() -> NetData {
        let mut addresses = heapless::Vec::<CISCO_CDP_ADDRESS, CISCO_CDP_MAX_ADDRESSES>::new();
        let mut a = [0u8; CISCO_CDP_MAX_ADDRESS_LEN];
        a[..4].copy_from_slice(&[10, 0, 0, 1]);
        for _ in 0..CISCO_CDP_MAX_ADDRESSES {
            push(&mut addresses, CISCO_CDP_ADDRESS { prot_type: 1, prot_len: 1, prot: 0xCC, addr_len: 4, addr: a });
        }
        let mut tlvs = heapless::Vec::<TLV_DATA, CISCO_CDP_MAX_TLVS>::new();
        for i in 0..CISCO_CDP_MAX_TLVS {
            push(&mut tlvs, tlv(i as u16, &[0xEE; LLDP_TLV_MAX_LEN]));
        }
        NetData {
            eth: eth(EthType::Unsupported),
            payload: NetPayload::Cisco(CiscoData::CDP(CDP_CISCO_DATA {
                Header: CISCO_CDP_HEADER { ver: 2, ttl: 180, chksm: 0xBEEF },
                addresses,
                Capabilities: 0x28,
                tlvs,
            })),
        }
    }

    /// Худший CDP занимает ровно `SER_MAX_FRAME_LEN`: формула в константе сходится с bincode.
    #[test]
    fn cdp_full_is_max_frame() {
        let bytes = roundtrip(&cdp_full());
        assert_eq!(bytes.len(), SER_MAX_FRAME_LEN, "update SER_MAX_FRAME_LEN after changing NetData");
    }

    /// Остальные «толстые» варианты не превышают CDP: максимум действительно у него.
    #[test]
    fn other_fat_frames_below_max() {
        let mut mgmt = heapless::Vec::<LLDP_MgmtAddr, LLDP_MAX_MGMT_ADDRS>::new();
        for _ in 0..LLDP_MAX_MGMT_ADDRS {
            push(&mut mgmt, LLDP_MgmtAddr { family: 2, addr_len: 16, addr: [1; 16], if_subtype: 2, if_number: 7 });
        }
        let mut tlvs = heapless::Vec::<TLV_DATA, LLDP_MAX_TLVS>::new();
        for i in 0..LLDP_MAX_TLVS {
            push(&mut tlvs, tlv(i as u16, &[0xEE; LLDP_TLV_MAX_LEN]));
        }
        let lldp = NetData {
            eth: eth(EthType::Lldp),
            payload: NetPayload::Lldp(LLDP_Data { TTL: 120, Sys_CAP_supported: 0xFFFF, Sys_CAP_enabled: 0xFFFF, mgmt_addrs: mgmt, tlvs }),
        };

        let full: heapless::String<UDP_SSDP_MAX> = hs(&"x".repeat(UDP_SSDP_MAX));
        let ssdp = NetData {
            eth: eth(EthType::Ipv6),
            payload: ip6(
                IpL4::Udp {
                    src_port: 1900,
                    dst_port: 1900,
                    app: UdpApp::Ssdp,
                    msg: Some(UdpMsg::Ssdp(SsdpMsg { start: full.clone(), nt: Some(full.clone()), usn: Some(full.clone()), location: Some(full) })),
                },
                65535,
            ),
        };

        let mut records = heapless::Vec::<IgmpV3GroupRecord, IGMP_V3_MAX_RECORDS>::new();
        for _ in 0..IGMP_V3_MAX_RECORDS {
            let mut sources = heapless::Vec::<Ipv4Addr, IGMP_V3_MAX_SOURCES>::new();
            for _ in 0..IGMP_V3_MAX_SOURCES {
                push(&mut sources, Ipv4Addr::new(10, 0, 0, 1));
            }
            push(&mut records, IgmpV3GroupRecord { record_type: IgmpV3RecordType::ModeIsExclude, multicast: Ipv4Addr::new(239, 1, 1, 1), sources });
        }
        let igmp = NetData {
            eth: eth(EthType::Ipv4),
            payload: ip4(IpL4::Igmp(IgmpData::V3Report(IgmpV3Report { checksum: 0, records })), 65535),
        };

        for (name, data) in [("lldp", lldp), ("ssdp", ssdp), ("igmp", igmp)] {
            let len = roundtrip(&data).len();
            assert!(len < SER_MAX_FRAME_LEN, "{name} frame is {len} bytes, max is {SER_MAX_FRAME_LEN}");
        }
    }

    /// Буфер с ёмкостью `SER_MAX_FRAME_LEN` не перевыделяется даже на худшем кадре.
    #[test]
    fn max_capacity_buffer_never_grows() {
        let mut buf = Vec::with_capacity(SER_MAX_FRAME_LEN);
        let cap = buf.capacity();
        encode(&cdp_full(), &mut buf).unwrap();
        encode(&tcp_frame(), &mut buf).unwrap();
        assert_eq!(buf.capacity(), cap);
    }

    /// Пустые Cisco-варианты без данных.
    #[test]
    fn roundtrip_cisco_unit_variants() {
        for c in [CiscoData::CGMP, CiscoData::VTP, CiscoData::DTP, CiscoData::PAGP, CiscoData::PVSTP, CiscoData::UDLD] {
            roundtrip(&NetData { eth: eth(EthType::Unsupported), payload: NetPayload::Cisco(c) });
        }
    }

    /// `NetPayload::Err` с разными вариантами `ParseError`, включая вложенные типы.
    #[test]
    fn roundtrip_parse_errors() {
        let src = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let dst = IpAddr::V4(Ipv4Addr::BROADCAST);
        for err in [
            ParseError::Unknown_Error,
            ParseError::Unsupported_Eth { id: 0x88E5 },
            ParseError::LLC_SNAP_Header_Broken { id: 0x05DC, header: [1, 2, 3, 4, 5, 6, 7, 8] },
            ParseError::Unsupported_Eth_SNAP_OUI { oui: [0, 0, 0x0C], prot_id: 0x2003 },
            ParseError::Eth_Broken { len: 9 },
            ParseError::Tcp_Broken { len: 12, src, dst },
            ParseError::Icmp6_Broken { len: 5, src, dst, icmp6_type: Icmp6Type::NeighborSolicitation },
            ParseError::Icmp4_Broken { len: 5, src, dst, icmp4_type: Icmp4Type::Unknown(42) },
            ParseError::Igmp_Broken { len: 3, src, dst, igmp_type: IgmpType::Query },
            ParseError::Ip4_Fragment { src, dst },
            ParseError::Arp_Unsupported { hw_type: 6, proto_type: 0x86DD, hw_len: 8, proto_len: 16 },
            ParseError::Cisco_Broken { len: 10, sub_type: 0x2004 },
        ] {
            roundtrip(&NetData { eth: eth(EthType::Unsupported), payload: NetPayload::Err(err) });
        }
    }

    /// Порча одного байта тела → `Checksum`.
    #[test]
    fn corrupted_body_fails_checksum() {
        let mut bytes = roundtrip(&tcp_frame());
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert_eq!(decode_err(&bytes), SerError::Checksum);
    }

    /// Буфер короче заголовка → `TooShort` с фактической длиной.
    #[test]
    fn truncated_header_is_too_short() {
        let bytes = roundtrip(&tcp_frame());
        assert_eq!(decode_err(&bytes[..SER_HEADER_LEN - 1]), SerError::TooShort { len: SER_HEADER_LEN - 1 });
        assert_eq!(decode_err(&[]), SerError::TooShort { len: 0 });
    }

    /// Обрезанное или дополненное тело → `Length` с обеими длинами.
    #[test]
    fn truncated_or_padded_body_is_length_error() {
        let bytes = roundtrip(&tcp_frame());
        let declared = (bytes.len() - SER_HEADER_LEN) as u32;

        let short = &bytes[..bytes.len() - 3];
        assert_eq!(decode_err(short), SerError::Length { declared, actual: declared as usize - 3 });

        let mut long = bytes.clone();
        long.extend_from_slice(&[0, 0]);
        assert_eq!(decode_err(&long), SerError::Length { declared, actual: declared as usize + 2 });
    }

    /// Чужая `version` → `Version`; `subversion` на разбор не влияет.
    #[test]
    fn foreign_version_rejected_subversion_ignored() {
        let mut bytes = roundtrip(&tcp_frame());
        bytes[OFF_SUBVERSION..OFF_SUBVERSION + 2].copy_from_slice(&(SER_SUBVERSION + 7).to_le_bytes());
        assert!(decode(&bytes).is_ok(), "subversion must not be checked");
        assert_eq!(read_header(&bytes).unwrap().subversion, SER_SUBVERSION + 7);

        bytes[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&(SER_VERSION + 1).to_le_bytes());
        assert_eq!(decode_err(&bytes), SerError::Version { got: SER_VERSION + 1 });
    }

    /// Правильный заголовок, но тело не bincode `NetData` → `Codec`.
    #[test]
    fn garbage_body_with_valid_header_is_codec_error() {
        let body = [0xFFu8; 8];
        let mut bytes = vec![0u8; SER_HEADER_LEN];
        bytes[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&SER_VERSION.to_le_bytes());
        bytes[OFF_BODY_LEN..OFF_BODY_LEN + 4].copy_from_slice(&(body.len() as u32).to_le_bytes());
        bytes[OFF_CHECKSUM..OFF_CHECKSUM + 8].copy_from_slice(&body_checksum(&body).to_le_bytes());
        bytes.extend_from_slice(&body);
        assert!(matches!(decode_err(&bytes), SerError::Codec(_)));
    }

    /// CRC-64/XZ: стандартный check-вектор и пустой вход.
    #[test]
    fn crc64_xz_known_vectors() {
        assert_eq!(body_checksum(b""), 0);
        assert_eq!(body_checksum(b"123456789"), 0x995D_C9BB_DF19_39FA);
    }

    /// Перестановка двух байт меняет CRC (в отличие от простой суммы).
    #[test]
    fn crc64_detects_swapped_bytes() {
        assert_ne!(body_checksum(b"ab"), body_checksum(b"ba"));
    }
}
