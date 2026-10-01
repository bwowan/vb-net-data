#![allow(non_snake_case, non_camel_case_types)]

/// Кадр с сетевой карты: сколько байт захватили, сколько было на проводе, сами данные.
#[derive(Default, Clone)]
pub struct CapData {
    pub cap_len : usize,
    pub orig_len: usize,
    pub data    : Vec<u8>,
}

pub const MAC_ADDRESS_LEN6:usize = 6;
/// 48-битный MAC (Ethernet). Сравнивается с адресом своего интерфейса, чтобы выставить направление.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr6(pub [u8; MAC_ADDRESS_LEN6]);

//broadcats templates
pub const BROADCAST_ADDRESS6             : MacAddr6 = MacAddr6([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
pub const CISCO_BROADCAST_ADDRESS6       : MacAddr6 = MacAddr6([0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);

//LLDP (Link Layer Discovery Protocol, IEEE 802.1AB)
pub const LLDP_BROADCAST_ADDRESS6        : MacAddr6 = MacAddr6([0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E]);

//Адреса в диапазоне от 01:80:C2:00:00:00 до 01:80:C2:00:00:2F зарезервированы для протоколов управления мостами
//(MAC Bridges) и сетевых протоколов контроля (Spanning Tree, 802.3ad LACP и др.).
pub const BRIDGE_BROADCAST_START_ADDRESS6: MacAddr6 = MacAddr6([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00]);
pub const BRIDGE_BROADCAST_END_ADDRESS6  : MacAddr6 = MacAddr6([0x01, 0x80, 0xC2, 0x00, 0x00, 0x2F]);

//pub const STP_BPDU_ADDRESS6       : MacAddr6 = MacAddr6([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00]);
//pub const CDP_ADDRESS6            : MacAddr6 = MacAddr6([0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);
//pub const VTP_ADDRESS6            : MacAddr6 = MacAddr6([0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);
//pub const DTP_ADDRESS6            : MacAddr6 = MacAddr6([0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);
//pub const PAGP_ADDRESS6           : MacAddr6 = MacAddr6([0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);


/// 64-битный MAC (EUI-64), на случай кадров не Ethernet-II.
#[derive(Default, Clone, Copy)]
pub struct MacAddr8(pub [u8; 8]);


pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};


/// Счётчики пакетов и байт за интервал вывода в консоль (`console_statistic`).
#[derive(Default, Clone, Copy, Debug)]
pub struct TrafficStats {
    pub rx_packets: u64, // Количество входящих пакетов
    pub tx_packets: u64, // Количество исходящих пакетов
    pub rx_bytes  : u64, // Объем входящего трафика в байтах
    pub tx_bytes  : u64, // Объем исходящего трафика в байтах
}

/// Сообщения, передаваемые между приложениями.
#[derive(Clone, Copy)]
pub enum NetMessage {
    TrafficStats(TrafficStats),
}

/// EtherType кадра: IPv4/IPv6 и L2-протоколы, которые разбираются отдельно от IP.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EthType {
    Ipv4,
    Ipv6,
    Arp,
    Rarp,
    Mpls,
    MplsMcast,
    Lldp,             // Link Layer Discovery Protocol (LLDP) \[IEEE 802.3\].
    Ectp,             //0x9003 Ethernet Configuration Test Protocol (Loopback) \[IEEE 802.3\]
    Unsupported,
}

/// Код операции ARP/RARP (поля operation в пакете).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ArpOp {
    Unknown(u16),
    Request,     // 1  RFC 826
    Reply,       // 2
    RarpRequest, // 3  RFC 903
    RarpReply,   // 4
}

/// Разобранный ARP/RARP Ethernet+IPv4: кто спрашивает/отвечает и про какой IP.
#[derive(Clone, Copy)]
pub struct ArpData {
    pub op         : ArpOp,
    pub sender_mac : MacAddr6,
    pub sender_ip  : Ipv4Addr,
    pub target_mac : MacAddr6,
    pub target_ip  : Ipv4Addr,
}

/// Верхняя метка MPLS-стека (label, TC, BOS, TTL). Дальнейшие метки не разбираются.
#[derive(Default, Clone, Copy)]
pub struct MplsData {
    pub label : u32,  // 20 bits
    pub tc    : u8,   // 3 bits (traffic class)
    pub bos   : bool, // bottom of stack
    pub ttl   : u8,
}

/// ECTP (EtherType 0x9003): skip count, код функции и MAC, куда слать ответ.
#[derive(Default, Clone, Copy)]
pub struct LoopbackData {
    pub skip_count: u16,
    pub function: u16,
    pub receipt_mac: MacAddr6, //who receive answer
    // LLDP fields can be added here if needed
}

/// IEEE 802.2 LLC (3 байта) перед SNAP в кадрах с length ≤ 0x05DB.
#[derive(Default, Clone, Copy)]
pub struct LLC_HEADER {
    pub dsap   : u8,            // Destination Service Access Point (обычно 0xAA)
    pub ssap   : u8,            // Source Service Access Point (обычно 0xAA)
    pub control: u8,            // Control field (обычно 0x03 - Unnumbered Information)
}

/// SNAP с OUI DEC (08:00:2B): LLC + OUI + protocol_id фирменного протокола DEC.
#[derive(Default, Clone, Copy)]
pub struct DECSnapHeader {
    pub dsap: u8,               // Destination Service Access Point (обычно 0xAA)
    pub ssap: u8,               // Source Service Access Point (обычно 0xAA)
    pub control: u8,            // Control field (обычно 0x03 - Unnumbered Information)
    pub oui: [u8; 3],           // Organizationally Unique Identifier DEC(08:00:2B), Cisco(00:00:0C)
    pub protocol_id: u16,       // Вот здесь и будут наши 0x0060, 0x005A и т.д.
}

/// Однобайтовый NLPID (ISO/IEC 9577): какой сетевой протокол закодирован в SNAP/CDP.
#[derive(Default, Clone, Copy)]
pub struct NLPID_DATA {
    pub nlpid: u8, // Network Layer Protocol ID (NLPID) - 1 byte (e.g., 0x81 for SNAP, 0x80 for IP, 0xCC for CDP, 0x83 for CLNP, 0x82 for ISO-TR4)
}
/* 
Смещение (байт),Размер,Поле,Описание
0,1 байт,Protocol Type,"Тип кодирования (0x01 = NLPID, 0x02 = 802.2)"
1,1 байт,Protocol Length,Длина идентификатора протокола (обычно 1)
2,N байт,Protocol ID,Идентификатор (для IPv4 это 0xCC)
2+N,2 байта,Address Length,Длина самого адреса (для IPv4 это 0x0004)
4+N,M байт,Address Value,"Бинарные данные адреса (например, 192.168.1.1)"
*/
/// Известные значения NLPID в Cisco-кадрах (CDP, IP, SNAP, CLNP).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CiscoNLPIDType {
    CDP,               // 0xCC - Cisco Discovery Protocol
    IP,                // 0x80 - IP Protocol
    SNAP,              // 0x81 - SubNetwork Access Protocol
    CLNP,              // 0x83 - ISO CLNP (Connectionless Network Protocol)
    ISO_TR4,           // 0x82 - ISO TR4
    Unknown(u8),
}

/// NLPID плюс cisco-specific поля после идентификатора протокола.
#[derive(Clone, Copy)]
pub struct CiscoNLPID_Data {
    pub nlpid_type      : CiscoNLPIDType, // Type of NLPID protocol
    pub cisco_ver       : u8,             // Cisco version/subtype
    pub reserved        : u8,             // Reserved byte
    pub payload_len     : u16,            // Payload length in bytes   
}

/// Заголовок CDP: версия (1 или 2), TTL объявления и checksum как у IP.
#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
pub struct CISCO_CDP_HEADER {
    pub ver  : u8,   // Обычно 0x01 или 0x02
    pub ttl  : u8,   // Time to Live в секундах
    pub chksm: u16,  // Стандартный IP-checksum (RFC 1071)
}

//длина может быть любой, но мы упрощаем, берём только начальный байты
pub const LLDP_TLV_MAX_LEN: usize = 64;
/// Универсальный TLV CDP/LLDP: тип, заявленная длина и обрезка значения до `LLDP_TLV_MAX_LEN`.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TLV_DATA {
    pub tlv_len : u16,
    pub tlv_type: u16,
    pub tlv_data: [u8; LLDP_TLV_MAX_LEN],
}


pub const CISCO_CDP_MAX_ADDRESS_LEN: usize = 16;
pub const CISCO_CDP_MAX_ADDRESSES: usize = 4;
/// Один адрес из CDP TLV Addresses: NLPID/802.2, код протокола и до 16 байт адреса.
#[derive(Default, Copy, Clone)]
pub struct CISCO_CDP_ADDRESS {
    pub prot_type: u8,
    pub prot_len : u8,
    pub prot     : u16, //reserved two bytes
    pub addr_len : u16,
    pub addr     : [u8; CISCO_CDP_MAX_ADDRESS_LEN], // Max IPv6 address length
}

pub const CISCO_CDP_MAX_TLVS: usize = 32;
/// Разобранный CDP: заголовок, адреса, Capabilities и остальные TLV (Device-ID и т.д.).
#[derive(Default, Clone)]
pub struct CDP_CISCO_DATA {
    pub Header         : CISCO_CDP_HEADER,
    pub addresses      : heapless::Vec<CISCO_CDP_ADDRESS, CISCO_CDP_MAX_ADDRESSES>,   // Type 0x0002
    pub Capabilities   : u32,                   // Type 0x0004
    pub tlvs           : heapless::Vec<TLV_DATA, CISCO_CDP_MAX_TLVS>,
}
/// Полезная нагрузка Cisco SNAP (OUI 00:00:0C). Сейчас заполняется только CDP.
#[derive(Clone)]
pub enum CiscoData {
    CDP(CDP_CISCO_DATA), // 0x2000	CDP    (Discovery)	      Поиск соседей и обмен информацией о железе.
    CGMP,                // 0x2001	CGMP   (Group Mgmt)	      Управление Multicast-группами (устаревший).
    VTP,                 // 0x2003	VTP    (VLAN Trunking)	  Синхронизация базы VLAN между коммутаторами.
    DTP,                 // 0x2004	DTP    (Dynamic Trunking) Согласование режима работы порта (Trunk или Access).
    PAGP,                // 0x200E	PAGP   (Aggregation)	  Протокол объединения каналов (EtherChannel).
    PVSTP,               // 0x010B	PVSTP+ (Spanning Tree)	  Работа дерева STP отдельно для каждого VLAN.
    UDLD,                // 0x010C	UDLD   (Link Detection)	  Проверка того, что связь по кабелю идет в обе стороны.
}


pub const LLDP_MAX_TLVS: usize = 16;
pub const LLDP_MAX_MGMT_ADDRS: usize = 4;

/// Management Address (TLV type 8, IEEE 802.1AB).
/// Value: addr_str_len(1) + family(1) + addr[N] + if_subtype(1) + if_number(4) + oid_len(1) [+ oid]
#[derive(Default, Clone, Copy)]
pub struct LLDP_MgmtAddr {
    pub family    : u8,   // IANA Address Family: 1=IPv4, 2=IPv6
    pub addr_len  : u8,   // длина адреса (без family)
    pub addr      : [u8; 16],
    pub if_subtype: u8,   // 1=unknown, 2=ifIndex, 3=system port number
    pub if_number : u32,
}

/// Разобранный LLDPDU: TTL, capabilities, адреса управления и прочие TLV.
#[derive(Default, Clone)]
pub struct LLDP_Data {
    pub TTL              : u16, //3 Время жизни информации LLDP в секундах
    pub Sys_CAP_supported: u16, //7 Поддерживаемые возможности системы
    pub Sys_CAP_enabled  : u16, //7 Активные возможности системы
    pub mgmt_addrs       : heapless::Vec<LLDP_MgmtAddr, LLDP_MAX_MGMT_ADDRS>, //8
    pub tlvs             : heapless::Vec<TLV_DATA, LLDP_MAX_TLVS>,
}


/// Содержимое Ethernet после разбора EtherType / SNAP: IP, ARP, MPLS, LLDP, CDP или ошибка.
#[derive(Clone)]
pub enum NetPayload {
    Err (ParseError),
    Ip  (IpData),
    Arp (ArpData),
    Mpls(MplsData),
    Lldp(LLDP_Data),
    Ectp(LoopbackData),
    DEC (DECSnapHeader),
    Cisco(CiscoData)
}

//pub fn EthType_2_ordi

/// Транспорт над IP: то, что `parse_l4` умеет отличить от `Unsupported_L4`.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub enum IpType {
    #[default]
    Unsupported,
    Tcp,
    Udp,
    Icmp4,
    Icmp6,
    Igmp,
    Esp,
}

/// ESP (IP protocol 50, RFC 4303): открыты SPI и sequence, дальше ciphertext.
/// Sequence и ICV не сохраняются. Длина пакета — `IpData.len`.
/// IPsec за NAT — это UDP/4500 (`UdpApp::EspOverUdp`), не этот тип.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EspData {
    pub spi: u32,
}

/// SPI (4) + Sequence Number (4). Короче — заголовок обрезан, SPI не читается.
pub const ESP_MIN_LEN: usize = 8;

/// UDP-приложение по известным портам (любая сторона пакета).
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub enum UdpApp {
    Dhcp4,
    Dhcp6,
    Dns,
    Mdns,
    Ssdp,
    Llmnr,
    Ntp,
    Quic,
    Wireguard,
    EspOverUdp,
    #[default]
    Other,
}

/// Сколько символов имени DNS сохраняем. Хвост длиннее обрезается, пакет остаётся DNS.
pub const UDP_QNAME_MAX: usize = 64;

/// Тип сообщения DHCP (опция 53, RFC 2132).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dhcp4Msg {
    Discover, // 1
    Offer,    // 2
    Request,  // 3
    Decline,  // 4
    Ack,      // 5
    Nak,      // 6
    Release,  // 7
    Inform,   // 8
    Other(u8),
}

/// Что удалось прочитать из тела UDP. Ярлык `UdpApp` при этом уже подтверждён.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum UdpMsg {
    /// Первое имя вопроса DNS, mDNS или LLMNR.
    Query(heapless::String<UDP_QNAME_MAX>),
    /// DHCP: magic cookie совпал. `msg` — опция 53, если она есть в срезе.
    Dhcp4 { msg: Option<Dhcp4Msg> },
}

// ── ICMPv4 (RFC 792, PMTU RFC 1191, Router Discovery RFC 1256) ──────────────
pub const ICMP4_TYPE_ECHO_REPLY:     u8 = 0;
pub const ICMP4_TYPE_DST_UNREACH:    u8 = 3;
pub const ICMP4_TYPE_REDIRECT:       u8 = 5;
pub const ICMP4_TYPE_ECHO_REQUEST:   u8 = 8;
pub const ICMP4_TYPE_RA:             u8 = 9;
pub const ICMP4_TYPE_RS:             u8 = 10;
pub const ICMP4_TYPE_TIME_EXCEEDED:  u8 = 11;
pub const ICMP4_TYPE_PARAM_PROBLEM:  u8 = 12;
pub const ICMP4_TYPE_TIMESTAMP:      u8 = 13;
pub const ICMP4_TYPE_TIMESTAMP_REPLY: u8 = 14;

/// Классификация ICMPv4 по первому байту. Для ошибки тип известен и у обрезанного пакета.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Icmp4Type {
    Unknown(u8),
    EchoReply,            // 0
    DestUnreach,          // 3
    Redirect,             // 5
    EchoRequest,          // 8
    RouterAdvertisement,  // 9   RFC 1256
    RouterSolicitation,   // 10
    TimeExceeded,         // 11
    ParamProblem,         // 12
    Timestamp,            // 13
    TimestampReply,       // 14
}

/// Разобранное ICMPv4-сообщение. Вложенная исходная дейтаграмма и список адресов RA не читаются.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Icmp4Data {
    EchoRequest { id: u16, seq: u16 },
    EchoReply   { id: u16, seq: u16 },
    DestUnreach { code: u8, mtu: Option<u16> },
    TimeExceeded { code: u8 },
    ParamProblem { code: u8, pointer: u8 },
    Redirect { code: u8, gateway: Ipv4Addr },
    Timestamp { id: u16, seq: u16, originate: u32, receive: u32, transmit: u32 },
    TimestampReply { id: u16, seq: u16, originate: u32, receive: u32, transmit: u32 },
    RouterAdvertisement { num_addrs: u8, addr_entry_size: u8, lifetime: u16 },
    RouterSolicitation,
    Unknown { type_u8: u8, code: u8 },
}

// ── ICMPv6 (RFC 4443, NDP RFC 4861, MLD RFC 2710/3810) ──────────────────────
pub const ICMP6_TYPE_DST_UNREACH:    u8 = 1;
pub const ICMP6_TYPE_PACKET_TOO_BIG: u8 = 2;
pub const ICMP6_TYPE_TIME_EXCEEDED:  u8 = 3;
pub const ICMP6_TYPE_PARAM_PROBLEM:  u8 = 4;
pub const ICMP6_TYPE_ECHO_REQUEST:   u8 = 128;
pub const ICMP6_TYPE_ECHO_REPLY:     u8 = 129;
pub const ICMP6_TYPE_MLD_QUERY:      u8 = 130;
pub const ICMP6_TYPE_MLD_REPORT:     u8 = 131;
pub const ICMP6_TYPE_MLD_DONE:       u8 = 132;
pub const ICMP6_TYPE_RS:             u8 = 133;
pub const ICMP6_TYPE_RA:             u8 = 134;
pub const ICMP6_TYPE_NS:             u8 = 135;
pub const ICMP6_TYPE_NA:             u8 = 136;
pub const ICMP6_TYPE_REDIRECT:       u8 = 137;
pub const ICMP6_TYPE_MLDV2_REPORT:   u8 = 143;

pub const ICMP6_NDP_TARGET_LEN: usize = 16;
pub const ICMP6_MLD_MIN_LEN:    usize = 24; // type..reserved + 16-byte group
pub const ICMP6_REDIRECT_MIN:   usize = 8 + 16 + 16;

/// Классификация ICMPv6 по первому байту. Для ошибки тип известен и у обрезанного пакета.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Icmp6Type {
    Unknown(u8),               //   ?   Неизвестный тип ICMPv6, сохраняется как u8
    DestUnreach,               //   1   Destination Unreachable (ошибка)
    PacketTooBig,              //   2   Packet Too Big (ошибка)
    TimeExceeded,              //   3   Time Exceeded (ошибка)
    ParamProblem,              //   4   Parameter Problem (ошибка)
    EchoRequest,               // 128   Echo Request — эхо-запрос
    EchoReply,                 // 129   Echo Reply — эхо-ответ
    MldQuery,                  // 130   Multicast Listener Query (MLD-запрос)
    MldReport,                 // 131   Multicast Listener Report (MLD-отчёт)
    MldDone,                   // 132   Multicast Listener Done (MLD покинул группу)
    MldV2Report,               // 143   Multicast Listener v2 Report (расширенный отчёт)
    RouterSolicitation,        // 133   Router Solicitation (NDP: запрос к маршрутизатору)
    RouterAdvertisement,       // 134   Router Advertisement (NDP: объявление маршрутизатора)
    NeighborSolicitation,      // 135   Neighbor Solicitation (NDP: запрос к соседу)
    NeighborAdvertisement,     // 136   Neighbor Advertisement (NDP: объявление соседа)
    Redirect,                  // 137   Redirect (перенаправление)
}

/// Разобранное ICMPv6-сообщение. NDP options и MLDv2 records не разбираются.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Icmp6Data {
    EchoRequest { id: u16, seq: u16 },
    EchoReply   { id: u16, seq: u16 },
    DestUnreach { code: u8 },
    PacketTooBig { mtu: u32 },
    TimeExceeded { code: u8 },
    ParamProblem { code: u8 },
    RouterSolicitation,
    RouterAdvertisement { hop_limit: u8, managed: bool, other_config: bool, lifetime: u16 },
    NeighborSolicitation { target: Ipv6Addr },
    NeighborAdvertisement { router: bool, solicited: bool, override_flag: bool, target: Ipv6Addr },
    Redirect { target: Ipv6Addr, destination: Ipv6Addr },
    MldQuery { max_resp_delay: u16, group: Ipv6Addr },
    MldReport { group: Ipv6Addr },
    MldDone { group: Ipv6Addr },
    MldV2Report,
    Unknown { type_u8: u8, code: u8 },
}

// ── IGMP (RFC 1112 v1, RFC 2236 v2, RFC 3376 v3) ────────────────────────────
pub const IGMP_TYPE_QUERY:     u8 = 0x11; // Membership Query (v1/v2/v3)
pub const IGMP_TYPE_V1_REPORT: u8 = 0x12; // IGMPv1 Membership Report
pub const IGMP_TYPE_V2_REPORT: u8 = 0x16; // IGMPv2 Membership Report
pub const IGMP_TYPE_V2_LEAVE:  u8 = 0x17; // IGMPv2 Leave Group
pub const IGMP_TYPE_V3_REPORT: u8 = 0x22; // IGMPv3 Membership Report

pub const IGMP_V1V2_LEN:          usize =  8; /// Минимальная длина IGMPv1/v2 пакета (Type, ... , Group Address). RFC 1112, 2236.
pub const IGMP_V3_QUERY_MIN_LEN:  usize = 12; /// Минимальная длина IGMPv3 Membership Query (без адресов источника). RFC 3376.
pub const IGMP_V3_REPORT_MIN_LEN: usize =  8; /// Минимальная длина IGMPv3 Membership Report (без записей групп). RFC 3376.
pub const IGMP_V3_RECORD_MIN_LEN: usize =  8; /// Минимальная длина одной записи IGMPv3 группы в Report. RFC 3376.
pub const IGMP_V3_MAX_SOURCES:    usize = 16; /// Максимальное количество адресов источников в одном IGMPv3 Query/Group Record.
pub const IGMP_V3_MAX_RECORDS:    usize =  8; /// Максимальное количество записей групп в одном IGMPv3 Report.

/// Классификация сообщения по первому байту и длине.
/// Для ошибки: тип известен даже если пакет обрезан.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IgmpType {
    Unknown(u8),  // неизвестный тип IGMP (u8 = тип)
    Query,        // 0x11, Membership Query, версия ещё не определена (короче 8 байт)
    V1Query,      // 0x11, IGMPv1 Membership Query
    V1Report,     // 0x12, IGMPv1 Membership Report
    V2Query,      // 0x11, IGMPv2 Membership Query (есть Max Resp Time)
    V2Report,     // 0x16, IGMPv2 Membership Report
    V2Leave,      // 0x17, IGMPv2 Leave Group
    V3Query,      // 0x11, IGMPv3 Membership Query (минимум 12 байт, с источниками)
    V3Report,     // 0x22, IGMPv3 Membership Report
}

/// IGMPv1: Type, Unused, Checksum, Group Address (8 байт). RFC 1112.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IgmpV1 {
    pub checksum: u16,
    pub group   : Ipv4Addr,
}

/// IGMPv2: Type, Max Resp Time, Checksum, Group Address (8 байт). RFC 2236.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IgmpV2 {
    pub max_resp_time: u8,  // в десятых долях секунды
    pub checksum     : u16,
    pub group        : Ipv4Addr,
}

/// IGMPv3 Membership Query. Минимум 12 байт + 4×N адресов источников. RFC 3376.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IgmpV3Query {
    pub max_resp_code             : u8,
    pub checksum                  : u16,
    pub group                     : Ipv4Addr,
    pub suppress_router_processing: bool, // S
    pub qrv                       : u8,   // Querier's Robustness Variable, 3 бита
    pub qqic                      : u8,   // Querier's Query Interval Code
    pub sources                   : heapless::Vec<Ipv4Addr, IGMP_V3_MAX_SOURCES>,
}

/// Тип записи в IGMPv3 Membership Report (RFC 3376 §4.2.12).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IgmpV3RecordType {
    ModeIsInclude,     // 1, MODE_IS_INCLUDE
    ModeIsExclude,     // 2, MODE_IS_EXCLUDE
    ChangeToInclude,   // 3, CHANGE_TO_INCLUDE
    ChangeToExclude,   // 4, CHANGE_TO_EXCLUDE
    AllowNewSources,   // 5, ALLOW_NEW_SOURCES
    BlockOldSources,   // 6, BLOCK_OLD_SOURCES
    Unknown(u8),       // неизвестный тип записи (u8 = код)
}

/// Одна группа в IGMPv3 Report: INCLUDE/EXCLUDE, multicast-адрес и список источников.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IgmpV3GroupRecord {
    pub record_type: IgmpV3RecordType,
    pub multicast  : Ipv4Addr,
    pub sources    : heapless::Vec<Ipv4Addr, IGMP_V3_MAX_SOURCES>,
}

/// IGMPv3 Membership Report. Минимум 8 байт + записи групп. RFC 3376.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IgmpV3Report {
    pub checksum: u16,
    pub records : heapless::Vec<IgmpV3GroupRecord, IGMP_V3_MAX_RECORDS>,
}

/// Разобранное IGMP-сообщение всех поддерживаемых версий.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum IgmpData {
    V1Query (IgmpV1),
    V1Report(IgmpV1),
    V2Query (IgmpV2),
    V2Report(IgmpV2),
    V2Leave (IgmpV2),
    V3Query (IgmpV3Query),
    V3Report(IgmpV3Report),
}


/// Ethernet-заголовок после разбора: MAC, направление относительно своего интерфейса, EtherType.
#[derive(Clone, Copy)]
pub struct EthData {
    pub src : MacAddr6,    // MAC-адрес источника 
    pub dst : MacAddr6,    // MAC-адрес назначения
    pub dir : EDirection,  // Направление (входящий/исходящий/широковещательный/неизвестный)
    pub prot: EthType,     // EtherType (например, IPv4, IPv6, ARP и др.)
}

/// Откуда кадр относительно MAC своего интерфейса (и multicast/broadcast по младшему биту dst).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EDirection {
    Unknown,
    Incoming,
    Outgoing,
    Broadcast,
    Multicast,
}

/// Транспорт одного IP-пакета. Порты есть только у TCP и UDP.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum IpL4 {
    Tcp   { src_port: u16, dst_port: u16 },
    Udp   { src_port: u16, dst_port: u16, app: UdpApp, msg: Option<UdpMsg> },
    Igmp  (IgmpData),
    Icmp4 (Icmp4Data),
    Icmp6 (Icmp6Data),
    Esp   (EspData),
    Other (IpType),
}

/// IPv4/IPv6: адреса, длина дейтаграммы и один вариант L4.
#[derive(Clone)]
pub struct IpData {
    pub src: IpAddr, // IP-адрес отправителя
    pub dst: IpAddr, // IP-адрес получателя
    pub len: usize,  // Длина payload (байт), без Ethernet-padding
    pub l4 : IpL4,   // TCP/UDP с портами, либо разобранные IGMP, ICMP, ESP
}


/// Результат разбора одного кадра: Ethernet + payload. Уходит в статистику и на печать.
#[derive(Clone)]
pub struct NetData {
    pub eth    : EthData,     // Ethernet-заголовок: src/dst MAC, направление, EtherType
    pub payload: NetPayload,  // L3 payload: разобранный IP/ARP/MPLS/LLDP, либо raw данные
}


/// Причина неудачного разбора L3/L4 пакета.
#[derive(Clone, Copy)]
pub enum ParseError {
    Unknown_Error,
    Unsupported_Eth          { id : u16   },                           // Неизвестный или неподдерживаемый EtherType.
    LLC_SNAP_TooShort_Broken { id : u16, len: usize },                 // должен быть длинее 8 байт
    LLC_SNAP_Header_Broken   { id : u16, header:[u8;8] },              // нераспознанный заголовок ()
    Unsupported_Eth_SNAP_OUI { oui:[u8;3], prot_id:u16 },
    Unsupported_L4           { id : u8    },                           // Протокол L4 не поддерживается (не TCP/UDP/ICMP/IGMP).
    Eth_Broken               { len: usize },                           // Кадр слишком короткий для Ethernet (меньше 14 байт).                         
    Ip4_Broken               { len: usize },                           // IPv4-заголовок не помещается в payload (меньше 20 байт).
    Ip6_Broken               { len: usize },                           // IPv6-заголовок или extension header не помещается в payload.
    Tcp_Broken               { len: usize, src: IpAddr, dst: IpAddr }, // Payload слишком короткий для TCP (меньше 20 байт) или заголовок невалиден.
    Udp_Broken               { len: usize, src: IpAddr, dst: IpAddr }, // Payload слишком короткий для UDP (меньше 8 байт) или заголовок невалиден.
    Icmp4_Broken             { len: usize, src: IpAddr, dst: IpAddr, icmp4_type: Icmp4Type }, // Обрезанный или неполный ICMPv4; icmp4_type — тип по первому байту.
    Icmp6_Broken             { len: usize, src: IpAddr, dst: IpAddr, icmp6_type: Icmp6Type }, // Обрезанный или неполный ICMPv6.
    Igmp_Broken              { len: usize, src: IpAddr, dst: IpAddr, igmp_type: IgmpType }, // Обрезанный или неполный IGMP; igmp_type — тип сообщения, если его удалось прочитать.
    Esp_Broken               { len: usize, src: IpAddr, dst: IpAddr }, // ESP короче 8 байт: SPI и sequence не помещаются.
    Ip4_Fragment             {             src: IpAddr, dst: IpAddr }, // IPv4-фрагмент (не первый); полный L4-заголовок может быть в другом фрагменте.
    Ip6_Fragment             {             src: IpAddr, dst: IpAddr }, // IPv6-фрагмент (не первый); полный L4-заголовок может быть в другом фрагменте.
    Arp_Broken               { len: usize },                           // ARP payload слишком короткий (нужно минимум 28 байт).
    Arp_Unsupported          { hw_type: u16, proto_type: u16, hw_len: u8, proto_len: u8 }, // не Ethernet+IPv4 ARP/RARP
    Mpls_Broken              { len: usize },                           // MPLS payload слишком короткий (нужно минимум 4 байта).
    Lldp_Broken              { len: usize },                           // LLDP payload слишком короткий (нужно минимум 4 байта).
    Ectp                     { len: usize },                           // 0x9003 Ethernet Configuration Test Protocol (ECTP) \[IEEE 802.3\]
    DEC_Broken               { len: usize, sub_type:u16 },             // proprietary DEC protocol
    Cisco_Broken             { len: usize, sub_type:u16 },             // 0x000C Cisco OUI, but unknown protocol_id or packet length
}
