#![allow(non_snake_case, non_camel_case_types)]

#[derive(Default, Clone)]
pub struct CapData {
    pub cap_len : usize,
    pub orig_len: usize,
    pub data    : Vec<u8>,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr6(pub [u8; 6]);

pub const CISCO_BROADCAST_ADDRESS6: MacAddr6 = MacAddr6([0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);
pub const BROADCAST_ADDRESS6      : MacAddr6 = MacAddr6([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
pub const LLDP_BROADCASTS         : [MacAddr6; 3] = [MacAddr6([0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E]), 
                                                     MacAddr6([0x01, 0x80, 0xC2, 0x00, 0x00, 0x03]),
                                                     MacAddr6([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00])];
//pub const STP_BPDU_ADDRESS6       : MacAddr6 = MacAddr6([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00]);
//pub const CDP_ADDRESS6            : MacAddr6 = MacAddr6([0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);
//pub const VTP_ADDRESS6            : MacAddr6 = MacAddr6([0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);
//pub const DTP_ADDRESS6            : MacAddr6 = MacAddr6([0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);
//pub const PAGP_ADDRESS6           : MacAddr6 = MacAddr6([0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);


#[derive(Default, Clone, Copy)]
pub struct MacAddr8(pub [u8; 8]);


pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};


#[derive(Default, Clone, Copy)]
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ArpOp {
    Unknown(u16),
    Request,   // 1
    Reply,     // 2
}

#[derive(Clone, Copy)]
pub struct ArpData {
    pub op         : ArpOp,
    pub sender_mac : MacAddr6,
    pub sender_ip  : Ipv4Addr,
    pub target_mac : MacAddr6,
    pub target_ip  : Ipv4Addr,
}

#[derive(Default, Clone, Copy)]
pub struct MplsData {
    pub label : u32,  // 20 bits
    pub tc    : u8,   // 3 bits (traffic class)
    pub bos   : bool, // bottom of stack
    pub ttl   : u8,
}

#[derive(Default, Clone, Copy)]
pub struct LoopbackData {
    pub skip_count: u16,
    pub function: u16,
    pub receipt_mac: MacAddr6, //who receive answer
    // LLDP fields can be added here if needed
}

#[derive(Default, Clone, Copy)]
pub struct LLC_HEADER {
    pub dsap   : u8,            // Destination Service Access Point (обычно 0xAA)
    pub ssap   : u8,            // Source Service Access Point (обычно 0xAA)
    pub control: u8,            // Control field (обычно 0x03 - Unnumbered Information)
}

#[derive(Default, Clone, Copy)]
pub struct DECSnapHeader {
    pub dsap: u8,               // Destination Service Access Point (обычно 0xAA)
    pub ssap: u8,               // Source Service Access Point (обычно 0xAA)
    pub control: u8,            // Control field (обычно 0x03 - Unnumbered Information)
    pub oui: [u8; 3],           // Organizationally Unique Identifier DEC(08:00:2B), Cisco(00:00:0C)
    pub protocol_id: u16,       // Вот здесь и будут наши 0x0060, 0x005A и т.д.
}

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
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CiscoNLPIDType {
    CDP,               // 0xCC - Cisco Discovery Protocol
    IP,                // 0x80 - IP Protocol
    SNAP,              // 0x81 - SubNetwork Access Protocol
    CLNP,              // 0x83 - ISO CLNP (Connectionless Network Protocol)
    ISO_TR4,           // 0x82 - ISO TR4
    Unknown(u8),
}

#[derive(Clone, Copy)]
pub struct CiscoNLPID_Data {
    pub nlpid_type      : CiscoNLPIDType, // Type of NLPID protocol
    pub cisco_ver       : u8,             // Cisco version/subtype
    pub reserved        : u8,             // Reserved byte
    pub payload_len     : u16,            // Payload length in bytes   
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
pub struct CISCO_CDP_HEADER {
    pub ver  : u8,   // Обычно 0x01 или 0x02
    pub ttl  : u8,   // Time to Live в секундах
    pub chksm: u16,  // Стандартный IP-checksum (RFC 1071)
}

//длина может быть любой, но мы упрощаем, берём только начальный байты
pub const LLDP_TLV_MAX_LEN: usize = 32;
#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
pub struct TLV_DATA {
    pub tlv_len : u16,
    pub tlv_type: u16,
    pub tlv_data: [u8; LLDP_TLV_MAX_LEN],
}

pub const CISCO_CDP_MAX_ADDRESS_LEN: usize = 16;
pub const CISCO_CDP_MAX_ADDRESSES: usize = 4;
#[derive(Default, Copy, Clone)]
pub struct CISCO_CDP_ADDRESS {
    pub prot_type: u8,
    pub prot_len : u8,
    pub prot     : u16, //reserved two bytes
    pub addr_len : u8,
    pub addr     : [u8; CISCO_CDP_MAX_ADDRESS_LEN], // Max IPv6 address length
}

#[derive(Default, Copy, Clone)]
pub struct CISCO_CDP_ADDRESSES {
    pub count    : u8,
    pub addresses: [CISCO_CDP_ADDRESS; CISCO_CDP_MAX_ADDRESSES], // Max 4 addresses
}

#[derive(Default, Copy, Clone)]
pub struct CDP_CISCO_DATA {
    pub Header         : CISCO_CDP_HEADER,
    pub DeviceId       : TLV_DATA,              // Type 0x0001
    pub Address        : CISCO_CDP_ADDRESSES,   // Type 0x0002
    pub PortId         : TLV_DATA,              // Type 0x0003
    pub Capabilities   : u32,                   // Type 0x0004
    pub SoftwareVersion: TLV_DATA,              // Type 0x0005
    pub Platform       : TLV_DATA,              // Type 0x0006
}
#[derive(Copy, Clone)]
pub enum CiscoData {
    CDP(CDP_CISCO_DATA), // 0x2000	CDP    (Discovery)	      Поиск соседей и обмен информацией о железе.
    CGMP,                // 0x2001	CGMP   (Group Mgmt)	      Управление Multicast-группами (устаревший).
    VTP,                 // 0x2003	VTP    (VLAN Trunking)	  Синхронизация базы VLAN между коммутаторами.
    DTP,                 // 0x2004	DTP    (Dynamic Trunking) Согласование режима работы порта (Trunk или Access).
    PAGP,                // 0x200E	PAGP   (Aggregation)	  Протокол объединения каналов (EtherChannel).
    PVSTP,               // 0x010B	PVSTP+ (Spanning Tree)	  Работа дерева STP отдельно для каждого VLAN.
    UDLD,                // 0x010C	UDLD   (Link Detection)	  Проверка того, что связь по кабелю идет в обе стороны.
}



#[derive(Default, Clone, Copy)]
pub struct LLDP_Data {
    pub Chassis_ID       : TLV_DATA, //1 Уникальный ID коммутатора (обычно MAC)
    pub Port_ID          : TLV_DATA, //2 Идентификатор порта (например, "GigabitEthernet0/1")
    pub TTL              : u16,      //3 Время жизни информации LLDP в секундах
    pub Port_DESC        : TLV_DATA, //4 Описание порта (например, "Ethernet port on Gi0/1")
    pub Sys_NAME         : TLV_DATA, //5 Имя системы (например, "MySwitch")
    pub Sys_DESC         : TLV_DATA, //6 Описание системы (например, "Cisco IOS Software...")
    pub Sys_CAP_supported: u16, //7 Поддерживаемые возможности системы (например, "Bridge, Router")
    pub Sys_CAP_enabled  : u16, //7 Поддерживаемые возможности системы (например, "Bridge, Router")
    pub Management_Addr  : TLV_DATA, //8 Адрес управления (например, IP-адрес устройства)
}

#[derive(Clone, Copy)]
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

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub enum IpType {
    #[default]
    Unsupported,
    Tcp,
    Udp,
    Icmp4,
    Icmp6,
}


#[derive(Clone, Copy)]
pub struct EthData {
    pub src : MacAddr6,
    pub dst : MacAddr6,
    pub dir : EDirection,
    pub prot: EthType,
}

#[derive(Clone, Copy)]
pub enum EDirection {
    Unknown,
    Incoming,
    Outgoing,
    Broadcast,
}

#[derive(Clone, Copy)]
pub struct IpData {
    pub protocol: IpType,
    pub src     : IpAddr,
    pub dst     : IpAddr,
    pub len     : usize,
    pub src_port: u16,
    pub dst_port: u16,
}


#[derive(Clone, Copy)]
pub struct NetData {
    pub eth    : EthData,
    pub payload: NetPayload,
}


/// Причина неудачного разбора L3/L4 пакета.
#[derive(Clone, Copy)]
pub enum ParseError {
    Unknown_Error,
    Unsupported_Eth          { id : u16   },                           // Неизвестный или неподдерживаемый EtherType.
    Unsupported_Eth_SNAP_OUI { oui:[u8;3], prot_id:u16 },
    Unsupported_L4           { id : u8    },                           // Протокол L4 не поддерживается (не TCP/UDP/ICMP).
    Eth_Broken               { len: usize },                           // Кадр слишком короткий для Ethernet (меньше 14 байт).                         
    Ip4_Broken               { len: usize },                           // IPv4-заголовок не помещается в payload (меньше 20 байт).
    Ip6_Broken               { len: usize },                           // IPv6-заголовок не помещается в payload (меньше 40 байт).
    Tcp_Broken               { len: usize, src: IpAddr, dst: IpAddr }, // Payload слишком короткий для TCP (меньше 20 байт) или заголовок невалиден.
    Udp_Broken               { len: usize, src: IpAddr, dst: IpAddr }, // Payload слишком короткий для UDP (меньше 8 байт) или заголовок невалиден.
    Icmp4_Broken             { len: usize, src: IpAddr, dst: IpAddr }, // Payload слишком короткий для ICMP (меньше 4 байт) или заголовок невалиден.
    Icmp6_Broken             { len: usize, src: IpAddr, dst: IpAddr }, // Payload слишком короткий для ICMPv6 или заголовок невалиден.
    Ip4_Fragment             {             src: IpAddr, dst: IpAddr }, // IPv4-фрагмент (не первый); полный L4-заголовок может быть в другом фрагменте.
    Arp_Broken               { len: usize },                           // ARP payload слишком короткий (нужно минимум 28 байт).
    Mpls_Broken              { len: usize },                           // MPLS payload слишком короткий (нужно минимум 4 байта).
    Lldp_Broken              { len: usize },                           // LLDP payload слишком короткий (нужно минимум 4 байта).
    Ectp                     { len: usize },                           // 0x9003 Ethernet Configuration Test Protocol (ECTP) \[IEEE 802.3\]
    DEC_Broken               { len: usize, sub_type:u16 },             // proprietary DEC protocol
    Cisco_Broken             { len: usize, sub_type:u16 },             // 0x000C Cisco OUI, but unknown protocol_id or packet length
}
