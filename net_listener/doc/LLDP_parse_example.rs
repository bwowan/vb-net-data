use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ====================== ОСНОВНЫЕ СТРУКТУРЫ ======================

#[derive(Debug, Clone)]
pub enum LldpTlv {
    ChassisId {
        subtype: u8,
        id: Vec<u8>,
        description: String,
    },
    PortId {
        subtype: u8,
        id: Vec<u8>,
        description: String,
    },
    TimeToLive(u16),
    PortDescription(String),
    SystemName(String),
    SystemDescription(String),
    SystemCapabilities {
        supported: u16,
        enabled: u16,
    },
    ManagementAddress {
        addr_family: u8,
        address: IpAddr,
        interface_number: u32,
    },
    OrgSpecific {
        oui: [u8; 3],
        subtype: u8,
        data: Vec<u8>,
    },
    EndOfLldpdu,
    Unknown {
        tlv_type: u8,
        value: Vec<u8>,
    },
}

impl fmt::Display for LldpTlv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LldpTlv::ChassisId { description, .. } => write!(f, "Chassis ID: {}", description),
            LldpTlv::PortId { description, .. } => write!(f, "Port ID: {}", description),
            LldpTlv::TimeToLive(ttl) => write!(f, "TTL: {} сек", ttl),
            LldpTlv::PortDescription(desc) => write!(f, "Port Description: {}", desc),
            LldpTlv::SystemName(name) => write!(f, "System Name: {}", name),
            LldpTlv::SystemDescription(desc) => write!(f, "System Description: {}", desc),
            LldpTlv::SystemCapabilities { supported, enabled } => {
                write!(f, "Capabilities: supported=0x{:04x}, enabled=0x{:04x}", supported, enabled)
            }
            LldpTlv::ManagementAddress { address, .. } => write!(f, "Management Address: {}", address),
            LldpTlv::OrgSpecific { oui, subtype, .. } => {
                write!(f, "Org Specific TLV (OUI {:02x}:{:02x}:{:02x}, subtype {})", oui[0], oui[1], oui[2], subtype)
            }
            LldpTlv::EndOfLldpdu => write!(f, "End of LLDPDU"),
            LldpTlv::Unknown { tlv_type, .. } => write!(f, "Unknown TLV (type {})", tlv_type),
        }
    }
}

// ====================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ======================

fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim_end_matches('\0').to_string()
}

fn bytes_to_mac(bytes: &[u8]) -> String {
    if bytes.len() == 6 {
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
    } else {
        format!("{:02x?}", bytes)
    }
}

// ====================== ОТДЕЛЬНЫЕ ФУНКЦИИ ПАРСИНГА КАЖДОГО TLV ======================

fn parse_chassis_id(value: &[u8]) -> Result<LldpTlv, String> {
    if value.is_empty() {
        return Err("Chassis ID: пустое значение".to_string());
    }
    let subtype = value[0];
    let id = value[1..].to_vec();

    let description = match subtype {
        4 => format!("MAC {}", bytes_to_mac(&id)), // самый частый
        1 => format!("Chassis ID: {}", bytes_to_string(&id)),
        _ => format!("subtype {}: {:02x?}", subtype, id),
    };

    Ok(LldpTlv::ChassisId { subtype, id, description })
}

fn parse_port_id(value: &[u8]) -> Result<LldpTlv, String> {
    if value.is_empty() {
        return Err("Port ID: пустое значение".to_string());
    }
    let subtype = value[0];
    let id = value[1..].to_vec();

    let description = match subtype {
        5 => bytes_to_string(&id), // Interface name (самый частый)
        3 => format!("MAC {}", bytes_to_mac(&id)),
        _ => format!("subtype {}: {:02x?}", subtype, id),
    };

    Ok(LldpTlv::PortId { subtype, id, description })
}

fn parse_ttl(value: &[u8]) -> Result<LldpTlv, String> {
    if value.len() != 2 {
        return Err("TTL: ожидалось 2 байта".to_string());
    }
    let ttl = u16::from_be_bytes([value[0], value[1]]);
    Ok(LldpTlv::TimeToLive(ttl))
}

fn parse_port_description(value: &[u8]) -> Result<LldpTlv, String> {
    Ok(LldpTlv::PortDescription(bytes_to_string(value)))
}

fn parse_system_name(value: &[u8]) -> Result<LldpTlv, String> {
    Ok(LldpTlv::SystemName(bytes_to_string(value)))
}

fn parse_system_description(value: &[u8]) -> Result<LldpTlv, String> {
    Ok(LldpTlv::SystemDescription(bytes_to_string(value)))
}

fn parse_system_capabilities(value: &[u8]) -> Result<LldpTlv, String> {
    if value.len() != 4 {
        return Err("System Capabilities: ожидалось 4 байта".to_string());
    }
    let supported = u16::from_be_bytes([value[0], value[1]]);
    let enabled = u16::from_be_bytes([value[2], value[3]]);
    Ok(LldpTlv::SystemCapabilities { supported, enabled })
}

fn parse_management_address(value: &[u8]) -> Result<LldpTlv, String> {
    if value.len() < 3 {
        return Err("Management Address: слишком короткий".to_string());
    }

    let addr_family = value[0];
    let addr_len = value[1] as usize;

    if value.len() < 2 + addr_len + 4 {
        return Err("Management Address: недостаточно байт".to_string());
    }

    let address_bytes = &value[2..2 + addr_len];
    let address = match addr_family {
        1 if addr_len == 4 => {
            // IPv4
            let ip = Ipv4Addr::new(address_bytes[0], address_bytes[1], address_bytes[2], address_bytes[3]);
            IpAddr::V4(ip)
        }
        2 if addr_len == 16 => {
            // IPv6
            let mut arr = [0u8; 16];
            arr.copy_from_slice(address_bytes);
            IpAddr::V6(Ipv6Addr::from(arr))
        }
        _ => return Err(format!("Неизвестный Address Family {}", addr_family)),
    };

    let interface_number = u32::from_be_bytes([
        value[2 + addr_len],
        value[2 + addr_len + 1],
        value[2 + addr_len + 2],
        value[2 + addr_len + 3],
    ]);

    Ok(LldpTlv::ManagementAddress {
        addr_family,
        address,
        interface_number,
    })
}

fn parse_org_specific(value: &[u8]) -> Result<LldpTlv, String> {
    if value.len() < 4 {
        return Err("Org Specific: слишком короткий".to_string());
    }
    let oui = [value[0], value[1], value[2]];
    let subtype = value[3];
    let data = value[4..].to_vec();

    Ok(LldpTlv::OrgSpecific { oui, subtype, data })
}

// ====================== ГЛАВНЫЙ ПАРСЕР ======================

pub fn parse_lldp(data: &[u8]) -> Result<Vec<LldpTlv>, String> {
    let mut pos = 0;
    let mut tlvs = Vec::new();

    while pos + 2 <= data.len() {
        let header = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let tlv_type = (header >> 9) as u8;        // 7 бит типа
        let tlv_length = (header & 0x01FF) as usize; // 9 бит длины

        pos += 2;

        if pos + tlv_length > data.len() {
            return Err(format!("TLV type {} обрезан (pos={}, len={})", tlv_type, pos, tlv_length));
        }

        let value = &data[pos..pos + tlv_length];
        pos += tlv_length;

        let tlv = match tlv_type {
            1 => parse_chassis_id(value)?,
            2 => parse_port_id(value)?,
            3 => parse_ttl(value)?,
            4 => parse_port_description(value)?,
            5 => parse_system_name(value)?,
            6 => parse_system_description(value)?,
            7 => parse_system_capabilities(value)?,
            8 => parse_management_address(value)?,
            127 => parse_org_specific(value)?,
            0 => LldpTlv::EndOfLldpdu,
            _ => LldpTlv::Unknown {
                tlv_type,
                value: value.to_vec(),
            },
        };

        tlvs.push(tlv);

        if tlv_type == 0 {
            break; // End of LLDPDU
        }
    }

    Ok(tlvs)
}

// ====================== ПРИМЕР ИСПОЛЬЗОВАНИЯ ======================

fn main() {
    // Твой дамп (можно копировать прямо из чата)
    let hex = "020704789a183f866504050565746833060200790a084d696b72746b41580c3f4d696b726f54696b20526f757465724f5320372e32302e322028737461626c652920323032352d31302d32312030373a32383a3230204c3431472d32617844100c0501c0a8570102000000040010181102fe80000000000000e68d8cfffe6601910200000004000e0400140014080b62724d61696e2f65746833fe070012bb01000104000032303a1d457501000000000000e48d8c660191f02f74ddcd5c0800";

    let data = hex_to_bytes(hex);

    println!("LLDP пакет: {} байт\n", data.len());

    match parse_lldp(&data) {
        Ok(tlvs) => {
            for (i, tlv) in tlvs.iter().enumerate() {
                println!("TLV {:02}: {}", i + 1, tlv);
            }
        }
        Err(e) => eprintln!("Ошибка парсинга: {}", e),
    }
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.replace([' ', '\n', '\r'], "");
    let mut bytes = Vec::with_capacity(hex.len() / 2);

    for chunk in hex.as_bytes().chunks(2) {
        if chunk.len() == 2 {
            let byte = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)
                .expect("Некорректный hex");
            bytes.push(byte);
        }
    }
    bytes
}
