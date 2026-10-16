use anyhow::Result;
use pcap;

fn prefix_len(mask: std::net::IpAddr) -> u32 {
    let bits: u128 = match mask {
        std::net::IpAddr::V4(ip) => u32::from(ip) as u128,
        std::net::IpAddr::V6(ip) => u128::from(ip),
    };
    bits.count_ones()
}

/// Имя, флаги pcap, MAC и адреса — одной строкой для меню выбора.
fn format_device_line(dev: &pcap::Device, mac: Option<pnet_datalink::MacAddr>) -> String {
    let mut flags = heapless::Vec::<&str, 5>::new();
    if dev.flags.is_up() {
        let _ = flags.push("up");
    }
    if dev.flags.is_running() {
        let _ = flags.push("running");
    }
    if dev.flags.is_wireless() {
        let _ = flags.push("wireless");
    }
    if dev.flags.is_loopback() {
        let _ = flags.push("loopback");
    }
    match dev.flags.connection_status {
        pcap::ConnectionStatus::Connected    => { let _ = flags.push("connected"); }
        pcap::ConnectionStatus::Disconnected => { let _ = flags.push("disconnected"); }
        pcap::ConnectionStatus::Unknown | pcap::ConnectionStatus::NotApplicable => {}
    }

    let mut parts: Vec<String> = Vec::new();
    if let Some(desc) = dev.desc.as_deref().filter(|d| !d.is_empty() && *d != dev.name) {
        parts.push(desc.to_string());
    }
    if !flags.is_empty() {
        parts.push(format!("[{}]", flags.join(" ")));
    }
    if let Some(mac) = mac {
        parts.push(mac.to_string());
    }
    for addr in &dev.addresses {
        match addr.netmask {
            Some(mask) => parts.push(format!("{}/{}", addr.addr, prefix_len(mask))),
            None               => parts.push(addr.addr.to_string()),
        }
    }
    if parts.is_empty() {
        dev.name.clone()
    } else {
        format!("{}  {}", dev.name, parts.join("  "))
    }
}

/// Спрашивает интерфейс, пока не введён номер из списка. `0` и `q` — выход без запуска.
/// В отладочной сборке меню не показывается: берётся первый интерфейс из списка.
pub fn select_network_device() -> Result<Option<pcap::Device>> {
    let devices = pcap::Device::list().map_err(|e| anyhow::anyhow!(e))?;
    if devices.is_empty() {
        return Err(anyhow::anyhow!("No network interfaces found"));
    }

    if cfg!(debug_assertions) {
        let net_device = devices[0].clone();
        println!("Debug build, selected first interface: {}", net_device.name);
        return Ok(Some(net_device));
    }

    let mac_by_name: std::collections::HashMap<String, pnet_datalink::MacAddr> =
        pnet_datalink::interfaces()
            .into_iter()
            .filter_map(|iface| iface.mac.map(|mac| (iface.name, mac)))
            .collect();

    loop {
        println!("Available interfaces:");
        for (i, dev) in devices.iter().enumerate() {
            let mac = mac_by_name.get(&dev.name).copied();
            println!("{}: {}", i + 1, format_device_line(dev, mac));
        }
        println!("Enter interface number (0 or q to quit):");

        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            return Ok(None);
        }
        let choice = input.trim();
        if choice == "0" || choice.eq_ignore_ascii_case("q") {
            return Ok(None);
        }
        if let Ok(n) = choice.parse::<usize>() {
            if (1..=devices.len()).contains(&n) {
                let net_device = devices[n - 1].clone();
                println!("Selected interface: {}", net_device.name);
                return Ok(Some(net_device));
            }
        }
        println!("Enter a number from 1 to {}, or 0 / q to quit.", devices.len());
    }
}
