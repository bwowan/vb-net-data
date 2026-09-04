# net_listener — контекст проекта

## Назначение
Консольное приложение для захвата и анализа сетевых пакетов. Часть workspace `/mnt/DevData/Job/NetData`.

## Архитектура (pipeline)

```
capture_loop  →[cap2parse: CapData]→  parse_loop (x4)  →[parse2stats: NetData]→  console_statistic
   (pcap)                                (pnet)                                      (stdout 1/сек)
```

Каналы: `flume::bounded`, все задачи — `tokio::spawn`.

## Файлы

| Файл | Роль |
|------|------|
| `src/main.rs` | Точка входа: выбор интерфейса, создание каналов, запуск задач |
| `src/capture.rs` | `capture_loop` — захват пакетов через pcap, отправляет `CapData` |
| `src/parser.rs` | `parse_loop` — разбирает Ethernet/IP/L4, отправляет `NetData` |
| `src/statistic.rs` | `console_statistic` — агрегирует и выводит статистику раз в секунду |

## Общие типы (crate `common`)

```rust
CapData      { cap_len, orig_len, data: Vec<u8> }
NetData      { eth: EthData, ip: Result<IpData, ParseError> }
EthData      { src, dst: MacAddr6, dir: EDirection, prot: EthType }
IpData       { protocol: IpType, src, dst: IpAddr, len: usize }
TrafficStats { rx_packets, tx_packets, rx_bytes, tx_bytes: u64 }
              + total_packets(), total_bytes()
              + Display: "RX: N packets / N bytes; TX: ..."

EDirection   :: Incoming | Outgoing | Broadcast | Unknown
EthType      :: Ipv4 | Ipv6 | Arp | Rarp | Mpls | MplsMcast | Unsupported
IpType       :: Tcp | Udp | Icmp4 | Icmp6 | Unsupported
```

`common` реэкспортирует всё через `pub use net_common::*` — использовать как `common::TrafficStats`.

## Текущее состояние

- `console_statistic`: работает через `tokio::select!`, выводит per-second статистику, сбрасывает счётчики каждую секунду
- `EDirection` в парсере всегда `Unknown` — определение rx/tx не реализовано
- UDS-сокет (`/tmp/net_listener_stats.sock`) создаётся, но данные через него пока не отправляются (код закомментирован)

## Запуск

```bash
cargo build --bin net_listener
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/net_listener
./target/debug/net_listener
```

## Зависимости
`pcap`, `pnet` / `pnet_packet` / `pnet_datalink`, `flume`, `tokio`, `anyhow`
