---
name: net-parser
description: >-
  Разбор кадров в NetData: etherparse, структуры в common, IpL4, heapless и кадр IPC.
---

# Парсинг сетевых пакетов (NetData)

Новый протокол или поле — по этой схеме. Контракт обрезки payload, фрагментов, расширений IPv6 и ярлыков UDP — в `net_listener/AGENTS.md`. То, что там отложено, без отдельной просьбы не начинать.

## Где что лежит

* Структуры — `common/src/net_common.rs`. Конструкторы — `impls.rs`, печать — `display.rs`.
* Разбор байт — `net_listener/src/parser.rs`, библиотека `etherparse`. Ручной разбор только там, где etherparse тип не узнаёт (это перечислено в `AGENTS.md`).
* `NetPayload` — содержимое Ethernet (Ip, Arp, Mpls, Lldp, …). IGMP и ICMP — внутри `IpData.l4: IpL4`, не варианты `NetPayload`.
* Списки и строки — `heapless::Vec` / `heapless::String` с уже заданным потолком. `Box` и неограниченный `String` не добавлять.
* Типы, которые входят в `NetData`, несут `Serialize` и `Deserialize`: кадр уходит в другой процесс. `Copy` только у типов без `heapless`. `IpData` — `Clone`, не `Copy`.

## Кадр IPC

Тело кадра собирает `common/src/net_serde.rs` (bincode 2, заголовок 16 байт). Новое поле `NetData` должно уложиться в `SER_MAX_FRAME_LEN`. Если размер вырос — поправить константу и тест `cdp_full_is_max_frame`.

## Как добавить протокол

1. Поле или вариант в `net_common.rs`: содержимое Ethernet — в `NetPayload`, транспорт над IP — в `IpL4`. Ошибку длины — в `ParseError`.
2. Ветка в `parser.rs`. Срез для L4 готовят `parse_ipv4` / `parse_ipv6`; `parse_l4` только читает его.
3. Заголовок брать у etherparse (`Ipv4Header`, `TcpHeader` и остальные). На сыром кадре не вызывать `unwrap` и `expect`.
4. `Display` в `display.rs`, если значение печатается.
5. Тест в `parser.rs`: над `#[test]` строка `///`. Прогон: `cargo test --bin net_listener` из каталога `net_listener`.
