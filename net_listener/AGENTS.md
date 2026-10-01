# net_listener — продолжение сессии

Репозиторий: `/mnt/DevData/Rust/NetData` (workspace — этот каталог). Типы — в `../common`.

Последний коммит `3fcf223` (`improve protocol parsing. add tests.`) уже на `origin/main`. После него **не закоммичены**: обрезка IP-payload, IPv6 extensions, фрагменты, IGMP, классификация UDP, ICMPv6, ESP (SPI), типы ICMPv4, комментарии к типам, hex-дамп ошибочного Ethernet-кадра. Не коммитить `*.heapsnapshot`.


## Контракт разбора

`parse_ipv4` / `parse_ipv6` готовят срез, `parse_l4` только читает L4.

- Длина payload — из `total_len` / `payload_length`. Если захват короче заявленного, берётся весь хвост. `payload_length == 0` у IPv6 не обрезается (jumbogram).
- `Ipv6Extensions::from_slice` пропускает Hop-by-Hop, Routing, Destination Options, Fragment, AH. В `parse_l4` уходит протокол после них.
- `fragment_offset != 0` → `Ip4_Fragment` / `Ip6_Fragment`, L4 не разбирается. Первый фрагмент (offset 0, MF=1) разбирается. `is_fragmenting_payload()` не использовать.
- `IpData.len` — длина этого среза (без Ethernet-padding). Статистика суммирует именно его.

Хелперы: `clamp_declared_payload`, `ipv4_payload_slice`, `ipv6_payload_slice`, `ipv6_l4_slice`.

## Что лежит в IpData

`NetPayload` — содержимое Ethernet (Ip, Arp, Mpls, Lldp, …). IGMP и ICMPv6 — внутри IP, не отдельные варианты `NetPayload`.

`IpData` больше не `Copy`. Транспорт — одно поле `l4: IpL4` (адреса и `len` снаружи). Порты только у `Tcp` и `Udp`.

- `Udp.app` — ярлык по порту **с любой стороны**. Специфичный важнее: DHCP/mDNS/SSDP, затем DNS/LLMNR/NTP, затем QUIC/WireGuard/ESP-UDP (`4500`), иначе `Other`.
- `Udp.msg` — подтверждение тела. DNS/mDNS/LLMNR: первое имя вопроса (сжатие указателями, не длиннее 64 символов); вопросов нет — ярлык остаётся без имени. Первая SRV в ответах: порт и целевой хост; приоритет и вес не читаются. SRV короче 7 байт или с именем вне rdata пропускается, обрезанный ответ не даёт порт. DHCP: magic cookie `63825363`. Опция 53 — тип, опция 12 — hostname (не длиннее 64, непечатное становится `?`), опция 50 — запрошенный адрес (ровно 4 байта). SSDP: первая строка `M-SEARCH`, `NOTIFY` или `HTTP/1.x`; заголовки `NT`, `USN`, `LOCATION` (не длиннее 128, пробел сохраняется, прочее непечатное — `?`). Cookie нет, имя DNS битое или тело не SSDP — ярлык снимается. DHCPv6: первый байт — тип 1–13. Типы 1–11 не короче 4 байт, relay 12–13 не короче 34. Иначе ярлык снимается. Transaction-id и опции не читаются. NBNS (UDP 137): первая метка — 32 символа `A`–`P`. Имя (15 байт без хвостовых пробелов), суффикс, NB или NBSTAT, код операции. Ответ: код результата и IPv4 первой целой NB-записи (6 байт). Иначе ярлык снимается. Запрос и ответ не связываются. QUIC и WireGuard по-прежнему только по порту.
- `Igmp` — v1/v2/v3. Query `0x11`: короче 8 байт → `IgmpType::Query`; ровно 8 и Max Resp = 0 → v1; ровно 8 и Max Resp ≠ 0 → v2; длиннее 8 → v3. `Igmp_Broken` несёт `igmp_type`.
- `Icmp6` — Echo, ошибки пути, NDP (RS/RA/NS/NA/Redirect), MLD 130–132 и MLDv2 143. У NS — Source LLA (MAC спрашивающего), у NA — Target LLA (MAC объявляемого соседа). Остальные options NDP и записи MLDv2 не разбираются. `Icmp6_Broken` несёт `icmp6_type`.
- `Icmp4` — Echo, Dest Unreach (у code 4 ещё MTU), Time Exceeded, Parameter Problem, Redirect, Timestamp, RA/RS. Вложенная дейтаграмма и список адресов RA не читаются. Короче 8 байт или Timestamp не из 20 байт → `Icmp4_Broken` с `icmp4_type`.
- `Esp` — протокол 50, только SPI. Короче 8 байт → `Esp_Broken`. UDP/4500 остаётся `UdpApp::EspOverUdp`. Ciphertext не читается.

## etherparse 0.19

IGMP не разбирает. ICMPv6: Echo, NS, NA, Dest Unreach, Packet Too Big узнаёт. **RS, RA, Redirect и MLD приходят как `Icmpv6Type::Unknown`** — тип читается из первого байта в `parse_icmp6_msg`.

ICMPv4: Echo, Dest Unreach, Redirect, Time Exceeded, Parameter Problem и Timestamp узнаёт. **RA (9) и RS (10) приходят как `Icmpv4Type::Unknown`**. Timestamp (тип 13/14, code 0) принимается только если срез ровно 20 байт.

## Что не закончено

Разбор UDP, ICMPv6 и ICMPv4 по плану сделан. Ниже — отложенное, без отдельной просьбы не начинать.

**TODO, локальная сеть** — следующий разбор, в этом порядке:

1. mDNS: тип сервиса PTR и метки `_service._proto`. Порт и хост первой SRV уже читаются.

Если такой трафик есть в сети: BPDU STP/RSTP (LLC DSAP/SSAP `0x42`, не SNAP); проверка заголовка WireGuard на UDP 51820.

**Хвост по-прежнему не читается:**

- Остальные NDP options у RA, NS и NA (префиксы, DNS). MAC соседа у NS (source LLA) и NA (target LLA) читается.
- Список адресов ICMPv4 Router Advertisement.
- Записи и списки источников MLDv2 Report: вариант `MldV2Report` пустой.
- Списки источников IGMP v3 обрезаются: не больше 16 адресов и 8 записей групп.
- QUIC по-прежнему только ярлык порта.

Контрольные суммы, сборка фрагментов, AH, GRE и SCTP тоже не делались.

## Проверки

`cargo test --bin net_listener` из этого каталога. Тесты в `src/parser.rs`, у каждого `#[test]` есть `///`.
