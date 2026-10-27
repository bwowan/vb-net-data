# Отладка NetData

Cargo пишет бинарники в `/tmpu/NetData` (`.cargo/config.toml`, `target-dir`), а не в `target/`.

- Слушатель: `/tmpu/NetData/debug/net_listener`
- Визуализатор: `/tmpu/NetData/debug/net_visualizator`

Слушателю нужны `cap_net_raw` и `cap_net_admin`. Визуализатору нет.

```bash
cargo build --bin net_listener
sudo setcap cap_net_raw,cap_net_admin=eip /tmpu/NetData/debug/net_listener
```

Журналы, потому что терминал слушателя занят экраном ratatui:

- `/tmpu/net_listener.log`
- `/tmpu/net_visualizator.log`

Английская версия: [DEBUGGING.md](DEBUGGING.md).

## Конфигурации запуска

Открывайте корень workspace `/mnt/DevData/Rust/NetData`. Конфигурации лежат в `.vscode/launch.json` (CodeLLDB, `"type": "lldb"`):

- `Debug executable 'net_listener'` — сборка, затем setcap на `/tmpu/NetData/debug/net_listener`
- `Debug executable 'net_listener' (built binary)` — тот же путь к бинарнику
- `Debug executable 'net_visualizator'`
- модульные тесты `common`, `net_listener` и `net_visualizator`

Если открыть папку `net_listener`, конфигурации в `net_listener/.vscode/launch.json` другие. `Debug as Root (via lldb-server)` ждёт уже запущенный сервер:

```bash
sudo lldb-server platform --listen "*:1234" --server
```

Задачи setcap во вложенной папке по-прежнему называют `target/debug`. Cargo туда бинарник не пишет. Ставьте capability на `/tmpu/NetData/debug/net_listener` или берите корневую задачу `Build-net_listener-setCap`.

## Командная строка

```bash
cargo build --bin net_listener
sudo setcap cap_net_raw,cap_net_admin=eip /tmpu/NetData/debug/net_listener
lldb /tmpu/NetData/debug/net_listener
```

`sudo lldb` тоже работает. Обычный путь — setcap.

## Если не запускается

### `cannot find -lpcap`

Не установлен пакет разработки libpcap.

**Ubuntu/Debian:**

```bash
sudo apt-get install libpcap-dev
```

**Fedora/RHEL:**

```bash
sudo dnf install libpcap-devel
```

**Arch Linux:**

```bash
sudo pacman -S libpcap
```

После этого соберите снова. Бинарник появится в `/tmpu/NetData/debug/`.

### Проверка набора инструментов

```bash
which lldb
pkg-config --modversion libpcap
ldconfig -p | grep pcap
```

CodeLLDB: Extensions, поиск «CodeLLDB». Корневые конфигурации запуска используют его.
