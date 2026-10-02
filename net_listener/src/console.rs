//! Экран статистики в том терминале, откуда запущен net_listener.
//! Поток один: он же учитывает кадры и только он пишет в tty.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{
    ArpData, EDirection, EthData, EthType, IpData, IpL4, MacAddr6, NetData, NetPayload, UdpApp,
};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode,
    enable_raw_mode,
    EnterAlternateScreen,
    LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::Terminal;
use tokio::sync::broadcast;

const FLOW_CAP   : usize    = 4096;
const ADDR_CAP   : usize    = 4096;
const UDP_CAP    : usize    = 256;
const RING_CAP   : usize    = 2048;
const IDLE       : Duration = Duration::from_secs(60);
const TOP_ADDR   : usize    = 30;
const DRAIN_BURST: usize    = 8000;

const ROLE_N     : usize    = 3;
const L4_N       : usize    = 6;
const IP_N       : usize    = 3;
const DIR_N      : usize    = 4;
const UDP_N      : usize    = 6;
const ETH_N      : usize    = 9;
const BUCKETS    : usize    = ROLE_N * L4_N * IP_N * DIR_N * UDP_N * ETH_N;

const HINT: &str = "h help   f filters   j/k scroll   +/- interval   q quit";

const HELP: &str = "\
Help

h or Esc       close this help
f              open filters
j/k, arrows    scroll one line
PgUp/PgDn      scroll one page
Home/End       top or bottom of the report
+ / -          faster or slower refresh
q or Ctrl-C    quit

TCP is counted as data because only ports are parsed.
Filters hide classes in the report. Totals already collected stay in memory.
Control packets and IPv4/IPv6 data headers are separate lists, so data does not push control lines out.
";

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[rustfmt::skip]
enum Role {
    Data    = 0,
    Control = 1,
    Other   = 2,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[rustfmt::skip]
enum L4 {
    Tcp     = 0,
    Udp     = 1,
    Icmp    = 2,
    Arp     = 3,
    Esp     = 4,
    None    = 5,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[rustfmt::skip]
enum IpVer {
    V4      = 0,
    V6      = 1,
    None    = 2,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[rustfmt::skip]
enum Dir {
    In      = 0,
    Out     = 1,
    Bcast   = 2,
    Other   = 3,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[rustfmt::skip]
enum UdpKind {
    Dns     = 0,
    Dhcp    = 1,
    Mdns    = 2,
    Ntp     = 3,
    Other   = 4,
    NotUdp  = 5,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[rustfmt::skip]
enum EthKind {
    V4      = 0,
    V6      = 1,
    Arp     = 2,
    Lldp    = 3,
    Mpls    = 4,
    Cisco   = 5,
    Dec     = 6,
    Ectp    = 7,
    Other   = 8,
}

#[derive(Clone, Copy)]
#[rustfmt::skip]
struct Marks {
    role: Role,
    l4:   L4,
    ip:   IpVer,
    dir:  Dir,
    udp:  UdpKind,
    eth:  EthKind,
}

impl Marks {
    fn pack(self) -> usize {
        ((((self.role as usize * L4_N + self.l4 as usize) * IP_N + self.ip as usize) * DIR_N
            + self.dir as usize)
            * UDP_N
            + self.udp as usize)
            * ETH_N
            + self.eth as usize
    }

    #[rustfmt::skip]
    fn unpack(mut i: usize) -> Self {
        let eth = i % ETH_N;
        i /= ETH_N;
        let udp = i % UDP_N;
        i /= UDP_N;
        let dir = i % DIR_N;
        i /= DIR_N;
        let ip = i % IP_N;
        i /= IP_N;
        let l4 = i % L4_N;
        i /= L4_N;
        Self {
            role: match i {
                0 => Role::Data,
                1 => Role::Control,
                _ => Role::Other,
            },
            l4:   match l4 {
                0 => L4::Tcp,
                1 => L4::Udp,
                2 => L4::Icmp,
                3 => L4::Arp,
                4 => L4::Esp,
                _ => L4::None,
            },
            ip:   match ip {
                0 => IpVer::V4,
                1 => IpVer::V6,
                _ => IpVer::None,
            },
            dir:  match dir {
                0 => Dir::In,
                1 => Dir::Out,
                2 => Dir::Bcast,
                _ => Dir::Other,
            },
            udp:  match udp {
                0 => UdpKind::Dns,
                1 => UdpKind::Dhcp,
                2 => UdpKind::Mdns,
                3 => UdpKind::Ntp,
                4 => UdpKind::Other,
                _ => UdpKind::NotUdp,
            },
            eth:  match eth {
                0 => EthKind::V4,
                1 => EthKind::V6,
                2 => EthKind::Arp,
                3 => EthKind::Lldp,
                4 => EthKind::Mpls,
                5 => EthKind::Cisco,
                6 => EthKind::Dec,
                7 => EthKind::Ectp,
                _ => EthKind::Other,
            },
        }
    }

    #[rustfmt::skip]
    fn passes(self, f: &Filters) -> bool {
        let role_ok = match self.role {
            Role::Data    => f.data,
            Role::Control => f.control,
            Role::Other   => f.other,
        };
        let l4_ok = match self.l4 {
            L4::Tcp            => f.tcp,
            L4::Udp            => f.udp,
            L4::Icmp           => f.icmp,
            L4::Arp            => f.arp,
            L4::Esp | L4::None => true,
        };
        let ip_ok = match self.ip {
            IpVer::V4   => f.ipv4,
            IpVer::V6   => f.ipv6,
            IpVer::None => true,
        };
        let dir_ok = match self.dir {
            Dir::In    => f.incoming,
            Dir::Out   => f.outgoing,
            Dir::Bcast => f.broadcast,
            Dir::Other => true,
        };
        let udp_ok = match self.udp {
            UdpKind::Dns                     => f.dns,
            UdpKind::Dhcp                    => f.dhcp,
            UdpKind::Mdns                    => f.mdns,
            UdpKind::Ntp                     => f.ntp,
            UdpKind::Other | UdpKind::NotUdp => true,
        };
        role_ok && l4_ok && ip_ok && dir_ok && udp_ok
    }
}

#[derive(Clone, Copy)]
#[rustfmt::skip]
struct Filters {
    data:      bool,
    control:   bool,
    other:     bool,
    tcp:       bool,
    udp:       bool,
    icmp:      bool,
    arp:       bool,
    ipv4:      bool,
    ipv6:      bool,
    incoming:  bool,
    outgoing:  bool,
    broadcast: bool,
    dns:       bool,
    dhcp:      bool,
    mdns:      bool,
    ntp:       bool,
}

impl Default for Filters {
    #[rustfmt::skip]
    fn default() -> Self {
        Self {
            data:      true,
            control:   true,
            other:     true,
            tcp:       true,
            udp:       true,
            icmp:      true,
            arp:       true,
            ipv4:      true,
            ipv6:      true,
            incoming:  true,
            outgoing:  true,
            broadcast: true,
            dns:       true,
            dhcp:      true,
            mdns:      true,
            ntp:       true,
        }
    }
}

#[derive(Clone, Copy)]
enum Fid {
    Data,
    Control,
    Other,
    Tcp,
    Udp,
    Icmp,
    Arp,
    Ipv4,
    Ipv6,
    Incoming,
    Outgoing,
    Broadcast,
    Dns,
    Dhcp,
    Mdns,
    Ntp,
}

impl Filters {
    #[rustfmt::skip]
    fn get(self, id: Fid) -> bool {
        match id {
            Fid::Data      => self.data,
            Fid::Control   => self.control,
            Fid::Other     => self.other,
            Fid::Tcp       => self.tcp,
            Fid::Udp       => self.udp,
            Fid::Icmp      => self.icmp,
            Fid::Arp       => self.arp,
            Fid::Ipv4      => self.ipv4,
            Fid::Ipv6      => self.ipv6,
            Fid::Incoming  => self.incoming,
            Fid::Outgoing  => self.outgoing,
            Fid::Broadcast => self.broadcast,
            Fid::Dns       => self.dns,
            Fid::Dhcp      => self.dhcp,
            Fid::Mdns      => self.mdns,
            Fid::Ntp       => self.ntp,
        }
    }

    #[rustfmt::skip]
    fn toggle(&mut self, id: Fid) {
        let bit = !self.get(id);
        match id {
            Fid::Data      => self.data      = bit,
            Fid::Control   => self.control   = bit,
            Fid::Other     => self.other     = bit,
            Fid::Tcp       => self.tcp       = bit,
            Fid::Udp       => self.udp       = bit,
            Fid::Icmp      => self.icmp      = bit,
            Fid::Arp       => self.arp       = bit,
            Fid::Ipv4      => self.ipv4      = bit,
            Fid::Ipv6      => self.ipv6      = bit,
            Fid::Incoming  => self.incoming  = bit,
            Fid::Outgoing  => self.outgoing  = bit,
            Fid::Broadcast => self.broadcast = bit,
            Fid::Dns       => self.dns       = bit,
            Fid::Dhcp      => self.dhcp      = bit,
            Fid::Mdns      => self.mdns      = bit,
            Fid::Ntp       => self.ntp       = bit,
        }
    }
}

enum MenuEntry {
    Head(&'static str),
    Item(Fid, &'static str),
}

const MENU: &[MenuEntry] = &[
    MenuEntry::Head("Role"),
    MenuEntry::Item(Fid::Data, "Data"),
    MenuEntry::Item(Fid::Control, "Control"),
    MenuEntry::Item(Fid::Other, "Other"),
    MenuEntry::Head("L4"),
    MenuEntry::Item(Fid::Tcp, "TCP"),
    MenuEntry::Item(Fid::Udp, "UDP"),
    MenuEntry::Item(Fid::Icmp, "ICMP"),
    MenuEntry::Item(Fid::Arp, "ARP"),
    MenuEntry::Head("IP version"),
    MenuEntry::Item(Fid::Ipv4, "IPv4"),
    MenuEntry::Item(Fid::Ipv6, "IPv6"),
    MenuEntry::Head("Direction"),
    MenuEntry::Item(Fid::Incoming, "Incoming"),
    MenuEntry::Item(Fid::Outgoing, "Outgoing"),
    MenuEntry::Item(Fid::Broadcast, "Broadcast"),
    MenuEntry::Head("UDP application"),
    MenuEntry::Item(Fid::Dns, "DNS"),
    MenuEntry::Item(Fid::Dhcp, "DHCP"),
    MenuEntry::Item(Fid::Mdns, "mDNS"),
    MenuEntry::Item(Fid::Ntp, "NTP"),
];

#[derive(Clone, Copy, Default)]
#[rustfmt::skip]
struct Tot {
    pkts:  u64,
    bytes: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[rustfmt::skip]
struct FlowKey {
    a:  IpAddr,
    b:  IpAddr,
    pa: u16,
    pb: u16,
}

#[rustfmt::skip]
struct FlowRec {
    packets:   u64,
    bytes:     u64,
    last:      Instant,
    ip:        IpVer,
    saw_in:    bool,
    saw_out:   bool,
    saw_bcast: bool,
}

#[rustfmt::skip]
struct AddrRec {
    role_bytes: [u64; ROLE_N],
    role_pkts:  [u64; ROLE_N],
    saw_in:     bool,
    saw_out:    bool,
    saw_bcast:  bool,
    ip:         IpVer,
    last:       Instant,
}

#[rustfmt::skip]
struct Tagged {
    text:  String,
    marks: Marks,
}

#[rustfmt::skip]
struct ReportLine {
    text: String,
    head: bool,
}

enum Mode {
    Report,
    Help,
    Filters,
}

#[rustfmt::skip]
struct Model {
    total:         Vec<Tot>,
    interval:      Vec<Tot>,
    last_second:   Vec<Tot>,
    flows:         HashMap<FlowKey, FlowRec>,
    addrs:         HashMap<IpAddr, AddrRec>,
    udp:           VecDeque<Tagged>,
    control:       VecDeque<Tagged>,
    data:          VecDeque<Tagged>,
    filters:       Filters,
    lines:         Vec<ReportLine>,
    scroll:        usize,
    view_rows:     usize,
    mode:          Mode,
    filter_cursor: usize,
    filter_scroll: usize,
    refresh:       Duration,
    rate_at:       Instant,
    list_dirty:    bool,
    redraw:        bool,
}

pub fn run(mut rx: broadcast::Receiver<Arc<NetData>>, shutdown: Arc<AtomicBool>) {
    let _guard = scopeguard::guard((), |_| restore_terminal());
    if enable_raw_mode().is_err() {
        return;
    }
    let mut stdout = io::stdout();
    if execute!(stdout, EnterAlternateScreen).is_err() {
        return;
    }
    let mut terminal = match Terminal::new(CrosstermBackend::new(stdout)) {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut model = Model::new();
    model.rebuild();
    let mut last_draw = Instant::now() - model.refresh;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        if !drain(&mut rx, &mut model) {
            break;
        }
        if poll_keys(&mut model, &shutdown) {
            break;
        }
        model.tick();
        let due = last_draw.elapsed() >= model.refresh;
        if due {
            model.list_dirty = true;
        }
        if model.list_dirty {
            model.rebuild();
            model.list_dirty = false;
            model.redraw = true;
        }
        if model.redraw || due {
            if terminal.draw(|frame| draw(frame, &mut model)).is_err() {
                break;
            }
            model.redraw = false;
            last_draw = Instant::now();
        }
    }
    shutdown.store(true, Ordering::Relaxed);
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let mut out = io::stdout();
    let _ = execute!(out, LeaveAlternateScreen);
}

fn drain(rx: &mut broadcast::Receiver<Arc<NetData>>, model: &mut Model) -> bool {
    for _ in 0..DRAIN_BURST {
        match rx.try_recv() {
            Ok(pkt) => model.ingest(&pkt),
            Err(broadcast::error::TryRecvError::Empty) => return true,
            Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
            Err(broadcast::error::TryRecvError::Closed) => return false,
        }
    }
    true
}

/// true — выйти из экрана.
fn poll_keys(model: &mut Model, shutdown: &AtomicBool) -> bool {
    let ready = match event::poll(Duration::from_millis(30)) {
        Ok(v) => v,
        Err(_) => return true,
    };
    if !ready {
        return false;
    }
    let ev = match event::read() {
        Ok(ev) => ev,
        Err(_) => return true,
    };
    match ev {
        Event::Resize(_, _) => model.redraw = true,
        Event::Key(key) if key.kind != KeyEventKind::Release => {
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                shutdown.store(true, Ordering::Relaxed);
                return true;
            }
            if on_key(model, key.code) {
                shutdown.store(true, Ordering::Relaxed);
                return true;
            }
        }
        _ => {}
    }
    false
}

fn on_key(model: &mut Model, code: KeyCode) -> bool {
    if matches!(code, KeyCode::Char('q') | KeyCode::Char('Q')) {
        return true;
    }
    match model.mode {
        Mode::Report => on_report_key(model, code),
        Mode::Help => {
            if matches!(code, KeyCode::Char('h') | KeyCode::Char('H') | KeyCode::Esc) {
                model.mode = Mode::Report;
                model.redraw = true;
            }
        }
        Mode::Filters => on_filter_key(model, code),
    }
    false
}

fn on_report_key(model: &mut Model, code: KeyCode) {
    let page = model.view_rows.max(1) as isize;
    match code {
        KeyCode::Char('h') | KeyCode::Char('H') => {
            model.mode = Mode::Help;
            model.redraw = true;
            return;
        }
        KeyCode::Char('f') | KeyCode::Char('F') => {
            model.mode = Mode::Filters;
            model.redraw = true;
            return;
        }
        KeyCode::Char('j') | KeyCode::Down => model.scroll_by(1),
        KeyCode::Char('k') | KeyCode::Up => model.scroll_by(-1),
        KeyCode::PageDown => model.scroll_by(page),
        KeyCode::PageUp => model.scroll_by(-page),
        KeyCode::Home => {
            model.scroll = 0;
            model.redraw = true;
        }
        KeyCode::End => {
            model.scroll = model.max_scroll();
            model.redraw = true;
        }
        KeyCode::Char('+') | KeyCode::Char('=') => {
            model.refresh = faster(model.refresh);
            model.redraw = true;
        }
        KeyCode::Char('-') => {
            model.refresh = slower(model.refresh);
            model.redraw = true;
        }
        _ => {}
    }
}

fn on_filter_key(model: &mut Model, code: KeyCode) {
    match code {
        KeyCode::Char('f') | KeyCode::Char('F') | KeyCode::Esc => {
            model.mode = Mode::Report;
            model.redraw = true;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            model.filter_cursor = step_menu(model.filter_cursor, -1);
            model.redraw = true;
        }
        KeyCode::Down | KeyCode::Char('j') => {
            model.filter_cursor = step_menu(model.filter_cursor, 1);
            model.redraw = true;
        }
        KeyCode::Char(' ') => {
            if let MenuEntry::Item(id, _) = MENU[model.filter_cursor] {
                model.filters.toggle(id);
                model.list_dirty = true;
                model.redraw = true;
            }
        }
        _ => {}
    }
}

fn step_menu(cur: usize, delta: isize) -> usize {
    let mut i = cur as isize;
    loop {
        i += delta;
        if i < 0 || i >= MENU.len() as isize {
            return cur;
        }
        if matches!(MENU[i as usize], MenuEntry::Item(_, _)) {
            return i as usize;
        }
    }
}

fn faster(d: Duration) -> Duration {
    match d.as_millis() {
        0..=200 => Duration::from_millis(200),
        201..=500 => Duration::from_millis(200),
        501..=1000 => Duration::from_millis(500),
        1001..=2000 => Duration::from_millis(1000),
        _ => Duration::from_millis(2000),
    }
}

fn slower(d: Duration) -> Duration {
    match d.as_millis() {
        0..=200 => Duration::from_millis(500),
        201..=500 => Duration::from_millis(1000),
        501..=1000 => Duration::from_millis(2000),
        1001..=2000 => Duration::from_millis(5000),
        _ => Duration::from_millis(5000),
    }
}

fn draw(frame: &mut ratatui::Frame, model: &mut Model) {
    match model.mode {
        Mode::Report => draw_report(frame, model),
        Mode::Help => {
            let p = Paragraph::new(HELP).style(Style::default().fg(Color::White));
            frame.render_widget(p, frame.area());
        }
        Mode::Filters => draw_filters(frame, model),
    }
}

fn draw_report(frame: &mut ratatui::Frame, model: &mut Model) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    model.view_rows = body.height as usize;
    model.clamp_scroll();

    let (pkts, bytes) = model.sum(&model.total);
    let (rate_pkts, rate_bytes) = model.sum(&model.last_second);
    let conns = model.live_flows();
    let head = format!(
        "Packets {pkts}    Bytes {bytes}\nRate {rate_pkts} pkt/s    {rate_bytes} B/s    TCP connections {conns}    refresh {}",
        refresh_label(model.refresh)
    );
    frame.render_widget(
        Paragraph::new(head).style(Style::default().fg(Color::White).bg(Color::Blue)),
        header,
    );

    let start = model.scroll;
    let end = (start + model.view_rows).min(model.lines.len());
    let rows: Vec<Line> = model.lines[start..end]
        .iter()
        .map(|line| {
            let style = if line.head {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Line::from(line.text.as_str()).style(style)
        })
        .collect();
    frame.render_widget(Paragraph::new(rows), body);
    frame.render_widget(
        Paragraph::new(HINT).style(Style::default().fg(Color::Black).bg(Color::Gray)),
        footer,
    );
}

fn draw_filters(frame: &mut ratatui::Frame, model: &mut Model) {
    let rows = frame.area().height as usize;
    model.keep_filter_visible(rows);
    let mut text = vec![Line::styled(
        "Filters    Space toggles    f or Esc returns",
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    )];
    let start = model.filter_scroll;
    let end = (start + rows.saturating_sub(1)).min(MENU.len());
    for (idx, entry) in MENU.iter().enumerate().skip(start).take(end - start) {
        let cursor = idx == model.filter_cursor;
        let line = match entry {
            MenuEntry::Head(title) => Line::styled(
                format!(" {title}"),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            MenuEntry::Item(id, label) => {
                let mark = if model.filters.get(*id) { "[x]" } else { "[ ]" };
                let body = format!(" {mark} {label}");
                if cursor {
                    Line::styled(body, Style::default().bg(Color::DarkGray).fg(Color::White))
                } else {
                    Line::from(body)
                }
            }
        };
        text.push(line);
    }
    frame.render_widget(Paragraph::new(text), frame.area());
}

fn refresh_label(d: Duration) -> String {
    let ms = d.as_millis();
    if ms % 1000 == 0 {
        format!("{}s", ms / 1000)
    } else {
        format!("{ms}ms")
    }
}

impl Model {
    #[rustfmt::skip]
    fn new() -> Self {
        let zero = vec![Tot::default(); BUCKETS];
        let mut cursor = 0;
        while !matches!(MENU[cursor], MenuEntry::Item(_, _)) {
            cursor += 1;
        }
        Self {
            total:         zero.clone(),
            interval:      zero.clone(),
            last_second:   zero,
            flows:         HashMap::new(),
            addrs:         HashMap::new(),
            udp:           VecDeque::new(),
            control:       VecDeque::new(),
            data:          VecDeque::new(),
            filters:       Filters::default(),
            lines:         Vec::new(),
            scroll:        0,
            view_rows:     20,
            mode:          Mode::Report,
            filter_cursor: cursor,
            filter_scroll: 0,
            refresh:       Duration::from_secs(1),
            rate_at:       Instant::now(),
            list_dirty:    true,
            redraw:        true,
        }
    }

    fn tick(&mut self) {
        if self.rate_at.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_second.clone_from(&self.interval);
        for t in &mut self.interval {
            *t = Tot::default();
        }
        let now = Instant::now();
        self.flows.retain(|_, rec| now.duration_since(rec.last) < IDLE);
        self.addrs.retain(|_, rec| now.duration_since(rec.last) < IDLE);
        self.rate_at = now;
    }

    fn ingest(&mut self, data: &NetData) {
        let marks = classify(data);
        let bytes = payload_bytes(data);
        let i = marks.pack();
        self.total[i].pkts += 1;
        self.total[i].bytes += bytes;
        self.interval[i].pkts += 1;
        self.interval[i].bytes += bytes;
        self.note_flow(data, marks, bytes);
        self.note_addr(data, marks, bytes);
        if is_named_udp(data) {
            push_lines(&mut self.udp, data, marks, UDP_CAP);
        }
        if marks.role == Role::Control {
            push_lines(&mut self.control, data, marks, RING_CAP);
        } else if marks.role == Role::Data && matches!(marks.ip, IpVer::V4 | IpVer::V6) {
            push_lines(&mut self.data, data, marks, RING_CAP);
        }
    }

    fn note_flow(&mut self, data: &NetData, marks: Marks, bytes: u64) {
        let NetPayload::Ip(ip) = &data.payload else {
            return;
        };
        let IpL4::Tcp { src_port, dst_port } = &ip.l4 else {
            return;
        };
        let key = flow_key(ip.src, *src_port, ip.dst, *dst_port);
        if let Some(rec) = self.flows.get_mut(&key) {
            rec.packets += 1;
            rec.bytes += bytes;
            rec.last = Instant::now();
            see_dir(marks.dir, &mut rec.saw_in, &mut rec.saw_out, &mut rec.saw_bcast);
            return;
        }
        if self.flows.len() >= FLOW_CAP {
            evict_oldest(&mut self.flows, |rec| rec.last);
        }
        let mut rec = FlowRec {
            packets: 1,
            bytes,
            last: Instant::now(),
            ip: marks.ip,
            saw_in: false,
            saw_out: false,
            saw_bcast: false,
        };
        see_dir(marks.dir, &mut rec.saw_in, &mut rec.saw_out, &mut rec.saw_bcast);
        self.flows.insert(key, rec);
    }

    fn note_addr(&mut self, data: &NetData, marks: Marks, bytes: u64) {
        let NetPayload::Ip(ip) = &data.payload else {
            return;
        };
        for addr in [ip.src, ip.dst] {
            if let Some(rec) = self.addrs.get_mut(&addr) {
                let r = marks.role as usize;
                rec.role_pkts[r] += 1;
                rec.role_bytes[r] += bytes;
                rec.last = Instant::now();
                see_dir(marks.dir, &mut rec.saw_in, &mut rec.saw_out, &mut rec.saw_bcast);
                continue;
            }
            if self.addrs.len() >= ADDR_CAP {
                evict_oldest(&mut self.addrs, |rec| rec.last);
            }
            let mut rec = AddrRec {
                role_bytes: [0; ROLE_N],
                role_pkts: [0; ROLE_N],
                saw_in: false,
                saw_out: false,
                saw_bcast: false,
                ip: match addr {
                    IpAddr::V4(_) => IpVer::V4,
                    IpAddr::V6(_) => IpVer::V6,
                },
                last: Instant::now(),
            };
            rec.role_pkts[marks.role as usize] = 1;
            rec.role_bytes[marks.role as usize] = bytes;
            see_dir(marks.dir, &mut rec.saw_in, &mut rec.saw_out, &mut rec.saw_bcast);
            self.addrs.insert(addr, rec);
        }
    }

    fn sum(&self, buckets: &[Tot]) -> (u64, u64) {
        let mut pkts = 0u64;
        let mut bytes = 0u64;
        for (i, t) in buckets.iter().enumerate() {
            if t.pkts == 0 {
                continue;
            }
            if Marks::unpack(i).passes(&self.filters) {
                pkts += t.pkts;
                bytes += t.bytes;
            }
        }
        (pkts, bytes)
    }

    fn live_flows(&self) -> usize {
        let now = Instant::now();
        self.flows
            .iter()
            .filter(|(key, rec)| {
                now.duration_since(rec.last) < IDLE && flow_visible(key, rec, &self.filters)
            })
            .count()
    }

    fn scroll_by(&mut self, delta: isize) {
        let max = self.max_scroll() as isize;
        let next = (self.scroll as isize + delta).clamp(0, max);
        self.scroll = next as usize;
        self.redraw = true;
    }

    fn max_scroll(&self) -> usize {
        self.lines.len().saturating_sub(self.view_rows.max(1))
    }

    fn clamp_scroll(&mut self) {
        let max = self.max_scroll();
        if self.scroll > max {
            self.scroll = max;
        }
    }

    fn keep_filter_visible(&mut self, rows: usize) {
        let window = rows.saturating_sub(1).max(1);
        if self.filter_cursor < self.filter_scroll {
            self.filter_scroll = self.filter_cursor;
        } else if self.filter_cursor >= self.filter_scroll + window {
            self.filter_scroll = self.filter_cursor + 1 - window;
        }
    }

    fn rebuild(&mut self) {
        let mut lines = Vec::new();
        push_protocols(&mut lines, self);
        push_addresses(&mut lines, self);
        push_flows(&mut lines, self);
        push_tagged(&mut lines, "UDP applications", &self.udp, &self.filters);
        push_tagged(&mut lines, "Control packets", &self.control, &self.filters);
        push_tagged(&mut lines, "Data headers", &self.data, &self.filters);
        self.lines = lines;
        self.clamp_scroll();
    }
}

fn push_protocols(lines: &mut Vec<ReportLine>, model: &Model) {
    head(lines, "Protocols");
    let mut any = false;
    let specs: [(L4, &str); 5] = [
        (L4::Tcp, "TCP"),
        (L4::Udp, "UDP"),
        (L4::Icmp, "ICMP/IGMP"),
        (L4::Arp, "ARP"),
        (L4::Esp, "ESP"),
    ];
    for (l4, name) in specs {
        let tot = fold_if(model, |m| m.l4 == l4);
        if tot.pkts > 0 {
            any = true;
            body(lines, &format!("  {name:<12} {} pkt    {} bytes", tot.pkts, tot.bytes));
        }
    }
    let eths: [(EthKind, &str); 8] = [
        (EthKind::V4, "IPv4"),
        (EthKind::V6, "IPv6"),
        (EthKind::Arp, "ARP ether"),
        (EthKind::Lldp, "LLDP"),
        (EthKind::Mpls, "MPLS"),
        (EthKind::Cisco, "Cisco"),
        (EthKind::Dec, "DEC"),
        (EthKind::Ectp, "ECTP"),
    ];
    for (eth, name) in eths {
        let tot = fold_if(model, |m| m.eth == eth);
        if tot.pkts > 0 {
            any = true;
            body(lines, &format!("  {name:<12} {} pkt    {} bytes", tot.pkts, tot.bytes));
        }
    }
    if !any {
        body(lines, "  none");
    }
}

fn fold_if(model: &Model, pred: impl Fn(Marks) -> bool) -> Tot {
    let mut acc = Tot::default();
    for (i, t) in model.total.iter().enumerate() {
        if t.pkts == 0 {
            continue;
        }
        let marks = Marks::unpack(i);
        if marks.passes(&model.filters) && pred(marks) {
            acc.pkts += t.pkts;
            acc.bytes += t.bytes;
        }
    }
    acc
}

fn push_addresses(lines: &mut Vec<ReportLine>, model: &Model) {
    head(lines, "Addresses");
    let now = Instant::now();
    let mut rows: Vec<(u64, u64, IpAddr)> = model
        .addrs
        .iter()
        .filter_map(|(addr, rec)| {
            if now.duration_since(rec.last) >= IDLE || !addr_visible(rec, &model.filters) {
                return None;
            }
            let (pkts, bytes) = addr_totals(rec, &model.filters);
            Some((bytes, pkts, *addr))
        })
        .collect();
    rows.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    rows.truncate(TOP_ADDR);
    if rows.is_empty() {
        body(lines, "  none");
        return;
    }
    for (bytes, pkts, addr) in rows {
        body(lines, &format!("  {addr:<40} {pkts} pkt    {bytes} bytes"));
    }
}

fn push_flows(lines: &mut Vec<ReportLine>, model: &Model) {
    head(lines, "Connections");
    let now = Instant::now();
    let mut rows: Vec<(&FlowKey, &FlowRec)> = model
        .flows
        .iter()
        .filter(|(key, rec)| now.duration_since(rec.last) < IDLE && flow_visible(key, rec, &model.filters))
        .collect();
    rows.sort_by(|a, b| b.1.last.cmp(&a.1.last));
    if rows.is_empty() {
        body(lines, "  none");
        return;
    }
    for (key, rec) in rows {
        body(
            lines,
            &format!(
                "  {}:{} <-> {}:{}    {} pkt    {} bytes",
                key.a, key.pa, key.b, key.pb, rec.packets, rec.bytes
            ),
        );
    }
}

fn push_tagged(lines: &mut Vec<ReportLine>, title: &str, ring: &VecDeque<Tagged>, filters: &Filters) {
    head(lines, title);
    let mut any = false;
    for row in ring {
        if row.marks.passes(filters) {
            any = true;
            body(lines, &format!("  {}", row.text));
        }
    }
    if !any {
        body(lines, "  none");
    }
}

fn head(lines: &mut Vec<ReportLine>, text: &str) {
    lines.push(ReportLine {
        text: text.to_string(),
        head: true,
    });
}

fn body(lines: &mut Vec<ReportLine>, text: &str) {
    lines.push(ReportLine {
        text: text.to_string(),
        head: false,
    });
}

fn addr_visible(rec: &AddrRec, f: &Filters) -> bool {
    let ip_ok = match rec.ip {
        IpVer::V4 => f.ipv4,
        IpVer::V6 => f.ipv6,
        IpVer::None => true,
    };
    ip_ok && dir_seen(rec.saw_in, rec.saw_out, rec.saw_bcast, f) && addr_totals(rec, f).0 > 0
}

fn addr_totals(rec: &AddrRec, f: &Filters) -> (u64, u64) {
    let mut pkts = 0u64;
    let mut bytes = 0u64;
    let on = [f.data, f.control, f.other];
    for i in 0..ROLE_N {
        if on[i] {
            pkts += rec.role_pkts[i];
            bytes += rec.role_bytes[i];
        }
    }
    (pkts, bytes)
}

fn flow_visible(key: &FlowKey, rec: &FlowRec, f: &Filters) -> bool {
    let _ = key;
    if !f.data || !f.tcp {
        return false;
    }
    let ip_ok = match rec.ip {
        IpVer::V4 => f.ipv4,
        IpVer::V6 => f.ipv6,
        IpVer::None => true,
    };
    ip_ok && dir_seen(rec.saw_in, rec.saw_out, rec.saw_bcast, f)
}

fn dir_seen(saw_in: bool, saw_out: bool, saw_bcast: bool, f: &Filters) -> bool {
    (saw_in && f.incoming) || (saw_out && f.outgoing) || (saw_bcast && f.broadcast) || (!saw_in && !saw_out && !saw_bcast)
}

#[rustfmt::skip]
fn see_dir(dir: Dir, saw_in: &mut bool, saw_out: &mut bool, saw_bcast: &mut bool) {
    match dir {
        Dir::In    => *saw_in    = true,
        Dir::Out   => *saw_out   = true,
        Dir::Bcast => *saw_bcast = true,
        Dir::Other => {}
    }
}

fn evict_oldest<K, V>(map: &mut HashMap<K, V>, last: impl Fn(&V) -> Instant)
where
    K: Clone + Eq + std::hash::Hash,
{
    if let Some(old) = map.iter().min_by_key(|(_, v)| last(v)).map(|(k, _)| k.clone()) {
        map.remove(&old);
    }
}

fn push_lines(ring: &mut VecDeque<Tagged>, data: &NetData, marks: Marks, cap: usize) {
    let text = format!("{data}");
    for line in text.split('\n') {
        if ring.len() >= cap {
            ring.pop_front();
        }
        ring.push_back(Tagged {
            text: line.to_string(),
            marks,
        });
    }
}

fn payload_bytes(data: &NetData) -> u64 {
    match &data.payload {
        NetPayload::Ip(ip) => ip.len as u64,
        _ => 0,
    }
}

fn is_named_udp(data: &NetData) -> bool {
    match &data.payload {
        NetPayload::Ip(ip) => matches!(
            &ip.l4,
            IpL4::Udp { app, .. } if *app != UdpApp::Other
        ),
        _ => false,
    }
}

fn flow_key(src: IpAddr, sport: u16, dst: IpAddr, dport: u16) -> FlowKey {
    if (src, sport) <= (dst, dport) {
        FlowKey { a: src, b: dst, pa: sport, pb: dport }
    } else {
        FlowKey { a: dst, b: src, pa: dport, pb: sport }
    }
}

#[rustfmt::skip]
fn classify(data: &NetData) -> Marks {
    let dir = match data.eth.dir {
        EDirection::Incoming                          => Dir::In,
        EDirection::Outgoing                          => Dir::Out,
        EDirection::Broadcast | EDirection::Multicast => Dir::Bcast,
        EDirection::Unknown                           => Dir::Other,
    };
    let mut marks = Marks {
        role: Role::Other,
        l4:   L4::None,
        ip:   IpVer::None,
        dir,
        udp:  UdpKind::NotUdp,
        eth:  eth_kind(data),
    };
    match &data.payload {
        NetPayload::Arp(_) => {
            marks.role = Role::Control;
            marks.l4 = L4::Arp;
        }
        NetPayload::Lldp(_) | NetPayload::Ectp(_) | NetPayload::DEC(_) | NetPayload::Cisco(_) => {
            marks.role = Role::Control;
        }
        NetPayload::Mpls(_) | NetPayload::Err(_) => {
            marks.role = Role::Other;
        }
        NetPayload::Ip(ip) => fill_ip(&mut marks, ip),
    }
    marks
}

fn fill_ip(marks: &mut Marks, ip: &IpData) {
    marks.ip = match ip.src {
        IpAddr::V4(_) => IpVer::V4,
        IpAddr::V6(_) => IpVer::V6,
    };
    match &ip.l4 {
        IpL4::Tcp { .. } => {
            marks.role = Role::Data;
            marks.l4 = L4::Tcp;
        }
        IpL4::Udp { app, .. } => {
            marks.l4 = L4::Udp;
            marks.udp = udp_kind(*app);
            marks.role = if is_control_udp(*app) {
                Role::Control
            } else {
                Role::Data
            };
        }
        IpL4::Igmp(_) | IpL4::Icmp4(_) | IpL4::Icmp6(_) => {
            marks.role = Role::Control;
            marks.l4 = L4::Icmp;
        }
        IpL4::Esp(_) => {
            marks.role = Role::Data;
            marks.l4 = L4::Esp;
        }
        IpL4::Other(_) => {
            marks.role = Role::Other;
        }
    }
}

fn is_control_udp(app: UdpApp) -> bool {
    matches!(
        app,
        UdpApp::Dhcp4
            | UdpApp::Dhcp6
            | UdpApp::Dns
            | UdpApp::Mdns
            | UdpApp::Ssdp
            | UdpApp::Llmnr
            | UdpApp::Nbns
            | UdpApp::Ntp
    )
}

#[rustfmt::skip]
fn udp_kind(app: UdpApp) -> UdpKind {
    match app {
        UdpApp::Dns                   => UdpKind::Dns,
        UdpApp::Dhcp4 | UdpApp::Dhcp6 => UdpKind::Dhcp,
        UdpApp::Mdns                  => UdpKind::Mdns,
        UdpApp::Ntp                   => UdpKind::Ntp,
        _                             => UdpKind::Other,
    }
}

#[rustfmt::skip]
fn eth_kind(data: &NetData) -> EthKind {
    match &data.payload {
        NetPayload::Lldp(_)  => return EthKind::Lldp,
        NetPayload::Cisco(_) => return EthKind::Cisco,
        NetPayload::DEC(_)   => return EthKind::Dec,
        NetPayload::Ectp(_)  => return EthKind::Ectp,
        NetPayload::Mpls(_)  => return EthKind::Mpls,
        NetPayload::Arp(_)   => return EthKind::Arp,
        _ => {}
    }
    match data.eth.prot {
        EthType::Ipv4                      => EthKind::V4,
        EthType::Ipv6                      => EthKind::V6,
        EthType::Arp | EthType::Rarp       => EthKind::Arp,
        EthType::Lldp                      => EthKind::Lldp,
        EthType::Mpls | EthType::MplsMcast => EthKind::Mpls,
        EthType::Ectp                      => EthKind::Ectp,
        EthType::Unsupported               => EthKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn frame(payload: NetPayload, prot: EthType, dir: EDirection) -> NetData {
        NetData {
            eth: EthData {
                src: MacAddr6::new([1, 0, 0, 0, 0, 1]),
                dst: MacAddr6::new([2, 0, 0, 0, 0, 2]),
                dir,
                prot,
            },
            payload,
        }
    }

    fn tcp(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> NetData {
        frame(
            NetPayload::Ip(IpData {
                src: IpAddr::V4(Ipv4Addr::from(src)),
                dst: IpAddr::V4(Ipv4Addr::from(dst)),
                len: 100,
                l4: IpL4::Tcp { src_port: sport, dst_port: dport },
            }),
            EthType::Ipv4,
            EDirection::Incoming,
        )
    }

    /// TCP IPv4 считается данными и попадает в кольцо заголовков, не в управление.
    #[test]
    fn tcp_is_data_header() {
        let mut model = Model::new();
        model.ingest(&tcp([10, 0, 0, 1], 40000, [1, 1, 1, 1], 443));
        assert_eq!(model.data.len(), 1);
        assert!(model.control.is_empty());
        assert!(model.data[0].text.contains("TCP"));
    }

    /// ARP остаётся в кольце управления, даже если следом идёт много TCP.
    #[test]
    fn control_ring_is_not_pushed_out_by_tcp() {
        let mut model = Model::new();
        model.ingest(&frame(
            NetPayload::Arp(ArpData::default()),
            EthType::Arp,
            EDirection::Broadcast,
        ));
        for n in 0..3000u16 {
            model.ingest(&tcp([10, 0, 0, 1], n, [1, 1, 1, 1], 80));
        }
        assert_eq!(model.control.len(), 1);
        assert!(model.control[0].text.contains("Arp"));
        assert!(model.data.len() <= RING_CAP);
    }

    /// DNS — управление. Оба направления TCP склеиваются в один поток.
    #[test]
    fn dns_is_control_and_tcp_directions_share_a_flow() {
        let mut model = Model::new();
        model.ingest(&frame(
            NetPayload::Ip(IpData {
                src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                dst: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                len: 60,
                l4: IpL4::Udp {
                    src_port: 12345,
                    dst_port: 53,
                    app: UdpApp::Dns,
                    msg: None,
                },
            }),
            EthType::Ipv4,
            EDirection::Outgoing,
        ));
        assert_eq!(model.control.len(), 1);
        assert!(model.data.is_empty());

        model.ingest(&tcp([10, 0, 0, 1], 10, [10, 0, 0, 2], 80));
        let back = frame(
            NetPayload::Ip(IpData {
                src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                len: 40,
                l4: IpL4::Tcp { src_port: 80, dst_port: 10 },
            }),
            EthType::Ipv4,
            EDirection::Outgoing,
        );
        model.ingest(&back);
        assert_eq!(model.flows.len(), 1);
        let rec = model.flows.values().next().unwrap();
        assert_eq!(rec.packets, 2);
    }

    /// Индекс корзины однозначно кодирует метки кадра.
    #[test]
    fn bucket_index_roundtrip() {
        for i in 0..BUCKETS {
            assert_eq!(Marks::unpack(i).pack(), i);
        }
    }
}
