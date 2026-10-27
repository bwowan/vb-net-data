//! Окно: полоса вкладок, два уровня фильтров, таблицы пакетов и соединений.
//! eframe 0.37 рисует через [`eframe::App::ui`], не через `update`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use egui_extras::{Column, TableBuilder};

use crate::filter::{self, Filter};
use crate::source::LinkState;
use crate::store::{self, ConnKey, ConnProto, ConnRec, Stats, Store, Tot};

/// Высота обычной строки таблицы.
const ROW_H: f32 = 18.0;
/// Кадры приходили недавно.
const LIVE: egui::Color32 = egui::Color32::from_rgb(80, 200, 120);
/// Линк есть, но давно молчит, или включена пауза.
const STALE: egui::Color32 = egui::Color32::from_rgb(220, 180, 60);
/// Hello уходит, кадров ещё не было.
const WAIT: egui::Color32 = egui::Color32::from_rgb(150, 150, 150);

/// Тип вкладки: что показывает таблица — кадры или агрегированные соединения.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TabKind {
    Packets,     // Кольцо кадров (`Store::pkts`).
    Connections, // Таблица соединений (`Store::conns`).
}

impl TabKind {
    /// Подпись на кнопке вкладки в полосе табов.
    fn label(self) -> &'static str {
        match self {
            TabKind::Packets     => "Packets",
            TabKind::Connections => "Connections",
        }
    }
}

struct Tab {
    /// Стабильный id для egui (`id_salt`), не индекс в `tabs`.
    id: u64,
    title: String,
    kind: TabKind,
    /// Локальный фильтр этой вкладки; вместе с глобальным — AND.
    filter: Filter,
    /// Раскрытая строка пакетов: `seq` кадра, не индекс в кольце.
    expanded: Option<u64>,
    /// Следовать за хвостом таблицы; снимается при ручной прокрутке вверх.
    autoscroll: bool,
    /// Смещение скролла в прошлом кадре — чтобы заметить прокрутку вверх.
    last_offset: Option<f32>,
    renaming: bool,
    /// Один кадр: после «Rename» поставить фокус в поле.
    focus_rename: bool,
}

impl Tab {
    fn new(id: u64, title: impl Into<String>, kind: TabKind) -> Self {
        Self {
            id,
            title: title.into(),
            kind,
            filter: Filter::default(),
            expanded: None,
            autoscroll: true,
            last_offset: None,
            renaming: false,
            focus_rename: false,
        }
    }
}

/// Корневое окно: Store общий с потоком приёма, пауза и shutdown — атомики.
pub struct App {
    store: Arc<Mutex<Store>>,
    paused: Arc<AtomicBool>,
    /// При закрытии окна поток приёма выходит на следующем `poll`.
    shutdown: Arc<AtomicBool>,
    /// Путь сокета listener — только для строки статуса.
    listener: String,
    global: Filter,
    tabs: Vec<Tab>,
    active: usize,
    next_id: u64,
}

impl App {
    /// Стартовый набор: одна вкладка Packets и одна Connections.
    pub fn new(
        store: Arc<Mutex<Store>>,
        paused: Arc<AtomicBool>,
        shutdown: Arc<AtomicBool>,
        listener: String,
    ) -> Self {
        Self {
            store,
            paused,
            shutdown,
            listener,
            global: Filter::default(),
            tabs: vec![
                Tab::new(1, "Packets", TabKind::Packets),
                Tab::new(2, "Connections", TabKind::Connections),
            ],
            active: 0,
            next_id: 3,
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Без мыши тоже обновляться: иначе новые пакеты появятся только при движении.
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(100));
        let store = Arc::clone(&self.store);
        let store = store.lock().unwrap_or_else(|err| err.into_inner());
        draw(
            ui,
            &self.listener,
            &self.paused,
            &mut self.global,
            &mut self.tabs,
            &mut self.active,
            &mut self.next_id,
            &store,
        );
    }

    fn on_exit(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

/// Верх — линк и глобальный фильтр, низ — счётчики, центр — вкладки.
fn draw(
    ui      : &mut egui::Ui,
    listener: &str,          // Путь сокета listener — только для строки статуса.
    paused  : &AtomicBool,   // Состояние паузы.
    global  : &mut Filter,   // Сворачиваемый глобальный фильтр.
    tabs    : &mut Vec<Tab>, // Полоса вкладок.
    active  : &mut usize,    // Индекс активной вкладки.
    next_id : &mut u64,      // Счётчик id для новых вкладок.    
    store   : &Store,        // Общий Store. 
) {
    egui::Panel::top("top").show(ui, |ui| top_bar(ui, store, listener, paused, global));
    egui::Panel::bottom("bottom").show(ui, |ui| bottom_bar(ui, store));
    egui::CentralPanel::default().show(ui, |ui| {
        tab_bar(ui, tabs, active, next_id);
        if tabs.is_empty() {
            ui.label("No tabs. Press + to add one.");
            return;
        }
        if *active >= tabs.len() {
            *active = 0;
        }
        let tab_id = tabs[*active].id;
        egui::CollapsingHeader::new("Filter")
            .id_salt(("local", tab_id))
            .default_open(false)
            .show(ui, |ui| tabs[*active].filter.ui(ui));
        match tabs[*active].kind {
            TabKind::Packets => packets(ui, global, &mut tabs[*active], store),
            TabKind::Connections => {
                let id = tabs[*active].id;
                connections(ui, global, &tabs[*active].filter, store, id);
            }
        }
    });
}

/// Состояние линка, Pause/Resume и сворачиваемый глобальный фильтр.
fn top_bar(
    ui: &mut egui::Ui,
    store: &Store,
    listener: &str,
    paused: &AtomicBool,
    global: &mut Filter,
) {
    ui.horizontal(|ui| {
        let (text, color) = link_label(store, listener);
        ui.colored_label(color, text);
        let on = paused.load(Ordering::Relaxed);
        if ui.button(if on { "Resume" } else { "Pause" }).clicked() {
            paused.store(!on, Ordering::Relaxed);
        }
        if on {
            ui.colored_label(STALE, "paused");
        }
    });
    egui::CollapsingHeader::new("Global filter")
        .default_open(false)
        .show(ui, |ui| global.ui(ui));
}

/// Подпись линка и цвет: waiting / live / stale.
fn link_label(store: &Store, listener: &str) -> (String, egui::Color32) {
    match store.link {
        LinkState::Waiting => (format!("waiting   {listener}"), WAIT),
        LinkState::Connected { last_rx } => {
            let secs = last_rx.elapsed().as_secs_f32();
            let color = if secs < 2.0 { LIVE } else { STALE };
            (format!("live {secs:.1}s   {listener}"), color)
        }
    }
}

/// Итоги за всё время, скорость за последнюю секунду, размер кольца.
fn bottom_bar(ui: &mut egui::Ui, store: &Store) {
    let stats = &store.stats;
    ui.label(format!(
        "Packets {}    Bytes {}    {} pkt/s    {} B/s    Connections {}    Decode errors {}    Ring {}",
        stats.packets,
        stats.bytes,
        stats.last_packets,
        stats.last_bytes,
        store.conns.len(),
        store.decode_errors,
        store.ring.len()
    ));
    let extra = breakdown(stats);
    if !extra.is_empty() {
        ui.label(egui::RichText::new(extra).weak());
    }
}

/// Краткая разбивка по направлению / L4 / IP / EtherType — только ненулевые.
fn breakdown(stats: &Stats) -> String {
    let mut parts = Vec::new();
    push_counts(&mut parts, &store::DIR_NAMES, &stats.dir);
    push_counts(&mut parts, &store::L4_NAMES, &stats.l4);
    push_counts(&mut parts, &store::IP_NAMES, &stats.ip);
    push_counts(&mut parts, &store::ETH_NAMES, &stats.eth);
    parts.join("   ")
}

fn push_counts(parts: &mut Vec<String>, names: &[&str], tots: &[Tot]) {
    for (name, tot) in names.iter().zip(tots) {
        if tot.pkts > 0 {
            parts.push(format!("{name} {}", tot.pkts));
        }
    }
}

/// Полоса вкладок: выбор, Rename/Close по правому клику, «+» и Follow.
/// Действия с вкладками копятся и применяются после рисования — нельзя менять `tabs` внутри цикла.
fn tab_bar(ui: &mut egui::Ui, tabs: &mut Vec<Tab>, active: &mut usize, next_id: &mut u64) {
    let mut add = None;
    let mut close = None;
    let mut start_rename = None;
    ui.horizontal(|ui| {
        for i in 0..tabs.len() {
            if tabs[i].renaming {
                let resp =
                    ui.add(egui::TextEdit::singleline(&mut tabs[i].title).desired_width(140.0));
                if tabs[i].focus_rename {
                    resp.request_focus();
                    tabs[i].focus_rename = false;
                } else if resp.lost_focus() {
                    tabs[i].renaming = false;
                    if tabs[i].title.trim().is_empty() {
                        tabs[i].title = tabs[i].kind.label().to_string();
                    }
                }
            } else {
                let resp = ui.selectable_label(*active == i, &tabs[i].title);
                if resp.clicked() {
                    *active = i;
                }
                resp.context_menu(|ui| {
                    if ui.button("Rename").clicked() {
                        start_rename = Some(i);
                        ui.close();
                    }
                    if ui.button("Close").clicked() {
                        close = Some(i);
                        ui.close();
                    }
                });
            }
        }
        ui.menu_button("+", |ui| {
            if ui.button("Packets").clicked() {
                add = Some(TabKind::Packets);
                ui.close();
            }
            if ui.button("Connections").clicked() {
                add = Some(TabKind::Connections);
                ui.close();
            }
        });
        if tabs
            .get(*active)
            .is_some_and(|tab| tab.kind == TabKind::Packets && !tab.autoscroll)
        {
            if ui.button("Follow").clicked() {
                tabs[*active].autoscroll = true;
                tabs[*active].last_offset = None;
            }
        }
    });
    if let Some(kind) = add {
        add_tab(tabs, active, next_id, kind);
    }
    if let Some(i) = close {
        close_tab(tabs, active, i);
    }
    if let Some(i) = start_rename {
        if let Some(tab) = tabs.get_mut(i) {
            tab.renaming = true;
            tab.focus_rename = true;
        }
    }
}

/// Новая вкладка получает уникальный `id` и становится активной.
fn add_tab(tabs: &mut Vec<Tab>, active: &mut usize, next_id: &mut u64, kind: TabKind) {
    let n = tabs.iter().filter(|tab| tab.kind == kind).count() + 1;
    let title = if n == 1 {
        kind.label().to_string()
    } else {
        format!("{} {n}", kind.label())
    };
    let id = *next_id;
    *next_id += 1;
    tabs.push(Tab::new(id, title, kind));
    *active = tabs.len() - 1;
}

/// Закрытие сдвигает `active`, чтобы он оставался валидным индексом.
fn close_tab(tabs: &mut Vec<Tab>, active: &mut usize, idx: usize) {
    if idx >= tabs.len() {
        return;
    }
    tabs.remove(idx);
    if tabs.is_empty() {
        *active = 0;
    } else if idx < *active {
        *active -= 1;
    } else if *active >= tabs.len() {
        *active = tabs.len() - 1;
    }
}

/// Таблица пакетов: фильтр → индексы в кольце → виртуальные строки.
/// Клик раскрывает полный `Display` под строкой; прокрутка вверх гасит autoscroll.
fn packets(ui: &mut egui::Ui, global: &Filter, tab: &mut Tab, store: &Store) {
    let idx: Vec<usize> = store
        .ring
        .iter()
        .enumerate()
        .filter(|(_, row)| filter::visible_row(global, &tab.filter, row))
        .map(|(i, _)| i)
        .collect();
    if store.ring.is_empty() {
        ui.label("no packets yet");
        return;
    }
    if idx.is_empty() {
        ui.label("no packets match the filter");
        return;
    }
    ui.label(format!("{} shown", idx.len()));

    let expanded = tab.expanded;
    let follow = tab.autoscroll;
    let prev_offset = tab.last_offset;
    let tab_id = tab.id;
    let detail = expanded.and_then(|seq| {
        idx.iter()
            .find(|&&i| store.ring[i].seq == seq)
            .map(|&i| format!("{}", store.ring[i].data))
    });
    let heights: Vec<f32> = idx
        .iter()
        .map(|&i| row_height(expanded == Some(store.ring[i].seq), &detail))
        .collect();

    let mut toggle = None;
    let output = TableBuilder::new(ui)
        .id_salt(("pk", tab_id))
        .striped(true)
        .resizable(true)
        .sense(egui::Sense::click())
        .stick_to_bottom(follow)
        .auto_shrink(egui::Vec2b::FALSE)
        .column(Column::exact(64.0))
        .column(Column::exact(108.0))
        .column(Column::exact(40.0))
        .column(Column::initial(64.0))
        .column(Column::initial(150.0).clip(true).at_least(80.0))
        .column(Column::initial(150.0).clip(true).at_least(80.0))
        .column(Column::initial(96.0))
        .column(Column::exact(72.0))
        .column(Column::remainder().clip(true).at_least(120.0))
        .header(22.0, |mut header| {
            for title in [
                "#", "Time", "Dir", "L2", "Src", "Dst", "Proto", "Len", "Info",
            ] {
                header.col(|ui| {
                    ui.strong(title);
                });
            }
        })
        .body(|body| {
            body.heterogeneous_rows(heights.into_iter(), |mut row| {
                let item = &store.ring[idx[row.index()]];
                let open = expanded == Some(item.seq);
                row.set_selected(open);
                cell(&mut row, &item.seq.to_string());
                cell(&mut row, &item.time);
                cell(&mut row, &item.dir);
                cell(&mut row, &item.l2);
                cell(&mut row, &item.src);
                cell(&mut row, &item.dst);
                cell(&mut row, &item.proto);
                cell(&mut row, &item.len.to_string());
                row.col(|ui| {
                    ui.add(egui::Label::new(&item.info).truncate());
                    if open {
                        if let Some(text) = &detail {
                            ui.add(
                                egui::Label::new(egui::RichText::new(text).monospace().size(12.0))
                                    .wrap(),
                            );
                        }
                    }
                });
                if row.response().clicked() {
                    toggle = Some(item.seq);
                }
            });
        });

    let offset = output.state.clamped_offset().y;
    let max_y = (output.content_size.y - output.inner_rect.height()).max(0.0);
    if follow {
        if let Some(prev) = prev_offset {
            if offset + 8.0 < prev && max_y - offset > 24.0 {
                tab.autoscroll = false;
            }
        }
    }
    tab.last_offset = Some(offset);
    if let Some(seq) = toggle {
        if tab.expanded == Some(seq) {
            tab.expanded = None;
        } else {
            tab.expanded = Some(seq);
            tab.autoscroll = false;
        }
    }
}

/// Раскрытая строка выше: считаем строки текста (~110 символов на линию).
fn row_height(open: bool, detail: &Option<String>) -> f32 {
    if !open {
        return ROW_H;
    }
    let Some(text) = detail else { return ROW_H };
    let lines = text
        .lines()
        .map(|line| line.len().div_ceil(110).max(1))
        .sum::<usize>()
        .max(1);
    ROW_H + 8.0 + lines as f32 * 15.0
}

/// Соединения: свежие сверху, байты в обе стороны отдельно.
fn connections(ui: &mut egui::Ui, global: &Filter, local: &Filter, store: &Store, tab_id: u64) {
    let mut rows: Vec<(&ConnKey, &ConnRec)> = store
        .conns
        .iter()
        .filter(|(key, rec)| filter::visible_conn(global, local, key, rec))
        .collect();
    rows.sort_by(|a, b| b.1.last.cmp(&a.1.last));
    if rows.is_empty() {
        let text = if store.conns.is_empty() {
            "no connections yet"
        } else {
            "no connections match the filter"
        };
        ui.label(text);
        return;
    }
    ui.label(format!("{} shown", rows.len()));
    TableBuilder::new(ui)
        .id_salt(("cn", tab_id))
        .striped(true)
        .resizable(true)
        .auto_shrink(egui::Vec2b::FALSE)
        .column(Column::initial(110.0))
        .column(Column::initial(180.0).clip(true).at_least(80.0))
        .column(Column::remainder().clip(true).at_least(80.0))
        .column(Column::exact(80.0))
        .column(Column::exact(90.0))
        .column(Column::exact(80.0))
        .column(Column::exact(90.0))
        .column(Column::exact(64.0))
        .header(22.0, |mut header| {
            for title in [
                "Proto",
                "A",
                "B",
                "Pkts A→B",
                "Bytes A→B",
                "Pkts B→A",
                "Bytes B→A",
                "Idle",
            ] {
                header.col(|ui| {
                    ui.strong(title);
                });
            }
        })
        .body(|body| {
            body.rows(ROW_H, rows.len(), |mut row| {
                let (key, rec) = rows[row.index()];
                let secs = rec.last.elapsed().as_secs();
                let idle = if secs < 60 {
                    format!("{secs}s")
                } else {
                    format!("{}m{}s", secs / 60, secs % 60)
                };
                cell(&mut row, &conn_proto(key, rec));
                cell(&mut row, &format!("{}:{}", key.a, key.pa));
                cell(&mut row, &format!("{}:{}", key.b, key.pb));
                cell(&mut row, &rec.pkts_ab.to_string());
                cell(&mut row, &rec.bytes_ab.to_string());
                cell(&mut row, &rec.pkts_ba.to_string());
                cell(&mut row, &rec.bytes_ba.to_string());
                cell(&mut row, &idle);
            });
        });
}

/// Подпись протокола в таблице соединений (TCP или UDP/приложение).
fn conn_proto(key: &ConnKey, rec: &ConnRec) -> String {
    match key.proto {
        ConnProto::Tcp => "TCP".to_string(),
        ConnProto::Udp if rec.udp_app == common::UdpApp::Other => "UDP".to_string(),
        ConnProto::Udp => format!("UDP/{}", rec.udp_app),
    }
}

/// Ячейка с обрезкой длинного текста.
fn cell(row: &mut egui_extras::TableRow<'_, '_>, text: &str) {
    row.col(|ui| {
        ui.add(egui::Label::new(text).truncate());
    });
}
