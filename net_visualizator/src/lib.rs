//! Переносимое ядро GUI. Нативный вход — `main.rs`, сокет — только `UdsSource`.
//! Время берётся из `web_time`: `std::time::Instant::now` в wasm32 паникует.
//!
//! Модули:
//! - [`app`] — окно egui (вкладки, таблицы, пауза);
//! - [`store`] — кольцо кадров, статистика, соединения;
//! - [`source`] — trait `DataSource` и Unix-клиент;
//! - [`filter`] — глобальный и локальный фильтр (AND);
//! - [`row`] — одна строка таблицы из `NetData`.

pub mod app;
pub mod filter;
pub mod row;
pub mod source;
pub mod store;
