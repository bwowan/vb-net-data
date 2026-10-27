//! Нативный GUI. Кадры приходят датаграммами от `net_listener` (`ipc_sender`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use net_visualizator::app::App;
use net_visualizator::source::{DataSource, UdsSource};
use net_visualizator::store::Store;

const DEFAULT_LISTENER: &str = "/tmpu/net_listener_stats2.sock"; // сокет `net_listener` (`SOCKET_PATH` в его `main`)
const DEFAULT_SOCKET: &str = "/tmpu/net_visualizator.sock"; // наш сокет: без bind клиенту некому отвечать
const BATCH_MAX: usize = 64; // сколько кадров копить, прежде чем брать мьютекс Store
const BATCH_WAIT: Duration = Duration::from_millis(20); // или сколько ждать пачку, если кадров меньше
const LINK_EVERY: Duration = Duration::from_millis(100); // даже без кадров раз в это время обновляем линк в Store
const IDLE_SLEEP: Duration = Duration::from_millis(2); // пауза при пустом `poll`, как у `ipc_sender`

struct Args {
    listener: String, // путь сокета `net_listener`
    socket: String,   // путь, который биндим сами
}

fn main() -> Result<()> {
    let args = parse_args()?;
    init_log()?;

    let source = UdsSource::open(&args.socket, &args.listener)
        .with_context(|| format!("bind {}", args.socket))?;
    let store = Arc::new(Mutex::new(Store::new()));
    let paused = Arc::new(AtomicBool::new(false));
    let shutdown = Arc::new(AtomicBool::new(false));

    // Приём в отдельном потоке: UI не должен блокироваться на UDS.
    let rx = {
        let store = Arc::clone(&store);
        let paused = Arc::clone(&paused);
        let shutdown = Arc::clone(&shutdown);
        thread::Builder::new()
            .name("netviz-rx".into())
            .spawn(move || {
                receive(source, store, paused, shutdown);
            })?
    };

    let app_store    = Arc::clone(&store);
    let app_paused   = Arc::clone(&paused);
    let app_shutdown = Arc::clone(&shutdown);
    let listener = args.listener.clone();
    let native = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_maximized(true)
            .with_title("Net Visualizator"),
        ..Default::default()
    };
    let run = eframe::run_native(
        "net_visualizator",
        native,
        Box::new(move |_cc| {
            Ok(Box::new(App::new(
                app_store,
                app_paused,
                app_shutdown,
                listener,
            )))
        }),
    );
    // Окно закрыто (или упало): просим поток приёма выйти и ждём его.
    shutdown.store(true, Ordering::Relaxed);
    let _ = rx.join();
    run.map_err(|err| anyhow!(err))?;
    Ok(())
}

/// `poll` не блокируется. Пустой ответ — сон 2 мс. В мьютекс кладём пачку,
/// не каждый кадр: до 64 штук или 20 мс. Состояние линка обновляется и без кадров.
fn receive(
    mut source: UdsSource,
    store: Arc<Mutex<Store>>,
    paused: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
) {
    let mut batch = Vec::new();
    let mut scratch = Vec::new();
    let mut last_flush = Instant::now();
    while !shutdown.load(Ordering::Relaxed) {
        scratch.clear();
        source.poll(&mut scratch);
        let idle = scratch.is_empty();
        batch.append(&mut scratch);
        let age = last_flush.elapsed();
        let flush = batch.len() >= BATCH_MAX
            || (!batch.is_empty() && age >= BATCH_WAIT)
            || age >= LINK_EVERY;
        if flush {
            let mut guard = store.lock().unwrap_or_else(|err| err.into_inner());
            // Пауза: статистика и соединения растут, кольцо не пишется.
            let keep = !paused.load(Ordering::Relaxed);
            for data in batch.drain(..) {
                guard.ingest(data, keep);
            }
            guard.tick();
            guard.evict_conns();
            guard.set_link(source.state());
            guard.set_decode_errors(source.decode_errors());
            last_flush = Instant::now();
        }
        if idle {
            thread::sleep(IDLE_SLEEP);
        }
    }
}

/// Лог в файл, как у `net_listener`: stdout занят окном / отладчиком.
fn init_log() -> Result<()> {
    let log_file = match std::fs::File::create("/tmpu/net_visualizator.log") {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Failed to create /tmpu/net_visualizator.log: {err}");
            return Err(err.into());
        }
    };
    tracing_subscriber::fmt()
        .with_writer(log_file)
        .with_ansi(false)
        .try_init()
        .map_err(|err| anyhow!(err))?;
    Ok(())
}

fn parse_args() -> Result<Args> {
    let mut listener = DEFAULT_LISTENER.to_string();
    let mut socket = DEFAULT_SOCKET.to_string();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listener" => {
                listener = args
                    .next()
                    .ok_or_else(|| anyhow!("--listener needs a path"))?;
            }
            "--socket" => {
                socket = args
                    .next()
                    .ok_or_else(|| anyhow!("--socket needs a path"))?;
            }
            "-h" | "--help" => {
                usage();
                std::process::exit(0);
            }
            other => {
                usage();
                bail!("unknown argument {other}");
            }
        }
    }
    Ok(Args { listener, socket })
}

fn usage() {
    eprintln!(
        "\
net_visualizator [--listener PATH] [--socket PATH]

  --listener   сокет net_listener (по умолчанию {DEFAULT_LISTENER})
  --socket     наш сокет (по умолчанию {DEFAULT_SOCKET})"
    );
}
