use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::Result;
use bevy::prelude::*;
use common::{NetMessage, TrafficStats};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

/// Сообщение от потока приема к Bevy.
#[derive(Debug)]
enum StatsMessage {
    Update(TrafficStats),
}

/// Обертка над TrafficStats для использования как Bevy Resource.
#[derive(Resource, Debug, Clone)]
struct TrafficStatsResource(TrafficStats);

impl Default for TrafficStatsResource {
    fn default() -> Self {
        Self(TrafficStats::default())
    }
}

impl std::ops::Deref for TrafficStatsResource {
    type Target = TrafficStats;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for TrafficStatsResource {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

fn main() -> Result<()> {
    // Канал между потоком приема UDS и Bevy-миром.
    let (stats_tx, stats_rx) = mpsc::unbounded_channel::<StatsMessage>();

    // Первый поток: прием статистики по Unix Domain Socket.
    let socket_path = "/tmp/net_visualizator_stats.sock";
    let _ = std::fs::remove_file(socket_path);
    let uds = UnixDatagram::bind(socket_path)?;
    uds.set_nonblocking(true)?;
    let uds = Arc::new(uds);

    let _receiver_thread = {
        let uds = uds.clone();
        let stats_tx = stats_tx.clone();
        thread::spawn(move || loop {
            let mut buf = [0u8; 2048];
            match uds.recv(&mut buf) {
                Ok(len) => {
                    let slice = &buf[..len];
                    if let Ok(message) = serde_json::from_slice::<NetMessage>(slice) {
                        match message {
                            NetMessage::TrafficStats(stats) => {
                                let _ = stats_tx.send(StatsMessage::Update(stats));
                            }
                        }
                    }
                }
                Err(_) => {
                    // Неблокирующий сокет — просто подождем чуть-чуть.
                    thread::sleep(Duration::from_millis(100));
                }
            }
        })
    };

    // Второй «поток» — Bevy (внутри много собственных потоков).
    // Оборачиваем tokio-runtime, чтобы иметь возможность non-blocking получать
    // статистику и класть её в ресурс Bevy.
    let rt = Runtime::new()?;

    App::new()
        .insert_resource(TrafficStatsResource::default())
        .insert_resource(StatsChannel { rt, stats_rx })
        .add_plugins(DefaultPlugins.set(WindowPlugin {
            primary_window: Some(Window {
                title: "Net Visualizator - Overview".into(),
                resolution: (1280_f32, 720_f32).into(),
                ..Default::default()
            }),
            ..Default::default()
        }))
        // Дополнительное окно с другими данными (пока просто пустое).
        .add_systems(Startup, setup_windows)
        .add_systems(Startup, setup_scene)
        .add_systems(Update, (pull_stats_from_channel, animate_from_stats))
        .run();

    // App::run() не возвращает управление
    Ok(())
}

/// Ресурс, обеспечивающий доступ к каналу и tokio-runtime
/// для неблокирующего приема статистики.
#[derive(Resource)]
struct StatsChannel {
    rt: Runtime,
    stats_rx: mpsc::UnboundedReceiver<StatsMessage>,
}

fn setup_windows(mut commands: Commands) {
    // Вторичное окно — позже здесь можно будет рисовать другой тип статистики.
    commands.spawn(Window {
        title: "Net Visualizator - Details".into(),
        resolution: (800_f32, 600_f32).into(),
        ..Default::default()
    });
}

fn setup_scene(
    mut commands: Commands,
    mut meshes: ResMut<Assets<Mesh>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
) {
    // Камера
    commands.spawn(Camera3dBundle::default());

    // Примитивный объект, который будем анимировать в зависимости от статистики.
    commands.spawn((
        PbrBundle {
            mesh: meshes.add(Cuboid::new(1.0, 1.0, 1.0)),
            material: materials.add(StandardMaterial {
                base_color: Color::srgb(0.0, 1.0, 0.0),
                ..Default::default()
            }),
            transform: Transform::from_xyz(0.0, 0.5, 0.0),
            ..Default::default()
        },
        StatsVisualMarker,
    ));

    // Источник света.
    commands.spawn(PointLightBundle {
        point_light: PointLight {
            intensity: 1500.0,
            shadows_enabled: true,
            ..Default::default()
        },
        transform: Transform::from_xyz(4.0, 8.0, 4.0),
        ..Default::default()
    });
}

#[derive(Component)]
struct StatsVisualMarker;

/// Забираем статистику из канала и обновляем ресурс `TrafficStatsResource`.
fn pull_stats_from_channel(
    mut stats: ResMut<TrafficStatsResource>,
    mut stats_chan: ResMut<StatsChannel>,
) {
    // Получаем все доступные сообщения, не блокируясь на кадр.
    // Используем try_recv для неблокирующего получения
    loop {
        match stats_chan.stats_rx.try_recv() {
            Ok(StatsMessage::Update(new_stats)) => {
                stats.0 = new_stats;
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                // Нет сообщений, выходим
                break;
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                // Канал закрыт
                break;
            }
        }
    }
}

/// Простая «3D-визуализация» — меняем размер/позицию объекта в зависимости от трафика.
fn animate_from_stats(
    stats: Res<TrafficStatsResource>,
    mut query: Query<&mut Transform, With<StatsVisualMarker>>,
) {
    if !stats.is_changed() {
        return;
    }

    let total_packets = stats.total_packets() as f32;
    let scale = 1.0 + (total_packets.log10().max(0.0) * 0.1);

    for mut transform in &mut query {
        transform.scale = Vec3::splat(scale);
        transform.translation.y = 0.5 * scale;
    }
}

