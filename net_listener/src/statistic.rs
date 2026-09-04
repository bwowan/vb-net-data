use common;
use flume;
use tokio::time::{self, Duration};

pub async fn console_statistic(receiver: flume::Receiver<common::NetData>) 
{
    let mut stats = common::TrafficStats::default();
    let mut interval = time::interval(Duration::from_secs(5));
    interval.tick().await; // пропускаем первый мгновенный тик

    loop {
        tokio::select! {
            result = receiver.recv_async() => {
                match result {
                    Ok(data) => {
                        let len = match data.payload {
                            common::NetPayload::Ip(ip) => ip.len,
                            _ => 0,
                        };
                        match data.eth.dir {
                            common::EDirection::Outgoing => {
                                stats.tx_packets += 1;
                                stats.tx_bytes   += len as u64;
                            }
                            _ => {
                                stats.rx_packets += 1;
                                stats.rx_bytes   += len as u64;
                            }
                        }
                    }
                    Err(_) => {
                        // Канал закрыт, выводим итоговую статистику
                        print_stats(&stats);
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                //print_stats(&stats);
                stats = common::TrafficStats::default();
            }
        }
    }
}

fn print_stats(stats: &common::TrafficStats) {
    println!("{}", stats);
}
