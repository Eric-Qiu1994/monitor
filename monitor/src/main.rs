mod api;
mod db;
mod geo;
mod host;
mod notify;

use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// 轻量服务器探针 — 主服务端
#[derive(Debug, Parser)]
#[command(name = "monitor", version, about = "Rust 轻量服务器探针 · 主服务")]
struct Cli {
    /// 监听地址
    #[arg(long, env = "MONITOR_LISTEN", default_value = "0.0.0.0:8080")]
    listen: SocketAddr,

    /// SQLite 数据库文件
    #[arg(long, env = "MONITOR_DB", default_value = "/data/monitor.db")]
    db: PathBuf,

    /// agent 上报鉴权 token（留空则不校验，仅建议内网使用）
    #[arg(long, env = "MONITOR_TOKEN")]
    token: Option<String>,

    /// 采样保留天数
    #[arg(long, env = "MONITOR_RETENTION_DAYS", default_value_t = 7)]
    retention_days: u32,

    /// 每台服务器最多保留的采样条数（硬上限，防爆盘）
    #[arg(long, env = "MONITOR_MAX_ROWS_PER_SERVER", default_value_t = 20_000)]
    max_rows_per_server: u32,

    /// 清理任务间隔（秒）
    #[arg(long, env = "MONITOR_CLEANUP_INTERVAL", default_value_t = 600)]
    cleanup_interval: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    let retention = api::retention_from(cli.retention_days, cli.max_rows_per_server);
    let db = db::open(&cli.db).context("初始化数据库失败")?;

    // 启动时先清一次，重启后立刻把超限数据压下去
    {
        let conn = db.lock().unwrap();
        match db::cleanup(&conn, retention) {
            Ok(s) => log::info!(
                "启动清理完成: 删除 {} 条采样, vacuum={}",
                s.metrics_deleted,
                s.vacuumed
            ),
            Err(e) => log::warn!("启动清理失败: {e:#}"),
        }
    }

    // 后台定期清理 —— 这是容器不爆盘的主要保障
    {
        let db = db.clone();
        let every = Duration::from_secs(cli.cleanup_interval.max(30));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.tick().await; // 首次立刻触发已在上面做过，跳过
            loop {
                tick.tick().await;
                // 保留天数以后台设置为准（0 = 用环境变量值）
                let days = {
                    let conn = db.lock().unwrap();
                    db::kv_get(&conn, "retention_days", "").parse::<u32>().ok()
                };
                let ret = api::retention_from(
                    days.unwrap_or(retention.days),
                    retention.max_rows_per_server,
                );
                let conn = db.lock().unwrap();
                match db::cleanup(&conn, ret) {
                    Ok(s) if s.metrics_deleted > 0 || s.vacuumed => log::info!(
                        "定期清理: 删除 {} 条采样, vacuum={}",
                        s.metrics_deleted,
                        s.vacuumed
                    ),
                    Ok(_) => log::debug!("定期清理: 无需删除"),
                    Err(e) => log::warn!("定期清理失败: {e:#}"),
                }
            }
        });
    }

    let state = api::AppState {
        db: db.clone(),
        token: cli.token.clone(),
        host: std::sync::Arc::new(host::HostSampler::start()),
    };
    let app = api::router(state);

    // 网站监控线程：阻塞 HTTP 检查放独立线程池线程，不阻塞 tokio runtime
    {
        let db = db.clone();
        std::thread::spawn(move || site_checker_loop(db));
    }
    // 离线通知线程
    {
        let db = db.clone();
        std::thread::spawn(move || offline_notify_loop(db));
    }

    // 运行时保留天数可被后台设置覆盖：清理任务里动态读取

    log::info!("monitor 监听 http://{}", cli.listen);
    if cli.token.is_none() {
        log::warn!("未设置 MONITOR_TOKEN，写接口无鉴权，请勿暴露到公网");
    }

    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .with_context(|| format!("bind {}", cli.listen))?;
    // into_make_service_with_connect_info：/api/report 需要拿 agent 来源 IP 做地理定位
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    log::info!("已退出");
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// 网站监控循环：每 5s 醒来，检查到期的站点（同步 ureq）。
/// ponytail: 串行检查，站点多且慢时可能拖长周期；并发需求上再改线程池。
fn site_checker_loop(db: db::Db) {
    let agent_cfg = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(10)))
        .build();
    let agent = ureq::Agent::new_with_config(agent_cfg);
    loop {
        let due: Vec<db::SiteRow> = {
            let conn = db.lock().unwrap();
            let now = chrono::Utc::now();
            match db::enabled_sites(&conn) {
                Ok(v) => v
                    .into_iter()
                    .filter(|s| {
                        let last = s
                            .last_check
                            .as_deref()
                            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                            .map(|t| t.with_timezone(&chrono::Utc));
                        match last {
                            None => true,
                            Some(t) => now.signed_duration_since(t)
                                >= chrono::Duration::seconds(s.interval_s as i64),
                        }
                    })
                    .collect(),
                Err(_) => Vec::new(),
            }
        };
        for site in due {
            let start = std::time::Instant::now();
            let ok = agent
                .get(&site.url)
                .call()
                .map(|r| r.status().as_u16() as u32)
                .unwrap_or(0);
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            let healthy = (200..400).contains(&ok);
            let now_str = db::now_str();
            {
                let conn = db.lock().unwrap();
                let _ = db::site_check_done(&conn, site.id, ok, ms, &now_str);
            }
            if !healthy && ok != site.last_status {
                // 状态翻转：正常→异常，发通知
                let conn = db.lock().unwrap();
                let cfg = notify::load_config(&conn);
                if cfg.site_on {
                    let text = format!("网站异常: {} ({}) 返回状态 {}", site.name, site.url, ok);
                    notify::send(&db, &cfg, "site", &text);
                }
                let _ = db::site_notify_done(&conn, site.id, &now_str);
            }
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

/// 离线通知循环：每 30s 检查一次状态翻转的服务器。
/// 状态机：
///   离线→在线：发一次恢复通知
///   在线→离线：发一次离线通知
/// ponytail: 状态全靠 HashSet 记忆，进程重启会把"已知离线"判为"刚离线"重发一次，可接受。
fn offline_notify_loop(db: db::Db) {
    // true = 上次看到时在线，false = 上次看到时离线；不在集合内视为首次观察。
    let mut prev_online: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    loop {
        std::thread::sleep(Duration::from_secs(30));
        let cfg = {
            let conn = db.lock().unwrap();
            notify::load_config(&conn)
        };
        if cfg.url.is_empty() {
            continue;
        }
        let interval = {
            let conn = db.lock().unwrap();
            db::kv_get(&conn, "report_interval", "0").parse::<u64>().unwrap_or(0)
        };
        let servers = {
            let conn = db.lock().unwrap();
            db::servers(&conn).unwrap_or_default()
        };
        let now = chrono::Utc::now();
        let now_str = db::now_str();
        for s in servers {
            let last = chrono::DateTime::parse_from_rfc3339(&s.last_seen)
                .ok()
                .map(|t| t.with_timezone(&chrono::Utc));
            // 每台单独设置的上报间隔优先；0 = 全局
            let eff_interval = if s.report_interval > 0 { s.report_interval } else { interval };
            let online = match last {
                Some(t) => now.signed_duration_since(t)
                    < chrono::Duration::seconds(api::online_window_secs(eff_interval)),
                None => false,
            };
            let prev = prev_online.get(&s.id).copied();
            let node = if s.hostname.is_empty() || s.name == s.hostname {
                s.name.clone()
            } else {
                format!("{} {}", s.name, s.hostname)
            };
            // 格式化 last_seen -> "YYYY-MM-DD HH:MM:SS"
            let last_str = match last {
                Some(t) => t.format("%Y-%m-%d %H:%M:%S").to_string(),
                None => "未知".to_string(),
            };
            if online {
                if prev == Some(false) {
                    // 离线 → 在线：发恢复通知
                    if cfg.offline_on {
                        let msg = format!("节点已恢复上报；最新上报 {last_str}");
                        let text = notify::render_tpl(&cfg.recover_tpl, &node, &msg, &now_str);
                        notify::send(&db, &cfg, "recover", &text);
                    }
                }
                prev_online.insert(s.id.clone(), true);
            } else {
                if prev == Some(true) {
                    // 在线 → 离线：发离线通知
                    if cfg.offline_on {
                        let offline_secs = match last {
                            Some(t) => now.signed_duration_since(t).num_seconds().max(0),
                            None => 0,
                        };
                        let mins = offline_secs / 60;
                        let msg = format!("离线 {mins} 分钟；最后上报 {last_str}");
                        let text = notify::render_tpl(&cfg.offline_tpl, &node, &msg, &now_str);
                        notify::send(&db, &cfg, "offline", &text);
                    }
                }
                prev_online.insert(s.id.clone(), false);
            }
        }
    }
}