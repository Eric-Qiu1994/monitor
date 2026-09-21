//! 探针 agent：采集本机指标并周期性 POST 到 monitor。

mod collect;

use anyhow::{Context, Result};
use clap::Parser;
use std::time::Duration;

/// 轻量服务器探针 — agent
#[derive(Debug, Parser)]
#[command(name = "monitor-agent", version, about = "Rust 轻量服务器探针 · agent")]
struct Cli {
    /// monitor 地址，例如 http://monitor.example.com:8080
    #[arg(long, env = "MONITOR_URL", default_value = "http://127.0.0.1:8080")]
    url: String,

    /// 上报 token，需与 monitor 的 MONITOR_TOKEN 一致
    #[arg(long, env = "MONITOR_TOKEN")]
    token: Option<String>,

    /// 上报间隔（秒）
    #[arg(long, env = "MONITOR_INTERVAL", default_value_t = 10)]
    interval: u64,

    /// 覆盖上报的主机名（默认取系统 hostname）
    #[arg(long, env = "MONITOR_HOSTNAME")]
    hostname: Option<String>,

    /// 出网 HTTP 代理，例如 http://172.16.1.1:1083
    #[arg(long, env = "MONITOR_PROXY")]
    proxy: Option<String>,

    /// 默认 ICMP 探测目标（后台登录后可覆盖；留空 = 不探测，检测点全部由后台下发）
    #[arg(long, env = "MONITOR_PING_TARGET", default_value = "")]
    ping_target: String,

    /// 探测方式：icmp / http / tcp（后台可覆盖）
    #[arg(long, env = "MONITOR_PING_METHOD", default_value = "icmp")]
    ping_method: String,

    /// 每轮 ping 包数（1–10）
    #[arg(long, env = "MONITOR_PING_COUNT", default_value_t = 3)]
    ping_count: u32,

    /// 只采集并打印一次，不上报（排障用）
    #[arg(long)]
    once: bool,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let endpoint = format!("{}/api/report", cli.url.trim_end_matches('/'));

    if cli.once {
        let local_cfg =
            collect::ProbeConfig::from_cli(&cli.ping_target, &cli.ping_method, cli.ping_count);
        let http = collect::build_agent(cli.proxy.as_deref())?;
        let cfg = collect::fetch_probe_config(
            &http,
            &cli.url,
            cli.token.as_deref(),
            &local_cfg,
            collect::effective_hostname(cli.hostname.as_deref()).as_deref(),
        );
        let r = collect::Collector::new(cli.hostname.as_deref())
            .sample_with_probe(&local_cfg, &cfg.targets)?;
        println!("{}", serde_json::to_string_pretty(&r)?);
        let errs = r.sanity_errors();
        if !errs.is_empty() {
            anyhow::bail!("采集数据未通过自检: {errs:?}");
        }
        println!("自检通过");
        return Ok(());
    }

    let agent = collect::build_agent(cli.proxy.as_deref().filter(|p| !p.trim().is_empty()))?;
    log::info!(
        "上报目标 {endpoint}，间隔 {}s{}",
        cli.interval,
        cli.proxy
            .as_deref()
            .map(|p| format!("，代理 {p}"))
            .unwrap_or_default()
    );

    let mut collector = collect::Collector::new(cli.hostname.as_deref().filter(|h| !h.trim().is_empty()));
    let local_cfg =
        collect::ProbeConfig::from_cli(&cli.ping_target, &cli.ping_method, cli.ping_count);
    // 探测配置由后台下发；拉取失败用 CLI 本地配置兜底
    // 带上有效 hostname，服务端据此套用该服务器的探测点排除表
    let host = collect::effective_hostname(cli.hostname.as_deref());
    let mut cfg = collect::fetch_probe_config(
        &agent,
        &cli.url,
        cli.token.as_deref(),
        &local_cfg,
        host.as_deref(),
    );
    // 上报间隔：后台 report_interval > 0 时用后台（覆盖 CLI），否则保留 CLI
    fn pick_interval(cli: u64, from_server: u64) -> u64 {
        if from_server > 0 { from_server.max(1) } else { cli.max(1) }
    }
    /// 分段睡眠：每小段结束前先刷新一次后台配置，间隔被调小时能提前醒来，
    /// 而不是傻等完旧的 5 分钟。间隔被调大时按新值重新睡（多睡的不退）。
    /// ponytail: 首轮上报在循环开头，间隔改动最多滞后 STEP 秒生效。
    const STEP: u64 = 15;
    let sleep_interval = |cfg: &mut collect::AgentProbeCfg| {
        let mut left = pick_interval(cli.interval, cfg.report_interval);
        while left > 0 {
            let nap = left.min(STEP);
            std::thread::sleep(Duration::from_secs(nap));
            left -= nap;
            *cfg = collect::fetch_probe_config(
                &agent,
                &cli.url,
                cli.token.as_deref(),
                &local_cfg,
                host.as_deref(),
            );
            left = left.min(pick_interval(cli.interval, cfg.report_interval));
        }
    };
    loop {
        // 单次上报：失败时按 fail_threshold × 10s 间隔快速重试；阈值内任意一次成功即落账。
        let threshold = cfg.fail_threshold.max(1);
        let mut attempt = 0u64;
        loop {
            match collector.sample_with_probe(&local_cfg, &cfg.targets) {
                Ok(r) => {
                    let errs = r.sanity_errors();
                    if !errs.is_empty() {
                        log::warn!("跳过本次上报，数据自检未通过: {errs:?}");
                        attempt += 1;
                    } else {
                        match post(&agent, &endpoint, cli.token.as_deref(), &r) {
                            Ok(()) => {
                                log::debug!("上报成功 cpu={:.1}%", r.cpu_usage);
                                break;
                            }
                            Err(e) => {
                                attempt += 1;
                                if attempt >= threshold {
                                    log::warn!(
                                        "上报连续失败 {attempt}/{threshold} 次（不计入离线统计），最后一次: {e:#}"
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    attempt += 1;
                    if attempt >= threshold {
                        log::warn!("采集连续失败 {attempt}/{threshold} 次: {e:#}");
                    }
                }
            }
            // 失败后 10s 重试；阈值未满则继续尝试，满了则退出内层、睡整段
            if attempt < threshold {
                std::thread::sleep(Duration::from_secs(10));
                // 期间允许后台配置变化（如阈值/间隔调小）
                cfg = collect::fetch_probe_config(
                    &agent,
                    &cli.url,
                    cli.token.as_deref(),
                    &local_cfg,
                    host.as_deref(),
                );
                continue;
            }
            break;
        }
        // 睡眠期间分段刷新后台配置，间隔改动最多滞后 STEP 秒生效
        sleep_interval(&mut cfg);
    }
}

fn post(
    agent: &ureq::Agent,
    endpoint: &str,
    token: Option<&str>,
    r: &monitor_common::Report,
) -> Result<()> {
    let mut req = agent.post(endpoint);
    if let Some(t) = token {
        req = req.header("x-token", t);
    }
    let resp = req.send_json(r).context("HTTP 请求失败")?;
    let status = resp.status();
    if status != 200 {
        anyhow::bail!("monitor 返回 {status}");
    }
    Ok(())
}
