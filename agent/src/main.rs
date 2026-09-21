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

    /// 反向通道监听地址：中心机可通过 GET /trigger?token=... 触发 agent 立即上报
    /// 设为 0.0.0.0:0 = 禁用；典型部署 0.0.0.0:9119
    /// ponytail: 默认开 0.0.0.0:9119；要硬关闭显式传 --listen 127.0.0.1:0
    #[arg(long, env = "MONITOR_AGENT_LISTEN", default_value = "0.0.0.0:9119")]
    listen: String,

    /// 反向通道令牌：启动时随机生成（持久化到 /etc/monitor-agent.token 与 install.sh 共享部署形态）
    /// ponytail: 写到磁盘是因为 systemd 重启要保留，否则 token 每次都变、monitor 端记录就废了
    #[arg(long, env = "MONITOR_AGENT_TOKEN")]
    listen_token: Option<String>,

    /// 反向连接地址：monitor 端用来触发本机的 IP（NAT 主机场景填公网可达 IP/DNS）；
    /// 空时 monitor 自动用上次上报的来源 IP——同网部署不用填
    #[arg(long, env = "MONITOR_AGENT_ADDR")]
    agent_addr: Option<String>,
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

    // 反向通道令牌：CLI/env 没传 → 持久化到 /etc/monitor-agent.token（与 install.sh 配套）
    let token_path = std::path::Path::new("/etc/monitor-agent.token");
    let listen_token: String = if let Some(t) = cli.listen_token.clone() {
        if t.trim().is_empty() { read_or_create_token(token_path) } else { t }
    } else {
        read_or_create_token(token_path)
    };
    log::info!("反向通道令牌长度 {} 字符（保存于 {}）", listen_token.len(), token_path.display());

    // 主动上报触发 flag + 版本
    let trigger = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let self_version = env!("CARGO_PKG_VERSION").to_string();
    // 启动 HTTP 监听（独立线程）
    {
        let trigger = trigger.clone();
        let token = listen_token.clone();
        let listen = cli.listen.clone();
        std::thread::spawn(move || run_trigger_listener(&listen, &token, trigger));
    }
    // 启动自更新检查（独立线程，每 30 分钟一次，不阻塞上报循环）
    {
        let url = cli.url.clone();
        let token = cli.token.clone();
        let proxy = cli.proxy.clone();
        let ver = self_version.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(30 * 60));
            if let Err(e) = check_self_update(&url, token.as_deref(), proxy.as_deref(), &ver) {
                log::debug!("自更新检查：{e:#}");
            }
        });
    }

    let mut collector = collect::Collector::new(cli.hostname.as_deref().filter(|h| !h.trim().is_empty()));
    collector.listen_port = listen_port_from(&cli.listen);
    collector.agent_token = listen_token.clone();
    collector.agent_addr = cli.agent_addr.clone().unwrap_or_default().trim().to_string();
    let self_version = collector.client_version.clone();
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
    // 拉取式指令轮询：与配置刷新共用 15s 节拍。trigger → 立即上报；update → 自更新。
    let poll_cmds = |trigger: &std::sync::Arc<std::sync::atomic::AtomicBool>,
                     self_version: &str| {
        let mut req = agent.get(&format!("{}/api/agent-cmd?hostname={}", cli.url.trim_end_matches('/'),
            urlencode(host.as_deref().unwrap_or_default())));
        if let Some(t) = cli.token.as_deref() {
            req = req.header("x-token", t);
        }
        let Ok(mut resp) = req.call() else { return; };
        let Ok(body) = resp.body_mut().read_to_vec() else { return; };
        let Ok(cmd) = serde_json::from_slice::<serde_json::Value>(&body) else { return; };
        if cmd.get("trigger").and_then(|v| v.as_bool()) == Some(true) {
            log::info!("轮询收到主动触发指令");
            trigger.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        if cmd.get("update").and_then(|v| v.as_bool()) == Some(true) {
            // 版本落后的信号（monitor 比对了 client_version）→ 立刻查详细版本并自更新
            if let Err(e) = check_self_update(&cli.url, cli.token.as_deref(), cli.proxy.as_deref(), self_version) {
                log::debug!("自更新: {e:#}");
            }
        }
    };
    let sleep_interval = |cfg: &mut collect::AgentProbeCfg| {
        let mut left = pick_interval(cli.interval, cfg.report_interval);
        while left > 0 {
            let nap = left.min(STEP);
            std::thread::sleep(Duration::from_secs(nap));
            left -= nap;
            poll_cmds(&trigger, &self_version);
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
        // 主动触发命中（中心机 GET /trigger）→ 立即采+上报，不等间隔。
        if trigger.swap(false, std::sync::atomic::Ordering::Relaxed) {
            log::info!("收到主动触发指令，跳过等待立即上报");
            post_report(&agent, &endpoint, cli.token.as_deref(), &mut collector, &local_cfg, &cfg.targets);
        }
        // 每次上报后查一次版本（自更新线程 30 分钟一轮；这里只是保险，每次上报都问一次也只多一个 GET）
        check_self_update(&cli.url, cli.token.as_deref(), cli.proxy.as_deref(), &self_version).ok();
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

/// 采+上报一次完整流程（供主动触发复用）
fn post_report(
    agent: &ureq::Agent,
    endpoint: &str,
    auth_token: Option<&str>,
    collector: &mut collect::Collector,
    local_cfg: &collect::ProbeConfig,
    targets: &[collect::ProbeTarget],
) -> bool {
    match collector.sample_with_probe(local_cfg, targets) {
        Ok(r) => {
            let errs = r.sanity_errors();
            if !errs.is_empty() {
                log::warn!("主动触发上报自检失败：{errs:?}");
                return false;
            }
            post(agent, endpoint, auth_token, &r).is_ok()
        }
        Err(e) => {
            log::warn!("主动触发采集失败: {e:#}");
            false
        }
    }
}

/// 读取或生成并写回 token（持久化到 /etc/monitor-agent.token）
/// ponytail: 文件权限 0600 就行；要严格 chmod 给 systemd service 的 Runtime=ReadOnlyPaths 留接口再说
fn read_or_create_token(path: &std::path::Path) -> String {
    if let Ok(s) = std::fs::read_to_string(path) {
        let s = s.trim().to_string();
        if !s.is_empty() { return s; }
    }
    // 16 字节随机 → 32 hex 字符
    let mut buf = [0u8; 16];
    // 读 /dev/urandom，失败兜底为 0（极低概率）
    let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| {
        use std::io::Read;
        f.read_exact(&mut buf)
    });
    let token: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    let _ = std::fs::write(path, &token);
    token
}

/// mini HTTP 监听：仅支持 GET /trigger?token=xxx，正确 token → 触发 flag。
/// ponytail: 单连接 + 立即关闭，无 keep-alive、无并发——触发频率 < 1/min，单连接足够。
fn run_trigger_listener(addr: &str, token: &str, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let listen = match std::net::TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => { log::warn!("反向通道 bind {addr} 失败：{e}"); return; }
    };
    log::info!("反向通道监听 {addr}（GET /trigger?token=...）");
    for stream in listen.incoming() {
        let Ok(mut s) = stream else { continue };
        use std::io::Read;
        let mut buf = [0u8; 1024];
        let n = match s.read(&mut buf) { Ok(n) => n, Err(_) => 0 };
        let req = String::from_utf8_lossy(&buf[..n]);
        // 仅解析第一行 GET /trigger?token=xxx HTTP/1.1
        let first = req.lines().next().unwrap_or("");
        let ok = first.contains("/trigger")
            && first.split(' ').nth(1).and_then(|p| {
                p.strip_prefix("/trigger?token=").map(|t| t == token)
            }).unwrap_or(false);
        let body = if ok {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
            r#"{"ok":true}"#
        } else {
            r#"{"ok":false,"err":"bad token"}"#
        };
        let resp = format!(
            "HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: {}
Connection: close

{}",
            body.len(), body
        );
        let _ = std::io::Write::write_all(&mut s, resp.as_bytes());
    }
}

/// 最小 percent-encode：query 参数安全字符之外全部转义
fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 解析 "0.0.0.0:9119" → 9119（失败兜底 0=关闭）
fn listen_port_from(s: &str) -> u16 {
    s.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(0)
}

/// 比对（tasker）中心机最新版本，低于则拉新二进制 + sha256 校验 + atomic rename。
/// 自更新：下载到原文件旁（foo.new），chmod +x，rename 覆盖；systemd Restart=always 自动拉起新二进制。
/// ponytail: 不杀自己进程——systemd 会在 exit 时立即拉起；当前进程负责下载+rename 然后退出。
///         这里只做"下载+rename"——exit 由 systemd 控制，本函数返回 Ok(true) 后调用方退出。
fn check_self_update(
    base_url: &str,
    auth_token: Option<&str>,
    proxy: Option<&str>,
    current_version: &str,
) -> Result<bool> {
    let mut agent = collect::build_agent(proxy.filter(|p| !p.trim().is_empty()))?;
    let info_url = format!("{}/api/agent-version", base_url.trim_end_matches('/'));
    let mut req = agent.get(&info_url);
    if let Some(t) = auth_token {
        req = req.header("x-token", t);
    }
    let mut resp = req.call().context("GET /api/agent-version")?;
    let info: serde_json::Value = serde_json::from_slice(&resp.body_mut().read_to_vec()?)
        .context("解析版本响应")?;
    let latest = info.get("version").and_then(|v| v.as_str()).unwrap_or("");
    if latest.is_empty() || latest == current_version {
        return Ok(false);
    }
    let arch = match std::env::consts::ARCH {
        "x86_64" => "monitor-agent-x86_64-musl",
        "aarch64" => "monitor-agent-aarch64-musl",
        other => anyhow::bail!("不支持的架构: {other}"),
    };
    let sha_expected = info.get("sha256").and_then(|v| v.get(arch)).and_then(|v| v.as_str());
    let Some(sha_expected) = sha_expected else { anyhow::bail!("中心机无 {arch} 二进制"); };
    let bin_url = format!("{}/agent-bin/{arch}", base_url.trim_end_matches('/'));
    log::info!("发现新版本 {latest}（当前 {current_version}），从 {bin_url} 下载");
    let mut req = agent.get(&bin_url);
    if let Some(t) = auth_token { req = req.header("x-token", t); }
    let mut resp = req.call().context("下载新二进制")?;
    let bytes = resp.body_mut().read_to_vec().context("读取二进制")?;
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(&bytes);
    let got = format!("{:x}", hasher.finalize());
    if got != sha_expected {
        anyhow::bail!("sha256 不匹配: 期望 {sha_expected}，实得 {got}");
    }
    let self_path = std::env::current_exe().context("找不到当前二进制路径")?;
    let new_path = self_path.with_extension("new");
    std::fs::write(&new_path, &bytes).context("写 .new 文件")?;
    let _ = std::fs::set_permissions(&new_path, std::os::unix::fs::PermissionsExt::from_mode(0o755));
    std::fs::rename(&new_path, &self_path).context("原子替换二进制")?;
    log::info!("已替换为新版本 {latest}，进程退出由 systemd 拉起新二进制");
    Ok(true)
}
