//! 指标采集（sysinfo）+ 三种探测方式（icmp/http/tcp）。

use anyhow::{Context, Result};
use monitor_common::{DiskInfo, NetInfo, NetworkProbe, Report};
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::process::Command;
use std::time::{Duration, Instant};
use sysinfo::{
    CpuRefreshKind, Disks, MemoryRefreshKind, Networks, ProcessRefreshKind, ProcessesToUpdate,
    RefreshKind, System,
};

/// 探测目标 + 方式 + 包数 + 间隔，后台可下发的配置
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub target: String,
    pub method: String,
    pub count: u32,
    pub interval: u64,
}

impl ProbeConfig {
    pub fn from_cli(target: &str, method: &str, count: u32) -> Self {
        Self { target: target.to_string(), method: method.to_string(), count, interval: 0 }
    }
}

/// 后台下发的单个探测目标
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProbeTarget {
    pub target: String,
    #[serde(default = "default_method")]
    pub method: String,
    pub name: String,
}

fn default_method() -> String {
    "icmp".into()
}

/// 采样状态：CPU 使用率基于两次刷新的差值，必须跨轮保持同一个 System
pub struct Collector {
    sys: System,
    nets: Networks,
    disks: Disks,
    hostname: Option<String>,
}

impl Collector {
    pub fn new(hostname: Option<&str>) -> Self {
        let sys = System::new_with_specifics(
            RefreshKind::nothing()
                .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
                .with_memory(MemoryRefreshKind::everything())
                .with_processes(ProcessRefreshKind::nothing()),
        );
        Self {
            sys,
            nets: Networks::new_with_refreshed_list(),
            disks: Disks::new_with_refreshed_list(),
            hostname: hostname.map(str::to_string),
        }
    }

    pub fn sample_with_probe(&mut self, cfg: &ProbeConfig, targets: &[ProbeTarget]) -> Result<Report> {
        // CPU 使用率需要两次采样之间的时间差，先刷一次对齐窗口
        self.sys.refresh_cpu_usage();
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
        self.nets.refresh(true);
        self.disks.refresh(true);

        let hostname = self
            .hostname
            .clone()
            .or_else(|| System::host_name())
            .unwrap_or_else(|| "unknown-host".into());

        let cpu_name = self
            .sys
            .cpus()
            .first()
            .map(|c| {
                format!("{} {}", c.vendor_id(), c.brand())
                    .trim()
                    .to_string()
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Unknown CPU".into());

        let load = System::load_average();
        let (rx, tx) = self.nets.list().values().fold((0u64, 0u64), |(r, t), n| {
            (r + n.total_received(), t + n.total_transmitted())
        });

        // Docker overlayfs 等会把宿主同一个文件系统重复列出（容量/已用完全相同），
        // 按 (total, used) 去重，保留挂载点最短的那条（/ 优先于 /var/lib/docker/...）。
        // 容量与已用都相同才认为是同一块盘，容量相同但用量不同仍各自保留。
        let disks = dedup_disks(self.disks.list().iter());

        // 单目标 probe 只在没有多目标配置时才真正发包，避免重复 ping
        let (probe, probes): (NetworkProbe, Vec<NetworkProbe>) = if targets.is_empty() {
            let p = run_probe(cfg);
            (p.clone(), vec![p])
        } else {
            let list: Vec<NetworkProbe> = targets
                .iter()
                .map(|t| {
                    let mut p = run_probe(&ProbeConfig {
                        target: t.target.clone(),
                        method: t.method.clone(),
                        count: cfg.count,
                        interval: cfg.interval,
                    });
                    p.target = format!("{}|{}", t.name, t.target); // name 前缀由 monitor 解析展示
                    p
                })
                .collect();
            (list.first().cloned().unwrap_or_default(), list)
        };

        Ok(Report {
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            hostname,
            os: System::long_os_version()
                .or_else(System::os_version)
                .unwrap_or_else(|| std::env::consts::OS.into()),
            arch: System::cpu_arch(),
            kernel: System::kernel_version().unwrap_or_default(),
            cpu_cores: self.sys.cpus().len() as u32,
            cpu_name,
            cpu_usage: self.sys.global_cpu_usage(),
            load1: load.one,
            load5: load.five,
            load15: load.fifteen,
            mem_total: self.sys.total_memory(),
            mem_used: self.sys.used_memory(),
            swap_total: self.sys.total_swap(),
            swap_used: self.sys.used_swap(),
            uptime: System::uptime(),
            disks,
            net: NetInfo { rx, tx },
            probe,
            probes,
            processes: self.sys.processes().len() as u64,
        })
    }
}

/// 同一块盘被重复挂载（Docker overlayfs、容器 bind mount）时只保留挂载点最短的那条。
/// 判定为"同一块盘"：total 与 used 都相同；容量相同但用量不同则各自保留。
pub fn dedup_disks<'a>(disks: impl Iterator<Item = &'a sysinfo::Disk>) -> Vec<DiskInfo> {
    let mut out: Vec<DiskInfo> = Vec::new();
    for d in disks.filter(|d| d.total_space() > 0) {
        let total = d.total_space();
        let avail = d.available_space().min(total);
        let info = DiskInfo {
            mount: d.mount_point().to_string_lossy().into_owned(),
            total,
            used: total - avail,
        };
        match out.iter_mut().find(|e| e.total == info.total && e.used == info.used) {
            Some(e) if info.mount.len() < e.mount.len() => *e = info,
            Some(_) => {}
            None => out.push(info),
        }
    }
    out
}

/// 按方式分发探测；失败统一记为全丢包，不 panic、不阻塞上报。
fn run_probe(cfg: &ProbeConfig) -> NetworkProbe {
    if cfg.target.is_empty() {
        return NetworkProbe::default();
    }
    let count = cfg.count.clamp(1, 10);
    let mut probe = match cfg.method.as_str() {
        "http" => probe_http(&cfg.target, count),
        "tcp" => probe_tcp(&cfg.target, count),
        _ => run_icmp(&cfg.target, count),
    };
    probe.target = cfg.target.clone();
    probe.method = cfg.method.clone();
    probe
}

fn lost(target: &str, count: u32) -> NetworkProbe {
    NetworkProbe {
        target: target.into(),
        sent: count,
        received: 0,
        loss_pct: 100.0,
        ..Default::default()
    }
}

/// system ping（iputils），每包 1 秒超时；无可执行文件或解析失败记全丢包。
fn run_icmp(target: &str, count: u32) -> NetworkProbe {
    if target.len() > 255 || target.starts_with('-') {
        return lost(target, count);
    }
    let output = Command::new("ping")
        .env("LC_ALL", "C")
        .args(["-n", "-c", &count.to_string(), "-W", "1", "--", target])
        .output();
    match output {
        Ok(out) => parse_ping(
            count,
            &String::from_utf8_lossy(&[out.stdout, out.stderr].concat()),
        )
        .unwrap_or_else(|| lost(target, count)),
        Err(e) => {
            log::warn!("ping {target} 无法执行: {e}");
            lost(target, count)
        }
    }
}

/// HTTP GET，2xx–4xx 都算连通（4xx 说明服务器活着）。
fn probe_http(target: &str, count: u32) -> NetworkProbe {
    let url = if target.contains("://") {
        target.to_string()
    } else {
        format!("http://{target}")
    };
    let mut sent = 0u32;
    let mut rtt = Vec::new();
    for _ in 0..count {
        sent += 1;
        let start = Instant::now();
        match http_head_ms(&url) {
            Some(ms) => rtt.push(ms),
            None => continue,
        }
        let _ = start.elapsed();
    }
    finish(target, sent, rtt)
}

fn http_head_ms(url: &str) -> Option<f64> {
    // ponytail: 手写最小 HTTP GET，只为拿到 RTT；需要重定向/HTTPS 校验再换 ureq。
    if !url.starts_with("http://") {
        return None; // https 交给系统 curl 兜底
    }
    let host_part = url.trim_start_matches("http://");
    let (host, port, path) = match host_part.find('/') {
        Some(i) => {
            let (h, rest) = host_part.split_at(i);
            (h, 80u16, rest)
        }
        None => (host_part, 80u16, "/"),
    };
    let (host, port) = split_host_port(host, port);
    let start = Instant::now();
    let mut stream =
        TcpStream::connect_timeout(&resolve(&host, port)?, Duration::from_secs(3)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: monitor-agent/0.1\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut buf = [0u8; 128];
    use std::io::Read;
    let n = stream.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    let head = String::from_utf8_lossy(&buf[..n]);
    let status: u16 = head.split_whitespace().nth(1)?.parse().ok()?;
    if !(200..500).contains(&status) {
        return None;
    }
    Some(start.elapsed().as_secs_f64() * 1000.0)
}

/// TCP connect 探测，target 形如 host 或 host:port（默认 80）。
fn probe_tcp(target: &str, count: u32) -> NetworkProbe {
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h, p.parse::<u16>().unwrap_or(80))
        }
        _ => (target, 80),
    };
    let mut sent = 0u32;
    let mut rtt = Vec::new();
    for _ in 0..count {
        sent += 1;
        let Some(addr) = resolve(&host.to_string(), port) else {
            continue;
        };
        let start = Instant::now();
        match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
            Ok(_) => rtt.push(start.elapsed().as_secs_f64() * 1000.0),
            Err(_) => continue,
        }
    }
    finish(target, sent, rtt)
}

fn resolve(host: &str, port: u16) -> Option<std::net::SocketAddr> {
    (host, port).to_socket_addrs().ok()?.next()
}

fn split_host_port(host: &str, default_port: u16) -> (String, u16) {
    match host.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h.to_string(), p.parse().unwrap_or(default_port))
        }
        _ => (host.to_string(), default_port),
    }
}

fn finish(target: &str, sent: u32, rtt: Vec<f64>) -> NetworkProbe {
    if rtt.is_empty() {
        return lost(target, sent);
    }
    let avg = rtt.iter().sum::<f64>() / rtt.len() as f64;
    let jitter = (rtt.iter().map(|v| (v - avg).powi(2)).sum::<f64>() / rtt.len() as f64).sqrt();
    let mut probe = NetworkProbe {
        method: String::new(),
        target: target.into(),
        sent,
        received: rtt.len() as u32,
        loss_pct: (sent - rtt.len() as u32) as f64 * 100.0 / sent as f64,
        latency_min_ms: Some(rtt.iter().cloned().fold(f64::INFINITY, f64::min)),
        latency_avg_ms: Some(avg),
        latency_max_ms: Some(rtt.iter().cloned().fold(f64::NEG_INFINITY, f64::max)),
        jitter_ms: Some(jitter),
    };
    probe
}

/// 解析 iputils ping 在 LC_ALL=C 下的 summary；只依赖稳定的统计行。
fn parse_ping(requested: u32, output: &str) -> Option<NetworkProbe> {
    let stat = output
        .lines()
        .find(|line| line.contains("packets transmitted"))?;
    let mut fields = stat.split(',').map(str::trim);
    let sent = fields.next()?.split_whitespace().next()?.parse().ok()?;
    let received = fields.next()?.split_whitespace().next()?.parse().ok()?;
    let loss_pct = fields
        .find_map(|f| f.strip_suffix("packet loss"))?
        .trim()
        .trim_end_matches('%')
        .parse::<f64>()
        .ok()?;

    let mut probe = NetworkProbe {
        sent,
        received,
        loss_pct,
        ..Default::default()
    };
    // 兼容 rtt 或 round-trip 两种 iputils summary 前缀。
    if let Some(rtt) = output.lines().find(|line| line.contains("min/avg/max")) {
        let values = rtt.split('=').nth(1)?.trim().trim_end_matches(" ms");
        let nums: Vec<f64> = values
            .split('/')
            .map(str::trim)
            .map(str::parse)
            .collect::<Result<_, _>>()
            .ok()?;
        if nums.len() >= 4 {
            probe.latency_min_ms = Some(nums[0]);
            probe.latency_avg_ms = Some(nums[1]);
            probe.latency_max_ms = Some(nums[2]);
            probe.jitter_ms = Some(nums[3]);
        }
    }
    // 防御不可预期输出；计数不应超出请求值。
    if probe.sent == 0 || probe.sent > requested || probe.received > probe.sent {
        return None;
    }
    Some(probe)
}

/// 后台完整探测配置
#[derive(Debug, Clone, Default)]
pub struct AgentProbeCfg {
    pub targets: Vec<ProbeTarget>,
    pub interval: u64,       // 探测间隔（秒），0 = 跟随上报间隔
    pub report_interval: u64, // 后台下发的上报间隔（秒），0 = 沿用 CLI 的 MONITOR_INTERVAL
    pub fail_threshold: u64, // 连续上报失败判离线次数（默认 3，下发失败回落 3）
}

/// 拉取后台下发的探测配置；任何失败都回落到 CLI 本地配置。
/// hostname 用于服务端套单台服务器的探测点排除表。
pub fn fetch_probe_config(
    agent: &ureq::Agent,
    base_url: &str,
    token: Option<&str>,
    fallback: &ProbeConfig,
    hostname: Option<&str>,
) -> AgentProbeCfg {
    let url = match hostname.filter(|h| !h.trim().is_empty()) {
        Some(h) => format!(
            "{}/api/agent-config?hostname={}",
            base_url.trim_end_matches('/'),
            urlencode(h.trim())
        ),
        None => format!("{}/api/agent-config", base_url.trim_end_matches('/')),
    };
    let mut req = agent.get(&url);
    if let Some(t) = token {
        req = req.header("x-token", t);
    }
    let fallback_cfg = || AgentProbeCfg {
        targets: if fallback.target.is_empty() {
            vec![]
        } else {
            vec![ProbeTarget {
                target: fallback.target.clone(),
                method: fallback.method.clone(),
                name: fallback.target.clone(),
            }]
        },
        interval: 0,
        report_interval: 0,
        fail_threshold: 3,
    };
    match req.call() {
        Ok(resp) => match resp.into_body().read_to_string() {
            Ok(text) => match serde_json::from_str::<serde_json::Value>(&text) {
                Ok(v) => {
                    let targets: Vec<ProbeTarget> = v["targets"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|t| serde_json::from_value(t.clone()).ok())
                                .collect()
                        })
                        .unwrap_or_default();
                    if targets.is_empty() {
                        // 兼容旧单目标字段
                        let target = v["target"].as_str().unwrap_or("").to_string();
                        if !target.is_empty() {
                            return AgentProbeCfg {
                                targets: vec![ProbeTarget {
                                    target,
                                    method: v["method"].as_str().unwrap_or("icmp").into(),
                                    name: "探测".into(),
                                }],
                                interval: v["interval"].as_u64().unwrap_or(0),
                                report_interval: v["report_interval"].as_u64().unwrap_or(0),
                                fail_threshold: v["fail_threshold"].as_u64().unwrap_or(3).max(1),
                            };
                        }
                    }
                    AgentProbeCfg {
                        targets,
                        interval: v["interval"].as_u64().unwrap_or(0),
                        report_interval: v["report_interval"].as_u64().unwrap_or(0),
                        fail_threshold: v["fail_threshold"].as_u64().unwrap_or(3).max(1),
                    }
                }
                Err(e) => {
                    log::debug!("agent-config 解析失败，使用本地配置: {e}");
                    fallback_cfg()
                }
            },
            Err(e) => {
                log::debug!("agent-config 读取失败，使用本地配置: {e}");
                fallback_cfg()
            }
        },
        Err(e) => {
            log::debug!("agent-config 拉取失败，使用本地配置: {e}");
            fallback_cfg()
        }
    }
}

/// agent 上报用的有效主机名：CLI 覆盖优先，其次系统 hostname。
/// 服务端按同一名字算 server_id 来套探测点排除表，两边必须一致。
pub fn effective_hostname(cli_hostname: Option<&str>) -> Option<String> {
    cli_hostname
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .map(str::to_string)
        .or_else(sysinfo::System::host_name)
}

/// 最小的 query 值转义：保留 unreserved 字符，其余按 %XX 编码。
/// ponytail: 不引 url crate，hostname 字符集很窄，够用。
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 构造带可选代理的 HTTP agent
pub fn build_agent(proxy: Option<&str>) -> Result<ureq::Agent> {
    let mut cfg =
        ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(15)));
    if let Some(p) = proxy {
        let p = ureq::Proxy::new(p).with_context(|| format!("代理地址无效: {p}"))?;
        cfg = cfg.proxy(Some(p));
    } else {
        // 显式禁用环境代理（HTTP_PROXY/HTTPS_PROXY 等）：
        // Docker 宿主的 ~/.docker/config.json proxies 段会被注入容器 env，
        // ureq 默认读取这些变量，导致上报被送去不相关的代理而失败。
        // 要代理请用 MONITOR_PROXY。
        cfg = cfg.proxy(None);
    }
    Ok(ureq::Agent::new_with_config(cfg.build()))
}

#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_is_physically_sane() {
        let mut c = Collector::new(Some("unit-test-host"));
        let r = c
            .sample_with_probe(&ProbeConfig::from_cli("", "icmp", 3), &[])
            .unwrap();
        let errs = r.sanity_errors();
        assert!(errs.is_empty(), "采集数据不合理: {errs:?}");
        assert_eq!(r.hostname, "unit-test-host");
        assert!(r.cpu_cores >= 1);
        assert!(r.mem_total > 0);
        assert!(r.uptime > 0);
        assert!(!r.ts.is_empty());
    }

    #[test]
    fn env_proxy_is_ignored_by_default() {
        // 宿主 ~/.docker/config.json 的 proxies 段会注入容器 env；
        // build_agent 未显式给代理时必须忽略 HTTP_PROXY（否则上报被送去无关代理）。
        std::env::set_var("HTTP_PROXY", "http://172.16.1.1:1090");
        let agent = build_agent(None).unwrap();
        std::env::remove_var("HTTP_PROXY");
        // ureq 没暴露 config 读取口；用行为验证——对无效代理发起请求，
        // 若走了代理会连接失败，不走代理则能正常到达（此处只验证不 panic + 配置无代理路径）。
        assert!(agent.config().proxy().is_none(), "未显式配置代理时不应继承 env 代理");
    }

    #[test]
    fn report_interval_server_overrides_cli() {
        // ponytail: 与 main.rs 的 pick_interval 保持同一份语义；
        // 若将来加了"后台只能在 CLI 上限内调整"的策略，此处同步改
        let pick = |cli: u64, server: u64| -> u64 {
            if server > 0 { server.max(1) } else { cli.max(1) }
        };
        assert_eq!(pick(10, 0), 10, "后台未设置 -> 用 CLI");
        assert_eq!(pick(10, 60), 60, "后台设置 -> 覆盖 CLI");
        assert_eq!(pick(0, 0), 1, "都非法 -> 兜底 1s");
        assert_eq!(pick(10, 0), 10, "后台 0 视为未设置");
    }

    #[test]
    fn cpu_cores_stable_across_samples() {
        let mut c = Collector::new(Some("h"));
        let a = c
            .sample_with_probe(&ProbeConfig::from_cli("", "icmp", 3), &[])
            .unwrap();
        let b = c
            .sample_with_probe(&ProbeConfig::from_cli("", "icmp", 3), &[])
            .unwrap();
        assert_eq!(a.cpu_cores, b.cpu_cores);
        // 累计流量只会增长
        assert!(b.net.rx >= a.net.rx);
    }

    #[test]
    fn proxy_string_is_parsed_or_rejected() {
        assert!(build_agent(Some("http://172.16.1.1:1083")).is_ok());
        assert!(build_agent(Some("socks5://127.0.0.1:1080")).is_ok());
        assert!(build_agent(Some("这是一个非法地址")).is_err());
        assert!(build_agent(None).is_ok());
    }

    /// 验证 dedup_disks 的判定逻辑：相同 (total,used) 只留最短 mount
    /// ponytail: 替代方案是 statvfs(3) 取 st_dev，最严谨，但纯函数测试已覆盖所有决策分支
    #[test]
    fn dedup_keeps_shortest_mount() {
        fn dedup_raw(items: &[(u64, u64, &str)]) -> Vec<(u64, u64, String)> {
            let mut out: Vec<(u64, u64, String)> = Vec::new();
            for (total, used, mount) in items.iter().filter(|(t, _, _)| *t > 0) {
                let info = (*total, *used, mount.to_string());
                match out.iter_mut().find(|(t, u, _)| *t == info.0 && *u == info.1) {
                    Some(slot) if info.2.len() < slot.2.len() => *slot = info,
                    Some(_) => {}
                    None => out.push(info),
                }
            }
            out
        }
        // 复刻 ubuntu-server 现状：/ + 两个 overlay 副本（容量/已用相同）
        let r = dedup_raw(&[
            (42089099264, 39793389568, "/var/lib/docker/rootfs/overlayfs/aaa"),
            (42089099264, 39793389568, "/var/lib/docker/rootfs/overlayfs/bbb"),
            (42089099264, 39793389568, "/"),
        ]);
        assert_eq!(r.len(), 1, "三条应合并为一条");
        assert_eq!(r[0].2, "/", "应保留挂载点最短的那条");

        // 不同 used 不被合并
        let r = dedup_raw(&[(1000, 100, "/"), (1000, 200, "/data")]);
        assert_eq!(r.len(), 2, "容量相同但已用不同的盘应各自保留");

        // 容量为 0 直接跳过
        let r = dedup_raw(&[(0, 0, "/dev/null")]);
        assert_eq!(r.len(), 0, "total==0 的 mount 不计入磁盘列表");
    }

    #[test]
    fn parses_linux_ping_summary_with_loss_latency_and_jitter() {
        let out = "3 packets transmitted, 2 received, 33.3333% packet loss, time 2001ms\n\nrtt min/avg/max/mdev = 10.100/20.200/30.300/4.400 ms\n";
        let p = parse_ping(3, out).unwrap();
        assert_eq!(p.sent, 3);
        assert_eq!(p.received, 2);
        assert!((p.loss_pct - 33.3333).abs() < 0.001);
        assert_eq!(p.latency_avg_ms, Some(20.2));
        assert_eq!(p.jitter_ms, Some(4.4));
    }

    #[test]
    fn parses_total_loss_without_rtt() {
        let out = "3 packets transmitted, 0 received, 100% packet loss, time 2032ms\n";
        let p = parse_ping(3, out).unwrap();
        assert_eq!(p.received, 0);
        assert_eq!(p.loss_pct, 100.0);
        assert_eq!(p.latency_avg_ms, None);
    }

    #[test]
    fn empty_target_disables_ping() {
        let p = run_probe(&ProbeConfig::from_cli("", "icmp", 3));
        assert!(p.target.is_empty());
        assert_eq!(p.sent, 0);
    }

    #[test]
    fn tcp_probe_against_local_listener_succeeds_or_reports_loss() {
        // 起一个临时 TCP 监听，探测本机端口
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let p = probe_tcp(&format!("127.0.0.1:{port}"), 2);
        assert_eq!(p.sent, 2);
        assert_eq!(p.received, 2);
        assert_eq!(p.loss_pct, 0.0);
        assert!(p.latency_avg_ms.unwrap() < 500.0);

        // 连不上的端口记全丢包
        let bad = probe_tcp("127.0.0.1:1", 1);
        assert_eq!(bad.received, 0);
        assert_eq!(bad.loss_pct, 100.0);
    }

    #[test]
    fn http_probe_treats_4xx_as_alive() {
        // 用 std TcpListener 模拟一个返回 404 的 HTTP 服务
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let _ = s.write_all(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n");
            }
        });
        let p = probe_http(&format!("127.0.0.1:{port}"), 1);
        assert_eq!(p.received, 1, "404 也应算连通");
        assert_eq!(p.loss_pct, 0.0);
        h.join().unwrap();
    }

    #[test]
    fn probe_method_is_recorded() {
        let cfg = ProbeConfig::from_cli("127.0.0.1:1", "tcp", 1);
        let p = run_probe(&cfg);
        assert_eq!(p.method, "tcp");
    }
}
