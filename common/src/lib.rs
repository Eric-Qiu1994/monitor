//! 共享类型：agent 上报 / monitor 接收 使用的数据结构。

use serde::{Deserialize, Serialize};

/// 单块磁盘
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiskInfo {
    pub mount: String,
    pub total: u64,
    pub used: u64,
}

/// 网络累计计数
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetInfo {
    pub rx: u64,
    pub tx: u64,
}

/// agent 对一个目标执行的一轮 ICMP ping 结果。
/// 无回包时所有延迟字段为 None，丢包率仍有意义。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkProbe {
    pub target: String,
    /// 探测方式：icmp（默认）/ http / tcp
    #[serde(default)]
    pub method: String,
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f64,
    pub latency_avg_ms: Option<f64>,
    pub latency_min_ms: Option<f64>,
    pub latency_max_ms: Option<f64>,
    /// ping mdev，作为 RTT 抖动的近似值
    pub jitter_ms: Option<f64>,
}

/// 探针上报的完整负载
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Report {
    /// 上报时间（agent 本地时间，RFC3339）
    pub ts: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub kernel: String,
    pub cpu_name: String,
    pub cpu_cores: u32,
    pub cpu_usage: f32,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub uptime: u64,
    pub disks: Vec<DiskInfo>,
    /// 累计流量（字节），monitor 侧换算成速率
    pub net: NetInfo,
    /// ICMP 探测：丢包、延迟与抖动（单目标，兼容旧 agent）
    pub probe: NetworkProbe,
    /// 多目标探测结果（v2 agent 上报；旧 agent 为空）
    #[serde(default)]
    pub probes: Vec<NetworkProbe>,
    /// 累计进程数
    pub processes: u64,
    /// 本机 IPv4 / IPv6（agent 自采，空串 = 无该族地址或旧 agent 未上报）
    #[serde(default)]
    pub ipv4: String,
    #[serde(default)]
    pub ipv6: String,
    /// agent 二进制版本（clap 自动注入 CARGO_PKG_VERSION）；空串 = 旧 agent 未上报
    #[serde(default)]
    pub client_version: String,
    /// agent 监听的反向触发端口（0 = 旧 agent 或禁用）
    #[serde(default)]
    pub listen_port: u16,
    /// agent 随机生成的触发令牌，monitor 主动探测时回传
    #[serde(default)]
    pub agent_token: String,
    /// agent 主动上报的"反向连接可达地址"——空串时 monitor 端用 connect_info IP。
    /// 跨 NAT 场景需要用户手动填（NAT 后 IP monitor 不可达）。
    #[serde(default)]
    pub agent_addr: String,
}

impl Report {
    /// 自检用：关键字段是否物理上说得通。返回违规列表，空即通过。
    pub fn sanity_errors(&self) -> Vec<String> {
        let mut e = Vec::new();
        if self.mem_total == 0 {
            e.push("mem_total == 0".into());
        }
        if self.mem_used > self.mem_total {
            e.push(format!(
                "mem_used({}) > mem_total({})",
                self.mem_used, self.mem_total
            ));
        }
        if self.swap_used > self.swap_total {
            e.push("swap_used > swap_total".into());
        }
        if !(0.0..=100.0).contains(&self.cpu_usage) {
            e.push(format!("cpu_usage out of range: {}", self.cpu_usage));
        }
        if self.cpu_cores == 0 {
            e.push("cpu_cores == 0".into());
        }
        for d in &self.disks {
            if d.used > d.total {
                e.push(format!("disk {} used > total", d.mount));
            }
        }
        if self.net.rx > u64::MAX / 2 || self.net.tx > u64::MAX / 2 {
            e.push("net counter absurdly large".into());
        }
        if self.probe.target.chars().count() > 255 {
            e.push("probe target too long".into());
        }
        if !["", "icmp", "http", "tcp"].contains(&self.probe.method.as_str()) {
            e.push(format!("probe method invalid: {}", self.probe.method));
        }
        if self.probe.received > self.probe.sent {
            e.push("probe received > sent".into());
        }
        if !(0.0..=100.0).contains(&self.probe.loss_pct) {
            e.push(format!(
                "probe loss_pct out of range: {}",
                self.probe.loss_pct
            ));
        }
        for (label, value) in [
            ("latency_avg_ms", self.probe.latency_avg_ms),
            ("latency_min_ms", self.probe.latency_min_ms),
            ("latency_max_ms", self.probe.latency_max_ms),
            ("jitter_ms", self.probe.jitter_ms),
        ] {
            if value.is_some_and(|v| !v.is_finite() || v < 0.0) {
                e.push(format!("probe {label} invalid"));
            }
        }
        if let (Some(min), Some(avg), Some(max)) = (
            self.probe.latency_min_ms,
            self.probe.latency_avg_ms,
            self.probe.latency_max_ms,
        ) {
            if min > avg || avg > max {
                e.push("probe latency min/avg/max inconsistent".into());
            }
        }
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Report {
        Report {
            mem_total: 1000,
            mem_used: 400,
            swap_total: 100,
            swap_used: 10,
            cpu_usage: 12.5,
            cpu_cores: 4,
            disks: vec![DiskInfo {
                mount: "/".into(),
                total: 100,
                used: 50,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn clean_report_passes() {
        assert!(base().sanity_errors().is_empty());
    }

    #[test]
    fn used_over_total_is_caught() {
        let mut r = base();
        r.mem_used = 5000;
        assert!(r.sanity_errors().iter().any(|e| e.contains("mem_used")));
    }

    #[test]
    fn bad_cpu_percent_is_caught() {
        let mut r = base();
        r.cpu_usage = 400.0;
        assert!(r.sanity_errors().iter().any(|e| e.contains("cpu_usage")));
    }

    #[test]
    fn network_probe_validation_rejects_invalid_loss_and_latency() {
        let mut r = base();
        r.probe = NetworkProbe {
            target: "1.1.1.1".into(),
            method: "icmp".into(),
            sent: 3,
            received: 2,
            loss_pct: 33.333,
            latency_avg_ms: Some(42.0),
            latency_min_ms: Some(40.0),
            latency_max_ms: Some(45.0),
            jitter_ms: Some(2.0),
        };
        assert!(r.sanity_errors().is_empty());

        r.probe.loss_pct = 101.0;
        assert!(r.sanity_errors().iter().any(|e| e.contains("loss_pct")));

        r.probe.loss_pct = 0.0;
        r.probe.latency_min_ms = Some(50.0);
        r.probe.latency_avg_ms = Some(40.0);
        assert!(r.sanity_errors().iter().any(|e| e.contains("latency")));
    }
}
