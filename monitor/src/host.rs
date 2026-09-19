//! 中心机（monitor 宿主/容器自身）资源采样。
//! 后台线程每 3s 刷一次，API 只读快照，避免请求路径里做 MINIMUM_CPU_UPDATE_INTERVAL 睡眠。

use std::sync::{Arc, Mutex};
use sysinfo::{CpuRefreshKind, Disks, MemoryRefreshKind, Networks, RefreshKind, System};

#[derive(Clone, Default, serde::Serialize)]
pub struct HostStats {
    pub cpu_usage: f32,
    pub cpu_name: String,
    pub cpu_cores: u32,
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    /// 实时速率（B/s），采样窗口 3s
    pub net_rx_bps: f64,
    pub net_tx_bps: f64,
    pub disks: Vec<HostDisk>,
}

#[derive(Clone, serde::Serialize)]
pub struct HostDisk {
    pub mount: String,
    pub total: u64,
    pub used: u64,
}

pub struct HostSampler {
    stats: Arc<Mutex<HostStats>>,
}

impl HostSampler {
    pub fn start() -> Self {
        let stats = Arc::new(Mutex::new(HostStats::default()));
        let st = stats.clone();
        std::thread::spawn(move || {
            let mut sys = System::new_with_specifics(
                RefreshKind::nothing()
                    .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
                    .with_memory(MemoryRefreshKind::everything()),
            );
            let mut nets = Networks::new_with_refreshed_list();
            let mut disks = Disks::new_with_refreshed_list();
            let (mut prev_rx, mut prev_tx) = (0u64, 0u64);
            loop {
                sys.refresh_cpu_usage();
                sys.refresh_memory();
                nets.refresh(true);
                disks.refresh(true);
                let (rx, tx) = nets.list().values().fold((0u64, 0u64), |(r, t), n| {
                    (r + n.total_received(), t + n.total_transmitted())
                });
                // 窗口固定 3s（与睡眠一致）；计数器回绕/清零会产生一次尖峰，可接受
                let (rx_bps, tx_bps) = (
                    rx.saturating_sub(prev_rx) as f64 / 3.0,
                    tx.saturating_sub(prev_tx) as f64 / 3.0,
                );
                prev_rx = rx;
                prev_tx = tx;
                let mut s = st.lock().unwrap();
                s.cpu_usage = sys.global_cpu_usage();
                s.cpu_name = sys
                    .cpus()
                    .first()
                    .map(|c| format!("{} {}", c.vendor_id(), c.brand()).trim().to_string())
                    .filter(|x| !x.is_empty())
                    .unwrap_or_else(|| "Unknown CPU".into());
                s.cpu_cores = sys.cpus().len() as u32;
                s.mem_total = sys.total_memory();
                s.mem_used = sys.used_memory();
                s.swap_total = sys.total_swap();
                s.swap_used = sys.used_swap();
                s.net_rx_bps = rx_bps;
                s.net_tx_bps = tx_bps;
                s.disks = disks
                    .list()
                    .iter()
                    // 过滤容器 bind-mount 伪挂载：/etc/hosts、/etc/hostname、/etc/resolv.conf
                    // 以及 docker volume 常见挂径；真实块设备挂载点一般在 / /data /home 等
                    .filter(|d| {
                        let m = d.mount_point().to_string_lossy();
                        !(m.starts_with("/etc/") || m.starts_with("/var/lib/docker/"))
                    })
                    .map(|d| HostDisk {
                        mount: d.mount_point().to_string_lossy().into(),
                        total: d.total_space(),
                        used: d.total_space() - d.available_space(),
                    })
                    .collect();
                drop(s);
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
        });
        Self { stats }
    }

    pub fn snapshot(&self) -> HostStats {
        self.stats.lock().unwrap().clone()
    }
}

// AppState 字段类型别名，api.rs 引用
pub type SharedSampler = Arc<HostSampler>;
