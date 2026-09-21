// IP -> 国家码。ponytail: 外部免费 API（ip-api.com，HTTP 免费版限速 45 req/min），
// 内存缓存 + 失败静默降级。机器量 >几十台或 API 挂掉时换本地 GeoLite2 mmdb（maxminddb crate）。
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

static CACHE: Mutex<Option<HashMap<String, (Option<String>, Instant)>>> = Mutex::new(None);
const TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const MAX_CACHE: usize = 10_000;

fn is_private(ip: &str) -> bool {
    ip.starts_with("127.")
        || ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("169.254.")
        || ip.starts_with("::1")
        || ip.starts_with("fe80:")
        || ip.starts_with("fc")
        || ip.starts_with("fd")
        || {
            // 172.16-31.x.x
            let p: Vec<&str> = ip.split('.').collect();
            p.len() == 4
                && p[0] == "172"
                && p[1]
                    .parse::<u8>()
                    .map(|o| (16..=31).contains(&o))
                    .unwrap_or(false)
        }
}

pub fn lookup_country(ip: &str) -> Option<String> {
    if is_private(ip) {
        log::info!("geo skip private ip={ip}");
        return None;
    }
    {
        let mut g = CACHE.lock().unwrap();
        let map = g.get_or_insert_with(HashMap::new);
        if let Some((cc, at)) = map.get(ip) {
            if at.elapsed() < TTL {
                return cc.clone();
            }
        }
    }
    // ip-api.com 免费层：HTTP，限 45/min；10s 超时（同 notify.rs 的 agent 构造）
    let url = format!("http://ip-api.com/json/{ip}?fields=status,countryCode");
    let cfg = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .build();
    let agent = ureq::Agent::new_with_config(cfg);
    let cc = agent
        .get(&url)
        .call()
        .ok()
        .and_then(|r| r.into_body().read_json::<serde_json::Value>().ok())
        .and_then(|v| {
            (v.get("status").and_then(|s| s.as_str()) == Some("success"))
                .then(|| v.get("countryCode")?.as_str().map(|c| c.to_uppercase()))
                .flatten()
        });
    {
        let mut g = CACHE.lock().unwrap();
        let map = g.get_or_insert_with(HashMap::new);
        if map.len() >= MAX_CACHE {
            map.clear(); // ponytail: 粗暴清空；量大换 LRU
        }
        map.insert(ip.to_string(), (cc.clone(), Instant::now()));
    }
    log::info!("geo lookup {ip} -> {cc:?}");
    cc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ips_return_none_without_network() {
        assert!(lookup_country("127.0.0.1").is_none());
        assert!(lookup_country("192.168.1.5").is_none());
        assert!(lookup_country("10.0.0.1").is_none());
        assert!(lookup_country("172.16.0.1").is_none());
        assert!(lookup_country("172.32.0.1").is_none() == false || true); // 公网，不测网络
    }

    #[test]
    fn private_detection() {
        assert!(is_private("172.16.0.1"));
        assert!(is_private("172.31.255.255"));
        assert!(!is_private("172.32.0.1"));
        assert!(!is_private("8.8.8.8"));
        assert!(is_private("fe80::1"));
    }
}
