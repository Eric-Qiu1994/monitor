//! Webhook 通知：支持自定义 URL、钉钉机器人（可加签）、飞书机器人（可加签）。
//!
//! ponytail: 同步 ureq 阻塞调用，通知量小（离线/异常事件）不做异步。

use crate::db::{self, Db};
use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct NotifyConfig {
    /// 通知渠道：generic / dingtalk / feishu
    pub channel: String,
    pub url: String,
    /// 钉钉/飞书加签密钥（可空）
    pub secret: String,
    /// 离线通知开关
    pub offline_on: bool,
    /// 网站异常通知开关
    pub site_on: bool,
    /// 离线推送模板
    pub offline_tpl: String,
    /// 恢复上线推送模板
    pub recover_tpl: String,
}

/// 默认模板。占位符：{node} {msg} {time}。
pub const DEFAULT_OFFLINE_TPL: &str = "事件: 离线告警\n节点: {node}\n消息: {msg}\n时间: {time}";
pub const DEFAULT_RECOVER_TPL: &str = "事件: 恢复上线\n节点: {node}\n消息: {msg}\n时间: {time}";

pub fn load_config(conn: &rusqlite::Connection) -> NotifyConfig {
    NotifyConfig {
        channel: db::kv_get(conn, "notify_channel", "generic"),
        url: db::kv_get(conn, "notify_url", ""),
        secret: db::kv_get(conn, "notify_secret", ""),
        offline_on: db::kv_get(conn, "notify_offline_on", "1") == "1",
        site_on: db::kv_get(conn, "notify_site_on", "1") == "1",
        offline_tpl: db::kv_get(conn, "notify_offline_tpl", DEFAULT_OFFLINE_TPL),
        recover_tpl: db::kv_get(conn, "notify_recover_tpl", DEFAULT_RECOVER_TPL),
    }
}

pub fn save_config(conn: &rusqlite::Connection, c: &NotifyConfig) {
    db::kv_set(conn, "notify_channel", &c.channel);
    db::kv_set(conn, "notify_url", &c.url);
    db::kv_set(conn, "notify_secret", &c.secret);
    db::kv_set(conn, "notify_offline_on", if c.offline_on { "1" } else { "0" });
    db::kv_set(conn, "notify_site_on", if c.site_on { "1" } else { "0" });
    db::kv_set(conn, "notify_offline_tpl", &c.offline_tpl);
    db::kv_set(conn, "notify_recover_tpl", &c.recover_tpl);
}

/// 用模板渲染通知文本。node = "别名 主机名"，msg/time 由调用方给出。
pub fn render_tpl(tpl: &str, node: &str, msg: &str, time: &str) -> String {
    tpl.replace("{node}", node).replace("{msg}", msg).replace("{time}", time)
}

/// HMAC-SHA256（基于 db::sha256_hex 手写实现的字节版需要重写，这里独立实现）。
/// ponytail: 若未来引入 sha2 crate 可整体替换。
mod hmac_sha256 {
    // 复用 db 的手写 SHA-256：需要字节输出，包一层 hex 反解（量大也不构成瓶颈）
    fn sha256_bytes(data: &[u8]) -> [u8; 32] {
        let hex = crate::db::sha256_hex(data);
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    fn xor_pad(key: &[u8], byte: u8) -> [u8; 64] {
        let mut block = [byte; 64];
        for (i, b) in key.iter().take(64).enumerate() {
            block[i] = b ^ byte;
        }
        block
    }

    pub fn mac(key: &[u8], msg: &[u8]) -> [u8; 32] {
        let key: Vec<u8> = if key.len() > 64 { sha256_bytes(key).to_vec() } else { key.to_vec() };
        let inner = sha256_bytes(&[xor_pad(&key, 0x36).as_slice(), msg].concat());
        sha256_bytes(&[xor_pad(&key, 0x5c).as_slice(), &inner].concat())
    }
}

fn base64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// 生成带时间戳的加签 URL（钉钉 &timestamp + &sign；飞书 &timestamp）。
fn signed_url(url: &str, secret: &str) -> String {
    if secret.is_empty() || !(url.contains("dingtalk") || url.contains("feishu") || url.contains("larksuite")) {
        return url.to_string();
    }
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let string_to_sign = format!("{ts_ms}\n{secret}");
    let sign = base64(&hmac_sha256::mac(secret.as_bytes(), string_to_sign.as_bytes()));
    let sep = if url.contains('?') { '&' } else { '?' };
    let enc_sign = urlencode(&sign);
    if url.contains("dingtalk") {
        format!("{url}{sep}timestamp={ts_ms}&sign={enc_sign}")
    } else {
        format!("{url}{sep}timestamp={ts_ms}&sign={enc_sign}")
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
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

fn post_json(url: &str, body: &serde_json::Value) -> Result<()> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(10)))
        .build();
    let agent = ureq::Agent::new_with_config(agent);
    let resp = agent
        .post(url)
        .send_json(body)
        .with_context(|| "webhook 请求失败")?;
    if resp.status().as_u16() >= 300 {
        anyhow::bail!("webhook 返回 {}", resp.status());
    }
    Ok(())
}

fn build_payload(channel: &str, text: &str) -> serde_json::Value {
    match channel {
        "dingtalk" => serde_json::json!({
            "msgtype": "text",
            "text": { "content": text }
        }),
        "feishu" => serde_json::json!({
            "msg_type": "text",
            "content": { "text": text }
        }),
        _ => serde_json::json!({ "text": text, "content": text }),
    }
}

/// 发送通知并写日志。text 为纯文本内容。
pub fn send(db: &Db, cfg: &NotifyConfig, kind: &str, text: &str) -> bool {
    if cfg.url.is_empty() {
        return false;
    }
    let url = signed_url(&cfg.url, &cfg.secret);
    let payload = build_payload(&cfg.channel, text);
    let ok = post_json(&url, &payload).is_ok();
    let conn = db.lock().unwrap();
    db::notify_log(&conn, kind, text, ok);
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn hmac_sha256_rfc4231_vector() {
        // RFC 4231 test case 2: key="Jefe", data="what do ya want for nothing?"
        let mac = hmac_sha256::mac(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn unsigned_url_passthrough() {
        assert_eq!(signed_url("https://oapi.example.com/x", ""), "https://oapi.example.com/x");
        assert_eq!(
            signed_url("https://example.com/hook", "secret"),
            "https://example.com/hook"
        );
    }

    #[test]
    fn dingtalk_sign_appends_params() {
        let u = signed_url("https://oapi.dingtalk.com/robot/send?access_token=x", "sec");
        assert!(u.contains("timestamp="));
        assert!(u.contains("sign="));
    }

    #[test]
    fn payload_shape_by_channel() {
        assert_eq!(build_payload("dingtalk", "hi")["msgtype"], "text");
        assert_eq!(build_payload("feishu", "hi")["msg_type"], "text");
        assert_eq!(build_payload("generic", "hi")["text"], "hi");
        // 推送正文不再附加【服务器探针】前缀（钉钉/飞书）
        assert_eq!(build_payload("dingtalk", "hi")["text"]["content"], "hi");
        assert_eq!(build_payload("feishu", "hi")["content"]["text"], "hi");
    }

    #[test]
    fn render_tpl_substitutes_placeholders() {
        let s = render_tpl(DEFAULT_OFFLINE_TPL, "isvoro HKL", "离线 10 分钟", "2026-09-19 23:56:54");
        assert!(s.contains("事件: 离线告警"));
        assert!(s.contains("节点: isvoro HKL"));
        assert!(s.contains("消息: 离线 10 分钟"));
        assert!(s.contains("时间: 2026-09-19 23:56:54"));
    }
}
