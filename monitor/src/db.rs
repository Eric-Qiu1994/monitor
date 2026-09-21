//! SQLite 存取 + 数据保留（防爆盘）。
//!
//! ponytail: 单个全局 Mutex<Connection>，低频写入场景够用；
//! 如果上报 QPS 上千再换 r2d2 连接池。

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub type Db = Arc<Mutex<Connection>>;

/// 保留策略
#[derive(Debug, Clone, Copy)]
pub struct Retention {
    pub days: u32,
    /// 每台服务器最多保留多少条采样（硬上限，防 agent 高频上报打爆磁盘）
    pub max_rows_per_server: u32,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CleanupStats {
    pub metrics_deleted: u64,
    pub vacuumed: bool,
}

pub fn open(path: &Path) -> Result<Db> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create dir {dir:?}"))?;
    }
    let conn = Connection::open(path).with_context(|| format!("open db {path:?}"))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=5000;
         PRAGMA auto_vacuum=INCREMENTAL;",
    )?;
    migrate(&conn)?;
    Ok(Arc::new(Mutex::new(conn)))
}

pub(crate) fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS servers (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            hostname    TEXT NOT NULL,
            os          TEXT NOT NULL DEFAULT '',
            arch        TEXT NOT NULL DEFAULT '',
            kernel      TEXT NOT NULL DEFAULT '',
            cpu_name    TEXT NOT NULL DEFAULT '',
            cpu_cores   INTEGER NOT NULL DEFAULT 0,
            note        TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL,
            last_seen   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS metrics (
            server_id   TEXT NOT NULL,
            ts          TEXT NOT NULL,
            cpu_usage   REAL NOT NULL DEFAULT 0,
            load1       REAL NOT NULL DEFAULT 0,
            load5       REAL NOT NULL DEFAULT 0,
            load15      REAL NOT NULL DEFAULT 0,
            mem_total   INTEGER NOT NULL DEFAULT 0,
            mem_used    INTEGER NOT NULL DEFAULT 0,
            swap_total  INTEGER NOT NULL DEFAULT 0,
            swap_used   INTEGER NOT NULL DEFAULT 0,
            uptime      INTEGER NOT NULL DEFAULT 0,
            net_rx      INTEGER NOT NULL DEFAULT 0,
            net_tx      INTEGER NOT NULL DEFAULT 0,
            processes   INTEGER NOT NULL DEFAULT 0,
            disks       TEXT NOT NULL DEFAULT '[]',
            probe_target TEXT NOT NULL DEFAULT '',
            probe_sent INTEGER NOT NULL DEFAULT 0,
            probe_received INTEGER NOT NULL DEFAULT 0,
            probe_loss_pct REAL NOT NULL DEFAULT 0,
            latency_avg_ms REAL,
            latency_min_ms REAL,
            latency_max_ms REAL,
            jitter_ms REAL,
            -- 多目标探测结果（JSON 数组）；旧库由 migrate 补列
            probes      TEXT NOT NULL DEFAULT '[]'
        );
        CREATE INDEX IF NOT EXISTS idx_metrics_server_ts ON metrics(server_id, ts);

        CREATE TABLE IF NOT EXISTS themes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            css         TEXT NOT NULL,
            builtin     INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS kv (
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            username   TEXT PRIMARY KEY,
            pass_hash  TEXT NOT NULL,
            salt       TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS probe_targets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            target      TEXT NOT NULL,
            method      TEXT NOT NULL DEFAULT 'icmp',
            enabled     INTEGER NOT NULL DEFAULT 1
        );

        -- 单台服务器的探测点排除表：默认无行 = 使用全部启用的探测点
        -- 按 target 地址而非 id 存：备份恢复会重建 probe_targets 导致 id 漂移
        CREATE TABLE IF NOT EXISTS probe_excludes (
            server_id   TEXT NOT NULL,
            target      TEXT NOT NULL,
            PRIMARY KEY (server_id, target)
        );

        CREATE TABLE IF NOT EXISTS sites (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            url         TEXT NOT NULL,
            interval_s  INTEGER NOT NULL DEFAULT 60,
            enabled     INTEGER NOT NULL DEFAULT 1,
            last_status INTEGER NOT NULL DEFAULT 0,
            last_ms     REAL,
            last_check  TEXT,
            last_notify TEXT
        );

        CREATE TABLE IF NOT EXISTS notify_log (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            ts   TEXT NOT NULL,
            kind TEXT NOT NULL,
            text TEXT NOT NULL,
            ok   INTEGER NOT NULL DEFAULT 0
        );
        "#,
    )?;
    migrate_metrics_probe_columns(conn)?;
    seed_themes(conn)?;
    seed_admin(conn)?;
    Ok(())
}

// ---------- 后台账号 ----------

/// 默认账号 admin/admin；首次登录后必须改密码。
fn seed_admin(conn: &Connection) -> Result<()> {
    let exists: Option<String> = conn
        .query_row("SELECT username FROM users LIMIT 1", [], |r| r.get(0))
        .optional()?;
    if exists.is_none() {
        create_user(conn, "admin", "admin")?;
    }
    Ok(())
}

fn hash_pass(password: &str, salt: &str) -> String {
    // ponytail: sha256+盐，2^60 预算内可暴力；需要抗离线爆破再换 argon2。
    let mut h = sha256_hex(salt.as_bytes());
    h = sha256_hex(format!("{h}:{password}").as_bytes());
    h
}

pub fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    // ponytail: 手写 SHA-256 只为不引依赖；量大再换 sha2 crate。
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut msg = data.to_vec();
    let bitlen = (msg.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = String::with_capacity(64);
    for v in h {
        write!(out, "{v:08x}").unwrap();
    }
    out
}

/// 新建用户；用户名/密码校验由调用方完成。
pub fn create_user(conn: &Connection, username: &str, password: &str) -> Result<()> {
    let salt = format!(
        "{:016x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    ) + username;
    conn.execute(
        "INSERT OR REPLACE INTO users (username, pass_hash, salt) VALUES (?1, ?2, ?3)",
        params![username, hash_pass(password, &salt), salt],
    )?;
    Ok(())
}

pub struct AdminUser {
    pub username: String,
}

/// 登录校验；成功返回用户。
pub fn verify_user(conn: &Connection, username: &str, password: &str) -> Result<Option<AdminUser>> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT pass_hash, salt FROM users WHERE username=?1",
            params![username],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        Some((stored, salt)) if stored == hash_pass(password, &salt) => Ok(Some(AdminUser {
            username: username.into(),
        })),
        _ => Ok(None),
    }
}

pub fn update_credentials(
    conn: &Connection,
    old_username: &str,
    old_password: &str,
    new_username: &str,
    new_password: &str,
) -> Result<bool> {
    if verify_user(conn, old_username, old_password)?.is_none() {
        return Ok(false);
    }
    create_user(conn, new_username, new_password)?;
    // 用户名变更时删掉旧账号
    if new_username != old_username {
        conn.execute("DELETE FROM users WHERE username=?1", params![old_username])?;
    }
    Ok(true)
}

// ---------- 探测配置（后台下发） ----------

pub fn get_probe_config(conn: &Connection) -> Result<(String, String, u32)> {
    let kv = |k: &str, d: &str| -> Result<String> {
        Ok(conn
            .query_row("SELECT v FROM kv WHERE k=?1", params![k], |r| r.get(0))
            .optional()?
            .unwrap_or_else(|| d.into()))
    };
    let target = kv("probe_target", "")?;
    let method = kv("probe_method", "icmp")?;
    let count: u32 = kv("probe_count", "3")?.parse().unwrap_or(3);
    Ok((target, method, count.clamp(1, 10)))
}

pub fn set_probe_config(conn: &Connection, target: &str, method: &str, count: u32) -> Result<()> {
    for (k, v) in [
        ("probe_target", target),
        ("probe_method", method),
        ("probe_count", &count.to_string()),
    ] {
        conn.execute(
            "INSERT OR REPLACE INTO kv (k, v) VALUES (?1, ?2)",
            params![k, v],
        )?;
    }
    Ok(())
}

// ---------- 多探测目标 ----------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProbeTargetRow {
    pub id: i64,
    pub name: String,
    pub target: String,
    pub method: String,
    pub enabled: bool,
}

pub fn add_probe_target(conn: &Connection, name: &str, target: &str, method: &str) -> Result<i64> {
    conn.execute(
        "INSERT INTO probe_targets (name, target, method) VALUES (?1, ?2, ?3)",
        params![name, target, method],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn delete_probe_target(conn: &Connection, id: i64) -> Result<bool> {
    Ok(conn.execute("DELETE FROM probe_targets WHERE id=?1", params![id])? > 0)
}

/// 编辑探测目标（name/target/method/enabled 全量覆盖）
pub fn update_probe_target(
    conn: &Connection,
    id: i64,
    name: &str,
    target: &str,
    method: &str,
    enabled: bool,
) -> Result<bool> {
    Ok(conn
        .execute(
            "UPDATE probe_targets SET name=?2, target=?3, method=?4, enabled=?5 WHERE id=?1",
            params![id, name, target, method, enabled as i64],
        )?
        > 0)
}

/// 后台可拿到的探测目标（含禁用的），agent 拉取时另有过滤
pub fn probe_targets_all(conn: &Connection) -> Result<Vec<ProbeTargetRow>> {
    probe_targets_impl(conn, false)
}

/// agent-config 用的列表：只含启用项
pub fn probe_targets_enabled(conn: &Connection) -> Result<Vec<ProbeTargetRow>> {
    probe_targets_impl(conn, true)
}

fn probe_targets_impl(conn: &Connection, only_enabled: bool) -> Result<Vec<ProbeTargetRow>> {
    let sql = format!(
        "SELECT id, name, target, method, enabled FROM probe_targets {} ORDER BY id",
        if only_enabled { "WHERE enabled=1" } else { "" }
    );
    let mut st = conn.prepare(&sql)?;
    let v = st
        .query_map([], |r| {
            Ok(ProbeTargetRow {
                id: r.get(0)?,
                name: r.get(1)?,
                target: r.get(2)?,
                method: r.get(3)?,
                enabled: r.get::<_, i64>(4)? != 0,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(v)
}

// ---------- 单服务器探测点排除 ----------

/// 某服务器被排除的探测点地址集合（按 target 地址，非 id）
pub fn probe_excludes(conn: &Connection, server_id: &str) -> Result<std::collections::HashSet<String>> {
    let mut st = conn.prepare("SELECT target FROM probe_excludes WHERE server_id=?1")?;
    let v = st
        .query_map(params![server_id], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<std::collections::HashSet<_>>>()?;
    Ok(v)
}

/// 全量覆盖某服务器的排除集合（前端传最终应排除的 target 地址列表）
pub fn set_probe_excludes(conn: &Connection, server_id: &str, targets: &[String]) -> Result<()> {
    conn.execute("DELETE FROM probe_excludes WHERE server_id=?1", params![server_id])?;
    let mut st = conn.prepare("INSERT OR IGNORE INTO probe_excludes (server_id, target) VALUES (?1, ?2)")?;
    for t in targets {
        st.execute(params![server_id, t])?;
    }
    Ok(())
}

/// agent 该用的启用探测点：全局启用列表减去该服务器排除的
pub fn probe_targets_for_server(conn: &Connection, server_id: &str) -> Result<Vec<ProbeTargetRow>> {
    let excl = probe_excludes(conn, server_id)?;
    Ok(probe_targets_enabled(conn)?
        .into_iter()
        .filter(|t| !excl.contains(&t.target))
        .collect())
}

/// 备份导出用：所有服务器的排除项
pub fn all_probe_excludes(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut st = conn.prepare("SELECT server_id, target FROM probe_excludes")?;
    let v = st
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(v)
}

/// 备份恢复用：全量替换排除表
pub fn restore_probe_excludes(conn: &Connection, rows: &[(String, String)]) -> Result<()> {
    conn.execute("DELETE FROM probe_excludes", [])?;
    let mut st = conn.prepare("INSERT OR IGNORE INTO probe_excludes (server_id, target) VALUES (?1, ?2)")?;
    for (sid, t) in rows {
        st.execute(params![sid, t])?;
    }
    Ok(())
}

// ---------- 网站监控 ----------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SiteRow {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub interval_s: u64,
    pub enabled: bool,
    pub last_status: u32,
    pub last_ms: Option<f64>,
    pub last_check: Option<String>,
}

const SITE_COLS: &str = "id, name, url, interval_s, enabled, last_status, last_ms, last_check";

fn map_site(r: &rusqlite::Row) -> rusqlite::Result<SiteRow> {
    Ok(SiteRow {
        id: r.get(0)?,
        name: r.get(1)?,
        url: r.get(2)?,
        interval_s: r.get::<_, i64>(3)? as u64,
        enabled: r.get::<_, i64>(4)? != 0,
        last_status: r.get::<_, i64>(5)? as u32,
        last_ms: r.get(6)?,
        last_check: r.get(7)?,
    })
}

pub fn sites(conn: &Connection) -> Result<Vec<SiteRow>> {
    let mut st = conn.prepare(&format!("SELECT {SITE_COLS} FROM sites ORDER BY id"))?;
    let v = st.query_map([], map_site)?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(v)
}

pub fn enabled_sites(conn: &Connection) -> Result<Vec<SiteRow>> {
    Ok(sites(conn)?.into_iter().filter(|s| s.enabled).collect())
}

pub fn upsert_site(
    conn: &Connection,
    id: Option<i64>,
    name: &str,
    url: &str,
    interval_s: u64,
    enabled: bool,
) -> Result<i64> {
    if let Some(id) = id {
        conn.execute(
            "UPDATE sites SET name=?2, url=?3, interval_s=?4, enabled=?5 WHERE id=?1",
            params![id, name, url, interval_s as i64, enabled as i64],
        )?;
        Ok(id)
    } else {
        conn.execute(
            "INSERT INTO sites (name, url, interval_s, enabled) VALUES (?1, ?2, ?3, ?4)",
            params![name, url, interval_s as i64, enabled as i64],
        )?;
        Ok(conn.last_insert_rowid())
    }
}

pub fn delete_site(conn: &Connection, id: i64) -> Result<bool> {
    Ok(conn.execute("DELETE FROM sites WHERE id=?1", params![id])? > 0)
}

pub fn site_check_done(
    conn: &Connection,
    id: i64,
    status: u32,
    ms: f64,
    now: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE sites SET last_status=?2, last_ms=?3, last_check=?4 WHERE id=?1",
        params![id, status as i64, ms, now],
    )?;
    Ok(())
}

pub fn site_notify_done(conn: &Connection, id: i64, now: &str) -> Result<()> {
    conn.execute(
        "UPDATE sites SET last_notify=?2 WHERE id=?1",
        params![id, now],
    )?;
    Ok(())
}

/// SQLite 的 CREATE TABLE IF NOT EXISTS 不会给旧库补字段；逐个检测再 ALTER。
fn migrate_metrics_probe_columns(conn: &Connection) -> Result<()> {
    let mut st = conn.prepare("PRAGMA table_info(metrics)")?;
    let names = st
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<std::collections::HashSet<_>>>()?;
    for (name, ty) in [
        ("probe_target", "TEXT NOT NULL DEFAULT ''"),
        ("probe_sent", "INTEGER NOT NULL DEFAULT 0"),
        ("probe_received", "INTEGER NOT NULL DEFAULT 0"),
        ("probe_loss_pct", "REAL NOT NULL DEFAULT 0"),
        ("latency_avg_ms", "REAL"),
        ("latency_min_ms", "REAL"),
        ("latency_max_ms", "REAL"),
        ("jitter_ms", "REAL"),
        // 多目标探测结果（v2 agent 的 probes 数组），仪表盘按目标画多条线
        ("probes", "TEXT NOT NULL DEFAULT '[]'"),
    ] {
        if !names.contains(name) {
            conn.execute_batch(&format!("ALTER TABLE metrics ADD COLUMN {name} {ty}"))?;
        }
    }
    // probe_targets.enabled：禁用的目标不下发 agent
    let mut st2 = conn.prepare("PRAGMA table_info(probe_targets)")?;
    let tnames = st2
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<std::collections::HashSet<_>>>()?;
    if !tnames.contains("enabled") {
        conn.execute_batch(
            "ALTER TABLE probe_targets ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1",
        )?;
    }
    // servers.country：服务器所属国家（后台手选，国旗 emoji 前端显示）
    let mut st3 = conn.prepare("PRAGMA table_info(servers)")?;
    let snames = st3
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<std::collections::HashSet<_>>>()?;
    drop(st3);
    if !snames.contains("country") {
        conn.execute_batch("ALTER TABLE servers ADD COLUMN country TEXT NOT NULL DEFAULT ''")?;
    }
    // servers.report_interval：每台上报间隔（秒），0 = 用系统设置全局值
    // servers.fail_threshold：连续上报失败判离线次数，0 = 用全局默认
    if !snames.contains("report_interval") {
        conn.execute_batch("ALTER TABLE servers ADD COLUMN report_interval INTEGER NOT NULL DEFAULT 0")?;
    }
    if !snames.contains("fail_threshold") {
        conn.execute_batch("ALTER TABLE servers ADD COLUMN fail_threshold INTEGER NOT NULL DEFAULT 0")?;
    }
    Ok(())
}

const THEME_MINIMAL: &str = include_str!("../themes/minimal-white.css");
const THEME_DARKGEEK: &str = include_str!("../themes/dark-geek.css");
const THEME_DEEPSPACE: &str = include_str!("../themes/deep-space.css");

fn seed_themes(conn: &Connection) -> Result<()> {
    let now = now_str();
    for (name, desc, css) in [
        ("极简白", "默认。浅色、干净、无装饰。", THEME_MINIMAL),
        (
            "深色极客",
            "暗色终端风，等宽字体，霓虹绿强调色。",
            THEME_DARKGEEK,
        ),
        (
            "深空青",
            "深空背景 + 青绿强调色，胶囊标签与渐变进度条。",
            THEME_DEEPSPACE,
        ),
    ] {
        conn.execute(
            "INSERT INTO themes (name, description, css, builtin, created_at, updated_at)
             VALUES (?1, ?2, ?3, 1, ?4, ?4)
             ON CONFLICT(name) DO NOTHING",
            params![name, desc, css, now],
        )?;
    }
    // 默认激活主题
    let has_active: Option<String> = conn
        .query_row("SELECT v FROM kv WHERE k='active_theme'", [], |r| r.get(0))
        .optional()?;
    if has_active.is_none() {
        conn.execute(
            "INSERT OR REPLACE INTO kv (k, v) VALUES ('active_theme', '极简白')",
            [],
        )?;
    }
    Ok(())
}

pub fn now_str() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// 由 hostname 派生稳定 id，agent 重装后不会变成新机器
pub fn server_id_for(hostname: &str) -> String {
    // FNV-1a 64，取 12 位十六进制
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in hostname.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("{h:016x}")[..12].to_string()
}

pub fn set_server_country(conn: &Connection, id: &str, country: &str) -> Result<()> {
    conn.execute(
        "UPDATE servers SET country=?2 WHERE id=?1",
        params![id, country],
    )?;
    Ok(())
}

pub fn upsert_server(
    conn: &Connection,
    id: &str,
    hostname: &str,
    os: &str,
    arch: &str,
    kernel: &str,
    cpu_name: &str,
    cpu_cores: u32,
) -> Result<()> {
    let now = now_str();
    conn.execute(
        "INSERT INTO servers (id, name, hostname, os, arch, kernel, cpu_name, cpu_cores, created_at, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
         ON CONFLICT(id) DO UPDATE SET
            hostname=excluded.hostname, os=excluded.os, arch=excluded.arch,
            kernel=excluded.kernel, cpu_name=excluded.cpu_name,
            cpu_cores=excluded.cpu_cores, last_seen=excluded.last_seen",
        params![id, hostname, hostname, os, arch, kernel, cpu_name, cpu_cores, now],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn insert_metric(conn: &Connection, r: &monitor_common::Report, id: &str) -> Result<()> {
    // 多目标结果为空时，把单目标 probe 也塞进数组，仪表盘只认 probes 就够了
    let probes = if r.probes.is_empty() {
        if r.probe.target.is_empty() {
            Vec::new()
        } else {
            vec![r.probe.clone()]
        }
    } else {
        r.probes.clone()
    };
    conn.execute(
        "INSERT INTO metrics (server_id, ts, cpu_usage, load1, load5, load15,
            mem_total, mem_used, swap_total, swap_used, uptime, net_rx, net_tx, processes, disks,
            probe_target, probe_sent, probe_received, probe_loss_pct,
            latency_avg_ms, latency_min_ms, latency_max_ms, jitter_ms, probes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
            ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)",
        params![
            id,
            r.ts,
            r.cpu_usage as f64,
            r.load1,
            r.load5,
            r.load15,
            r.mem_total as i64,
            r.mem_used as i64,
            r.swap_total as i64,
            r.swap_used as i64,
            r.uptime as i64,
            r.net.rx as i64,
            r.net.tx as i64,
            r.processes as i64,
            serde_json::to_string(&r.disks).unwrap_or_else(|_| "[]".into()),
            r.probe.target,
            r.probe.sent as i64,
            r.probe.received as i64,
            r.probe.loss_pct,
            r.probe.latency_avg_ms,
            r.probe.latency_min_ms,
            r.probe.latency_max_ms,
            r.probe.jitter_ms,
            serde_json::to_string(&probes).unwrap_or_else(|_| "[]".into()),
        ],
    )?;
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ServerRow {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub kernel: String,
    pub cpu_name: String,
    pub cpu_cores: u32,
    pub note: String,
    pub country: String,
    pub last_seen: String,
    /// 每台上报间隔（秒），0 = 用系统设置全局值
    pub report_interval: u64,
    /// 连续上报失败判离线次数，0 = 用全局默认
    pub fail_threshold: u64,
}

pub fn servers(conn: &Connection) -> Result<Vec<ServerRow>> {
    let mut st = conn.prepare(
        "SELECT id, name, hostname, os, arch, kernel, cpu_name, cpu_cores, note, country, last_seen,
                report_interval, fail_threshold
         FROM servers ORDER BY name",
    )?;
    let rows = st
        .query_map([], |r| {
            Ok(ServerRow {
                id: r.get(0)?,
                name: r.get(1)?,
                hostname: r.get(2)?,
                os: r.get(3)?,
                arch: r.get(4)?,
                kernel: r.get(5)?,
                cpu_name: r.get(6)?,
                cpu_cores: r.get(7)?,
                note: r.get(8)?,
                country: r.get(9)?,
                last_seen: r.get(10)?,
                report_interval: r.get::<_, i64>(11)?.max(0) as u64,
                fail_threshold: r.get::<_, i64>(12)?.max(0) as u64,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(st);
    Ok(rows)
}

/// 更新单服务器上报间隔 / 失败阈值（0 = 回落全局默认）
pub fn set_server_timing(conn: &Connection, id: &str, report_interval: u64, fail_threshold: u64) -> Result<bool> {
    Ok(conn.execute(
        "UPDATE servers SET report_interval=?2, fail_threshold=?3 WHERE id=?1",
        params![id, (report_interval.min(3600)) as i64, (fail_threshold.min(100)) as i64],
    )? > 0)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricRow {
    pub ts: String,
    pub cpu_usage: f64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub uptime: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub processes: u64,
    pub disks: Vec<monitor_common::DiskInfo>,
    pub probe: monitor_common::NetworkProbe,
    /// 多目标探测（v2 agent 上报）；旧 agent 上报时由 insert_metric 把单目标 probe 复制进来
    #[serde(default)]
    pub probes: Vec<monitor_common::NetworkProbe>,
}

fn map_metric(r: &rusqlite::Row) -> rusqlite::Result<MetricRow> {
    let disks: String = r.get(13)?;
    let probes: String = r.get(22)?;
    Ok(MetricRow {
        ts: r.get(0)?,
        cpu_usage: r.get(1)?,
        load1: r.get(2)?,
        load5: r.get(3)?,
        load15: r.get(4)?,
        mem_total: r.get::<_, i64>(5)? as u64,
        mem_used: r.get::<_, i64>(6)? as u64,
        swap_total: r.get::<_, i64>(7)? as u64,
        swap_used: r.get::<_, i64>(8)? as u64,
        uptime: r.get::<_, i64>(9)? as u64,
        net_rx: r.get::<_, i64>(10)? as u64,
        net_tx: r.get::<_, i64>(11)? as u64,
        processes: r.get::<_, i64>(12)? as u64,
        disks: serde_json::from_str(&disks).unwrap_or_default(),
        probe: monitor_common::NetworkProbe {
            target: r.get(14)?,
            method: String::new(),
            sent: r.get::<_, i64>(15)? as u32,
            received: r.get::<_, i64>(16)? as u32,
            loss_pct: r.get(17)?,
            latency_avg_ms: r.get(18)?,
            latency_min_ms: r.get(19)?,
            latency_max_ms: r.get(20)?,
            jitter_ms: r.get(21)?,
        },
        probes: serde_json::from_str(&probes).unwrap_or_default(),
    })
}

const METRIC_COLS: &str = "ts, cpu_usage, load1, load5, load15, mem_total, mem_used,
    swap_total, swap_used, uptime, net_rx, net_tx, processes, disks,
    probe_target, probe_sent, probe_received, probe_loss_pct,
    latency_avg_ms, latency_min_ms, latency_max_ms, jitter_ms, probes";

/// 最近 n 条，时间正序返回
pub fn history(conn: &Connection, id: &str, n: u32) -> Result<Vec<MetricRow>> {
    let mut st = conn.prepare(&format!(
        "SELECT {METRIC_COLS} FROM (
            SELECT {METRIC_COLS} FROM metrics WHERE server_id=?1 ORDER BY ts DESC LIMIT ?2
         ) ORDER BY ts ASC"
    ))?;
    let v = st
        .query_map(params![id, n], map_metric)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(v)
}

pub fn server_exists(conn: &Connection, id: &str) -> Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM servers WHERE id=?1",
        params![id],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

pub fn rename_server(conn: &Connection, id: &str, name: &str) -> Result<()> {
    conn.execute("UPDATE servers SET name=?2 WHERE id=?1", params![id, name])?;
    Ok(())
}

pub fn delete_server(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM metrics WHERE server_id=?1", params![id])?;
    conn.execute("DELETE FROM probe_excludes WHERE server_id=?1", params![id])?;
    conn.execute("DELETE FROM servers WHERE id=?1", params![id])?;
    Ok(())
}

// ---------- 通用 kv 设置 ----------

pub fn kv_get(conn: &Connection, key: &str, default: &str) -> String {
    conn.query_row("SELECT v FROM kv WHERE k=?1", params![key], |r| r.get(0))
        .optional()
        .ok()
        .flatten()
        .unwrap_or_else(|| default.into())
}

pub fn kv_set(conn: &Connection, key: &str, value: &str) {
    let _ = conn.execute(
        "INSERT OR REPLACE INTO kv (k, v) VALUES (?1, ?2)",
        params![key, value],
    );
}

// ---------- 通知日志 ----------

pub fn notify_log(conn: &Connection, kind: &str, text: &str, ok: bool) {
    let _ = conn.execute(
        "INSERT INTO notify_log (ts, kind, text, ok) VALUES (?1, ?2, ?3, ?4)",
        params![now_str(), kind, text, ok as i64],
    );
}

// ---------- 主题 ----------

#[derive(Debug, Clone, serde::Serialize)]
pub struct ThemeRow {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub css: String,
    pub builtin: bool,
    pub updated_at: String,
}

const THEME_COLS: &str = "id, name, description, css, builtin, updated_at";

fn map_theme(r: &rusqlite::Row) -> rusqlite::Result<ThemeRow> {
    Ok(ThemeRow {
        id: r.get(0)?,
        name: r.get(1)?,
        description: r.get(2)?,
        css: r.get(3)?,
        builtin: r.get::<_, i64>(4)? != 0,
        updated_at: r.get(5)?,
    })
}

pub fn themes(conn: &Connection) -> Result<Vec<ThemeRow>> {
    let mut st = conn.prepare(&format!(
        "SELECT {THEME_COLS} FROM themes ORDER BY builtin DESC, name"
    ))?;
    let v = st
        .query_map([], map_theme)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(v)
}

pub fn theme_by_name(conn: &Connection, name: &str) -> Result<Option<ThemeRow>> {
    Ok(conn
        .query_row(
            &format!("SELECT {THEME_COLS} FROM themes WHERE name=?1"),
            params![name],
            map_theme,
        )
        .optional()?)
}

pub fn create_theme(conn: &Connection, name: &str, desc: &str, css: &str) -> Result<i64> {
    let now = now_str();
    conn.execute(
        "INSERT INTO themes (name, description, css, builtin, created_at, updated_at)
         VALUES (?1, ?2, ?3, 0, ?4, ?4)",
        params![name, desc, css, now],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn update_theme(conn: &Connection, id: i64, name: &str, desc: &str, css: &str) -> Result<()> {
    conn.execute(
        "UPDATE themes SET name=?2, description=?3, css=?4, updated_at=?5 WHERE id=?1",
        params![id, name, desc, css, now_str()],
    )?;
    Ok(())
}

/// 返回 false 表示主题不存在；内置主题拒绝删除
pub fn delete_theme(conn: &Connection, id: i64) -> Result<DeleteOutcome> {
    let builtin: Option<i64> = conn
        .query_row("SELECT builtin FROM themes WHERE id=?1", params![id], |r| {
            r.get(0)
        })
        .optional()?;
    match builtin {
        None => Ok(DeleteOutcome::NotFound),
        Some(1) => Ok(DeleteOutcome::Builtin),
        Some(_) => {
            conn.execute("DELETE FROM themes WHERE id=?1", params![id])?;
            Ok(DeleteOutcome::Ok)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeleteOutcome {
    Ok,
    Builtin,
    NotFound,
}

pub fn active_theme_name(conn: &Connection) -> Result<String> {
    Ok(conn
        .query_row("SELECT v FROM kv WHERE k='active_theme'", [], |r| r.get(0))
        .optional()?
        .unwrap_or_else(|| "极简白".into()))
}

pub fn set_active_theme(conn: &Connection, name: &str) -> Result<bool> {
    if theme_by_name(conn, name)?.is_none() {
        return Ok(false);
    }
    conn.execute(
        "INSERT OR REPLACE INTO kv (k, v) VALUES ('active_theme', ?1)",
        params![name],
    )?;
    Ok(true)
}

// ---------- 清理 ----------

/// 删除过期采样 + 兜底行数上限，压缩 WAL，必要时回收空间。
/// 返回删除行数，供调用方决定是否 VACUUM。
pub fn cleanup(conn: &Connection, ret: Retention) -> Result<CleanupStats> {
    let mut stats = CleanupStats::default();
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(ret.days as i64))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    stats.metrics_deleted +=
        conn.execute("DELETE FROM metrics WHERE ts < ?1", params![cutoff])? as u64;

    // 每台机器只留最近 max_rows_per_server 条
    stats.metrics_deleted += conn.execute(
        "DELETE FROM metrics WHERE rowid IN (
            SELECT rowid FROM metrics m
            WHERE (SELECT COUNT(*) FROM metrics m2
                   WHERE m2.server_id = m.server_id AND m2.ts >= m.ts) > ?1
         )",
        params![ret.max_rows_per_server],
    )? as u64;

    // 清掉已经没有采样的僵尸服务器记录
    conn.execute(
        "DELETE FROM servers WHERE last_seen < ?1
           AND id NOT IN (SELECT DISTINCT server_id FROM metrics)",
        params![cutoff],
    )?;

    conn.execute_batch("PRAGMA incremental_vacuum; PRAGMA wal_checkpoint(TRUNCATE);")?;

    // 空闲页占比高才做整库 VACUUM（代价大，不能每次都跑）
    let page_count: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let free_count: i64 = conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
    if page_count > 2000 && free_count * 4 > page_count {
        conn.execute_batch("VACUUM")?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        stats.vacuumed = true;
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_db() -> Db {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        Arc::new(Mutex::new(conn))
    }

    fn rep(ts: &str, host: &str) -> monitor_common::Report {
        monitor_common::Report {
            ts: ts.into(),
            hostname: host.into(),
            cpu_usage: 10.0,
            cpu_cores: 2,
            mem_total: 1000,
            mem_used: 200,
            ..Default::default()
        }
    }

    #[test]
    fn probe_targets_filter_by_enabled() {
        let db = mem_db();
        let c = db.lock().unwrap();
        add_probe_target(&c, "CF", "1.1.1.1", "icmp").unwrap();
        let id2 = add_probe_target(&c, "GG", "8.8.8.8", "icmp").unwrap();
        // 关掉 GG
        assert!(update_probe_target(&c, id2, "GG", "8.8.8.8", "icmp", false).unwrap());
        let all = probe_targets_all(&c).unwrap();
        assert_eq!(all.len(), 2);
        let enabled = probe_targets_enabled(&c).unwrap();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].name, "CF");
        assert!(all.iter().any(|r| !r.enabled && r.name == "GG"));
    }

    #[test]
    fn probe_targets_per_server_excludes() {
        let db = mem_db();
        let c = db.lock().unwrap();
        add_probe_target(&c, "CF", "1.1.1.1", "icmp").unwrap();
        add_probe_target(&c, "GG", "8.8.8.8", "icmp").unwrap();
        // 服务器 A 排除 GG（按地址）
        set_probe_excludes(&c, "srvA", &["8.8.8.8".into()]).unwrap();
        let a = probe_targets_for_server(&c, "srvA").unwrap();
        assert_eq!(a.len(), 1, "A 应只剩 CF");
        assert_eq!(a[0].target, "1.1.1.1");
        // 服务器 B 无排除行 = 全部（默认语义）
        assert_eq!(probe_targets_for_server(&c, "srvB").unwrap().len(), 2, "B 默认拿到全部启用项");
        // 清空排除 = 回到全部
        set_probe_excludes(&c, "srvA", &[]).unwrap();
        assert_eq!(probe_targets_for_server(&c, "srvA").unwrap().len(), 2);
        // 排除一个不存在的地址不应出错，也不影响结果
        set_probe_excludes(&c, "srvA", &["9.9.9.9".into()]).unwrap();
        assert_eq!(probe_targets_for_server(&c, "srvA").unwrap().len(), 2);
    }

    #[test]
    fn server_timing_roundtrip_and_clamp() {
        let db = mem_db();
        let c = db.lock().unwrap();
        // agent 上报一次，生成服务器行
        let r = monitor_common::Report { hostname: "timing-test".into(), ..Default::default() };
        let id = server_id_for("timing-test");
        upsert_server(&c, &id, "timing-test", "linux", "x86_64", "k", "cpu", 1).unwrap();
        assert!(!set_server_timing(&c, "nope", 60, 5).unwrap(), "不存在 id 应返回 false");
        assert!(set_server_timing(&c, &id, 99999, 999).unwrap(), "clamp 后仍应更新成功");
        let s = servers(&c).unwrap().into_iter().find(|s| s.id == id).unwrap();
        assert_eq!(s.report_interval, 3600, "间隔上限 3600");
        assert_eq!(s.fail_threshold, 100, "阈值上限 100");
        // 归零 = 回落全局
        assert!(set_server_timing(&c, &id, 0, 0).unwrap());
        let s = servers(&c).unwrap().into_iter().find(|s| s.id == id).unwrap();
        assert_eq!((s.report_interval, s.fail_threshold), (0, 0));
        let _ = r;
    }

    #[test]
    fn seeds_builtin_themes_and_active() {
        let db = mem_db();
        let c = db.lock().unwrap();
        let t = themes(&c).unwrap();
        assert!(t.iter().all(|x| x.builtin), "全部应为内置主题");
        let names: Vec<&str> = t.iter().map(|x| x.name.as_str()).collect();
        for want in ["极简白", "深色极客", "深空青"] {
            assert!(names.contains(&want), "缺少内置主题 {want}");
        }
        assert_eq!(active_theme_name(&c).unwrap(), "极简白");
    }

    #[test]
    fn builtin_theme_cannot_be_deleted_but_custom_can() {
        let db = mem_db();
        let c = db.lock().unwrap();
        let builtin_id = theme_by_name(&c, "深色极客").unwrap().unwrap().id;
        assert_eq!(
            delete_theme(&c, builtin_id).unwrap(),
            DeleteOutcome::Builtin
        );
        let id = create_theme(&c, "自定义", "x", "body{}").unwrap();
        assert_eq!(delete_theme(&c, id).unwrap(), DeleteOutcome::Ok);
        assert_eq!(delete_theme(&c, 9999).unwrap(), DeleteOutcome::NotFound);
    }

    #[test]
    fn admin_default_credentials_and_change() {
        let db = mem_db();
        let c = db.lock().unwrap();
        // 默认 admin/admin 能登录
        assert!(verify_user(&c, "admin", "admin").unwrap().is_some());
        assert!(verify_user(&c, "admin", "wrong").unwrap().is_none());

        // 改用户名+密码需要验证旧密码
        assert!(update_credentials(&c, "admin", "bad", "root", "s3cret").unwrap() == false);
        assert!(update_credentials(&c, "admin", "admin", "root", "s3cret").unwrap());
        assert!(verify_user(&c, "root", "s3cret").unwrap().is_some());
        assert!(verify_user(&c, "admin", "admin").unwrap().is_none());
    }

    #[test]
    fn probe_config_roundtrip_with_clamp() {
        let db = mem_db();
        let c = db.lock().unwrap();
        let (t, m, n) = get_probe_config(&c).unwrap();
        // 默认不再带内置探测目标（1.1.1.1）；检测点由 probe_targets 表下发
        assert_eq!((t.as_str(), m.as_str(), n), ("", "icmp", 3));
        set_probe_config(&c, "223.5.5.5", "tcp", 99).unwrap();
        let (t, m, n) = get_probe_config(&c).unwrap();
        assert_eq!((t.as_str(), m.as_str(), n), ("223.5.5.5", "tcp", 10));
    }

    #[test]
    fn cleanup_drops_expired_and_enforces_row_cap() {
        let db = mem_db();
        let c = db.lock().unwrap();
        upsert_server(&c, "abc", "h1", "linux", "x86_64", "6.1", "cpu", 4).unwrap();

        // 3 条过期
        for i in 0..3 {
            insert_metric(
                &c,
                &rep(&format!("2000-01-0{}T00:00:00Z", i + 1), "h1"),
                "abc",
            )
            .unwrap();
        }
        // 10 条新鲜
        for i in 0..10 {
            let ts = (chrono::Utc::now() - chrono::Duration::seconds(100 - i))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            insert_metric(&c, &rep(&ts, "h1"), "abc").unwrap();
        }

        let s = cleanup(
            &c,
            Retention {
                days: 7,
                max_rows_per_server: 4,
            },
        )
        .unwrap();
        assert!(s.metrics_deleted >= 9, "deleted={}", s.metrics_deleted);
        let left = history(&c, "abc", 100).unwrap();
        assert_eq!(left.len(), 4, "row cap not enforced");
        // 保留的必须是最新的
        assert!(left.first().unwrap().ts > "2000-01-01T00:00:00Z".to_string());
    }

    #[test]
    fn server_id_is_stable_and_distinct() {
        assert_eq!(server_id_for("host-a"), server_id_for("host-a"));
        assert_ne!(server_id_for("host-a"), server_id_for("host-b"));
    }
}
