//! HTTP 层：agent 上报 + 只读仪表盘 API + 主题管理 API。

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use monitor_common::Report;
use rusqlite::params;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::db::{self, Db, Retention};
use crate::host::SharedSampler;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub token: Option<String>,
    pub host: SharedSampler,
}

pub fn router(state: AppState) -> Router {
    let admin_page_route = admin_page_path(&state);
    let mut r = Router::new()
        .route("/", get(dashboard))
        .route("/agent-bin/{file}", get(agent_bin))
        .route(&admin_page_route, get(admin_page))
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/public/dash-config", get(dash_config))
        // agent
        .route("/api/report", post(report))
        .route("/api/agent-config", get(agent_config))
        // 服务器
        .route("/api/servers", get(list_servers))
        .route("/api/servers/{id}", get(get_server))
        .route("/api/servers/{id}/history", get(get_history))
        .route("/api/servers/{id}", put(rename_server))
        .route("/api/servers/{id}", delete(remove_server))
        // 主题
        .route("/api/themes", get(list_themes))
        .route("/api/themes", post(create_theme))
        .route("/api/themes/{id}", put(update_theme))
        .route("/api/themes/{id}", delete(remove_theme))
        .route("/api/themes/active", get(get_active_theme))
        .route("/api/themes/active", put(set_active_theme))
        .route("/api/theme.css", get(theme_css))
        // 后台
        .route("/api/admin/login", post(admin_login))
        .route("/api/admin/logout", post(admin_logout))
        .route("/api/admin/credentials", put(admin_credentials))
        .route(
            "/api/admin/probe-config",
            get(admin_get_probe).put(admin_set_probe),
        )
        // 多探测目标
        .route(
            "/api/admin/probe-targets",
            get(list_probe_targets).post(add_probe_target),
        )
        .route(
            "/api/admin/probe-targets/{id}",
            delete(remove_probe_target).put(update_probe_target),
        )
        // 网站监控
        .route("/api/admin/sites", get(list_sites).post(save_site))
        .route("/api/admin/sites/{id}", delete(remove_site))
        // 通知设置
        .route("/api/admin/notify", get(get_notify).put(set_notify).post(test_notify))
        // 备份恢复
        .route("/api/admin/backup", get(backup_export))
        .route("/api/admin/restore", post(restore_import))
        // 仪表盘显示设置 + 数据保留
        .route(
            "/api/admin/settings",
            get(get_settings).put(set_settings),
        )
        // 清空全部采集数据（保留服务器列表与配置）
        .route("/api/admin/metrics", delete(clear_metrics))
        // 中心机自身资源占用（关于页）
        .route("/api/admin/host-stats", get(host_stats));
    if admin_page_route != "/admin" {
        // 自定义路径时 /admin 保留为后备入口；默认时只注册一条，避免 axum 重复路由 panic
        r = r.route("/admin", get(admin_page));
    }
    r.with_state(Arc::new(state))
}

// ---------- 鉴权 ----------

fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let Some(expected) = state.token.as_deref() else {
        return Ok(());
    };
    let got = headers
        .get("x-token")
        .or_else(|| headers.get(header::AUTHORIZATION))
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or(v))
        .unwrap_or("");
    if got == expected {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "invalid token").into_response())
    }
}

/// 后台接口：接受 admin 会话，也接受 agent token（兼容原管理脚本）。
fn authorize_admin(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if authorize(state, headers).is_ok() && state.token.is_some() {
        return Ok(());
    }
    if admin_session(state, headers).is_some() {
        return Ok(());
    }
    Err((StatusCode::UNAUTHORIZED, "unauthorized").into_response())
}

/// 从请求头解析有效会话 token，命中返回。
fn admin_session(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let got = headers
        .get("x-admin-session")
        .and_then(|v| v.to_str().ok())?;
    let conn = state.db.lock().unwrap();
    let stored: Option<String> = conn
        .query_row("SELECT v FROM kv WHERE k='admin_session'", [], |r| r.get(0))
        .ok();
    stored.filter(|s| constant_eq(s, got))
}

fn constant_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn new_session_token() -> String {
    // ponytail: 时间+进程熵拼 sha256；要求强随机会话再换 rand。
    db::sha256_hex(
        format!(
            "{}:{}:{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            uuid_fallback()
        )
        .as_bytes(),
    )
}

fn uuid_fallback() -> String {
    std::thread::current().id().fork_map()
}

trait ForkMap {
    fn fork_map(self) -> String;
}
impl ForkMap for std::thread::ThreadId {
    fn fork_map(self) -> String {
        format!("{self:?}")
    }
}

// ---------- 后台 ----------

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

async fn admin_login(State(st): State<Arc<AppState>>, Json(b): Json<LoginBody>) -> Response {
    let conn = st.db.lock().unwrap();
    match db::verify_user(&conn, b.username.trim(), &b.password) {
        Ok(Some(_)) => {
            let token = new_session_token();
            let _ = conn.execute(
                "INSERT OR REPLACE INTO kv (k, v) VALUES ('admin_session', ?1)",
                params![token],
            );
            Json(json!({ "ok": true, "session": token })).into_response()
        }
        Ok(None) => (StatusCode::UNAUTHORIZED, "用户名或密码错误").into_response(),
        Err(e) => {
            log::error!("login: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "login failed").into_response()
        }
    }
}

async fn admin_logout(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if admin_session(&st, &headers).is_some() {
        let conn = st.db.lock().unwrap();
        let _ = conn.execute("DELETE FROM kv WHERE k='admin_session'", []);
    }
    (StatusCode::OK, "ok").into_response()
}

#[derive(Deserialize)]
struct CredentialsBody {
    old_username: String,
    old_password: String,
    new_username: String,
    new_password: String,
}

async fn admin_credentials(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(b): Json<CredentialsBody>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let (nu, np) = (b.new_username.trim(), b.new_password.as_str());
    if nu.is_empty() || nu.chars().count() > 48 {
        return (StatusCode::BAD_REQUEST, "invalid username").into_response();
    }
    if np.len() < 6 {
        return (StatusCode::BAD_REQUEST, "password must be >= 6 chars").into_response();
    }
    let conn = st.db.lock().unwrap();
    match db::update_credentials(&conn, &b.old_username, &b.old_password, nu, np) {
        Ok(true) => {
            // 凭据变更后旧会话作废
            let _ = conn.execute("DELETE FROM kv WHERE k='admin_session'", []);
            (StatusCode::OK, "ok").into_response()
        }
        Ok(false) => (StatusCode::UNAUTHORIZED, "旧用户名或密码错误").into_response(),
        Err(e) => {
            log::error!("credentials: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "update failed").into_response()
        }
    }
}

async fn admin_get_probe(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let conn = st.db.lock().unwrap();
    match db::get_probe_config(&conn) {
        // target/method 已废弃（多目标时代），只保留 count 供后台统一设置每轮探测次数
        Ok((_target, _method, count)) => {
            Json(json!({ "count": count })).into_response()
        }
        Err(e) => {
            log::error!("probe config: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "query failed").into_response()
        }
    }
}

#[derive(Deserialize)]
struct ProbeBody {
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default = "default_count")]
    count: u32,
}
fn default_count() -> u32 {
    3
}

async fn admin_set_probe(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(b): Json<ProbeBody>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let conn = st.db.lock().unwrap();
    // target/method 若未提供则沿用旧值；多目标时代它们只作 fallback
    let (old_target, old_method, _old_count) = db::get_probe_config(&conn).unwrap_or_default();
    let target = b.target.as_deref().unwrap_or(&old_target).to_string();
    let method = b
        .method
        .as_deref()
        .unwrap_or(&old_method)
        .to_string();
    if !["icmp", "http", "tcp"].contains(&method.as_str()) {
        return (StatusCode::BAD_REQUEST, "method must be icmp/http/tcp").into_response();
    }
    if target.chars().count() > 255 || target.starts_with('-') {
        return (StatusCode::BAD_REQUEST, "invalid target").into_response();
    }
    match db::set_probe_config(&conn, &target, &method, b.count.clamp(1, 10)) {
        Ok(()) => (StatusCode::OK, "ok").into_response(),
        Err(e) => {
            log::error!("probe config: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "update failed").into_response()
        }
    }
}

/// agent 每轮拉取探测配置；token 校验（未设 token 则放行）。
/// probe_targets 表为空时回落到旧单目标 kv 配置。
async fn agent_config(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = authorize(&st, &headers) {
        return e;
    }
    let conn = st.db.lock().unwrap();
    // 只下发启用的目标；禁用的留在后台列表里可随时改回来
    let targets = db::probe_targets_enabled(&conn).unwrap_or_default();
    match db::get_probe_config(&conn) {
        Ok((target, method, count)) => {
            let _ = (target, method);
            let report_interval: u64 = db::kv_get(&conn, "report_interval", "0")
                .parse().unwrap_or(0).clamp(0, 3600);
            Json(json!({
                "targets": targets,
                "count": count,
                "report_interval": report_interval,
            }))
            .into_response()
        }
        Err(e) => {
            log::error!("agent config: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "query failed").into_response()
        }
    }
}

// ---------- agent 上报 ----------

async fn report(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(r): Json<Report>,
) -> Response {
    if let Err(e) = authorize(&st, &headers) {
        return e;
    }
    // 信任边界：上报数据先做物理合理性校验，脏数据不进库
    let errs = r.sanity_errors();
    if !errs.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "errors": errs })),
        )
            .into_response();
    }
    if r.hostname.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "hostname required").into_response();
    }

    let id = db::server_id_for(&r.hostname);
    let conn = st.db.lock().unwrap();
    let res = (|| -> anyhow::Result<()> {
        db::upsert_server(
            &conn,
            &id,
            &r.hostname,
            &r.os,
            &r.arch,
            &r.kernel,
            &r.cpu_name,
            r.cpu_cores,
        )?;
        db::insert_metric(&conn, &r, &id)?;
        Ok(())
    })();
    match res {
        Ok(()) => Json(json!({ "ok": true, "server_id": id })).into_response(),
        Err(e) => {
            log::error!("report failed: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "store failed").into_response()
        }
    }
}

// ---------- 服务器查询 ----------

async fn list_servers(State(st): State<Arc<AppState>>) -> Response {
    let conn = st.db.lock().unwrap();
    match db::servers(&conn) {
        Ok(rows) => {
            // 附带最新一条采样，前端一张表就够用
            let out: Vec<_> = rows
                .iter()
                .map(|s| {
                    let latest = db::history(&conn, &s.id, 1).ok().and_then(|mut v| v.pop());
                    let interval = db::kv_get(&conn, "report_interval", "0")
                        .parse::<u64>()
                        .unwrap_or(0);
                    let online = is_online(&s.last_seen, interval);
                    json!({
                        "id": s.id, "name": s.name, "hostname": s.hostname,
                        "os": s.os, "arch": s.arch, "kernel": s.kernel,
                        "cpu_name": s.cpu_name, "cpu_cores": s.cpu_cores,
                        "note": s.note, "last_seen": s.last_seen, "online": online,
                        "latest": latest,
                    })
                })
                .collect();
            Json(out).into_response()
        }
        Err(e) => {
            log::error!("list servers: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "query failed").into_response()
        }
    }
}

/// 超过 3 个上报周期没动静算离线；窗口跟随后台配置的 report_interval
/// （默认 10s 时为 35s；设 5 分钟则放宽到 15 分钟）
/// 另加 10 分钟宽限：后台把间隔从大改小时，旧 agent 的长睡眠还没醒，
/// 立即按新窗口判定会误报离线。上线普遍后可收紧。
/// ponytail: 固定宽限覆盖不了 >10 分钟的间隔调小；那时改 per-server interval 下发
pub fn online_window_secs(report_interval: u64) -> i64 {
    (report_interval.max(1) as i64 * 3).max(35) + 600
}

fn is_online(last_seen: &str, report_interval: u64) -> bool {
    match chrono::DateTime::parse_from_rfc3339(last_seen) {
        Ok(t) => {
            chrono::Utc::now().signed_duration_since(t.with_timezone(&chrono::Utc))
                < chrono::Duration::seconds(online_window_secs(report_interval))
        }
        Err(_) => false,
    }
}

async fn get_server(State(st): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let conn = st.db.lock().unwrap();
    if !db::server_exists(&conn, &id).unwrap_or(false) {
        return (StatusCode::NOT_FOUND, "no such server").into_response();
    }
    let s = match db::servers(&conn) {
        Ok(v) => v.into_iter().find(|x| x.id == id),
        Err(e) => {
            log::error!("{e:#}");
            None
        }
    };
    let history = db::history(&conn, &id, 120).unwrap_or_default();
    Json(json!({ "server": s, "history": history })).into_response()
}

#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default = "default_n")]
    n: u32,
}
fn default_n() -> u32 {
    120
}

async fn get_history(
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    let conn = st.db.lock().unwrap();
    if !db::server_exists(&conn, &id).unwrap_or(false) {
        return (StatusCode::NOT_FOUND, "no such server").into_response();
    }
    match db::history(&conn, &id, q.n.clamp(1, 9000)) {
        Ok(v) => Json(v).into_response(),
        Err(e) => {
            log::error!("{e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "query failed").into_response()
        }
    }
}

#[derive(Deserialize)]
struct RenameBody {
    name: String,
}
async fn rename_server(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(b): Json<RenameBody>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let name = b.name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return (StatusCode::BAD_REQUEST, "name must be 1..=64 chars").into_response();
    }
    let conn = st.db.lock().unwrap();
    match db::rename_server(&conn, &id, name) {
        Ok(()) => (StatusCode::OK, "ok").into_response(),
        Err(e) => {
            log::error!("{e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "update failed").into_response()
        }
    }
}

async fn remove_server(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let conn = st.db.lock().unwrap();
    match db::delete_server(&conn, &id) {
        Ok(()) => (StatusCode::OK, "ok").into_response(),
        Err(e) => {
            log::error!("{e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "delete failed").into_response()
        }
    }
}

// ---------- 主题 ----------

async fn list_themes(State(st): State<Arc<AppState>>) -> Response {
    let conn = st.db.lock().unwrap();
    match db::themes(&conn).and_then(|t| Ok((t, db::active_theme_name(&conn)?))) {
        Ok((t, active)) => Json(json!({ "themes": t, "active": active })).into_response(),
        Err(e) => {
            log::error!("{e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "query failed").into_response()
        }
    }
}

#[derive(Deserialize)]
struct ThemeBody {
    name: String,
    #[serde(default)]
    description: String,
    css: String,
}

/// 主题 CSS 会直接注入 <style>，必须挡住 </style> 逃逸与远程加载
fn validate_theme(b: &ThemeBody) -> Result<(), String> {
    let name = b.name.trim();
    if name.is_empty() || name.chars().count() > 48 {
        return Err("name must be 1..=48 chars".into());
    }
    if b.css.trim().is_empty() {
        return Err("css must not be empty".into());
    }
    if b.css.len() > 512 * 1024 {
        return Err("css too large (max 512 KiB)".into());
    }
    let lower = b.css.to_ascii_lowercase();
    for bad in [
        "</style",
        "<script",
        "javascript:",
        "expression(",
        "@import",
    ] {
        if lower.contains(bad) {
            return Err(format!("css contains forbidden token: {bad}"));
        }
    }
    Ok(())
}

async fn create_theme(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(b): Json<ThemeBody>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    if let Err(msg) = validate_theme(&b) {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }
    let conn = st.db.lock().unwrap();
    if db::theme_by_name(&conn, b.name.trim())
        .unwrap_or(None)
        .is_some()
    {
        return (StatusCode::CONFLICT, "theme name exists").into_response();
    }
    match db::create_theme(&conn, b.name.trim(), &b.description, &b.css) {
        Ok(id) => Json(json!({ "id": id })).into_response(),
        Err(e) => {
            log::error!("{e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "insert failed").into_response()
        }
    }
}

async fn update_theme(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(b): Json<ThemeBody>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    if let Err(msg) = validate_theme(&b) {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }
    let conn = st.db.lock().unwrap();
    match db::update_theme(&conn, id, b.name.trim(), &b.description, &b.css) {
        Ok(()) => (StatusCode::OK, "ok").into_response(),
        Err(e) => {
            log::error!("{e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "update failed").into_response()
        }
    }
}

async fn remove_theme(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let conn = st.db.lock().unwrap();
    match db::delete_theme(&conn, id) {
        Ok(db::DeleteOutcome::Ok) => (StatusCode::OK, "ok").into_response(),
        Ok(db::DeleteOutcome::Builtin) => {
            (StatusCode::FORBIDDEN, "builtin theme cannot be deleted").into_response()
        }
        Ok(db::DeleteOutcome::NotFound) => (StatusCode::NOT_FOUND, "no such theme").into_response(),
        Err(e) => {
            log::error!("{e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "delete failed").into_response()
        }
    }
}

async fn get_active_theme(State(st): State<Arc<AppState>>) -> Response {
    let conn = st.db.lock().unwrap();
    let name = db::active_theme_name(&conn).unwrap_or_else(|_| "极简白".into());
    match db::theme_by_name(&conn, &name) {
        Ok(Some(t)) => Json(json!({ "name": t.name, "css": t.css })).into_response(),
        _ => (StatusCode::NOT_FOUND, "active theme missing").into_response(),
    }
}

#[derive(Deserialize)]
struct ActiveBody {
    name: String,
}
async fn set_active_theme(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(b): Json<ActiveBody>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let conn = st.db.lock().unwrap();
    match db::set_active_theme(&conn, &b.name) {
        Ok(true) => (StatusCode::OK, "ok").into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such theme").into_response(),
        Err(e) => {
            log::error!("{e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "update failed").into_response()
        }
    }
}

/// 仪表盘用 <link rel=stylesheet href="/api/theme.css">
async fn theme_css(State(st): State<Arc<AppState>>) -> Response {
    let conn = st.db.lock().unwrap();
    let name = db::active_theme_name(&conn).unwrap_or_else(|_| "极简白".into());
    match db::theme_by_name(&conn, &name) {
        Ok(Some(t)) => ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], t.css).into_response(),
        _ => (
            [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
            ":root{}".to_string(),
        )
            .into_response(),
    }
}

/// 仪表盘公开显示配置（无需鉴权，仅开关与小时数）
async fn dash_config(State(st): State<Arc<AppState>>) -> Response {
    let conn = st.db.lock().unwrap();
    Json(json!({
        "disksTotalOnly": db::kv_get(&conn, "dash_disks_total_only", "1") == "1",
        "showTraffic": db::kv_get(&conn, "dash_show_traffic", "1") == "1",
        "probeHours": db::kv_get(&conn, "dash_probe_hours", "8").parse::<u32>().unwrap_or(8).clamp(1, 72),
        "lossHours": db::kv_get(&conn, "dash_loss_hours", "8").parse::<u32>().unwrap_or(8).clamp(1, 72),
        "showLatencyChart": db::kv_get(&conn, "dash_show_latency_chart", "1") == "1",
        "showLossChart": db::kv_get(&conn, "dash_show_loss_chart", "1") == "1",
        "showCpuChart": db::kv_get(&conn, "dash_show_cpu_chart", "1") == "1",
        "adminPath": normalize_admin_path(&db::kv_get(&conn, "admin_path", "admin")),
        "showAdminLink": db::kv_get(&conn, "dash_show_admin_link", "1") == "1",
        "siteTitle": db::kv_get(&conn, "site_title", "服务器探针"),
        "pageTitle": db::kv_get(&conn, "page_title", "服务器探针"),
    }))
    .into_response()
}

// ---------- 多探测目标 ----------

async fn list_probe_targets(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let conn = st.db.lock().unwrap();
    match db::probe_targets_all(&conn) {
        Ok(v) => Json(v).into_response(),
        Err(e) => {
            log::error!("{e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "query failed").into_response()
        }
    }
}

#[derive(Deserialize)]
struct ProbeTargetBody {
    name: String,
    target: String,
    #[serde(default = "default_method_str")]
    method: String,
}
fn default_method_str() -> String {
    "icmp".into()
}

async fn add_probe_target(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(b): Json<ProbeTargetBody>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let (name, target) = (b.name.trim(), b.target.trim());
    if name.is_empty() || name.chars().count() > 64 {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }
    if target.is_empty() || target.chars().count() > 255 {
        return (StatusCode::BAD_REQUEST, "invalid target").into_response();
    }
    if !["icmp", "http", "tcp"].contains(&b.method.as_str()) {
        return (StatusCode::BAD_REQUEST, "method must be icmp/http/tcp").into_response();
    }
    let conn = st.db.lock().unwrap();
    match db::add_probe_target(&conn, name, target, &b.method) {
        Ok(id) => Json(json!({ "id": id })).into_response(),
        Err(e) => {
            log::error!("{e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "insert failed").into_response()
        }
    }
}

#[derive(Deserialize)]
struct ProbeTargetUpdate {
    name: String,
    target: String,
    #[serde(default = "default_method_str")]
    method: String,
    #[serde(default = "default_true")]
    enabled: bool,
}
async fn update_probe_target(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(b): Json<ProbeTargetUpdate>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let (name, target) = (b.name.trim(), b.target.trim());
    if name.is_empty() || name.chars().count() > 64 {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }
    if target.is_empty() || target.chars().count() > 255 || target.starts_with('-') {
        return (StatusCode::BAD_REQUEST, "invalid target").into_response();
    }
    if !["icmp", "http", "tcp"].contains(&b.method.as_str()) {
        return (StatusCode::BAD_REQUEST, "method must be icmp/http/tcp").into_response();
    }
    let conn = st.db.lock().unwrap();
    match db::update_probe_target(&conn, id, name, target, &b.method, b.enabled) {
        Ok(true) => (StatusCode::OK, "ok").into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such target").into_response(),
        Err(e) => {
            log::error!("{e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "update failed").into_response()
        }
    }
}

async fn remove_probe_target(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let conn = st.db.lock().unwrap();
    match db::delete_probe_target(&conn, id) {
        Ok(true) => (StatusCode::OK, "ok").into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such target").into_response(),
        Err(e) => {
            log::error!("{e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "delete failed").into_response()
        }
    }
}

// ---------- 网站监控 ----------

async fn list_sites(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let conn = st.db.lock().unwrap();
    match db::sites(&conn) {
        Ok(v) => Json(v).into_response(),
        Err(e) => {
            log::error!("{e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "query failed").into_response()
        }
    }
}

#[derive(Deserialize)]
struct SiteBody {
    #[serde(default)]
    id: Option<i64>,
    name: String,
    url: String,
    #[serde(default = "default_interval")]
    interval_s: u64,
    #[serde(default = "default_true")]
    enabled: bool,
}
fn default_interval() -> u64 {
    60
}
fn default_true() -> bool {
    true
}

async fn save_site(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(b): Json<SiteBody>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let (name, url) = (b.name.trim(), b.url.trim());
    if name.is_empty() || name.chars().count() > 64 {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return (StatusCode::BAD_REQUEST, "url must start with http:// or https://").into_response();
    }
    if url.chars().count() > 512 {
        return (StatusCode::BAD_REQUEST, "url too long").into_response();
    }
    let interval = b.interval_s.clamp(10, 3600);
    let conn = st.db.lock().unwrap();
    match db::upsert_site(&conn, b.id, name, url, interval, b.enabled) {
        Ok(id) => Json(json!({ "id": id })).into_response(),
        Err(e) => {
            log::error!("{e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "save failed").into_response()
        }
    }
}

async fn remove_site(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let conn = st.db.lock().unwrap();
    match db::delete_site(&conn, id) {
        Ok(true) => (StatusCode::OK, "ok").into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such site").into_response(),
        Err(e) => {
            log::error!("{e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "delete failed").into_response()
        }
    }
}

// ---------- 通知设置 ----------

#[derive(Deserialize, Default)]
struct NotifyBody {
    #[serde(default)]
    channel: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    secret: String,
    #[serde(default = "default_true")]
    offline_on: bool,
    #[serde(default = "default_true")]
    site_on: bool,
}

async fn get_notify(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let conn = st.db.lock().unwrap();
    let c = crate::notify::load_config(&conn);
    Json(json!({
        "channel": c.channel, "url": c.url, "secret": c.secret,
        "offline_on": c.offline_on, "site_on": c.site_on,
    }))
    .into_response()
}

async fn set_notify(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(b): Json<NotifyBody>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    if !["generic", "dingtalk", "feishu"].contains(&b.channel.as_str()) {
        return (StatusCode::BAD_REQUEST, "channel must be generic/dingtalk/feishu").into_response();
    }
    if !b.url.is_empty() && !b.url.starts_with("http://") && !b.url.starts_with("https://") {
        return (StatusCode::BAD_REQUEST, "url must start with http(s)://").into_response();
    }
    if b.url.chars().count() > 512 || b.secret.chars().count() > 256 {
        return (StatusCode::BAD_REQUEST, "url/secret too long").into_response();
    }
    let conn = st.db.lock().unwrap();
    crate::notify::save_config(
        &conn,
        &crate::notify::NotifyConfig {
            channel: b.channel,
            url: b.url.trim().to_string(),
            secret: b.secret.trim().to_string(),
            offline_on: b.offline_on,
            site_on: b.site_on,
        },
    );
    (StatusCode::OK, "ok").into_response()
}

#[derive(Deserialize)]
struct TestNotifyBody {
    #[serde(default = "default_test_text")]
    text: String,
}
fn default_test_text() -> String {
    "测试通知：服务器探针通知通道正常。".into()
}

/// 阻塞 HTTP 放独立线程，避免卡 tokio worker。
async fn test_notify(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(b): Json<TestNotifyBody>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let db = st.db.clone();
    let cfg = {
        let conn = db.lock().unwrap();
        crate::notify::load_config(&conn)
    };
    if cfg.url.is_empty() {
        return (StatusCode::BAD_REQUEST, "未配置 Webhook URL").into_response();
    }
    let text = b.text;
    let ok = tokio::task::spawn_blocking(move || crate::notify::send(&db, &cfg, "test", &text))
        .await
        .unwrap_or(false);
    if ok {
        (StatusCode::OK, "已发送").into_response()
    } else {
        (StatusCode::BAD_GATEWAY, "发送失败，请检查 URL/密钥").into_response()
    }
}

// ---------- 备份恢复（设置 + 历史指标） ----------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MetricBackupRow {
    server_id: String,
    ts: String,
    cpu_usage: f64,
    load1: f64, load5: f64, load15: f64,
    mem_total: u64, mem_used: u64,
    swap_total: u64, swap_used: u64,
    uptime: u64,
    net_rx: u64, net_tx: u64,
    processes: u64,
    disks: String,                  // JSON 数组原样
    probe_target: String,
    probe_sent: u32, probe_received: u32, probe_loss_pct: f64,
    latency_avg_ms: Option<f64>, latency_min_ms: Option<f64>,
    latency_max_ms: Option<f64>, jitter_ms: Option<f64>,
    probes: String,                 // JSON 数组原样
}

async fn backup_export(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let conn = st.db.lock().unwrap();
    let metrics: Vec<MetricBackupRow> = {
        let mut stmt = conn.prepare(
            "SELECT server_id, ts, cpu_usage, load1, load5, load15, mem_total, mem_used,
                    swap_total, swap_used, uptime, net_rx, net_tx, processes, disks,
                    probe_target, probe_sent, probe_received, probe_loss_pct,
                    latency_avg_ms, latency_min_ms, latency_max_ms, jitter_ms, probes
             FROM metrics ORDER BY server_id, ts"
        ).unwrap_or_else(|_| {
            // 老库没 probes 列：fallback 查老字段
            conn.prepare(
                "SELECT server_id, ts, cpu_usage, load1, load5, load15, mem_total, mem_used,
                        swap_total, swap_used, uptime, net_rx, net_tx, processes, disks,
                        probe_target, probe_sent, probe_received, probe_loss_pct,
                        latency_avg_ms, latency_min_ms, latency_max_ms, jitter_ms, '' as probes
                 FROM metrics ORDER BY server_id, ts"
            ).expect("prepare metrics backup")
        });
        let collected: rusqlite::Result<Vec<MetricBackupRow>> = stmt.query_map([], |r| Ok(MetricBackupRow {
            server_id: r.get(0)?, ts: r.get(1)?,
            cpu_usage: r.get(2)?, load1: r.get(3)?, load5: r.get(4)?, load15: r.get(5)?,
            mem_total: r.get::<_, i64>(6)? as u64, mem_used: r.get::<_, i64>(7)? as u64,
            swap_total: r.get::<_, i64>(8)? as u64, swap_used: r.get::<_, i64>(9)? as u64,
            uptime: r.get::<_, i64>(10)? as u64,
            net_rx: r.get::<_, i64>(11)? as u64, net_tx: r.get::<_, i64>(12)? as u64,
            processes: r.get::<_, i64>(13)? as u64,
            disks: r.get(14)?,
            probe_target: r.get(15)?,
            probe_sent: r.get::<_, i64>(16)? as u32, probe_received: r.get::<_, i64>(17)? as u32,
            probe_loss_pct: r.get(18)?,
            latency_avg_ms: r.get(19)?, latency_min_ms: r.get(20)?,
            latency_max_ms: r.get(21)?, jitter_ms: r.get(22)?,
            probes: r.get(23)?,
        })).and_then(|m| m.collect::<rusqlite::Result<Vec<_>>>());
        collected.unwrap_or_default()
    };
    let out = json!({
        "version": 2,
        "exported_at": db::now_str(),
        "kv": {
            "probe_target": db::kv_get(&conn, "probe_target", ""),
            "probe_method": db::kv_get(&conn, "probe_method", "icmp"),
            "probe_count": db::kv_get(&conn, "probe_count", "3"),
            "notify_channel": db::kv_get(&conn, "notify_channel", "generic"),
            "notify_url": db::kv_get(&conn, "notify_url", ""),
            "notify_secret": db::kv_get(&conn, "notify_secret", ""),
            "notify_offline_on": db::kv_get(&conn, "notify_offline_on", "1"),
            "notify_site_on": db::kv_get(&conn, "notify_site_on", "1"),
            "active_theme": db::kv_get(&conn, "active_theme", "极简白"),
            "dash_disks_total_only": db::kv_get(&conn, "dash_disks_total_only", "1"),
            "dash_show_traffic": db::kv_get(&conn, "dash_show_traffic", "1"),
            "dash_probe_hours": db::kv_get(&conn, "dash_probe_hours", "8"),
            "dash_loss_hours": db::kv_get(&conn, "dash_loss_hours", "8"),
            "report_interval": db::kv_get(&conn, "report_interval", "0"),
        },
        "probe_targets": db::probe_targets_all(&conn).unwrap_or_default(),
        "sites": db::sites(&conn).unwrap_or_default(),
        "themes": db::themes(&conn).unwrap_or_default().into_iter().filter(|t| !t.builtin).collect::<Vec<_>>(),
        // 所有历史指标（磁盘、CPU、内存、网络、探针）
        "metrics": metrics,
    });
    Json(out).into_response()
}

#[derive(Deserialize)]
struct RestoreBody {
    kv: std::collections::HashMap<String, serde_json::Value>,
    #[serde(default)]
    probe_targets: Vec<db::ProbeTargetRow>,
    #[serde(default)]
    sites: Vec<db::SiteRow>,
    /// 可选：要还原的指标历史（settings-only 备份里没有这一项）
    #[serde(default)]
    metrics: Vec<MetricBackupRow>,
}

async fn restore_import(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(b): Json<RestoreBody>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    // 信任边界：恢复的 kv 只接受白名单键
    const ALLOWED: &[&str] = &[
        "probe_target", "probe_method", "probe_count",
        "notify_channel", "notify_url", "notify_secret",
        "notify_offline_on", "notify_site_on",
        "active_theme", "dash_disks_total_only", "dash_show_traffic", "report_interval",
        "dash_probe_hours", "dash_loss_hours",
        "dash_show_latency_chart", "dash_show_loss_chart", "dash_show_cpu_chart",
        "admin_path", "dash_show_admin_link", "site_title", "page_title",
    ];
    let conn = st.db.lock().unwrap();
    let res = (|| -> anyhow::Result<()> {
        for (k, v) in &b.kv {
            if ALLOWED.contains(&k.as_str()) {
                if let Some(s) = v.as_str() {
                    db::kv_set(&conn, k, s);
                }
            }
        }
        conn.execute("DELETE FROM probe_targets", [])?;
        for t in &b.probe_targets {
            db::add_probe_target(&conn, &t.name, &t.target, &t.method)?;
        }
        conn.execute("DELETE FROM sites", [])?;
        for s in &b.sites {
            db::upsert_site(&conn, None, &s.name, &s.url, s.interval_s, s.enabled)?;
        }
        // 历史指标：先清空 metrics 表再批量插入（用户已二次确认覆盖）
        if !b.metrics.is_empty() {
            conn.execute("DELETE FROM metrics", [])?;
            for m in &b.metrics {
                conn.execute(
                    "INSERT INTO metrics (server_id, ts, cpu_usage, load1, load5, load15,
                        mem_total, mem_used, swap_total, swap_used, uptime, net_rx, net_tx,
                        processes, disks,
                        probe_target, probe_sent, probe_received, probe_loss_pct,
                        latency_avg_ms, latency_min_ms, latency_max_ms, jitter_ms, probes)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                        ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)",
                    rusqlite::params![
                        m.server_id, m.ts,
                        m.cpu_usage, m.load1, m.load5, m.load15,
                        m.mem_total as i64, m.mem_used as i64,
                        m.swap_total as i64, m.swap_used as i64,
                        m.uptime as i64,
                        m.net_rx as i64, m.net_tx as i64,
                        m.processes as i64,
                        m.disks,
                        m.probe_target,
                        m.probe_sent as i64, m.probe_received as i64,
                        m.probe_loss_pct,
                        m.latency_avg_ms, m.latency_min_ms, m.latency_max_ms, m.jitter_ms,
                        if m.probes.is_empty() { "[]".to_string() } else { m.probes.clone() },
                    ],
                )?;
            }
        }
        Ok(())
    })();
    match res {
        Ok(()) => (StatusCode::OK, "ok").into_response(),
        Err(e) => {
            log::error!("restore: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "restore failed").into_response()
        }
    }
}

// ---------- 清空采集数据 ----------

/// 清空全部 metrics（延迟/丢包/CPU 等采样），保留服务器列表与配置。
/// 前端已二次确认。VACUUM 让 db 文件立刻缩回去（清空是低频操作，直接全量）。
async fn clear_metrics(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let conn = st.db.lock().unwrap();
    let res = (|| -> anyhow::Result<u64> {
        let n = conn.execute("DELETE FROM metrics", [])?;
        conn.execute("VACUUM", [])?;
        Ok(n as u64)
    })();
    match res {
        Ok(n) => Json(json!({ "ok": true, "deleted": n })).into_response(),
        Err(e) => {
            log::error!("clear metrics: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "clear failed").into_response()
        }
    }
}

// ---------- 后台设置 ----------

/// 后台入口路径（kv `admin_path`，默认 /admin；仅支持 /xxx 单段字母数字）
pub fn admin_page_path(st: &AppState) -> String {
    let conn = st.db.lock().unwrap();
    normalize_admin_path(&db::kv_get(&conn, "admin_path", "admin"))
}

/// 归一化：只允许 [a-zA-Z0-9_-] 组成的单段（不带斜杠），失败回退 admin
pub fn normalize_admin_path(p: &str) -> String {
    let p = p.trim().trim_start_matches('/');
    let ok = !p.is_empty()
        && p.len() <= 32
        && p != "api" && p != "agent-bin" && p != "healthz" && p != "theme.css"
        && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok { format!("/{}", p) } else { "/admin".into() }
}

async fn host_stats(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    Json(st.host.snapshot()).into_response()
}

// ---------- 仪表盘显示设置 + 数据保留 ----------

#[derive(Deserialize, Default)]
struct SettingsBody {
    #[serde(default)]
    dash_disks_total_only: Option<bool>,
    #[serde(default)]
    dash_show_traffic: Option<bool>,
    #[serde(default)]
    retention_days: Option<u32>,
    /// agent 上报间隔（秒），0 = 沿用 CLI 的 MONITOR_INTERVAL
    #[serde(default)]
    report_interval: Option<u64>,
    #[serde(default)]
    dash_probe_hours: Option<u32>,
    #[serde(default)]
    dash_loss_hours: Option<u32>,
    /// 仪表盘是否显示延迟图表
    #[serde(default)]
    dash_show_latency_chart: Option<bool>,
    /// 仪表盘是否显示丢包率图表
    #[serde(default)]
    dash_show_loss_chart: Option<bool>,
    /// 仪表盘是否显示 CPU 使用率图表
    #[serde(default)]
    dash_show_cpu_chart: Option<bool>,
    /// 后台入口路径（单段字母数字，默认 admin）
    #[serde(default)]
    admin_path: Option<String>,
    /// 仪表盘是否显示"管理后台"入口链接
    #[serde(default)]
    dash_show_admin_link: Option<bool>,
    /// 仪表盘顶部主标题（H1）
    #[serde(default)]
    site_title: Option<String>,
    /// 浏览器标签页标题（<title>）
    #[serde(default)]
    page_title: Option<String>,
}

async fn get_settings(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let conn = st.db.lock().unwrap();
    Json(json!({
        "dash_disks_total_only": db::kv_get(&conn, "dash_disks_total_only", "1") == "1",
        "dash_show_traffic": db::kv_get(&conn, "dash_show_traffic", "1") == "1",
        "retention_days": db::kv_get(&conn, "retention_days", "30").parse::<u32>().unwrap_or(30),
        "report_interval": db::kv_get(&conn, "report_interval", "0").parse::<u64>().unwrap_or(0),
        "dash_probe_hours": db::kv_get(&conn, "dash_probe_hours", "8").parse::<u32>().unwrap_or(8),
        "dash_loss_hours": db::kv_get(&conn, "dash_loss_hours", "8").parse::<u32>().unwrap_or(8),
        "dash_show_latency_chart": db::kv_get(&conn, "dash_show_latency_chart", "1") == "1",
        "dash_show_loss_chart": db::kv_get(&conn, "dash_show_loss_chart", "1") == "1",
        "dash_show_cpu_chart": db::kv_get(&conn, "dash_show_cpu_chart", "1") == "1",
        "admin_path": db::kv_get(&conn, "admin_path", "admin"),
        "dash_show_admin_link": db::kv_get(&conn, "dash_show_admin_link", "1") == "1",
        "site_title": db::kv_get(&conn, "site_title", "服务器探针"),
        "page_title": db::kv_get(&conn, "page_title", "服务器探针"),
    }))
    .into_response()
}

async fn set_settings(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(b): Json<SettingsBody>,
) -> Response {
    if let Err(e) = authorize_admin(&st, &headers) {
        return e;
    }
    let conn = st.db.lock().unwrap();
    if let Some(v) = b.dash_disks_total_only {
        db::kv_set(&conn, "dash_disks_total_only", if v { "1" } else { "0" });
    }
    if let Some(v) = b.dash_show_traffic {
        db::kv_set(&conn, "dash_show_traffic", if v { "1" } else { "0" });
    }
    if let Some(d) = b.retention_days {
        db::kv_set(&conn, "retention_days", &d.min(3650).to_string());
    }
    if let Some(s) = b.report_interval {
        db::kv_set(&conn, "report_interval", &s.min(3600).to_string());
    }
    // 仪表盘折线图窗口（小时）；超出范围夹回 1..=72
    if let Some(h) = b.dash_probe_hours {
        db::kv_set(&conn, "dash_probe_hours", &h.clamp(1, 72).to_string());
    }
    if let Some(h) = b.dash_loss_hours {
        db::kv_set(&conn, "dash_loss_hours", &h.clamp(1, 72).to_string());
    }
    if let Some(v) = b.dash_show_latency_chart {
        db::kv_set(&conn, "dash_show_latency_chart", if v { "1" } else { "0" });
    }
    if let Some(v) = b.dash_show_loss_chart {
        db::kv_set(&conn, "dash_show_loss_chart", if v { "1" } else { "0" });
    }
    if let Some(v) = b.dash_show_cpu_chart {
        db::kv_set(&conn, "dash_show_cpu_chart", if v { "1" } else { "0" });
    }
    if let Some(p) = &b.admin_path {
        db::kv_set(&conn, "admin_path", normalize_admin_path(p).trim_start_matches('/'));
    }
    if let Some(v) = b.dash_show_admin_link {
        db::kv_set(&conn, "dash_show_admin_link", if v { "1" } else { "0" });
    }
    if let Some(v) = &b.site_title {
        db::kv_set(&conn, "site_title", v.trim());
    }
    if let Some(v) = &b.page_title {
        db::kv_set(&conn, "page_title", v.trim());
    }
    (StatusCode::OK, "ok").into_response()
}

// ---------- 页面 ----------

async fn dashboard() -> Html<&'static str> {
    Html(include_str!("../ui/index.html"))
}

/// 一键脚本下载 agent 二进制：/agent-bin/{file}
/// 目录优先 MONITOR_AGENT_BIN_DIR（默认 ./dist 和镜像内 /usr/local/share/monitor/agent-bin）
/// ponytail: 无目录列出页；二进制文件名即 API，install.sh 里写死
async fn agent_bin(Path(file): Path<String>) -> Response {
    // 只允许纯文件名，防路径穿越
    if file.contains('/') || file.contains("..") || file.contains('\\') {
        return (StatusCode::BAD_REQUEST, "bad file name").into_response();
    }
    const CT: &str = "application/octet-stream";
    let mut candidates = vec!["/usr/local/share/monitor/agent-bin".to_string()];
    if let Ok(d) = std::env::var("MONITOR_AGENT_BIN_DIR") {
        candidates.insert(0, d);
    }
    candidates.push("dist".into());
    for dir in candidates {
        let p = std::path::Path::new(&dir).join(&file);
        if let Ok(bytes) = std::fs::read(&p) {
            return (
                [(header::CONTENT_TYPE, CT), (header::CACHE_CONTROL, "no-store")],
                bytes,
            )
                .into_response();
        }
    }
    (StatusCode::NOT_FOUND, "no such file").into_response()
}
async fn admin_page() -> Html<&'static str> {
    Html(include_str!("../ui/admin.html"))
}

/// 启动时预先解一次，配置写错要立刻炸而不是等第一次写库
pub fn retention_from(days: u32, max_rows: u32) -> Retention {
    Retention {
        days: days.max(1),
        max_rows_per_server: max_rows.max(10),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(name: &str, css: &str) -> ThemeBody {
        ThemeBody {
            name: name.into(),
            description: String::new(),
            css: css.into(),
        }
    }

    #[test]
    fn rejects_style_escape_and_remote_import() {
        assert!(validate_theme(&body("t", ":root{--bg:#fff}")).is_ok());
        assert!(validate_theme(&body("t", "x{} </style><script>alert(1)</script>")).is_err());
        assert!(validate_theme(&body("t", "@import url(http://evil)")).is_err());
        assert!(validate_theme(&body("t", "a{background:url(javascript:alert(1))}")).is_err());
    }

    #[test]
    fn rejects_empty_and_oversized() {
        assert!(validate_theme(&body("t", "   ")).is_err());
        assert!(validate_theme(&body("", "a{}")).is_err());
        assert!(validate_theme(&body("t", &"a".repeat(600 * 1024))).is_err());
    }

    #[test]
    fn online_window_boundaries() {
        let now = chrono::Utc::now();
        // 默认（interval=0 → 10s 周期 → 35s 窗口 + 600s 宽限）
        assert!(is_online(&(now - chrono::Duration::seconds(5)).to_rfc3339(), 0));
        assert!(!is_online(&(now - chrono::Duration::seconds(700)).to_rfc3339(), 0));
        assert!(!is_online("garbage", 0));
        // 5 分钟上报周期 → 15 分钟窗口 + 宽限
        assert!(is_online(&(now - chrono::Duration::seconds(600)).to_rfc3339(), 300));
        assert!(!is_online(&(now - chrono::Duration::seconds(1600)).to_rfc3339(), 300));
        assert_eq!(online_window_secs(0), 635);
        assert_eq!(online_window_secs(300), 1500);
        assert_eq!(online_window_secs(5), 635);
    }

    #[test]
    fn retention_clamps_absurd_config() {
        assert_eq!(retention_from(0, 0).days, 1);
        assert_eq!(retention_from(7, 0).max_rows_per_server, 10);
    }

    #[test]
    fn admin_path_normalization() {
        assert_eq!(normalize_admin_path("admin"), "/admin");
        assert_eq!(normalize_admin_path("/panel"), "/panel");
        assert_eq!(normalize_admin_path("My-Secret_1"), "/My-Secret_1");
        assert_eq!(normalize_admin_path(""), "/admin");
        assert_eq!(normalize_admin_path("a/b"), "/admin"); // 禁多段
        assert_eq!(normalize_admin_path("api"), "/admin"); // 禁保留段
        assert_eq!(normalize_admin_path("管理"), "/admin"); // 仅 ASCII
        assert_eq!(normalize_admin_path(&"x".repeat(33)), "/admin");
    }
}
