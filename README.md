# monitor：Rust 轻量服务器探针

一个可自托管的服务器监控项目：

- `monitor`：主服务，**Rust + axum + SQLite**，提供仪表盘、API、主题管理与历史数据保留。
- `monitor-agent`：轻量 agent，读取本机 CPU、内存、磁盘、负载、网络累计流量和进程数后定期上报。

不依赖 Redis、Prometheus、Node.js 或外部数据库。默认单机一个 SQLite 文件即可运行。

## 功能

- CPU、Load、内存、Swap、磁盘、进程数、系统运行时长。
- 网络累计流量及仪表盘上基于相邻采样计算的实时上下行速率。
- ICMP 探测：目标可配置，每轮默认 3 包；显示平均/最小/最大延迟、丢包率与 RTT 抖动（mdev）。
- 离线判定：35 秒无上报即显示离线。
- 主服务以共享 Token 校验 agent 上报和后台写操作。
- 两套内置主题：**极简白**、**深色极客**。
- 后台 `/admin` 可切换、创建、编辑、删除自定义 CSS 主题。
- SQLite WAL 模式；按**保留天数**和**每台最大采样条数**双重清理，定时 checkpoint / incremental vacuum，避免数据和 WAL 不受控增长。
- Docker 多阶段构建，运行容器为非 root；Compose 带只读根文件系统、临时目录大小限制和数据卷。

> 当前版本为 IPv4/IPv6 无关的主机指标采集；不做端口扫描、命令执行或远程 shell。

---

## 快速部署（推荐 Docker）

### 1. 主服务

```bash
git clone <你的仓库地址> monitor
cd monitor
cp .env.example .env
```

编辑 `.env`，至少修改 Token：

```dotenv
MONITOR_TOKEN=换成至少32位随机字符串
MONITOR_PORT=8080
```

启动：

```bash
docker compose up -d --build
docker compose ps
docker compose logs --tail=50 monitor
```

打开：

- 仪表盘：`http://主服务IP:8080/`
- 后台管理：`http://主服务IP:8080/admin`
- 健康检查：`http://主服务IP:8080/healthz`

Docker Hub 镜像发布后可不本地构建：

```bash
# 在 compose.yml 中保留 image: qjj223/monitor:latest，移除 build: 区块
# 然后：
docker compose pull
docker compose up -d
```

### 2. 部署 agent

agent 可以直接使用同一份源码构建，也可以从 Docker 镜像复制：

```bash
# 从发布的 agent 镜像提取当前架构二进制
id=$(docker create qjj223/monitor-agent:0.1.1)
docker cp "$id":/usr/local/bin/monitor-agent ./monitor-agent
docker rm "$id"
chmod +x ./monitor-agent
sudo install -m 0755 ./monitor-agent /usr/local/bin/monitor-agent
```

创建 systemd 服务 `/etc/systemd/system/monitor-agent.service`：

```ini
[Unit]
Description=monitor agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/monitor-agent \
  --url http://MONITOR_HOST:8080 \
  --token REPLACE_WITH_MONITOR_TOKEN \
  --interval 10
Restart=always
RestartSec=5
DynamicUser=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

替换 `MONITOR_HOST` 与 Token 后启用：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now monitor-agent
sudo systemctl status monitor-agent
journalctl -u monitor-agent -f
```

### agent 走 HTTP 代理

如果 agent 主机只有代理能访问主服务：

```bash
monitor-agent \
  --url http://MONITOR_HOST:8080 \
  --token 'YOUR_TOKEN' \
  --proxy 代理地址 \
  --interval 10
```

等价环境变量：

```bash
MONITOR_URL=http://MONITOR_HOST:8080 \
MONITOR_TOKEN='YOUR_TOKEN' \
MONITOR_PROXY=代理地址 \
MONITOR_PING_TARGET=1.1.1.1 \
MONITOR_PING_COUNT=3 \
monitor-agent
```
### 或者使用中心机器一键脚本

安装：

```bash
curl -fsSL http://<中心机地址>/agent-bin/install.sh | sh -s -- http://<中心机地址> token
```

卸载：

```bash
curl -fsSL http://<中心机地址>/agent-bin/uninstall.sh | sh
```

---

### 延迟、丢包与抖动

agent 每次上报会运行 `ping -c 3 -W 1`，默认探测 `1.1.1.1`。仪表盘的“探测”行显示目标、**平均 RTT、丢包率、mdev 抖动**；历史 API 同时保留最小/最大 RTT。

**探测配置优先级**：管理后台（“延迟检测设置”里配置的目标列表）> 本地 CLI/环境变量 `MONITOR_PING_TARGET`。后台有配置时只探测后台的目标；后台为空才使用本地配置作为兜底（这时只发一个目标）。

```bash
# 改为探测百度 DNS（后台无配置时生效）
monitor-agent --ping-target 223.5.5.5 --ping-count 3 ...

# 使用环境变量
MONITOR_PING_TARGET=223.5.5.5 MONITOR_PING_COUNT=5 monitor-agent ...

# 无需探测时关闭（上报里会显示“未启用”）
MONITOR_PING_TARGET='' monitor-agent ...
```

计数范围是 1–10，单包超时为 1 秒；目标彻底不可达、系统没有 `ping`、或 ICMP 被防火墙过滤时，当前轮记为 100% 丢包、延迟显示 `-`。它测的是 **agent 到目标** 的路径，不是浏览器到服务器的路径。

---

## 不用 Docker 的本地运行

要求 Rust `1.95+`。

```bash
# 主服务
cargo run -p monitor -- \
  --listen 0.0.0.0:8080 \
  --db ./data/monitor.db \
  --token 'YOUR_LONG_RANDOM_TOKEN'

# 另一个终端启动 agent
cargo run -p agent -- \
  --url http://127.0.0.1:8080 \
  --token 'YOUR_LONG_RANDOM_TOKEN' \
  --interval 10
```

仅检查本机采集（不发送数据）：

```bash
monitor-agent --once
# 或
cargo run -p agent -- --once
```

测试与 release 构建：

```bash
cargo test
cargo build --release --locked
```

release 输出：

```text
target/release/monitor
target/release/monitor-agent
```

---

## 数据与清理策略

主服务将数据存至 `/data/monitor.db`（Compose 中为 Docker 命名卷 `monitor-data`）。

默认策略：

| 环境变量 / 参数 | 默认值 | 含义 |
|---|---:|---|
| `MONITOR_RETENTION_DAYS` | `7` | 删除 7 天前的采样 |
| `MONITOR_MAX_ROWS_PER_SERVER` | `20000` | 每台服务器最多保留 20,000 条，作为硬上限 |
| `MONITOR_CLEANUP_INTERVAL` | `600` | 每 10 分钟执行删除、WAL checkpoint 与 incremental vacuum |

若 agent 间隔为 10 秒，20,000 条大约是 **2.3 天**；若目标是保留完整 7 天，可将上限调整到至少 `60480`：

```dotenv
MONITOR_RETENTION_DAYS=7
MONITOR_MAX_ROWS_PER_SERVER=65000
```

按照机器数量和磁盘预算设置。SQLite 文件仍应通过 Docker volume 或备份策略保护：

```bash
# Compose 数据卷路径（查看后自行备份）
docker volume inspect monitor_monitor-data
```

不要对正在活跃写入的 `.db` 文件直接 `cp`；SQLite WAL 模式建议用 `sqlite3 .backup` 或先停止容器再备份整个卷。

---

## API

`MONITOR_TOKEN` 开启时，下列写接口需带：

```http
X-Token: <MONITOR_TOKEN>
```

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/healthz` | 健康检查 |
| `POST` | `/api/admin/login` | 后台登录，返回会话 token |
| `POST` | `/api/admin/logout` | 注销会话 |
| `PUT` | `/api/admin/credentials` | 修改后台用户名 / 密码 |
| `GET/PUT` | `/api/admin/probe-config` | 查看 / 设置探测配置（需会话或 token） |
| `GET` | `/api/agent-config` | agent 拉取探测配置（需 token） |
| `POST` | `/api/report` | agent 上报 |
| `GET` | `/api/servers` | 全部服务器及最新采样 |
| `GET` | `/api/servers/:id/history?n=120` | 历史采样，`n` 最大 2000 |
| `PUT` | `/api/servers/:id` | 改名，JSON：`{"name":"..."}` |
| `DELETE` | `/api/servers/:id` | 删除服务器及采样 |
| `GET/POST` | `/api/themes` | 查询 / 新建主题 |
| `PUT/DELETE` | `/api/themes/:id` | 修改 / 删除主题（内置主题不可删除） |
| `GET/PUT` | `/api/themes/active` | 当前主题 / 切换主题 |
| `GET` | `/api/theme.css` | 当前主题 CSS |

自定义主题 CSS 限制为最多 512 KiB，并禁止 `</style>`、`<script>`、`javascript:`、`expression(` 和 `@import`，避免后台主题成为脚本注入入口。

---

## 发布 Docker Hub

Docker 引擎安装并运行后，在项目根目录：

```bash
docker build --target monitor-runtime -t qjj223/monitor:latest .
docker build --target agent-runtime -t qjj223/monitor-agent:latest .

docker login -u qjj223
docker push qjj223/monitor:latest
docker push qjj223/monitor-agent:latest
```

建议同步打一个不可变版本标签：

```bash
docker tag qjj223/monitor:latest qjj223/monitor:0.1.0
docker tag qjj223/monitor-agent:latest qjj223/monitor-agent:0.1.0
docker push qjj223/monitor:0.1.0
docker push qjj223/monitor-agent:0.1.0
```

构建/推送使用代理（Docker daemon 配置 `HTTP_PROXY` / `HTTPS_PROXY`）请按宿主机环境设置。不要将 Docker Hub 密码写入本仓库、Dockerfile、compose 文件或 shell 历史。

---

## 项目结构

```text
monitor/
├── monitor/                 # axum 主服务、SQLite、页面和内置主题
├── agent/                   # sysinfo 采集与 HTTP 上报
├── common/                  # 双方共用 Report 数据结构和自检
├── Dockerfile               # 多阶段构建，monitor-runtime / agent-runtime targets
├── compose.yml              # 主服务部署
└── README.md
```

## 后台管理

访问 `/admin`，默认账号 **admin / admin**，首次登录后请立即在「修改后台账号」中更改。

后台可管理：

1. **主题**：新建、编辑（上传 CSS 内容）、启用、删除（内置主题不可删）。
2. **延迟探测设置**：选择 **ICMP Ping / HTTP Ping / TCP Ping**，设置目标与每轮次数；agent 每个上报周期自动拉取，无需重启。
   - ICMP：系统 `ping`，单包 1 秒超时。
   - HTTP：`GET http://目标`（可写完整 URL），HTTP 2xx–4xx 都视为连通。
   - TCP：TCP 握手，目标写 `host` 或 `host:port`（默认 80）。
3. **后台账号**：修改用户名和密码（需验证旧凭据，改完重新登录）。

后台接口优先使用登录会话（`x-admin-session` 头）；设置了 `MONITOR_TOKEN` 时，token 依然可直接调用管理接口以兼容脚本。

## 安全建议

1. 必须设置 `MONITOR_TOKEN`；未设置只适合隔离测试网络。
2. 生产环境将 Web UI 放到反向代理后，用 HTTPS 与额外访问控制保护 `/admin`。
3. agent 到主服务建议走 VPN、私网或 HTTPS 反向代理；Token 是 bearer credential，不能放在截图或公开日志中。
4. 给 Docker 数据卷做定期备份，并用 `docker system df` 观察 Docker 自身空间占用。
