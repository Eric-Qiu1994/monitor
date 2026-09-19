# Docker 构建与部署

本项目是一个 Rust workspace，包含两个二进制：主服务器 `monitor`（axum + SQLite）和采集端 `monitor-agent`。根目录的单个多阶段 [Dockerfile](Dockerfile) 会构建两个镜像目标，[compose.yml](compose.yml) 只跑主服务器；agent 通常直接用构建出的镜像跑在目标机器上。

## 前置要求

- Docker 20.10+（compose 用 v2 子命令 `docker compose`）
- 内存 ≥ 2GB：release 构建含 LTO，内存不足会失败

## 1. 配置

```bash
cp .env.example .env
# 生成随机 token 并写入 .env
sed -i "s/^MONITOR_TOKEN=.*/MONITOR_TOKEN=$(openssl rand -hex 32)/" .env
```

`.env` 关键项：

| 变量 | 作用 | 默认 |
|---|---|---|
| `MONITOR_TOKEN` | agent 上报鉴权 token，**必填**，两端必须一致 | 无 |
| `MONITOR_PORT` | 主服务器对外端口 | 8080 |
| `MONITOR_RETENTION_DAYS` | 数据保留天数 | 7 |
| `MONITOR_PING_TARGET` / `MONITOR_PING_COUNT` | agent 默认探测目标与包数 | 1.1.1.1 / 3 |

## 2. 构建镜像

Dockerfile 定义了两个最终 stage：`monitor-runtime` 和 `agent-runtime`（同一个多阶段文件）。

```bash
# 主服务器（compose up 会自动构建，可跳过手动构建）
docker compose build monitor

# agent
docker build --target agent-runtime -t qjj223/monitor-agent:latest .
```

构建说明：

- 依赖层缓存：Dockerfile 先只 COPY 各 `Cargo.toml` + `Cargo.lock`，源码改动不会触发依赖重编译。
- `--locked` 强制使用 `Cargo.lock`，保证可复现。
- 运行镜像基于 `debian:bookworm-slim`，非 root 用户 `monitor`（uid 10001），仅装 `ca-certificates`；agent 额外装 `iputils-ping`（ICMP 探测需要）。

## 3. 启动主服务器

```bash
docker compose up -d
curl http://127.0.0.1:8080/   # 验证
```

compose 已加固：`read_only` 根文件系统 + `no-new-privileges` + 非 root 用户，SQLite 数据落在命名卷 `monitor-data`（挂载 `/data`）。

## 4. 启动 agent

把上一步构建的 agent 镜像传到目标机器（`docker save` / `docker load`，或推送到 registry），然后：

```bash
docker run -d --name monitor-agent \
  --restart unless-stopped \
  --network host \
  -e MONITOR_URL=http://主服务器IP:8080 \
  -e MONITOR_TOKEN=<与主服务器相同的token> \
  -e MONITOR_PING_TARGET=1.1.1.1 \
  qjj223/monitor-agent:latest
```

说明：

- `--network host` 是推荐做法：ICMP ping 和主机指标（sysinfo 读的是容器所在内核，网络用 host 才反映真实网卡 IP/连接数）。
- 不想用 host 网络时，去掉该参数并保证能访问 `MONITOR_URL`；ICMP 可能因容器无 cap_net_raw 失败，可设 `MONITOR_PING_METHOD=http` 回退到 HTTP 探测，或加 `--cap-add NET_RAW`。
- 全部 agent 环境变量与 CLI 参数见 `agent/src/main.rs`（`MONITOR_URL`、`MONITOR_TOKEN`、`MONITOR_INTERVAL`、`MONITOR_HOSTNAME`、`MONITOR_PROXY`、`MONITOR_PING_*`）。

## 6. 一键部署脚本

把下面整段存成**仓库根目录**下的 `deploy.sh`（脚本要读同目录的 `compose.yml` 和 `.env.example`），然后 `chmod +x deploy.sh`：

```bash
#!/usr/bin/env bash
# monitor 一键部署（放在仓库根目录）
#   主服务器：./deploy.sh server
#   采集端：  ./deploy.sh agent http://主服务器IP:8080 <token>
set -euo pipefail

IMAGE_AGENT=qjj223/monitor-agent:latest

command -v docker >/dev/null || { echo "未安装 docker"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "需要 docker compose v2"; exit 1; }

case "${1:-}" in
server)
  cd "$(dirname "$0")"
  [ -f compose.yml ] || { echo "请在仓库根目录运行（找不到 compose.yml）"; exit 1; }
  # 首次运行生成 .env 与随机 token；已有 .env 则原样保留
  if [ ! -f .env ]; then
    cp .env.example .env
    sed -i "s|^MONITOR_TOKEN=.*|MONITOR_TOKEN=$(openssl rand -hex 32)|" .env
  fi
  TOKEN=$(grep '^MONITOR_TOKEN=' .env | cut -d= -f2-)
  [ -n "$TOKEN" ] || { echo "请在 .env 里设置 MONITOR_TOKEN"; exit 1; }
  docker compose up -d --build
  echo
  echo "主服务器已启动：http://$(hostname -I | awk '{print $1}'):${MONITOR_PORT:-8080}"
  echo "后台：/admin（默认 admin/admin，登录后请立即改密码）"
  echo "agent token：$TOKEN"
  ;;
agent)
  if [ $# -lt 3 ]; then
    echo "用法：$0 agent http://主服务器IP:8080 <token>"
    echo "token 在主服务器仓库的 .env 里（MONITOR_TOKEN）"
    exit 1
  fi
  docker pull "$IMAGE_AGENT"
  docker rm -f monitor-agent 2>/dev/null || true
  docker run -d --name monitor-agent --restart unless-stopped --network host \
    -e MONITOR_URL="$2" \
    -e MONITOR_TOKEN="$3" \
    "$IMAGE_AGENT"
  echo "agent 已启动。看日志：docker logs -f monitor-agent"
  ;;
*)
  echo "用法："
  echo "  $0 server                                  # 部署主服务器"
  echo "  $0 agent http://主服务器IP:8080 <token>      # 部署采集端"
  exit 1
  ;;
esac
```

验收：主服务器 `curl http://127.0.0.1:8080/api/public/dash-config` 返回 JSON；agent `docker logs monitor-agent` 无 `上报失败`。

> agent 上传的磁盘列表已按设备去重（Docker overlayfs 不会重复上报同一块盘），无需额外配置。

## 7. 常用运维

```bash
docker compose logs -f monitor        # 主服务器日志
docker logs -f monitor-agent          # agent 日志
docker compose down                   # 停止（保留数据卷）
docker compose down -v                # 停止并删除数据
docker compose up -d --build          # 改代码后重建
```

数据备份：直接拷贝卷内容 `docker run --rm -v monitor-data:/data -v $PWD:/b alpine cp /data/monitor.db /b/`。
