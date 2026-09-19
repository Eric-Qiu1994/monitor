# sysinfo 0.39.6 要求 Rust 1.95+；构建两个二进制后分成两个最小运行镜像。
# agent 跨平台二进制由宿主 ./build-agent.sh 预先产到 dist/（builder 内 rustup
# 下载被网络卡死，不在镜像里重复编）。
FROM rust:1.98-bookworm AS builder
WORKDIR /src

# 先复制清单，依赖层可复用；之后再复制源码。
COPY Cargo.toml Cargo.lock ./
COPY common/Cargo.toml common/Cargo.toml
COPY monitor/Cargo.toml monitor/Cargo.toml
COPY agent/Cargo.toml agent/Cargo.toml
COPY common/src common/src
COPY monitor/src monitor/src
COPY monitor/themes monitor/themes
COPY monitor/ui monitor/ui
COPY agent/src agent/src
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime-base
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home monitor \
 && mkdir /data \
 && chown monitor:monitor /data
USER monitor

FROM runtime-base AS monitor-runtime
COPY --from=builder /src/target/release/monitor /usr/local/bin/monitor
COPY dist/ /usr/local/share/monitor/agent-bin/
VOLUME ["/data"]
EXPOSE 8080
ENV MONITOR_LISTEN=0.0.0.0:8080 \
    MONITOR_DB=/data/monitor.db \
    MONITOR_RETENTION_DAYS=7 \
    MONITOR_MAX_ROWS_PER_SERVER=20000 \
    MONITOR_CLEANUP_INTERVAL=600
ENTRYPOINT ["/usr/local/bin/monitor"]

FROM runtime-base AS agent-runtime
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/*
USER monitor
COPY --from=builder /src/target/release/monitor-agent /usr/local/bin/monitor-agent
ENTRYPOINT ["/usr/local/bin/monitor-agent"]
