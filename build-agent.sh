#!/usr/bin/env bash
# 交叉编译 monitor-agent 二进制到 dist/
# 平台：x86_64 / aarch64；musl 二进制通吃 Debian/Ubuntu/Alpine
# 依赖：rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-gnu
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
OUT=${OUT:-dist}
mkdir -p "$OUT"

# aarch64 gnu 的交叉 linker（见 .cargo/config.toml）；musl 靠 musl-gcc
export CC_x86_64_unknown_linux_musl=musl-gcc

build() {
  local t=$1 out=$2
  echo "== $t -> $out"
  cargo build --release --locked -p agent --target "$t"
  cp "target/$t/release/monitor-agent" "$OUT/$out"
}

build x86_64-unknown-linux-musl    monitor-agent-x86_64-musl
build x86_64-unknown-linux-gnu     monitor-agent-x86_64-gnu
build aarch64-unknown-linux-gnu    monitor-agent-aarch64-gnu

# aarch64-musl：本机缺交叉 musl 工具链时跳过（Alpine arm64 请用 Docker 镜像）
if command -v aarch64-linux-musl-gcc >/dev/null 2>&1; then
  export CC_aarch64_unknown_linux_musl=aarch64-linux-musl-gcc
  build aarch64-unknown-linux-musl  monitor-agent-aarch64-musl
else
  echo "== 跳过 aarch64-musl（无 aarch64-linux-musl-gcc）；Alpine arm64 用 Docker 镜像部署"
fi

for f in "$OUT"/monitor-agent-*; do
  [ -f "$f" ] && strip -s "$f" 2>/dev/null || true
done
ls -lh "$OUT"
