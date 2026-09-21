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

# aarch64-musl：优先本机交叉工具链；没有就用 Docker 交叉镜像（amd64 上直接编，
# 不需要 qemu）；两者都没有才跳过。Alpine arm64 必须有这个产物，否则装不上。
if command -v aarch64-linux-musl-gcc >/dev/null 2>&1; then
  export CC_aarch64_unknown_linux_musl=aarch64-linux-musl-gcc
  build aarch64-unknown-linux-musl  monitor-agent-aarch64-musl
elif command -v docker >/dev/null 2>&1; then
  echo "== aarch64-musl 经 Docker 交叉镜像（messense/rust-musl-cross）"
  IMG=messense/rust-musl-cross:aarch64-musl
  TGT=aarch64-unknown-linux-musl
  # 宿主 cargo 的源镜像地址（如 rsproxy）。容器内网常不通，此时挂载宿主
  # registry 缓存 + 同一镜像源就能离线编；宿主的 linker 配置别覆盖（镜像自带）。
  MIRROR=$(sed -n 's/^registry *= *"\(.*\)"/\1/p' "$HOME/.cargo/config.toml" 2>/dev/null | head -1)
  mount_src=()
  [ -d "$HOME/.cargo/registry" ] && mount_src+=(-v "$HOME/.cargo/registry":/root/.cargo/registry)
  src_cfg=()
  if [ -n "$MIRROR" ]; then
    src_cfg=(--config source.crates-io.replace-with='"mirror"' \
             --config "source.mirror.registry=\"$MIRROR\"")
  fi
  common=(-v "$PWD":/home/rust/src "${mount_src[@]}" "${src_cfg[@]}")
  if docker run --rm --network=none -e CARGO_NET_OFFLINE=true "${common[@]}" "$IMG" \
       cargo build --release --locked --offline -p agent --target "$TGT" 2>/dev/null; then
    echo "== （离线，命中宿主 cargo 缓存）"
  else
    echo "== （离线不可用，改为联网编译）"
    docker run --rm -v "$PWD":/home/rust/src "$IMG" \
      cargo build --release --locked -p agent --target "$TGT"
  fi
  cp "target/$TGT/release/monitor-agent" "$OUT/monitor-agent-aarch64-musl"
else
  echo "== 跳过 aarch64-musl（无 aarch64-linux-musl-gcc 也无 docker）；Alpine arm64 将无法安装"
fi

for f in "$OUT"/monitor-agent-*; do
  [ -f "$f" ] && strip -s "$f" 2>/dev/null || true
done
ls -lh "$OUT"
