#!/bin/sh
# 一键发布：bump 补丁版本 → 全链构建推送
# 用法: ./release.sh          (0.1.0 → 0.1.1)
#       ./release.sh 0.2.0    (显式指定)
set -e
cd "$(dirname "$0")"

# 1. bump workspace 版本（所有 crate 同步）
OLD=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
if [ -n "$1" ]; then NEW="$1"; else
  MAJ=$(echo $OLD | cut -d. -f1); MIN=$(echo $OLD | cut -d. -f2); PAT=$(echo $OLD | cut -d. -f3)
  NEW="$MAJ.$MIN.$((PAT+1))"
fi
sed -i "s/^version = \"$OLD\"/version = \"$NEW\"/" Cargo.toml
# workspace 版本变化同步进 Cargo.lock（--locked 需要一致）
cargo update -w --offline 2>/dev/null || cargo update -w
echo "version: $OLD -> $NEW"

# 2. agent 四平台产物 + monitor
./build-agent.sh
sha256sum dist/monitor-agent-* > dist/sha256sum.txt
cargo build --release --locked

# 3. 双镜像双 tag
for i in 1 2 3; do
  docker build --target monitor-runtime -t qjj223/monitor:latest -t qjj223/monitor:$NEW . \
  && docker build --target agent-runtime -t qjj223/monitor-agent:latest -t qjj223/monitor-agent:$NEW . \
  && docker push qjj223/monitor:latest && docker push qjj223/monitor:$NEW \
  && docker push qjj223/monitor-agent:latest && docker push qjj223/monitor-agent:$NEW \
  && echo "RELEASED $NEW" && exit 0
  echo "retry $i"; sleep 5
done
exit 1
