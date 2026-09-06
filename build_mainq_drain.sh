#!/bin/zsh
# 构建 mainq_drain.node（macOS 专用，架构跟随当前 node）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"

# 找 node 头文件：优先 $NODE_INC，其次跟随当前 PATH 里的 node
if [[ -z "${NODE_INC:-}" ]]; then
  NODE_BIN="${NODE_BIN:-$(command -v node || true)}"
  [[ -n "${NODE_BIN:-}" ]] || NODE_BIN="$HOME/.workbuddy/binaries/node/versions/22.22.2-2/bin/node"
  NODE_INC="$(dirname "$(dirname "$NODE_BIN")")/include/node"
fi
[[ -f "$NODE_INC/node_api.h" ]] || { echo "node headers not found at $NODE_INC (set NODE_INC=...)" >&2; exit 1; }

ARCH="$(lipo -archs "${NODE_BIN:-$(command -v node)}" 2>/dev/null | awk '{print $1}')"
[[ -n "$ARCH" ]] || ARCH="$(uname -m)"

clang -shared -fPIC -arch "$ARCH" \
  -I"$NODE_INC" \
  -DNODE_GYP_MODULE_NAME=mainq_drain \
  -undefined dynamic_lookup \
  -o "$ROOT/mainq_drain.node" \
  "$ROOT/mainq_drain.m" \
  -framework Foundation

echo "built $ROOT/mainq_drain.node ($ARCH)"
