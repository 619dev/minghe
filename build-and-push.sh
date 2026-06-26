#!/usr/bin/env bash
# ============================================================
# build-and-push.sh — 鸣鹤 (MingHe) Docker 多架构镜像构建与推送
# ============================================================
#
# 支持两种构建后端：
#   1. Depot.dev（更快，需要 depot CLI）
#   2. Docker Buildx（通用，Docker 自带）
#
# 用法:
#   ./build-and-push.sh                          # 构建并推送 latest
#   TAG=v0.1.0 ./build-and-push.sh               # 构建并推送指定版本
#   PUSH=0 ./build-and-push.sh                   # 仅构建不推送
#   BUILDER=buildx ./build-and-push.sh           # 强制使用 docker buildx
#   BUILDER=depot ./build-and-push.sh            # 强制使用 depot
#   REPO=myuser TAG=v0.1.0 ./build-and-push.sh   # 自定义仓库和版本
#
# 环境变量:
#   REPO      — Docker Hub 用户名/组织名          (默认: facilisvelox)
#   TAG       — 镜像标签                           (默认: latest)
#   PUSH      — 是否推送到仓库 1=推送 0=仅构建      (默认: 1)
#   BUILDER   — 构建后端 depot|buildx|auto        (默认: auto)
#   PLATFORM  — 目标平台                           (默认: linux/amd64,linux/arm64)
#
# ============================================================
set -euo pipefail

# ---- 配置 ----
REPO="${REPO:-facilisvelox}"
TAG="${TAG:-latest}"
PUSH="${PUSH:-1}"
BUILDER="${BUILDER:-auto}"
PLATFORM="${PLATFORM:-linux/amd64,linux/arm64}"

IMAGE="${REPO}/minghe"

# ---- 颜色输出 ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log()   { echo -e "${CYAN}[鸣鹤]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ---- 选择构建后端 ----
select_builder() {
  if [[ "$BUILDER" == "depot" ]]; then
    if ! command -v depot &> /dev/null; then
      fail "'depot' 命令未找到，请安装或使用 BUILDER=buildx"
    fi
    echo "depot"
  elif [[ "$BUILDER" == "buildx" ]]; then
    if ! command -v docker &> /dev/null; then
      fail "'docker' 命令未找到"
    fi
    echo "buildx"
  else
    # auto: 优先 depot，回退 buildx
    if command -v depot &> /dev/null; then
      echo "depot"
    elif command -v docker &> /dev/null; then
      echo "buildx"
    else
      fail "未找到 'depot' 或 'docker' 命令，请安装其中之一"
    fi
  fi
}

SELECTED_BUILDER=$(select_builder)

# ---- 确保 buildx builder 存在 ----
setup_buildx() {
  if ! docker buildx inspect minghe-builder &> /dev/null 2>&1; then
    log "正在创建 buildx builder: minghe-builder"
    docker buildx create --name minghe-builder --use --driver docker-container
  else
    docker buildx use minghe-builder
  fi
}

# ---- 是否同时标记 latest ----
ALSO_LATEST="no"
[[ "$TAG" != "latest" ]] && ALSO_LATEST="yes"

# ---- 构建函数 ----
build_and_push() {
  local name="$1"
  local context="$2"
  local tag="$3"
  local also_latest="$4"

  # 构建 tag 参数列表
  local tags=("-t" "${name}:${tag}")
  [[ "$also_latest" == "yes" && "$tag" != "latest" ]] && tags+=("-t" "${name}:latest")

  local tag_display="${name}:${tag}"
  [[ "$also_latest" == "yes" && "$tag" != "latest" ]] && tag_display="${tag_display}, ${name}:latest"

  log "构建镜像: ${tag_display}"
  log "架构: ${PLATFORM}"
  log "构建后端: ${SELECTED_BUILDER}"

  if [[ "$SELECTED_BUILDER" == "depot" ]]; then
    # ---- Depot 构建 ----
    if [[ "$PUSH" == "1" ]]; then
      log "模式: 构建 + 推送 (depot)"
      depot build \
        --platform "$PLATFORM" \
        "${tags[@]}" \
        --push \
        "$context"
    else
      log "模式: 仅构建 (depot)"
      depot build \
        --platform "$PLATFORM" \
        "${tags[@]}" \
        --load \
        "$context"
    fi
  else
    # ---- Docker Buildx 构建 ----
    setup_buildx

    if [[ "$PUSH" == "1" ]]; then
      log "模式: 构建 + 推送 (buildx)"
      docker buildx build \
        --platform "$PLATFORM" \
        "${tags[@]}" \
        --push \
        "$context"
    else
      log "模式: 仅构建 (buildx)"
      # --load 不支持多平台，单平台时使用 --load，多平台时只构建不加载
      if [[ "$PLATFORM" == *","* ]]; then
        warn "多平台构建不推送时无法加载到本地 Docker，仅验证构建"
        docker buildx build \
          --platform "$PLATFORM" \
          "${tags[@]}" \
          "$context"
      else
        docker buildx build \
          --platform "$PLATFORM" \
          "${tags[@]}" \
          --load \
          "$context"
      fi
    fi
  fi
}

# ---- 主流程 ----
echo ""
echo "  ╔═══════════════════════════════════════╗"
echo "  ║   鸣鹤 MingHe — Docker 镜像构建       ║"
echo "  ╚═══════════════════════════════════════╝"
echo ""
log "仓库:     ${REPO}"
log "标签:     ${TAG}"
log "推送:     $([ "$PUSH" == "1" ] && echo "是" || echo "否")"
log "构建器:   ${SELECTED_BUILDER}"
log "目标平台: ${PLATFORM}"
echo ""

# 构建鸣鹤 SIP 服务器镜像
build_and_push "$IMAGE" "." "$TAG" "$ALSO_LATEST"

echo ""
ok "构建完成！"
echo ""

if [[ "$PUSH" == "1" ]]; then
  ok "镜像已推送:"
  echo "   docker pull ${IMAGE}:${TAG}"
  [[ "$ALSO_LATEST" == "yes" ]] && echo "   docker pull ${IMAGE}:latest"
else
  ok "镜像已构建（本地）:"
  echo "   docker images ${IMAGE}"
fi

echo ""
echo "  运行方式:"
echo "   docker compose up -d"
echo "   或:"
echo "   docker run -d \\"
echo "     -p 5061:5061/tcp \\"
echo "     -p 20000-20020:20000-20020/udp \\"
echo "     -v \$(pwd)/config:/app/config:ro \\"
echo "     -v minghe-certs:/app/certs \\"
echo "     ${IMAGE}:${TAG}"
echo ""
