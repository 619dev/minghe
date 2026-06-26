# ============================================================
# 鸣鹤 (MingHe) SIP Server — 多阶段构建
# ============================================================

# ---- 阶段 1: 构建 ----
FROM rust:bookworm AS builder

WORKDIR /build

# 先复制依赖清单，利用 Docker 层缓存
COPY Cargo.toml Cargo.lock* ./

# 创建虚拟 main.rs 来预编译依赖
RUN mkdir -p src && \
    echo 'fn main() { println!("placeholder"); }' > src/main.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# 复制实际源码并编译
COPY src/ src/

# 触发重新编译（因为 src/main.rs 变了）
RUN touch src/main.rs && \
    cargo build --release

# ---- 阶段 2: 运行 ----
FROM debian:bookworm-slim

# 安装最小运行时依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        && \
    rm -rf /var/lib/apt/lists/*

# 创建非 root 用户
RUN groupadd -r minghe && \
    useradd -r -g minghe -d /app -s /sbin/nologin minghe

WORKDIR /app

# 从构建阶段复制二进制
COPY --from=builder /build/target/release/minghe /app/minghe

# 创建必要的目录
RUN mkdir -p /app/certs /app/config && \
    chown -R minghe:minghe /app

# 默认配置文件（可被卷挂载覆盖）
COPY config.toml /app/config/config.toml

# 切换到非 root 用户
USER minghe

# SIP TLS 端口
EXPOSE 5061/tcp

# RTP 媒体端口范围（默认约 10 通并发）
EXPOSE 20000-20020/udp

# 健康检查：检查进程是否存活
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD pgrep minghe > /dev/null || exit 1

# 数据卷
VOLUME ["/app/certs", "/app/config"]

# 启动命令
ENTRYPOINT ["/app/minghe"]
CMD ["-c", "/app/config/config.toml"]
