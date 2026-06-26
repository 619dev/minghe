//! 鸣鹤 (MingHe) — 最小化安全 SIP 语音通信服务器
//!
//! 纯 TLS 信令 + SRTP 媒体加密的内部分机通信系统。

mod config;
mod media;
mod sip;
mod tls;

use clap::Parser;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

/// 鸣鹤 SIP 语音服务器命令行参数
#[derive(Parser, Debug)]
#[command(name = "minghe")]
#[command(version, about = "鸣鹤 — 最小化安全 SIP 语音通信服务")]
struct Cli {
    /// 配置文件路径
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

/// 打印启动横幅
fn print_banner() {
    let banner = r#"
    ╔═══════════════════════════════════════════════╗
    ║                                               ║
    ║            鸣 鹤  MingHe SIP Server            ║
    ║                                               ║
    ║         安全语音通信  ·  TLS + SRTP            ║
    ║                                               ║
    ╚═══════════════════════════════════════════════╝
"#;
    println!("{}", banner);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 解析命令行参数
    let cli = Cli::parse();

    // 初始化日志系统
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    // 打印启动横幅
    print_banner();

    // 加载配置
    tracing::info!("正在加载配置文件: {}", cli.config);
    let config = config::AppConfig::load(&cli.config)?;
    tracing::info!(
        "配置加载成功 — 主体: {}, SIP 端口: {}, 分机范围: {}-{}",
        config.server.host,
        config.server.sip_port,
        config.extensions.range_start,
        config.extensions.range_end
    );

    let media_addr = config.get_media_addr();
    tracing::info!("媒体地址: {}", media_addr);

    let config = Arc::new(config);

    // 初始化 TLS
    tracing::info!("正在初始化 TLS...");
    let tls_acceptor = tls::setup_tls(&config.tls, &config.server.host)?;
    tracing::info!("TLS 初始化完成");

    // 启动证书自动续期后台任务
    tls::start_cert_renewal_task(
        tls_acceptor.clone(),
        config.tls.clone(),
        config.server.host.clone(),
    );

    // 创建注册服务（含 Digest 认证）
    let registrar = Arc::new(sip::registrar::RegistrarService::new(
        config.server.host.clone(),
        config.extensions.default_password.clone(),
        config.passwords.clone(),
        config.extensions.range_start,
        config.extensions.range_end,
    ));

    // 启动注册清理后台任务
    registrar.start_cleanup_task();

    // 创建媒体中继管理器
    let media_manager = Arc::new(media::relay::MediaRelayManager::new(
        config.media.rtp_port_start,
        config.media.rtp_port_end,
        media_addr,
    ));

    tracing::info!(
        "鸣鹤 SIP 服务器正在启动于 {}:{}",
        config.server.listen_addr,
        config.server.sip_port
    );

    // 启动 SIP TLS 服务器
    let server_handle = {
        let config = Arc::clone(&config);
        let registrar = Arc::clone(&registrar);
        let media_manager = Arc::clone(&media_manager);
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            if let Err(e) = sip::server::run(config, tls_acceptor, registrar, media_manager).await {
                tracing::error!("SIP 服务器运行错误: {}", e);
            }
        })
    };

    // 等待关闭信号
    tracing::info!("服务器已就绪，按 Ctrl+C 优雅关闭");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("收到关闭信号，正在优雅停止服务...");
        }
        result = server_handle => {
            match result {
                Ok(_) => tracing::info!("SIP 服务器已停止"),
                Err(e) => tracing::error!("SIP 服务器任务异常: {}", e),
            }
        }
    }

    tracing::info!("鸣鹤服务器已关闭。再见！");
    Ok(())
}
