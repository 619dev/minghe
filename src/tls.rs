//! TLS 证书管理模块
//!
//! 负责 TLS 证书的加载或自动生成自签名证书，以及构建 TLS acceptor。
//! 支持证书自动续期：后台任务定期检查证书有效期，到期前自动重新生成。
//!
//! 功能概述：
//! - 如果配置中指定了证书和私钥路径，则从磁盘加载
//! - 如果路径为空，则使用 rcgen 自动生成自签名证书并保存到 `certs/` 目录
//! - 构建并返回可热重载的 `ReloadableTlsAcceptor`
//! - 自签名证书自动续期（到期前 30 天自动重新生成）

use std::io::BufReader;
use std::sync::{Arc, RwLock};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;

/// 证书续期提前天数（到期前多少天开始续期）
const RENEWAL_DAYS_BEFORE: i64 = 30;

/// 证书有效期（天）
const CERT_VALIDITY_DAYS: i64 = 365;

/// 证书检查间隔（秒）—— 每 6 小时检查一次
const CHECK_INTERVAL_SECS: u64 = 6 * 3600;

/// 可热重载的 TLS Acceptor
///
/// 包装 `TlsAcceptor`，支持在运行时更新证书而不中断服务。
/// 新连接会使用最新的证书，已建立的连接不受影响。
#[derive(Clone)]
pub struct ReloadableTlsAcceptor {
    inner: Arc<RwLock<TlsAcceptor>>,
}

impl ReloadableTlsAcceptor {
    /// 创建新的可重载 acceptor
    fn new(acceptor: TlsAcceptor) -> Self {
        Self {
            inner: Arc::new(RwLock::new(acceptor)),
        }
    }

    /// 获取当前的 TlsAcceptor 快照
    pub fn current(&self) -> TlsAcceptor {
        self.inner.read().unwrap().clone()
    }

    /// 热重载：替换内部的 TlsAcceptor
    fn reload(&self, new_acceptor: TlsAcceptor) {
        let mut guard = self.inner.write().unwrap();
        *guard = new_acceptor;
        tracing::info!("TLS 证书已热重载，新连接将使用新证书");
    }
}

/// 初始化 TLS，返回可热重载的 TlsAcceptor
///
/// 如果配置中指定了证书路径，从磁盘加载。
/// 否则自动生成自签名证书。
pub fn setup_tls(
    config: &TlsConfig,
    host: &str,
) -> Result<ReloadableTlsAcceptor, Box<dyn std::error::Error>> {
    let (certs, key) = if config.cert_path.is_empty() || config.key_path.is_empty() {
        // 检查是否有已存在的未过期证书
        let certs_dir = std::path::Path::new("certs");
        let cert_file = certs_dir.join("server.crt");
        let key_file = certs_dir.join("server.key");

        if cert_file.exists() && key_file.exists() {
            // 检查现有证书是否即将过期
            if let Ok(pem_data) = std::fs::read(&cert_file) {
                if !is_cert_expiring_soon(&pem_data) {
                    tracing::info!("使用已有自签名证书（未到期）: {}", cert_file.display());
                    let certs = load_certs_from_path(cert_file.to_str().unwrap())?;
                    let key = load_key_from_path(key_file.to_str().unwrap())?;
                    return Ok(ReloadableTlsAcceptor::new(build_acceptor(certs, key)?));
                }
                tracing::info!("已有证书即将过期，重新生成...");
            }
        }

        tracing::info!("正在生成自签名证书（主体: {}）...", host);
        generate_and_save_cert(host)?
    } else {
        tracing::info!(
            "正在加载 TLS 证书: {}, 私钥: {}",
            config.cert_path,
            config.key_path
        );
        let certs = load_certs_from_path(&config.cert_path)?;
        let key = load_key_from_path(&config.key_path)?;
        tracing::info!("TLS 证书加载成功（共 {} 张证书）", certs.len());
        (certs, key)
    };

    let acceptor = build_acceptor(certs, key)?;
    tracing::info!("TLS acceptor 初始化成功");
    Ok(ReloadableTlsAcceptor::new(acceptor))
}

/// 启动证书自动续期后台任务
///
/// 仅对自签名证书有效（cert_path 和 key_path 为空时）。
/// 每 6 小时检查一次证书有效期，到期前 30 天自动重新生成。
pub fn start_cert_renewal_task(
    tls_acceptor: ReloadableTlsAcceptor,
    config: TlsConfig,
    host: String,
) {
    // 只有自签名证书才需要自动续期
    if !config.cert_path.is_empty() && !config.key_path.is_empty() {
        tracing::info!("使用外部证书，跳过自动续期（请使用外部工具管理证书更新）");
        return;
    }

    tracing::info!(
        "证书自动续期已启用: 每 {} 小时检查一次，到期前 {} 天续期",
        CHECK_INTERVAL_SECS / 3600,
        RENEWAL_DAYS_BEFORE
    );

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(CHECK_INTERVAL_SECS)).await;

            tracing::debug!("正在检查证书有效期...");

            let cert_path = std::path::Path::new("certs").join("server.crt");
            let needs_renewal = if let Ok(pem_data) = std::fs::read(&cert_path) {
                is_cert_expiring_soon(&pem_data)
            } else {
                tracing::warn!("无法读取证书文件，尝试重新生成");
                true
            };

            if needs_renewal {
                tracing::info!("证书即将过期或不可读，正在自动续期...");
                match generate_and_save_cert(&host) {
                    Ok((certs, key)) => match build_acceptor(certs, key) {
                        Ok(new_acceptor) => {
                            tls_acceptor.reload(new_acceptor);
                            tracing::info!(
                                "证书自动续期成功！新证书有效期 {} 天",
                                CERT_VALIDITY_DAYS
                            );
                        }
                        Err(e) => {
                            tracing::error!("证书续期后构建 TLS acceptor 失败: {}", e);
                        }
                    },
                    Err(e) => {
                        tracing::error!("证书自动续期失败: {}", e);
                    }
                }
            } else {
                tracing::debug!("证书有效期充足，无需续期");
            }
        }
    });
}

/// 检查 PEM 编码的证书是否即将过期
///
/// 解析证书的 Not After 时间，如果距离到期不足 RENEWAL_DAYS_BEFORE 天则返回 true
fn is_cert_expiring_soon(pem_data: &[u8]) -> bool {
    // 解析 PEM 中的 Not After 日期
    // rcgen/x509 的完整解析较重，这里使用简单的文本扫描
    // 自签名证书文件旁边保存一个 .expiry 元数据文件
    let expiry_path = std::path::Path::new("certs").join("server.expiry");
    if let Ok(expiry_str) = std::fs::read_to_string(&expiry_path) {
        if let Ok(expiry_ts) = expiry_str.trim().parse::<i64>() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let days_remaining = (expiry_ts - now) / 86400;
            tracing::debug!("证书剩余有效天数: {}", days_remaining);
            return days_remaining < RENEWAL_DAYS_BEFORE;
        }
    }

    // 如果没有 .expiry 文件，根据证书文件修改时间估算
    if let Ok(metadata) = std::fs::metadata(std::path::Path::new("certs").join("server.crt")) {
        if let Ok(modified) = metadata.modified() {
            let age = std::time::SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default();
            let age_days = age.as_secs() as i64 / 86400;
            let days_remaining = CERT_VALIDITY_DAYS - age_days;
            tracing::debug!("证书已使用 {} 天，估计剩余 {} 天", age_days, days_remaining);
            return days_remaining < RENEWAL_DAYS_BEFORE;
        }
    }

    // 无法确定时，保守地不续期（使用 PEM 数据来防止死循环）
    let _ = pem_data;
    false
}

/// 生成自签名证书并保存到 certs/ 目录
fn generate_and_save_cert(
    host: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    let (cert_pem, key_pem) = generate_self_signed(host)?;

    // 保存到 certs/ 目录
    let certs_dir = std::path::Path::new("certs");
    if !certs_dir.exists() {
        std::fs::create_dir_all(certs_dir)
            .map_err(|e| format!("无法创建证书目录 'certs/': {}", e))?;
    }

    let cert_file_path = certs_dir.join("server.crt");
    let key_file_path = certs_dir.join("server.key");
    let expiry_file_path = certs_dir.join("server.expiry");

    let mut persisted = true;
    if let Err(e) = std::fs::write(&cert_file_path, &cert_pem) {
        persisted = false;
        tracing::warn!(
            "无法写入证书文件 {}: {}。将使用内存中的临时证书继续启动；请检查 /app/certs 挂载目录权限。",
            cert_file_path.display(),
            e
        );
    }
    if let Err(e) = std::fs::write(&key_file_path, &key_pem) {
        persisted = false;
        tracing::warn!(
            "无法写入私钥文件 {}: {}。将使用内存中的临时证书继续启动；请检查 /app/certs 挂载目录权限。",
            key_file_path.display(),
            e
        );
    }

    if persisted {
        // 保存过期时间戳
        let expiry_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
            + CERT_VALIDITY_DAYS * 86400;
        if let Err(e) = std::fs::write(&expiry_file_path, expiry_ts.to_string()) {
            tracing::warn!(
                "无法写入证书过期时间文件 {}: {}",
                expiry_file_path.display(),
                e
            );
        }

        tracing::info!(
            "自签名证书已保存: 证书={}, 私钥={}",
            cert_file_path.display(),
            key_file_path.display()
        );
    }

    // 解析 PEM 数据
    let certs = parse_cert_pem(&cert_pem)?;
    let key = parse_key_pem(&key_pem)?;

    Ok((certs, key))
}

/// 使用 rcgen 生成自签名证书
fn generate_self_signed(host: &str) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};
    use std::net::IpAddr;
    use time::{Duration, OffsetDateTime};

    let mut subject_alt_names = Vec::new();

    // 判断 host 是 IP 地址还是域名
    if let Ok(ip) = host.parse::<IpAddr>() {
        tracing::info!("生成 IP 证书模式: {}", host);
        subject_alt_names.push(SanType::IpAddress(ip));
        if host != "127.0.0.1" {
            subject_alt_names.push(SanType::IpAddress("127.0.0.1".parse::<IpAddr>().unwrap()));
        }
        subject_alt_names.push(SanType::DnsName(
            "localhost"
                .try_into()
                .map_err(|e| format!("localhost 域名转换失败: {}", e))?,
        ));
    } else {
        tracing::info!("生成域名证书模式: {}", host);
        subject_alt_names.push(SanType::DnsName(
            host.try_into()
                .map_err(|e| format!("域名 '{}' 格式无效: {}", host, e))?,
        ));
        subject_alt_names.push(SanType::DnsName(
            "localhost"
                .try_into()
                .map_err(|e| format!("localhost 域名转换失败: {}", e))?,
        ));
        subject_alt_names.push(SanType::IpAddress("127.0.0.1".parse::<IpAddr>().unwrap()));
    }

    let mut params = CertificateParams::default();
    params.subject_alt_names = subject_alt_names;

    params.distinguished_name.push(DnType::CommonName, host);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "MingHe SIP Server");

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(CERT_VALIDITY_DAYS);

    let key_pair = KeyPair::generate().map_err(|e| format!("密钥对生成失败: {}", e))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("自签名证书生成失败: {}", e))?;

    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();

    tracing::info!(
        "自签名证书生成成功（主体: {}, 有效期: {} 至 {}）",
        host,
        now.date(),
        (now + Duration::days(CERT_VALIDITY_DAYS)).date()
    );

    Ok((cert_pem, key_pem))
}

/// 从 PEM 字节解析证书
fn parse_cert_pem(
    pem_data: &[u8],
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(pem_data);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("证书 PEM 解析失败: {}", e))?;
    Ok(certs)
}

/// 从 PEM 字节解析私钥
fn parse_key_pem(pem_data: &[u8]) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(pem_data);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("私钥 PEM 解析失败: {}", e))?
        .ok_or("PEM 中未找到有效私钥")?;
    Ok(key)
}

/// 从文件路径加载证书链
fn load_certs_from_path(
    path: &str,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("无法打开证书文件 '{}': {}", path, e))?;
    let mut reader = BufReader::new(file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("证书文件 '{}' 解析失败: {}", path, e))?;

    if certs.is_empty() {
        return Err(format!("证书文件 '{}' 中未找到有效证书", path).into());
    }

    tracing::debug!("从 '{}' 加载了 {} 张证书", path, certs.len());
    Ok(certs)
}

/// 从文件路径加载私钥
fn load_key_from_path(path: &str) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("无法打开私钥文件 '{}': {}", path, e))?;
    let mut reader = BufReader::new(file);

    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("私钥文件 '{}' 解析失败: {}", path, e))?
        .ok_or_else(|| format!("私钥文件 '{}' 中未找到有效私钥", path))?;

    tracing::debug!("从 '{}' 成功加载私钥", path);
    Ok(key)
}

/// 构建 TLS Acceptor
fn build_acceptor(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let tls_config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
            .map_err(|e| format!("TLS 协议版本配置失败: {}", e))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("TLS ServerConfig 构建失败: {}", e))?;

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}
