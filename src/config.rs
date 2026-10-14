//! 配置模块
//!
//! 从 config.toml 加载服务器配置，包括 SIP 服务、分机范围和 TLS 证书；可选 Bria SRTP 媒体中继配置。

use serde::Deserialize;
use std::collections::HashMap;

/// 应用程序顶层配置
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    /// SIP 服务器配置
    pub server: ServerConfig,
    /// 分机配置
    pub extensions: ExtensionConfig,
    /// TLS 证书配置
    pub tls: TlsConfig,
    /// 显式启用 Bria 兼容媒体中继；不设置时使用端到端协议。
    #[serde(default)]
    pub media: Option<MediaConfig>,
    /// 分机独立密码（可选，覆盖 default_password）
    #[serde(default)]
    pub passwords: HashMap<String, String>,
}

/// SIP 服务器基本配置
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Explicit SIP Digest selection; compatibility is opt-in.
    #[serde(default)]
    pub digest_algorithm: DigestAlgorithm,
    /// 监听地址（如 "0.0.0.0"）
    pub listen_addr: String,
    /// SIP TLS 端口（默认 5061）
    pub sip_port: u16,
    /// 服务器域名或 IP 地址
    /// 用于 SIP URI 和 TLS 证书生成
    /// 支持域名（如 "minghe.local"）和 IP 地址（如 "192.168.1.100"）
    pub host: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DigestAlgorithm {
    #[default]
    Sha256,
    Md5,
}

impl DigestAlgorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Md5 => "MD5",
        }
    }
    pub fn hex_length(self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Md5 => 32,
        }
    }
}

impl ServerConfig {
    /// 判断 host 是否为 IP 地址
    pub fn is_ip_host(&self) -> bool {
        self.host.parse::<std::net::IpAddr>().is_ok()
    }
}

/// 分机号码配置
#[derive(Debug, Clone, Deserialize)]
pub struct ExtensionConfig {
    /// 分机起始号码（含）
    pub range_start: u32,
    /// 分机结束号码（含）
    pub range_end: u32,
    /// 所有分机的默认密码
    pub default_password: String,
}

/// TLS 证书配置
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// 证书文件路径（留空则自动生成自签名证书）
    pub cert_path: String,
    /// 私钥文件路径（留空则自动生成自签名证书）
    pub key_path: String,
}

/// SDES compatibility or opaque ZRTP relay; selected explicitly, never downgraded.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaConfig {
    #[serde(default)]
    pub mode: MediaMode,
    pub rtp_port_start: u16,
    pub rtp_port_end: u16,
    pub media_addr: String,
}

/// Explicit profiles never fall back to one another.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaMode {
    #[default]
    Sdes,
    Zrtp,
}

impl AppConfig {
    /// 从指定路径加载并解析 TOML 配置文件
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("无法读取配置文件 '{}': {}", path, e))?;
        let config: AppConfig = toml::from_str(&content).map_err(|_| {
            format!(
                "配置文件解析错误 '{}'（为避免泄露密码，省略原始内容）",
                path
            )
        })?;

        if config.tls.cert_path.is_empty() != config.tls.key_path.is_empty() {
            return Err("cert_path 和 key_path 必须同时设置或同时留空".into());
        }
        if config.server.host.is_empty()
            || !config
                .server
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))
        {
            return Err("host 必须是有效的域名或 IP，不能包含 SIP 分隔符".into());
        }
        for password in
            std::iter::once(&config.extensions.default_password).chain(config.passwords.values())
        {
            if password.len() < 12
                || password.starts_with("CHANGE_ME")
                || password == "minghe@2024"
                || password == "YourPassword123"
            {
                return Err("请设置至少 12 字节的强密码，不能使用示例密码".into());
            }
        }
        if config
            .extensions
            .range_end
            .saturating_sub(config.extensions.range_start)
            >= 10000
        {
            return Err("分机范围最多允许 10000 个号码".into());
        }
        // 基本校验
        if config.extensions.range_start > config.extensions.range_end {
            return Err(format!(
                "分机范围无效: range_start ({}) > range_end ({})",
                config.extensions.range_start, config.extensions.range_end
            )
            .into());
        }

        if let Some(media) = &config.media {
            if media.rtp_port_start == 0
                || media.rtp_port_start % 2 != 0
                || media.rtp_port_end.saturating_sub(media.rtp_port_start) < 4
            {
                return Err("媒体端口范围至少需要两个非零偶数 RTP 端口".into());
            }
            if media.mode == MediaMode::Zrtp && media.rtp_port_end % 2 != 0 {
                return Err("ZRTP 媒体端口范围结束值必须为偶数，确保包含配对的 RTCP 端口".into());
            }
            let ip = media
                .media_addr
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| "media_addr 必须是客户端可访问的服务器 IPv4 地址")?;
            if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                return Err("media_addr 必须是客户端可访问的服务器 IPv4 地址".into());
            }
            match media.mode {
                MediaMode::Sdes => tracing::warn!(
                    "已启用 Bria 兼容 SRTP 中继：服务器终止媒体加密，此模式不是端到端加密"
                ),
                MediaMode::Zrtp => tracing::info!(
                    "已启用 ZRTP 密文中继：密钥由客户端协商；客户端必须强制 ZRTP 并核对 SAS"
                ),
            }
        }

        // 校验独立密码中的分机号是否在范围内
        for (ext_str, _) in &config.passwords {
            if let Ok(ext_num) = ext_str.parse::<u32>() {
                if ext_num.to_string() != *ext_str
                    || ext_num < config.extensions.range_start
                    || ext_num > config.extensions.range_end
                {
                    return Err("独立密码的分机号必须是范围内的规范十进制号码".into());
                }
            } else {
                return Err(
                    format!("密码配置中的分机号 '{}' 格式无效（应为数字）", ext_str).into(),
                );
            }
        }

        if !config.passwords.is_empty() {
            tracing::info!("已加载 {} 个分机独立密码配置", config.passwords.len());
        }

        Ok(config)
    }

    /// 检查给定的分机号码是否在配置的有效范围内
    pub fn is_valid_extension(&self, ext: u32) -> bool {
        ext >= self.extensions.range_start && ext <= self.extensions.range_end
    }

    /// 获取指定分机的密码
    ///
    /// 优先返回 [passwords] 中的独立密码，未配置则返回 default_password
    pub fn get_password(&self, extension: &str) -> &str {
        if let Some(pwd) = self.passwords.get(extension) {
            pwd
        } else {
            &self.extensions.default_password
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsafe_configuration_without_echoing_secrets() {
        let template = include_str!("../config.template.toml");
        let valid = template.replace("CHANGE_ME_TO_A_STRONG_PASSWORD", "test-only-long-password");
        let path =
            std::env::temp_dir().join(format!("minghe-config-{}.toml", uuid::Uuid::new_v4()));
        std::fs::write(&path, &valid).unwrap();
        assert!(AppConfig::load(path.to_str().unwrap()).is_ok());
        assert_eq!(
            AppConfig::load(path.to_str().unwrap())
                .unwrap()
                .server
                .digest_algorithm,
            DigestAlgorithm::Sha256
        );
        std::fs::write(
            &path,
            valid.replace("[server]", "[server]\ndigest_algorithm = 'md5'"),
        )
        .unwrap();
        assert_eq!(
            AppConfig::load(path.to_str().unwrap())
                .unwrap()
                .server
                .digest_algorithm,
            DigestAlgorithm::Md5
        );
        std::fs::write(
            &path,
            valid.replace("[server]", "[server]\ndigest_algorithm = 'automatic'"),
        )
        .unwrap();
        assert!(AppConfig::load(path.to_str().unwrap()).is_err());
        // Media configuration explicitly selects compatibility mode.
        std::fs::write(
            &path,
            format!("{valid}\n[media]\nmedia_addr = '203.0.113.10'\nrtp_port_start = 20000\nrtp_port_end = 20010\n"),
        )
        .unwrap();
        assert_eq!(
            AppConfig::load(path.to_str().unwrap())
                .unwrap()
                .media
                .unwrap()
                .mode,
            MediaMode::Sdes
        );
        let zrtp = format!("{valid}\n[media]\nmode = 'zrtp'\nmedia_addr = '203.0.113.10'\nrtp_port_start = 20000\nrtp_port_end = 20020\n");
        std::fs::write(&path, &zrtp).unwrap();
        assert_eq!(
            AppConfig::load(path.to_str().unwrap())
                .unwrap()
                .media
                .unwrap()
                .mode,
            MediaMode::Zrtp
        );
        std::fs::write(
            &path,
            zrtp.replace("rtp_port_end = 20020", "rtp_port_end = 20021"),
        )
        .unwrap();
        assert!(AppConfig::load(path.to_str().unwrap()).is_err());
        std::fs::write(&path, zrtp.replace("'zrtp'", "'automatic'")).unwrap();
        assert!(AppConfig::load(path.to_str().unwrap()).is_err());
        for bad in [
            template.to_string(),
            valid.replace("test-only-long-password", "short"),
            valid.replace("key_path = \"\"", "key_path = \"key.pem\""),
            valid.replace("range_end = 2000", "range_end = 999"),
        ] {
            std::fs::write(&path, bad).unwrap();
            assert!(AppConfig::load(path.to_str().unwrap()).is_err());
        }
        for media in [
            "media_addr = '0.0.0.0'\nrtp_port_start = 20000\nrtp_port_end = 20020",
            "media_addr = '203.0.113.10'\nrtp_port_start = 20001\nrtp_port_end = 20020",
            "media_addr = '203.0.113.10'\nrtp_port_start = 0\nrtp_port_end = 20020",
            "media_addr = '203.0.113.10'\nrtp_port_start = 20000\nrtp_port_end = 20002",
            "media_addr = 'sip.example.com'\nrtp_port_start = 20000\nrtp_port_end = 20020",
        ] {
            std::fs::write(&path, format!("{valid}\n[media]\n{media}\n")).unwrap();
            assert!(AppConfig::load(path.to_str().unwrap()).is_err());
        }
        std::fs::write(&path, "password = 'DO_NOT_LOG_THIS_SECRET'\nINVALID").unwrap();
        let error = AppConfig::load(path.to_str().unwrap())
            .unwrap_err()
            .to_string();
        assert!(!error.contains("DO_NOT_LOG_THIS_SECRET"));
        std::fs::remove_file(path).unwrap();
    }
}
