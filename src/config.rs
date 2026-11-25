use crate::errors::*;
use crate::rules;
use arc_swap::ArcSwap;
use hyper::header::{HeaderName, HeaderValue};
use serde::Deserialize;
use serde_with::{DisplayFromStr, Map, serde_as};
use std::collections::{BTreeMap, BTreeSet};
use std::mem;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio_rustls::rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};

#[derive(Debug)]
pub struct Shared {
    config: ArcSwap<Config>,
    tls: ArcSwap<Option<Arc<ServerConfig>>>,
    path: PathBuf,
}

impl Shared {
    pub fn new(config: Config, path: PathBuf) -> Self {
        Self {
            config: ArcSwap::from_pointee(config),
            tls: ArcSwap::from_pointee(None),
            path,
        }
    }

    pub async fn reload_certs(&self) -> Result<()> {
        let config = self.config();
        let Some(tls) = &config.tls else {
            self.tls.store(Arc::new(None));
            return Ok(());
        };

        let cert_path = &tls.cert_path;
        let private_key_path = &tls.private_key_path;

        // Read from disk
        let cert = fs::read(&cert_path)
            .await
            .with_context(|| format!("Failed to read TLS certificate file: {cert_path:?}"))?;

        let private_key = fs::read(&private_key_path).await.with_context(|| {
            format!("Failed to read TLS private key file: {private_key_path:?}")
        })?;

        // Parse file contents
        let certs = CertificateDer::pem_slice_iter(&cert)
            .map(|cert| cert.map_err(Error::from))
            .collect::<Result<Vec<_>>>()
            .with_context(|| {
                format!("Failed to parse TLS certificate from PEM file: {cert_path:?}")
            })?;

        let private_key = PrivateKeyDer::from_pem_slice(&private_key).with_context(|| {
            format!("Failed to parse TLS private key from PEM file: {private_key_path:?}")
        })?;

        // Finalize TLS config
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .context("Failed to create TLS server config")?;

        self.tls.store(Arc::new(Some(Arc::new(config))));

        Ok(())
    }

    pub fn replace_config(&self, config: Config) {
        self.config.store(Arc::new(config));
    }

    pub fn config(&self) -> arc_swap::Guard<Arc<Config>> {
        self.config.load()
    }

    pub fn tls(&self) -> arc_swap::Guard<Arc<Option<Arc<ServerConfig>>>> {
        self.tls.load()
    }

    pub fn config_path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Config {
    pub daemon: Daemon,
    pub tls: Option<Tls>,
    #[serde(default)]
    pub index: Index,
    pub defaults: Defaults,
    #[serde(default)]
    pub allowed: Vec<Rule>,
}

impl Config {
    pub async fn load(path: &Path) -> Result<Self> {
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| anyhow!("Failed to read config file: {path:?}"))?;
        let config = Self::parse_str(&content)
            .with_context(|| anyhow!("Failed to parse config file: {path:?}"))?;
        Ok(config)
    }

    pub fn parse_str(s: &str) -> Result<Self> {
        let mut config = toml::from_str::<Self>(s)?;
        for (i, rule) in config.allowed.iter_mut().enumerate() {
            while let Some((extra, _)) = rule.extra.pop_first() {
                warn!("Rule #{i} has unexpected configuration key: {extra:?}");
            }
            rule.hosts = mem::take(&mut rule.hosts)
                .into_iter()
                .filter_map(|host| {
                    if host == "*" {
                        Some(host)
                    } else if let Some(host) = rules::normalize_host(&host) {
                        Some(host)
                    } else {
                        warn!("Rule #{i} has invalid host, ignoring: {host:?}");
                        None
                    }
                })
                .collect();
        }
        Ok(config)
    }
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Daemon {
    pub bind_addr: SocketAddr,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Tls {
    pub cert_path: PathBuf,
    pub private_key_path: PathBuf,
}

#[serde_as]
#[derive(Debug, Default, PartialEq, Deserialize)]
pub struct Index {
    pub file_path: Option<PathBuf>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub content_type: Option<HeaderValue>,
    #[serde(default)]
    #[serde_as(as = "Map<DisplayFromStr, DisplayFromStr>")]
    pub http_headers: Vec<(HeaderName, HeaderValue)>,
}

#[serde_as]
#[derive(Debug, PartialEq, Deserialize)]
pub struct Defaults {
    #[serde_as(as = "DisplayFromStr")]
    pub tls_handshake_timeout: HumanTime,
    #[serde_as(as = "DisplayFromStr")]
    pub max_request_size: HumanSize,
    pub user_agent: String,
    #[serde_as(as = "DisplayFromStr")]
    pub connect_timeout: HumanTime,
    #[serde_as(as = "DisplayFromStr")]
    pub read_timeout: HumanTime,
    pub max_redirects: usize,
}

// Used by HumanSize and HumanTime parsing functions
fn parse_num(s: &str) -> Result<u64> {
    let s = s.trim();
    let n = s.parse()?;
    Ok(n)
}

#[derive(Debug, PartialEq)]
pub struct HumanSize {
    pub value: u64,
}

impl FromStr for HumanSize {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = if let Some(value) = s.strip_suffix("KiB") {
            let value = parse_num(value)?;
            value * 1024
        } else if let Some(value) = s.strip_suffix("MiB") {
            let value = parse_num(value)?;
            value * 1024 * 1024
        } else if let Some(value) = s.strip_suffix("GiB") {
            let value = parse_num(value)?;
            value * 1024 * 1024 * 1024
        } else if let Some(value) = s.strip_suffix("B") {
            parse_num(value)?
        } else {
            bail!("Invalid size unit: {s:?}");
        };

        Ok(HumanSize { value })
    }
}

#[derive(Debug, PartialEq)]
pub struct HumanTime {
    pub value: Duration,
}

impl FromStr for HumanTime {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = if let Some(value) = s.strip_suffix("ms") {
            let value = parse_num(value)?;
            Duration::from_millis(value)
        } else if let Some(value) = s.strip_suffix('s') {
            let value = parse_num(value)?;
            Duration::from_secs(value)
        } else if let Some(value) = s.strip_suffix('m') {
            let value = parse_num(value)?;
            Duration::from_secs(value * 60)
        } else if let Some(value) = s.strip_suffix('h') {
            let value = parse_num(value)?;
            Duration::from_secs(value * 3600)
        } else {
            bail!("Invalid time format: {s:?}");
        };

        Ok(HumanTime { value })
    }
}

#[derive(Debug, Default, PartialEq, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub hosts: BTreeSet<String>,
    pub path: Option<String>,
    #[serde(default)]
    pub require_dns_ohttp_discovery: bool,
    pub arbitrary_paths: Option<bool>,
    #[serde(default)]
    pub deny: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}

impl Rule {
    pub fn contains_host(&self, text: &str) -> bool {
        self.hosts.contains(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::fs;

    #[test]
    fn parse_minimal_rule() {
        let rule = toml::from_str::<Rule>("").unwrap();
        assert_eq!(rule, Rule::default());
    }

    #[test]
    fn test_rule_catch_extra_data() {
        let rule = toml::from_str::<Rule>(
            r#"
hosts = ["example.com"]
require_dns_ohttp_discovery = true
foo = {}
typo = "value"
asdf = []
        "#,
        )
        .unwrap();
        assert_eq!(
            rule,
            Rule {
                hosts: ["example.com".into()].into_iter().collect(),
                require_dns_ohttp_discovery: true,
                extra: [
                    ("foo".into(), toml::Value::Table(Default::default())),
                    ("typo".into(), toml::Value::String("value".into())),
                    ("asdf".into(), toml::Value::Array(vec![])),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            }
        );
    }

    #[tokio::test]
    async fn parse_example_config() {
        let config = fs::read_to_string("contrib/ocloak.conf").await.unwrap();
        let config = toml::from_str::<Config>(&config).unwrap();
        assert_eq!(
            config,
            Config {
                daemon: Daemon {
                    bind_addr: "127.0.0.1:1312".parse().unwrap(),
                },
                tls: None,
                index: Default::default(),
                defaults: Defaults {
                    tls_handshake_timeout: "15s".parse().unwrap(),
                    max_request_size: "8 MiB".parse().unwrap(),
                    user_agent: "ohttp-relay".into(),
                    connect_timeout: "15s".parse().unwrap(),
                    read_timeout: "30s".parse().unwrap(),
                    max_redirects: 2,
                },
                allowed: vec![Rule {
                    hosts: ["*".into()].into_iter().collect(),
                    path: None,
                    require_dns_ohttp_discovery: true,
                    ..Default::default()
                },]
            }
        );
    }

    #[tokio::test]
    async fn parse_expanded_example_config() {
        let config = fs::read_to_string("contrib/ocloak.conf").await.unwrap();
        let config = config.lines().map(|line| line.strip_prefix("#").unwrap_or(line)).fold(
            String::new(),
            |mut acc, line| {
                acc.push_str(line);
                acc.push('\n');
                acc
            },
        );
        let config = toml::from_str::<Config>(&config).unwrap();
        assert_eq!(
            config,
            Config {
                daemon: Daemon {
                    bind_addr: "127.0.0.1:1312".parse().unwrap(),
                },
                tls: Some(Tls {
                    cert_path: "/etc/ocloak/cert.pem".into(),
                    private_key_path: "/etc/ocloak/private_key.pem".into(),
                }),
                index: Index {
                    file_path: Some("contrib/index.html".into()),
                    content_type: Some("text/html; charset=utf-8".parse().unwrap()),
                    http_headers: vec![(
                        "Strict-Transport-Security".parse().unwrap(),
                        "max-age=31536000; includeSubDomains; preload"
                            .parse()
                            .unwrap(),
                    )],
                },
                defaults: Defaults {
                    tls_handshake_timeout: "15s".parse().unwrap(),
                    max_request_size: "8 MiB".parse().unwrap(),
                    user_agent: "ohttp-relay".into(),
                    connect_timeout: "15s".parse().unwrap(),
                    read_timeout: "30s".parse().unwrap(),
                    max_redirects: 2,
                },
                allowed: vec![
                    Rule {
                        hosts: ["example.com"].into_iter().map(String::from).collect(),
                        ..Default::default()
                    },
                    Rule {
                        hosts: ["example.com"].into_iter().map(String::from).collect(),
                        arbitrary_paths: Some(true),
                        ..Default::default()
                    },
                    Rule {
                        hosts: ["example.com"].into_iter().map(String::from).collect(),
                        path: Some("/.not-well-known/ohttp-gateway".into()),
                        ..Default::default()
                    },
                    Rule {
                        hosts: ["example.com"].into_iter().map(String::from).collect(),
                        deny: true,
                        ..Default::default()
                    },
                    Rule {
                        hosts: ["*".into()].into_iter().collect(),
                        path: None,
                        require_dns_ohttp_discovery: true,
                        ..Default::default()
                    },
                ]
            }
        );
    }

    #[test]
    fn test_parse_human_size() {
        let hs = "8 MiB".parse::<HumanSize>().unwrap();
        assert_eq!(hs.value, 8 * 1024 * 1024);

        let value = "16KiB".parse::<HumanSize>().unwrap();
        assert_eq!(value.value, 16 * 1024);

        let value = "1 GiB".parse::<HumanSize>().unwrap();
        assert_eq!(value.value, 1024 * 1024 * 1024);

        let value = "512B".parse::<HumanSize>().unwrap();
        assert_eq!(value.value, 512);

        let value = "4".parse::<HumanSize>();
        assert!(value.is_err());
    }

    #[test]
    fn test_parse_human_time() {
        let value = "5m".parse::<HumanTime>().unwrap();
        assert_eq!(value.value, Duration::from_secs(5 * 60));

        let value = "2h".parse::<HumanTime>().unwrap();
        assert_eq!(value.value, Duration::from_secs(2 * 3600));

        let value = "250ms".parse::<HumanTime>().unwrap();
        assert_eq!(value.value, Duration::from_millis(250));

        let value = "23 s".parse::<HumanTime>().unwrap();
        assert_eq!(value.value, Duration::from_secs(23));

        let value = "12".parse::<HumanTime>();
        assert!(value.is_err());
    }
}
