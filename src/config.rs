use crate::errors::*;
use serde::Deserialize;
use serde_with::{DisplayFromStr, serde_as};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, PartialEq, Deserialize)]
pub struct Config {
    pub daemon: Daemon,
    pub defaults: Defaults,
    #[serde(default)]
    pub allowed: Vec<Rule>,
}

impl Config {
    pub async fn load(path: &Path) -> Result<Self> {
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| anyhow!("Failed to read config file: {path:?}"))?;
        let config = toml::from_str::<Config>(&content)
            .with_context(|| anyhow!("Failed to parse config file: {path:?}"))?;
        Ok(config)
    }
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Daemon {
    pub bind_addr: SocketAddr,
}

#[serde_as]
#[derive(Debug, PartialEq, Deserialize)]
pub struct Defaults {
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
    #[serde(default)]
    pub arbitrary_paths: bool,
    #[serde(default)]
    pub deny: bool,
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

    #[tokio::test]
    async fn parse_example_config() {
        let config = fs::read_to_string("contrib/ocloak.conf").await.unwrap();
        let config = toml::from_str::<Config>(&config).unwrap();
        assert_eq!(
            config,
            Config {
                daemon: Daemon {
                    bind_addr: "127.0.0.1:1312".parse().unwrap()
                },
                defaults: Defaults {
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
        let config = config.lines().map(|line| line.trim_prefix("#")).fold(
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
                    bind_addr: "127.0.0.1:1312".parse().unwrap()
                },
                defaults: Defaults {
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
                        arbitrary_paths: true,
                        ..Default::default()
                    },
                    Rule {
                        hosts: ["example.com"].into_iter().map(String::from).collect(),
                        path: Some("/.not-well-known/ohttp-gateway".into()),
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
