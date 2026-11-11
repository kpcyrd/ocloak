use crate::errors::*;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Default, PartialEq, Deserialize)]
pub struct Config {
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

#[derive(Debug, Default, PartialEq, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub hosts: BTreeSet<String>,
    pub path: Option<String>,
    #[serde(default)]
    pub require_dns_ohttp_discovery: bool,
    #[serde(default)]
    pub arbitrary_paths: bool,
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
                allowed: vec![
                    Rule {
                        hosts: [
                            "ccc.de",
                            "crypto.cloudflare.com",
                            "example.com",
                            "ohttp.test.orca.toys",
                            "target.ohttp.info",
                            "x.y.z.abc",
                        ]
                        .into_iter()
                        .map(String::from)
                        .collect(),
                        arbitrary_paths: true,
                        ..Default::default()
                    },
                    Rule {
                        hosts: ["*".into(),].into_iter().collect(),
                        path: Some("/.well-known/ohttp-gateway".into()),
                        require_dns_ohttp_discovery: true,
                        ..Default::default()
                    },
                ]
            }
        );
    }
}
