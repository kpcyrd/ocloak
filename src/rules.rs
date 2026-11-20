use crate::config::Rule;
use crate::dns::Resolver;
use crate::errors::*;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq)]
pub struct Destination<'a> {
    pub host: url::Host,
    pub path: Option<Cow<'a, str>>,
}

impl<'a> Destination<'a> {
    /// Parse the URL tail into a `Destination` struct
    ///
    /// This can't be FromStr because we want a borrowed lifetime
    pub fn parse(path: &'a str) -> Option<Self> {
        let (host, tail) = path
            .split_once('/')
            .map(|(host, tail)| (host, Some(tail)))
            .unwrap_or_else(|| (path, None));

        if host.ends_with('.') {
            return None;
        }

        if host.chars().any(|c| c.is_uppercase()) {
            return None;
        }

        let host = url::Host::parse(host).ok()?;

        Some(Self {
            host,
            path: tail.map(Cow::Borrowed),
        })
    }

    fn host(&self) -> Option<&str> {
        if let url::Host::Domain(host) = &self.host {
            Some(host)
        } else {
            None
        }
    }

    /// Convert the destination into an ohttp-gateway URL
    pub fn to_url(&self) -> String {
        let mut url = format!("https://{}/", self.host);

        if let Some(tail) = &self.path {
            url.push_str(tail);
        } else {
            url.push_str(".well-known/ohttp-gateway");
        }

        url
    }

    /// Check if the destination matches a given rule's host filter
    pub fn matches_rule_selector(&self, rule: &Rule) -> bool {
        let Some(host) = self.host() else {
            return false;
        };
        rule.contains_host(host) || rule.contains_host("*")
    }

    /// Check if the destination is allowed by evaluating all rules
    pub async fn authorize(
        &self,
        resolver: &Resolver,
        rules: &'a [Rule],
    ) -> Result<Option<Cow<'_, Self>>> {
        let mut dns_ohttp_discovery_available = None;

        // Ensure the destination is a domain, not an IP address
        let Some(host) = self.host() else {
            return Ok(None);
        };

        for (i, rule) in rules.iter().enumerate() {
            // Check if the rule's `host=` selector applies
            if !self.matches_rule_selector(rule) {
                continue;
            }

            // If the rule requires DNS-based OHTTP discovery, check DNS if not done yet
            if rule.require_dns_ohttp_discovery {
                trace!("Rule requires DNS-based OHTTP discovery for host {host:?}");

                let discovered = if let Some(result) = dns_ohttp_discovery_available {
                    result
                } else {
                    let result = resolver.probe_ohttp(host).await?.unwrap_or(false);
                    dns_ohttp_discovery_available = Some(result);
                    result
                };

                if discovered {
                    debug!("Successfully detected DNS-based OHTTP discovery for host {host:?}");
                } else {
                    continue;
                }
            }

            let dest = if self.path.is_none() {
                // If the destination has not specified a path
                if let Some(path) = &rule.path {
                    // The rule specifies a path, use it, but strip the leading slash if present
                    let path = path.trim_prefix("/");
                    Cow::Owned(Self {
                        host: self.host.clone(),
                        path: Some(Cow::Borrowed(path)),
                    })
                } else {
                    // Leave the path as `None`, implies default path
                    Cow::Borrowed(self)
                }
            } else if rule.arbitrary_paths {
                // If a custom path is set and the rule allows arbitrary paths, permit it
                Cow::Borrowed(self)
            } else {
                continue;
            };

            trace!("Request has matched rule #{i}");

            if !rule.deny {
                // Return the resolved, permitted destination
                return Ok(Some(dest));
            } else {
                // Indicate the request has no permitted destination
                debug!("Request for host {host:?} denied by rule #{i}");
                return Ok(None);
            }
        }

        debug!("Refusing request for host {host:?}, no rule matched");
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_path_to_url() {
        let dest = Destination::parse("example.com");
        assert_eq!(
            dest,
            Some(Destination {
                host: url::Host::parse("example.com").unwrap(),
                path: None,
            })
        );
        assert_eq!(
            dest.unwrap().to_url(),
            "https://example.com/.well-known/ohttp-gateway"
        );

        let dest = Destination::parse("example.com/some/path");
        assert_eq!(
            dest,
            Some(Destination {
                host: url::Host::parse("example.com").unwrap(),
                path: Some(Cow::Borrowed("some/path")),
            })
        );
        assert_eq!(dest.unwrap().to_url(), "https://example.com/some/path");

        let dest = Destination::parse("example.com/");
        assert_eq!(
            dest,
            Some(Destination {
                host: url::Host::parse("example.com").unwrap(),
                path: Some(Cow::Borrowed("")),
            })
        );
        assert_eq!(dest.unwrap().to_url(), "https://example.com/");

        let dest = Destination::parse("");
        assert_eq!(dest, None);
    }

    #[test]
    fn test_map_path_to_url_invalid_host() {
        for host in [
            "invalid.host.\\q.example.com",
            "",
            " ",
            "https://example.com",
            "foo:bar@example.com",
            "example.com:8080",
            "example.com.",
            "EXAMPLE.COM",
        ] {
            let dest = Destination::parse(host);
            assert!(dest.is_none(), "Host: {}", host);
        }
    }

    #[test]
    fn test_map_path_to_url_valid_host() {
        for host in [
            "example.com",
            // Useful test case, but don't rely on this being valid in the future
            "😺.com",
        ] {
            let dest = Destination::parse(host);
            assert!(dest.is_some(), "Host: {}", host);
        }
    }

    #[tokio::test]
    async fn test_authorize() {
        // empty rules
        let resolver = Resolver::new().await;
        let dest = Destination::parse("example.com").unwrap();
        let rules = &[];
        let resolved = dest.authorize(&resolver, rules).await.unwrap();
        assert_eq!(resolved.as_deref(), None);

        // "allow any" rule
        let rules = &[Rule {
            hosts: ["*".into()].into_iter().collect(),
            ..Default::default()
        }];
        let resolved = dest.authorize(&resolver, rules).await.unwrap();
        assert_eq!(
            resolved.as_deref(),
            Some(&Destination {
                host: url::Host::parse("example.com").unwrap(),
                path: None,
            })
        );
        assert_eq!(
            resolved.map(|d| d.to_url()).as_deref(),
            Some("https://example.com/.well-known/ohttp-gateway"),
        );

        // rule with specified path
        let resolver = Resolver::new().await;
        let dest = Destination::parse("example.com").unwrap();
        let rules = &[Rule {
            hosts: ["*".into()].into_iter().collect(),
            path: Some("/.not-well-known/ohttp-gateway".into()),
            ..Default::default()
        }];
        let resolved = dest.authorize(&resolver, rules).await.unwrap();
        assert_eq!(
            resolved.as_deref(),
            Some(&Destination {
                host: url::Host::parse("example.com").unwrap(),
                path: Some(Cow::Borrowed(".not-well-known/ohttp-gateway")),
            })
        );
        assert_eq!(
            resolved.map(|d| d.to_url()).as_deref(),
            Some("https://example.com/.not-well-known/ohttp-gateway"),
        );
    }
}
