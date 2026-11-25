use crate::config::Rule;
use crate::dns::Resolver;
use crate::errors::*;
use std::borrow::Cow;

pub fn normalize_host(raw: &str) -> Option<String> {
    // WHATWG considers `*` and `*.com` valid url hostnames, but we don't
    if memchr::memchr(b'*', raw.as_bytes()).is_some() {
        return None;
    }

    let host = url::Host::parse(raw).ok()?;
    if let url::Host::Domain(domain) = host
        && !domain.ends_with('.')
    {
        Some(domain)
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Destination<'a> {
    pub host: String,
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

        let host = normalize_host(host)?;

        Some(Self {
            host,
            path: tail.map(Cow::Borrowed),
        })
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
        rule.contains_host(&self.host) || rule.contains_host("*")
    }

    /// Check if the destination is allowed by evaluating all rules
    pub async fn authorize(
        &self,
        resolver: &Resolver,
        rules: &'a [Rule],
    ) -> Result<Option<Cow<'_, Self>>> {
        let mut dns_ohttp_discovery_available = None;

        for (i, rule) in rules.iter().enumerate() {
            // Check if the rule's `host=` selector applies
            if !self.matches_rule_selector(rule) {
                continue;
            }

            // If the rule requires DNS-based OHTTP discovery, check DNS if not done yet
            if rule.require_dns_ohttp_discovery {
                trace!(
                    "Rule requires DNS-based OHTTP discovery for host {:?}",
                    self.host
                );

                let discovered = if let Some(result) = dns_ohttp_discovery_available {
                    result
                } else {
                    let result = resolver.probe_ohttp(&self.host).await?.unwrap_or(false);
                    dns_ohttp_discovery_available = Some(result);
                    result
                };

                if discovered {
                    debug!(
                        "Successfully detected DNS-based OHTTP discovery for host {:?}",
                        self.host
                    );
                } else {
                    continue;
                }
            }

            let dest = if self.path.is_none() {
                if rule.deny {
                    None
                } else
                // If the destination has not specified a path
                if let Some(path) = &rule.path {
                    // The rule specifies a path, use it, but strip the leading slash if present
                    let path = path.strip_prefix("/").unwrap_or(path);
                    Some(Cow::Owned(Self {
                        host: self.host.clone(),
                        path: Some(Cow::Borrowed(path)),
                    }))
                } else {
                    // Leave the path as `None`, implies default path
                    Some(Cow::Borrowed(self))
                }
            } else if !rule.deny && rule.arbitrary_paths == Some(true) {
                // If a custom path is set and the rule allows arbitrary paths, permit it
                Some(Cow::Borrowed(self))
            } else if rule.deny && rule.arbitrary_paths != Some(false) {
                // If a custom path is set and the rule is a deny rule, proceed
                // with this rule unless arbitrary_paths is explicitly set to false
                None
            } else {
                continue;
            };

            trace!("Request has matched rule #{i}");

            if let Some(dest) = dest {
                // Return the resolved, permitted destination
                return Ok(Some(dest));
            } else {
                // Indicate the request has no permitted destination
                debug!("Request for host {:?} denied by rule #{i}", self.host);
                return Ok(None);
            }
        }

        debug!("Refusing request for host {:?}, no rule matched", self.host);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_hosts() {
        for (input, expected) in &[
            ("example.com", Some("example.com")),
            ("example.com.", None),
            ("EXAMPLE.COM", Some("example.com")),
            ("example.com:8080", None),
            ("example.com%2E", None),
            ("example.com\u{3002}", None),
            ("example.com\x00", None),
            ("example%2ecom", Some("example.com")),
            ("exa\u{AD}mple.com", Some("example.com")),
            ("bücher.tld", Some("xn--bcher-kva.tld")),
            ("😺.com", Some("xn--138h.com")),
            ("xn--138h.com", Some("xn--138h.com")),
            ("invalid.host.\\q.example.com", None),
            ("example.com/foo", None),
            ("", None),
            (" ", None),
            (".", None),
            ("https://example.com", None),
            ("foo@example.com", None),
            ("foo:bar@example.com", None),
            ("*", None),
            ("*.example.com", None),
            ("127.0.0.1", None),
            ("127.0.0.1:8080", None),
            ("::1", None),
            ("[::1]", None),
            ("[::1]:8080", None),
            ("%example.com", None),
        ] {
            assert_eq!(normalize_host(input).as_deref(), *expected);
        }
    }

    #[test]
    fn test_map_path_to_url() {
        let dest = Destination::parse("example.com");
        assert_eq!(
            dest,
            Some(Destination {
                host: "example.com".into(),
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
                host: "example.com".into(),
                path: Some(Cow::Borrowed("some/path")),
            })
        );
        assert_eq!(dest.unwrap().to_url(), "https://example.com/some/path");

        let dest = Destination::parse("example.com/");
        assert_eq!(
            dest,
            Some(Destination {
                host: "example.com".into(),
                path: Some(Cow::Borrowed("")),
            })
        );
        assert_eq!(dest.unwrap().to_url(), "https://example.com/");

        let dest = Destination::parse("");
        assert_eq!(dest, None);
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
                host: "example.com".into(),
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
                host: "example.com".into(),
                path: Some(Cow::Borrowed(".not-well-known/ohttp-gateway")),
            })
        );
        assert_eq!(
            resolved.map(|d| d.to_url()).as_deref(),
            Some("https://example.com/.not-well-known/ohttp-gateway"),
        );
    }

    #[tokio::test]
    async fn test_deny_and_custom_paths() {
        // Custom paths only match rules if arbitrary_paths=true, but custom paths always
        // match deny rules unless arbitrary_paths=false.

        let resolver = Resolver::new().await;

        // no path, deny arbitrary_paths not set
        let dest = Destination::parse("example.com").unwrap();
        let rules = &[
            Rule {
                hosts: ["*".into()].into_iter().collect(),
                deny: true,
                ..Default::default()
            },
            Rule {
                hosts: ["*".into()].into_iter().collect(),
                arbitrary_paths: Some(true),
                ..Default::default()
            },
        ];
        let resolved = dest.authorize(&resolver, rules).await.unwrap();
        assert_eq!(resolved.as_deref(), None);

        // no path, deny arbitrary_paths=true
        let dest = Destination::parse("example.com").unwrap();
        let rules = &[
            Rule {
                hosts: ["*".into()].into_iter().collect(),
                deny: true,
                arbitrary_paths: Some(true),
                ..Default::default()
            },
            Rule {
                hosts: ["*".into()].into_iter().collect(),
                arbitrary_paths: Some(true),
                ..Default::default()
            },
        ];
        let resolved = dest.authorize(&resolver, rules).await.unwrap();
        assert_eq!(resolved.as_deref(), None);

        // no path, deny arbitrary_paths=false
        let dest = Destination::parse("example.com").unwrap();
        let rules = &[
            Rule {
                hosts: ["*".into()].into_iter().collect(),
                deny: true,
                arbitrary_paths: Some(false),
                ..Default::default()
            },
            Rule {
                hosts: ["*".into()].into_iter().collect(),
                arbitrary_paths: Some(true),
                ..Default::default()
            },
        ];
        let resolved = dest.authorize(&resolver, rules).await.unwrap();
        assert_eq!(resolved.as_deref(), None);

        // path, deny arbitrary_paths not set
        let dest = Destination::parse("example.com/foo").unwrap();
        let rules = &[
            Rule {
                hosts: ["*".into()].into_iter().collect(),
                deny: true,
                ..Default::default()
            },
            Rule {
                hosts: ["*".into()].into_iter().collect(),
                arbitrary_paths: Some(true),
                ..Default::default()
            },
        ];
        let resolved = dest.authorize(&resolver, rules).await.unwrap();
        assert_eq!(resolved.as_deref(), None);

        // path, deny arbitrary_paths=true
        let dest = Destination::parse("example.com/foo").unwrap();
        let rules = &[
            Rule {
                hosts: ["*".into()].into_iter().collect(),
                deny: true,
                arbitrary_paths: Some(true),
                ..Default::default()
            },
            Rule {
                hosts: ["*".into()].into_iter().collect(),
                arbitrary_paths: Some(true),
                ..Default::default()
            },
        ];
        let resolved = dest.authorize(&resolver, rules).await.unwrap();
        assert_eq!(resolved.as_deref(), None);

        // path, deny arbitrary_paths=false
        let dest = Destination::parse("example.com/foo").unwrap();
        let rules = &[
            Rule {
                hosts: ["*".into()].into_iter().collect(),
                deny: true,
                arbitrary_paths: Some(false),
                ..Default::default()
            },
            Rule {
                hosts: ["*".into()].into_iter().collect(),
                arbitrary_paths: Some(true),
                ..Default::default()
            },
        ];
        let resolved = dest.authorize(&resolver, rules).await.unwrap();
        assert_eq!(
            resolved.as_deref(),
            Some(&Destination {
                host: "example.com".into(),
                path: Some(Cow::Borrowed("foo")),
            })
        );
    }
}
