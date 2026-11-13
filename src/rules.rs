use crate::config::Rule;
use crate::dns::Resolver;
use crate::errors::*;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq)]
pub struct Destination<'a> {
    pub host: Cow<'a, str>,
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

        if host.is_empty() {
            return None;
        }

        Some(Self {
            host: Cow::Borrowed(host),
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

    /// Check if the destination has a port specified in the host
    pub fn includes_port(&self) -> bool {
        self.host.contains(':')
    }

    /// Check if the destination matches a given rule's host filter
    pub fn matches_rule_selector(&self, rule: &Rule) -> bool {
        rule.contains_host(&self.host) || (rule.contains_host("*") && !self.includes_port())
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
                let discovered = if let Some(result) = dns_ohttp_discovery_available {
                    result
                } else {
                    let result = resolver.probe_ohttp(&self.host).await?.unwrap_or(false);
                    dns_ohttp_discovery_available = Some(result);
                    result
                };

                if !discovered {
                    continue;
                }
            }

            let dest = if self.path.is_none() {
                // If the destination has not specified a path
                if let Some(path) = &rule.path {
                    // The rule specifies a path, use it
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
                return Ok(None);
            }
        }

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
                host: Cow::Borrowed("example.com"),
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
                host: Cow::Borrowed("example.com"),
                path: Some(Cow::Borrowed("some/path")),
            })
        );
        assert_eq!(dest.unwrap().to_url(), "https://example.com/some/path");

        let dest = Destination::parse("example.com/");
        assert_eq!(
            dest,
            Some(Destination {
                host: Cow::Borrowed("example.com"),
                path: Some(Cow::Borrowed("")),
            })
        );
        assert_eq!(dest.unwrap().to_url(), "https://example.com/");

        let dest = Destination::parse("");
        assert_eq!(dest, None);
    }
}
