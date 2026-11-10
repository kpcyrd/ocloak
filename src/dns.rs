use crate::errors::*;
use domain::base::{Name, Question, Rtype};
use domain::rdata::Soa;
use domain::rdata::svcb::Https;
use domain::rdata::svcb::value::AllValues;
use domain::resolv::stub::StubResolver;
use domain::resolv::stub::conf::{ResolvConf, SearchSuffix};
use tokio::time::{Duration, Instant};

const MAX_CACHE_ENTRIES: u64 = 64_000;
const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(900);

#[derive(Debug, Clone)]
struct CacheEntry {
    value: Option<bool>,
    // TODO: moka has a better mechanism for expiry
    expires_at: Instant,
}

impl CacheEntry {
    pub fn new(value: Option<bool>, ttl: Duration) -> Self {
        Self {
            value,
            expires_at: Instant::now() + ttl,
        }
    }

    pub fn expired(&self) -> bool {
        self.expires_at <= Instant::now()
    }
}

pub struct Resolver {
    resolver: StubResolver,
    cache: moka::future::Cache<String, CacheEntry>,
}

impl Resolver {
    pub async fn new() -> Self {
        // Use system resolvers but never use default domain names or search domains
        // This briefly calls into blocking code and should only be done during startup
        let mut conf = ResolvConf::default();
        conf.options.default_names = false;
        conf.options.search = SearchSuffix::root().into();

        let resolver = StubResolver::from_conf(conf);
        let cache = moka::future::Cache::new(MAX_CACHE_ENTRIES);
        Self { resolver, cache }
    }

    pub async fn query_cache_only(&self, name: &str) -> Option<Option<bool>> {
        self.cache
            .get(name)
            .await
            .filter(|e| !e.expired())
            .map(|e| e.value)
    }

    pub async fn query(&self, name: &str) -> Result<Option<bool>> {
        if let Some(entry) = self.query_cache_only(name).await {
            return Ok(entry);
        }

        let qname: Name<Vec<u8>> = name.parse()?;
        let question = Question::new_in(&qname, Rtype::HTTPS);

        let answer = self
            .resolver
            .query(question)
            .await
            .with_context(|| anyhow!("Failed to send DNS request for {name:?}"))?;
        let answer = answer.answer()?;

        let mut found_ohttp = None;
        let mut found_ttl = None;

        'outer: for record in answer.limit_to::<Https<_, _>>().flatten() {
            let text = record.data().to_string();
            debug!("Found HTTPS record: {name:?} => {text:?}");

            let ttl = Duration::from(record.ttl());

            // We found an HTTPS record, unless we explicitly find an ohttp param we return false
            found_ohttp = Some(false);
            found_ttl = Some(ttl);

            let https = record.data();
            for param in https.params().iter::<AllValues<_>>() {
                let Ok(param) = param else {
                    continue;
                };
                trace!("HTTPS record param: {name:?} => {param:?}");

                if matches!(param, AllValues::Ohttp(_)) {
                    debug!("Found ohttp discovery param in HTTPS record: {name:?}");
                    found_ohttp = Some(true);
                    found_ttl = Some(ttl);
                    break 'outer;
                }
            }
        }

        // Use TTL of record we used, or fallback to SOA record minimum TTL
        let ttl = if let Some(ttl) = found_ttl {
            ttl
        } else {
            // Get authority section and it's SOA record
            answer
                .next_section()?
                .into_iter()
                .flat_map(|authority| authority.limit_to::<Soa<_>>())
                .flatten()
                .map(|record| {
                    let soa = record.data();
                    trace!("SOA record: {:?}", soa);

                    // RFC 2308: min(SOA RR TTL, SOA MINIMUM).
                    let ttl = record.ttl().min(soa.minimum());

                    Duration::from(ttl)
                })
                .min()
                .unwrap_or(DEFAULT_NEGATIVE_TTL)
        };

        // Add to DNS cache, to avoid flooding nameservers
        self.cache
            .insert(name.to_string(), CacheEntry::new(found_ohttp, ttl))
            .await;

        Ok(found_ohttp)
    }
}
