use crate::args::Plumbing;
use crate::dns;
use crate::errors::*;

pub async fn run(args: &Plumbing) -> Result<()> {
    match args {
        Plumbing::CheckDns(dns) => {
            let resolver = dns::Resolver::new().await;

            for name in &dns.names {
                match resolver.query(name).await? {
                    Some(true) => info!("Found HTTPS DNS records WITH ohttp discovery: {name:?}"),
                    Some(false) => {
                        info!("Found HTTPS DNS records WITHOUT ohttp discovery: {name:?}")
                    }
                    None => info!("Missing HTTPS DNS records: {name:?}"),
                }
            }
        }
    }

    Ok(())
}
