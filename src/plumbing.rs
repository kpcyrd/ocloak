use crate::args::Plumbing;
use crate::dns;
use crate::errors::*;
use domain::base::Rtype;
use domain::rdata::Https;

pub async fn run(args: &Plumbing) -> Result<()> {
    match args {
        Plumbing::CheckDns(dns) => {
            let resolver = dns::Resolver::new().await;

            for name in &dns.names {
                match resolver.probe_ohttp(name).await? {
                    Some(true) => info!("Found HTTPS DNS records WITH ohttp discovery: {name:?}"),
                    Some(false) => {
                        info!("Found HTTPS DNS records WITHOUT ohttp discovery: {name:?}")
                    }
                    None => info!("Missing HTTPS DNS records: {name:?}"),
                }
            }
        }
        Plumbing::QueryHttpsRr(query) => {
            let resolver = dns::Resolver::new().await;
            for name in &query.names {
                let answer = resolver.query(name, Rtype::HTTPS).await?;
                let answer = answer.answer()?;

                for record in answer.limit_to::<Https<_, _>>().flatten() {
                    let text = record.data().to_string();
                    debug!("Found HTTPS record: {name:?} => {text:?}");

                    let value = record.data().params();
                    println!("{value}");
                }
            }
        }
    }

    Ok(())
}
