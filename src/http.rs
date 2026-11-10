use crate::errors::*;
use reqwest::redirect;
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const USER_AGENT: &str = "ohttp-relay";
const MAX_REDIRECTS: usize = 2;

pub fn client() -> Result<reqwest::Client> {
    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .user_agent(USER_AGENT)
        .redirect(redirect::Policy::custom(|attempt| {
            let url = attempt.url();
            debug!("Redirect attempted to: {:?}", url.as_str());

            if attempt.previous().len() > MAX_REDIRECTS {
                attempt.error("too many redirects")
            } else if Some(url.origin()) != attempt.previous().last().map(|u| u.origin()) {
                attempt.error("can't redirect to different security origin")
            } else {
                attempt.follow()
            }
        }))
        .build()?;
    Ok(http)
}
