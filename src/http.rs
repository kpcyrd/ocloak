use crate::config::Defaults;
use crate::errors::*;
use reqwest::redirect;

pub fn client(defaults: &Defaults) -> Result<reqwest::Client> {
    let max_redirects = defaults.max_redirects;

    let http = reqwest::Client::builder()
        .connect_timeout(defaults.connect_timeout.value)
        .read_timeout(defaults.read_timeout.value)
        .user_agent(&defaults.user_agent)
        .redirect(redirect::Policy::custom(move |attempt| {
            let url = attempt.url();
            debug!("Redirect attempted to: {:?}", url.as_str());

            if attempt.previous().len() > max_redirects {
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
