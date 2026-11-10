use crate::errors::*;
use crate::http;
use std::convert::Infallible;
use std::net::SocketAddr;
use warp::{
    Filter, filters::path::Tail, http::StatusCode, hyper::body::Bytes, reject::MethodNotAllowed,
    reply::Reply,
};

const MAX_REQUEST_SIZE: u64 = 1024 * 1024 * 8;

pub struct Daemon {
    pub bind_addr: SocketAddr,
}

fn map_path_to_url(path: &str) -> Option<String> {
    let (host, tail) = path
        .split_once('/')
        .map(|(host, tail)| (host, Some(tail)))
        .unwrap_or_else(|| (path, None));

    if host.is_empty() {
        return None;
    }

    let mut url = format!("https://{host}/");

    if let Some(tail) = tail {
        url.push_str(tail);
    } else {
        url.push_str(".well-known/ohttp-gateway");
    }

    Some(url)
}

async fn ohttp_post(
    http: reqwest::Client,
    path: Tail,
    content_type: Option<String>,
    body: Bytes,
) -> Result<impl warp::Reply, Infallible> {
    if content_type.as_deref() != Some("message/ohttp-req") {
        return Ok(warp::reply::with_status(
            "400 - Content-Type must be message/ohttp-req\n",
            StatusCode::BAD_REQUEST,
        )
        .into_response());
    }

    let Some(url) = map_path_to_url(path.as_str()) else {
        return Ok(
            warp::reply::with_status("400 - Host is required\n", StatusCode::BAD_REQUEST)
                .into_response(),
        );
    };

    // TODO: validate the host against the rule set. e.g. ports can only be used if the host is explicitly allowed

    debug!("Forwarding ohttp request: {url:?} ({} bytes)", body.len());
    trace!("Forwarding ohttp request body: {body:?}");

    let gateway_response = http
        .post(url)
        .header("Content-Type", "message/ohttp-req")
        // .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .body(body)
        .send()
        .await;

    let Ok(resp) = gateway_response.inspect_err(|err| error!("Error: {err:#}")) else {
        return Ok(
            warp::reply::with_status("502 - Bad Gateway\n", StatusCode::BAD_GATEWAY)
                .into_response(),
        );
    };

    let Ok(bytes) = resp
        .bytes()
        .await
        .inspect_err(|err| error!("Error: {err:#}"))
    else {
        return Ok(
            warp::reply::with_status("502 - Bad Gateway\n", StatusCode::BAD_GATEWAY)
                .into_response(),
        );
    };

    let bytes = bytes.as_ref().to_vec();
    Ok(warp::reply::with_status(bytes, StatusCode::OK).into_response())
}

async fn rejection(err: warp::Rejection) -> Result<impl warp::Reply, Infallible> {
    let (code, message) = if err.is_not_found() {
        (StatusCode::NOT_FOUND, "POST /ohttp/{host}\n")
    } else if let Some(_err) = err.find::<MethodNotAllowed>() {
        (StatusCode::NOT_FOUND, "POST /ohttp/{host}\n")
    } else {
        error!("Unhandled rejection: {:?}", err);
        (StatusCode::INTERNAL_SERVER_ERROR, "500 - server error\n")
    };

    Ok(warp::reply::with_status(message, code))
}

pub async fn run(daemon: &Daemon) -> Result<()> {
    let http = http::client()?;
    let http = warp::any().map(move || http.clone());

    let ohttp = warp::post()
        .and(http)
        .and(warp::path("ohttp"))
        .and(warp::path::tail())
        .and(warp::header::optional::<String>("content-type"))
        .and(warp::body::content_length_limit(MAX_REQUEST_SIZE))
        .and(warp::body::bytes())
        .and_then(ohttp_post);

    let log = warp::log("httpd");

    let routes = ohttp.recover(rejection);
    info!("Starting HTTP server on {}", daemon.bind_addr);
    warp::serve(routes.with(log)).run(daemon.bind_addr).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_path_to_url() {
        assert_eq!(
            map_path_to_url("example.com").as_deref(),
            Some("https://example.com/.well-known/ohttp-gateway")
        );
        assert_eq!(
            map_path_to_url("example.com/some/path").as_deref(),
            Some("https://example.com/some/path")
        );
        assert_eq!(
            map_path_to_url("example.com/").as_deref(),
            Some("https://example.com/")
        );
        assert_eq!(map_path_to_url("").as_deref(), None);
    }
}
