use crate::config::Config;
use crate::dns::Resolver;
use crate::errors::*;
use crate::http;
use crate::rules::Destination;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use warp::{
    Filter, filters::path::Tail, http::StatusCode, hyper::body::Bytes, reject::MethodNotAllowed,
    reply::Reply,
};

pub struct Daemon {
    pub bind_addr: SocketAddr,
    pub config: PathBuf,
}

async fn ohttp_post(
    http: reqwest::Client,
    resolver: Arc<Resolver>,
    config: Arc<Config>,
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

    let Some(dest) = Destination::parse(path.as_str()) else {
        return Ok(
            warp::reply::with_status("400 - Host is required\n", StatusCode::BAD_REQUEST)
                .into_response(),
        );
    };

    // Validate the destination against the rule set
    let dest = match dest.authorize(&resolver, &config.allowed).await {
        Ok(Some(dest)) => dest,
        Ok(None) => {
            return Ok(warp::reply::with_status(
                "403 - Destination not permitted\n",
                StatusCode::FORBIDDEN,
            )
            .into_response());
        }
        Err(err) => {
            error!("Error: {err:#}");
            return Ok(
                warp::reply::with_status("502 - Bad Gateway\n", StatusCode::BAD_GATEWAY)
                    .into_response(),
            );
        }
    };

    // Prepare the request
    let url = dest.to_url();
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
    let config = Arc::new(Config::load(&daemon.config).await?);

    let http = http::client(&config.defaults)?;
    let http = warp::any().map(move || http.clone());

    let resolver = Arc::new(Resolver::new().await);
    let resolver = warp::any().map(move || resolver.clone());

    let content_length_limit =
        warp::body::content_length_limit(config.defaults.max_request_size.value);
    let config_filter = warp::any().map(move || config.clone());

    let ohttp = warp::post()
        .and(http)
        .and(resolver)
        .and(config_filter)
        .and(warp::path("ohttp"))
        .and(warp::path::tail())
        .and(warp::header::optional::<String>("content-type"))
        .and(content_length_limit)
        .and(warp::body::bytes())
        .and_then(ohttp_post);

    let log = warp::log("httpd");

    let routes = ohttp.recover(rejection);
    info!("Starting HTTP server on {}", daemon.bind_addr);
    warp::serve(routes.with(log)).run(daemon.bind_addr).await;

    Ok(())
}
