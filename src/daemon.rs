use crate::config::{Config, Shared};
use crate::dns::Resolver;
use crate::errors::*;
use crate::http;
use crate::rules::Destination;
use crate::server;
use crate::signals;
use futures_util::{Stream, StreamExt};
use hyper::body::Buf;
use hyper::header::{CONTENT_TYPE, HeaderValue};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::{Duration, Instant, timeout_at};
use tokio_util::io::ReaderStream;
use warp::{
    Filter,
    filters::path::Tail,
    http::StatusCode,
    reject::{self, MethodNotAllowed, Rejection},
    reply::Reply,
};

pub struct Daemon {
    pub bind_addr: SocketAddr,
    pub config: Config,
    pub config_path: PathBuf,
}

fn server_error() -> impl warp::Reply {
    warp::reply::with_status("500 - Server Error\n", StatusCode::INTERNAL_SERVER_ERROR)
}

fn bad_gateway() -> impl warp::Reply {
    warp::reply::with_status("502 - Bad Gateway\n", StatusCode::BAD_GATEWAY)
}

async fn read_body_stream(
    mut stream: impl Stream<Item = Result<impl Buf, warp::Error>> + Unpin + Send + Sync,
    read_timeout: Duration,
    size_limit: usize,
) -> Result<Vec<u8>> {
    let deadline = Instant::now() + read_timeout;
    let mut buf = Vec::new();
    while let Some(chunk) = timeout_at(deadline, stream.next()).await?.transpose()? {
        let chunk = chunk.chunk();

        if buf.len().saturating_add(chunk.len()) > size_limit {
            return Err(anyhow!("Body size exceeds limit"));
        }

        buf.extend_from_slice(chunk);
    }
    Ok(buf)
}

async fn ohttp_post(
    http: reqwest::Client,
    resolver: Arc<Resolver>,
    shared: Arc<Shared>,
    path: Tail,
    content_type: Option<String>,
    body: impl Stream<Item = Result<impl Buf, warp::Error>> + Unpin + Send + Sync,
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
    let config = shared.config();
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
            return Ok(bad_gateway().into_response());
        }
    };

    // Read request body
    let Ok(body) = read_body_stream(
        body,
        config.defaults.read_timeout.value,
        config
            .defaults
            .max_request_size
            .value
            .try_into()
            .unwrap_or(usize::MAX),
    )
    .await
    else {
        return Ok(warp::reply::with_status(
            "408 - Request Timeout\n",
            StatusCode::REQUEST_TIMEOUT,
        )
        .into_response());
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
        return Ok(bad_gateway().into_response());
    };
    let status = resp.status();

    if !(status.is_success() || status.is_client_error() || status.is_server_error()) {
        return Ok(bad_gateway().into_response());
    }

    let mut response = warp::reply::stream(resp.bytes_stream()).into_response();
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("message/ohttp-res"));
    Ok(response)
}

async fn index(shared: Arc<Shared>) -> Result<impl warp::Reply, Rejection> {
    let config = shared.config();
    let Some(path) = &config.index.file_path else {
        return Err(reject::not_found());
    };

    let Ok(file) = fs::File::open(path)
        .await
        .with_context(|| format!("Failed to open index file: {path:?}"))
        .inspect_err(|err| error!("Error: {err:#}"))
    else {
        return Ok(server_error().into_response());
    };

    let mut file = BufReader::new(file);
    let Ok(peek) = file
        .fill_buf()
        .await
        .with_context(|| format!("Failed to read from index file: {path:?}"))
        .inspect_err(|err| error!("Error: {err:#}"))
    else {
        return Ok(server_error().into_response());
    };

    let content_type = if let Some(content_type) = config.index.content_type.clone() {
        content_type
    } else if peek.starts_with(b"<") {
        HeaderValue::from_static("text/html; charset=utf-8")
    } else {
        HeaderValue::from_static("text/plain; charset=utf-8")
    };

    let stream = ReaderStream::new(file);
    let mut response = warp::reply::stream(stream).into_response();
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, content_type);
    headers.extend(config.index.http_headers.iter().cloned());
    Ok(response)
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

pub async fn run(daemon: Daemon) -> Result<()> {
    let config = daemon.config;

    let http = http::client(&config.defaults)?;
    let http = warp::any().map(move || http.clone());

    let resolver = Arc::new(Resolver::new().await);
    let resolver = warp::any().map(move || resolver.clone());

    let shared = Arc::new(Shared::new(config, daemon.config_path));
    shared.reload_certs().await?;

    let sigterm = signals::sigterm();
    let sighup = signals::sighup(shared.clone());

    let shared_filter = {
        let shared = shared.clone();
        warp::any().map(move || shared.clone())
    };

    let ohttp = warp::post()
        .and(http)
        .and(resolver)
        .and(shared_filter.clone())
        .and(warp::path("ohttp"))
        .and(warp::path::tail())
        .and(warp::header::optional::<String>("content-type"))
        .and(warp::body::stream())
        .and_then(ohttp_post);
    let index = warp::get()
        .and(shared_filter)
        .and(warp::path::end())
        .and_then(index);

    let log = warp::log("httpd");

    let routes = ohttp.or(index).recover(rejection);
    info!("Starting HTTP server on {}", daemon.bind_addr);

    tokio::select!(
        res = server::serve(routes.with(log), daemon.bind_addr, shared) => res,
        _ = sigterm => Ok(()),
        _ = sighup => Ok(()),
    )
}
