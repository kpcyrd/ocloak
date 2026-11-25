/// Source code heavily borrows from https://github.com/seanmonstar/warp internals
use crate::config::Shared;
use crate::errors::*;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::{
    io::{self, AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use warp::{Filter, reply::Reply};

/*
use hyper::http;
use std::task::{Context, Poll};
use tower_service::Service;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RemoteAddr(pub(crate) SocketAddr);

#[derive(Clone, Debug)]
pub(super) struct RemoteAddrService<S> {
    inner: S,
    remote_addr: SocketAddr,
}

impl<S> RemoteAddrService<S> {
    pub(super) fn new(inner: S, remote_addr: SocketAddr) -> Self {
        Self { inner, remote_addr }
    }
}

impl<S, B> Service<http::Request<B>> for RemoteAddrService<S>
where
    S: Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        req.extensions_mut().insert(RemoteAddr(self.remote_addr));
        self.inner.call(req)
    }
}
*/

#[allow(clippy::large_enum_variant)]
enum Stream {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(tcp) => Pin::new(tcp).poll_read(cx, buf),
            Stream::Tls(tls) => Pin::new(tls).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Tcp(tcp) => Pin::new(tcp).poll_write(cx, buf),
            Stream::Tls(tls) => Pin::new(tls).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(tcp) => Pin::new(tcp).poll_flush(cx),
            Stream::Tls(tls) => Pin::new(tls).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(tcp) => Pin::new(tcp).poll_shutdown(cx),
            Stream::Tls(tls) => Pin::new(tls).poll_shutdown(cx),
        }
    }
}

pub async fn serve<F, R>(routes: F, addr: SocketAddr, shared: Arc<Shared>) -> Result<()>
where
    F: Filter<Extract = (R,), Error = std::convert::Infallible> + Clone + Send + Sync + 'static,
    R: Reply,
{
    let listener = TcpListener::bind(addr).await?;

    let service = warp::service(routes);

    loop {
        let Ok((tcp, _remote_addr)) = listener.accept().await else {
            warn!("Failed to accept TCP connection");
            sleep(Duration::from_millis(100)).await;
            continue;
        };
        let service = service.clone();
        let shared = shared.clone();

        tokio::spawn(async move {
            let stream = if let Some(tls) = shared.tls().as_ref() {
                let acceptor = TlsAcceptor::from(tls.clone());

                let config = shared.config();
                match timeout(
                    config.defaults.tls_handshake_timeout.value,
                    acceptor.accept(tcp),
                )
                .await
                {
                    Ok(Ok(tls)) => Stream::Tls(tls),
                    Ok(Err(err)) => {
                        debug!("TLS connection error: {err}");
                        return;
                    }
                    Err(_err) => {
                        debug!("TLS handshake with client timed out");
                        return;
                    }
                }
            } else {
                Stream::Tcp(tcp)
            };

            // Explicitly call `.http1_only()` to avoid a code branch that ignores timeouts
            // https://github.com/hyperium/hyper/issues/3962
            // https://chaos.social/@kpcyrd/117627839810424285
            let mut builder =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .http1_only();

            builder
                .http1()
                .auto_date_header(false)
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(15));

            // let service = RemoteAddrService::new(service, remote_addr);
            let service = TowerToHyperService::new(service);

            let connection = builder.serve_connection(TokioIo::new(stream), service);

            if let Err(err) = connection.await {
                debug!("HTTP connection error: {err}");
            }
        });
    }
}
