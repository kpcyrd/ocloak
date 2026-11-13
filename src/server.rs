/// Source code heavily borrows from https://github.com/seanmonstar/warp internals
use crate::errors::*;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
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

pub async fn serve<F, R>(routes: F, addr: SocketAddr) -> Result<()>
where
    F: Filter<Extract = (R,), Error = !> + Clone + Send + Sync + 'static,
    R: Reply,
{
    let listener = TcpListener::bind(addr).await?;

    let service = warp::service(routes);

    loop {
        let (tcp, _remote_addr) = listener.accept().await?;
        let service = service.clone();

        tokio::spawn(async move {
            let mut builder =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());

            builder
                .http1()
                .auto_date_header(false)
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(15));

            // let service = RemoteAddrService::new(service, remote_addr);
            let service = TowerToHyperService::new(service);

            let connection = builder.serve_connection(TokioIo::new(tcp), service);

            if let Err(err) = connection.await {
                debug!("HTTP connection error: {err}");
            }
        });
    }
}
