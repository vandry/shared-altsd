use futures::TryFutureExt;
use std::env;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Code, Status, transport::Server};
use trust_dns_proto::xfer::retry_dns_handle::RetryableError;
use trust_dns_resolver::{TokioAsyncResolver, error::ResolveErrorKind, system_conf::read_system_conf};

use crate::config::Config;
use crate::server::Handshaker;
use crate::tlsa::{TLSAFuture, TLSAProvider};

use crate::grpc::gcp::handshaker_service_server::HandshakerServiceServer;

impl TLSAProvider for TokioAsyncResolver {
    fn background_tlsa_lookup(self: Arc<Self>, name: String) -> TLSAFuture {
        Box::pin(tokio::spawn(async move {
            let r = self.tlsa_lookup(name)
                .await
                .map_err(|e| {
                    let msg = match e.kind() {
                        ResolveErrorKind::NoRecordsFound { query, response_code, .. } => format!(
                            "DNS query {} returned {}", query, response_code),
                        _ => format!("Error resolving DNS name: {}", e),
                    };
                    if e.should_retry() {
                        Status::unavailable(msg)
                    } else {
                        Status::internal(msg)
                    }
                })?;
            Ok(r.iter().cloned().collect())
        }).map_ok_or_else(
            |e| Err(Status::new(Code::Internal, format!("DNS query task error: {}", e))),
            |f| f
        ))
    }
}

pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args: Vec<_> = env::args_os().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} listen-uds-socket-path certificate_and_key.pem",
                  args[0].to_string_lossy());
        std::process::exit(3);
    }
    let socket_path = Path::new(&args[1]);
    let config_path = Path::new(&args[2]);
    let config = Arc::new(Config::new_from_file(config_path)?);

    let mut sighup = signal(SignalKind::hangup())?;
    let config_for_reloading = config.clone();
    tokio::spawn(async move {
        loop {
            sighup.recv().await;
            if let Err(e) = config_for_reloading.reload() {
                log::error!("Error reloading config: {}", e);
            }
        }
    });

    let (resolver_config, mut resolver_opts) = read_system_conf()?;
    resolver_opts.validate = true;  // DNSSEC is essential
    resolver_opts.ndots = 0;  // All names are FQDNs
    let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts)?;

    // TODO(vandry): This does not seem to do much.
    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber)?;

    let handshaker = Handshaker::new(config, Arc::new(resolver));

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => Ok(l),
        Err(listen_err) if listen_err.kind() == ErrorKind::AddrInUse => {
            // Check if this is a stale socket.
            match tokio::net::UnixStream::connect(socket_path).await {
                Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                    log::warn!("Cleaning up stale socket {}", socket_path.to_string_lossy());
                    std::fs::remove_file(socket_path)?;
                    // Try again.
                    UnixListener::bind(socket_path)
                }
                _ => Err(listen_err)
            }
        }
        Err(e) => Err(e)
    }?;
    log::info!("Listening on {}", socket_path.to_string_lossy());
    let listener_stream = UnixListenerStream::new(listener);

    Server::builder()
        .add_service(HandshakerServiceServer::new(handshaker))
        .serve_with_incoming(listener_stream)
        .await?;

    Ok(())
}
