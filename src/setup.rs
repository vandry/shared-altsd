use log;
use std::env;
use std::io::ErrorKind;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

use crate::config::Config;
use crate::server::Handshaker;

use crate::grpc::gcp::handshaker_service_server::HandshakerServiceServer;

pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let socket_path = &args[1];
    let config = Config::new_from_file(std::path::Path::new(&args[2]))?;

    // TODO(vandry): This does not seem to do much.
    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber)?;

    env_logger::init();
    let handshaker = Handshaker::new(config);

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => Ok(l),
        Err(listen_err) if listen_err.kind() == ErrorKind::AddrInUse => {
            // Check if this is a stale socket.
            match tokio::net::UnixStream::connect(socket_path).await {
                Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                    log::warn!("Cleaning up stale socket {}", socket_path);
                    std::fs::remove_file(socket_path)?;
                    // Try again.
                    UnixListener::bind(socket_path)
                }
                _ => Err(listen_err)
            }
        }
        Err(e) => Err(e)
    }?;
    log::info!("Listening on {}", socket_path);
    let listener_stream = UnixListenerStream::new(listener);

    Server::builder()
        .add_service(HandshakerServiceServer::new(handshaker))
        .serve_with_incoming(listener_stream)
        .await?;

    Ok(())
}
