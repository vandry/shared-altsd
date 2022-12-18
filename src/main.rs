pub mod grpc {
    pub mod gcp {
        tonic::include_proto!("grpc.gcp");
    }
}

pub mod shared_alts_pb {
    tonic::include_proto!("shared_alts");
}

mod config;
mod exchange;
mod server;
mod setup;
#[cfg(test)]
mod test;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    setup::main().await
}
