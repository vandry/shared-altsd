use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tonic::Status;
use trust_dns_proto::rr::rdata::tlsa::TLSA;

pub type TLSAFuture = Pin<Box<dyn Future<Output = Result<Vec<TLSA>, Status>> + Send>>;

pub trait TLSAProvider: Send + Sync + 'static {
    fn background_tlsa_lookup(self: Arc<Self>, name: String) -> TLSAFuture;
}

pub fn tlsa_name(common_name: &str) -> String {
    format!("_shared-alts.{}{}", common_name, if common_name.ends_with(".") { "" } else { "." })
}

pub fn check_tlsa(records: Vec<TLSA>) -> Result<(), Status> {
    println!("TODO check TLSA: {:?}", records);
    Ok(())
}
