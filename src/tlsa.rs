use sha2::{Digest, Sha256, Sha512};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tonic::Status;
use trust_dns_proto::rr::rdata::tlsa::{CertUsage, Matching, Selector, TLSA};

pub type TLSAFuture = Pin<Box<dyn Future<Output = Result<Vec<TLSA>, Status>> + Send>>;

pub trait TLSAProvider: Send + Sync + 'static {
    fn background_tlsa_lookup(self: Arc<Self>, name: String) -> TLSAFuture;
}

pub fn tlsa_name(common_name: &str) -> String {
    format!("_shared-alts.{}{}", common_name, if common_name.ends_with(".") { "" } else { "." })
}

pub fn check_tlsa(records: &Vec<TLSA>, cert: &[u8], public_key: &[u8]) -> Result<(), Status> {
    for record in records {
        if record.cert_usage() != CertUsage::DomainIssued {
            continue;  // We only support pure TLSA, not combined with CA validation.
        }
        let hash_input = match record.selector() {
            Selector::Full => cert,
            Selector::Spki => public_key,
            _ => {
                continue;
            }
        };
        if match record.matching() {
            Matching::Raw => hash_input == record.cert_data(),
            Matching::Sha256 => {
                let mut h = Sha256::new();
                h.update(hash_input);
                *h.finalize().as_slice() == *record.cert_data()
            }
            Matching::Sha512 => {
                let mut h = Sha512::new();
                h.update(hash_input);
                *h.finalize().as_slice() == *record.cert_data()
            }
            _ => false,
        } {
            return Ok(());
        }
    }
    Err(Status::unauthenticated(format!("None of the {} available TLSA records matched", records.len())))
}
