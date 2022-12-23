use ring::signature;
use ring::signature::KeyPair;
use rustls_pemfile::{Item, read_one};
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::iter;
use std::sync::Arc;
use x509_parser::parse_x509_certificate;

#[derive(Debug)]
pub struct CertAndKey {
    pub cert_bytes: Vec<u8>,
    pub common_name: String,
    pub key: signature::RsaKeyPair,
}

#[derive(Debug)]
pub enum CertAndKeyReadError {
    IoError(std::io::Error),
    BadCert(x509_parser::nom::Err<x509_parser::error::X509Error>),
    BadKey(ring::error::KeyRejected),
    MissingCert,
    MissingCommonName,
    MissingKey,
    CertAndKeyMismatch,
}

impl std::error::Error for CertAndKeyReadError {}

impl std::fmt::Display for CertAndKeyReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertAndKeyReadError::IoError(e) => write!(f, "{}", e),
            CertAndKeyReadError::MissingCert => write!(f, "No X509 certificate found"),
            CertAndKeyReadError::MissingCommonName => write!(f, "No common name in X509 certificate"),
            CertAndKeyReadError::MissingKey => write!(f, "No RSA keypair found"),
            CertAndKeyReadError::CertAndKeyMismatch => write!(f, "Certificate and key mismatch"),
            CertAndKeyReadError::BadCert(e) => write!(f, "X509 certificate rejected: {}", e),
            CertAndKeyReadError::BadKey(e) => write!(f, "RSA key rejected: {}", e),
        }
    }
}

fn read_certificate_and_key(mut reader: &mut dyn BufRead) -> Result<CertAndKey, CertAndKeyReadError> {
    let mut maybe_cert_bytes = None;
    let mut maybe_key = None;
    for item in iter::from_fn(|| read_one(&mut reader).transpose()) {
        match item.unwrap() {
            Item::X509Certificate(c) => {
                maybe_cert_bytes = Some(c);
            }
            Item::PKCS8Key(k) => {
                maybe_key = Some(signature::RsaKeyPair::from_pkcs8(&k));
            }
            Item::RSAKey(k) => {
                maybe_key = Some(signature::RsaKeyPair::from_der(&k));
            }
            _ => (),
        }
    }
    let key = maybe_key
        .ok_or(CertAndKeyReadError::MissingKey)?
        .map_err(CertAndKeyReadError::BadKey)?;
    let cert_bytes = maybe_cert_bytes.ok_or(CertAndKeyReadError::MissingCert)?;
    let cert = match parse_x509_certificate(&cert_bytes) {
        Ok((_rem, x509)) => x509,
        Err(e) => {
            return Err(CertAndKeyReadError::BadCert(e));
        }
    };
    // TODO(vandry): Check cert.public_key().algorithm. It appears to look like:
    // AlgorithmIdentifier {
    //     algorithm: OID(1.2.840.113549.1.1.1),
    //     parameters: Some(Any {
    //         header: Header {
    //             class: Universal, constructed: false, tag: Tag(5),
    //             length: Definite(0), raw_tag: Some([5])
    //         },
    //         data: []
    //     })
    // }
    if cert.public_key().subject_public_key.data != key.public_key().as_ref() {
        return Err(CertAndKeyReadError::CertAndKeyMismatch);
    }
    let common_name = cert.subject().iter_common_name().next()
        .ok_or(CertAndKeyReadError::MissingCommonName)?
        .as_str()
        .map_err(|_| CertAndKeyReadError::MissingCommonName)?
        .to_string();
    Ok(CertAndKey {
        cert_bytes,
        common_name,
        key,
    })
}

pub struct Config {
    // TODO(vandry): This is a Arc<> so that it can be reloaded, for example
    // on SIGHUP, and allow existing requests to continue using old CertAndKey.
    // Do that.
    cert_and_key: Arc<CertAndKey>,
}

impl Config {
    pub fn new_from_file(filename: &std::path::Path) -> Result<Self, CertAndKeyReadError> {
        let f = File::open(filename).map_err(CertAndKeyReadError::IoError)?;
        Ok(Self {
            cert_and_key: Arc::new(read_certificate_and_key(&mut BufReader::new(f))?),
        })
    }

    #[cfg(test)]
    pub fn new_from_string(contents: &str) -> Result<Self, CertAndKeyReadError> {
        let mut f = std::io::Cursor::new(contents);
        Ok(Self {
            cert_and_key: Arc::new(read_certificate_and_key(&mut f)?),
        })
    }

    pub fn get(&self) -> Arc<CertAndKey> {
        self.cert_and_key.clone()
    }
}
