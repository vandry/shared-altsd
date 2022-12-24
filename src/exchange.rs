use k256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret, ecdh::SharedSecret};
use rand_core::{RngCore, OsRng};
use ring::{rand, signature};
use prost::Message;
use sha2::Sha256;
use std::collections::HashSet;
use std::io::Cursor;
use std::sync::Arc;
use tonic::{Code, Status};
use x509_parser::{parse_x509_certificate, time::ASN1Time};

use crate::config::CertAndKey;
use crate::tlsa::{TLSAFuture, TLSAProvider, check_tlsa, tlsa_name};

use crate::grpc::gcp::{RpcProtocolVersions, HandshakerResult};
use crate::grpc::gcp::{Identity, identity::IdentityOneof};
use crate::shared_alts_pb::{Hello, KeyExchange, NamedCurve, SignedParams};

const MAGIC: &str = "shared-alts-v1";
const RANDOM_SIZE: usize = 32;

// We do not really care what record protocol get negociated, but we do need
// to recognise it because it determines the length of the key that we will
// be expected to supply. So just support this single hardcoded one.
const SUPPORTED_RECORD_PROTOCOL: &str = "ALTSRP_GCM_AES128_REKEY";
const SUPPORTED_RECORD_PROTOCOL_KEY_SIZE: usize = 44;

pub fn record_protocol_supported(record_protocols: &[String]) -> bool {
    record_protocols.iter().any(|rp| *rp == SUPPORTED_RECORD_PROTOCOL)
}

pub struct Exchange<T: TLSAProvider> {
    local_username: String,
    cert_and_key: Arc<CertAndKey>,
    client_random: [u8; RANDOM_SIZE],
    server_random: [u8; RANDOM_SIZE],
    ecdhe_secret: EphemeralSecret,
    ecdhe_shared: Option<SharedSecret>,
    peer_cert_bytes: Option<Vec<u8>>,
    peer_public_key_bytes: Option<Vec<u8>>,
    peer_public_key: Option<signature::UnparsedPublicKey<Vec<u8>>>,
    peer_common_name: Option<String>,
    now: ASN1Time,
    resolver: Arc<T>,

    // If empty, ignore.
    // If non-empty, fail the handshake if none match the remote identity.
    target_identities: Vec<Identity>,

    tlsa_future: Option<TLSAFuture>,

    // Stuff we do not care about but which must be relayed to the other side.
    // We carry it in SignedParams.
    application_protocols: Vec<String>,
    rpc_versions: Option<RpcProtocolVersions>,

    peer_rpc_versions: Option<RpcProtocolVersions>,
    peer_username: Option<String>,
}

impl<T: TLSAProvider> Exchange<T> {
    pub fn new(local_username: &str, cert_and_key: Arc<CertAndKey>, now: ASN1Time, resolver: Arc<T>) -> Self {
        Self {
            local_username: String::from(local_username),
            cert_and_key,
            client_random: [0u8; RANDOM_SIZE],
            server_random: [0u8; RANDOM_SIZE],
            ecdhe_secret: EphemeralSecret::random(&mut OsRng),
            ecdhe_shared: None,
            peer_cert_bytes: None,
            peer_public_key: None,
            peer_public_key_bytes: None,
            peer_common_name: None,
            application_protocols: Vec::new(),
            rpc_versions: None,
            peer_rpc_versions: None,
            peer_username: None,
            target_identities: Vec::new(),
            tlsa_future: None,
            now,
            resolver,
        }
    }

    pub fn set_start_parameters(&mut self, application_protocols: Vec<String>, rpc_versions: Option<RpcProtocolVersions>, target_identities: Vec<Identity>) {
        self.application_protocols = application_protocols;
        self.rpc_versions = rpc_versions;
        self.target_identities = target_identities;
    }

    fn gen_hello(&self, random: &[u8; RANDOM_SIZE]) -> Hello {
        Hello {
            magic: Some(String::from(MAGIC)),
            random: Some(random.to_vec()),
            certificate: Some(self.cert_and_key.cert_bytes.clone()),
        }
    }

    pub fn gen_client_hello(&mut self) -> Hello {
        OsRng.fill_bytes(&mut self.client_random);
        self.gen_hello(&self.client_random)
    }

    pub fn gen_server_hello(&mut self) -> Hello {
        OsRng.fill_bytes(&mut self.server_random);
        self.gen_hello(&self.server_random)
    }

    fn accept_hello(&mut self, hello: Hello) -> Result<[u8; RANDOM_SIZE], Status> {
        if self.peer_cert_bytes.is_some() {
            return Err(Status::new(Code::InvalidArgument, "Got duplicate Hello message"));
        }
        if hello.magic.ok_or_else(|| Status::new(Code::InvalidArgument, "Got Hello message with no magic"))? != MAGIC {
            return Err(Status::new(Code::InvalidArgument, "Got Hello message with wrong magic"));
        }

        let peer_cert_bytes = hello.certificate
            .ok_or_else(|| Status::new(Code::InvalidArgument, "Received hello message without certificate"))?;
        let cert = match parse_x509_certificate(&peer_cert_bytes) {
            Ok((_rem, x509)) => Ok(x509),
            Err(_) => Err(Status::new(Code::InvalidArgument, "Got Hello message with unparseable certificate")),
        }?;
        self.peer_public_key = Some(signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256, cert.public_key().subject_public_key.data.to_vec()));
        self.peer_public_key_bytes = Some(cert.public_key().raw.to_vec());

        let validity = cert.validity();
        if self.now.lt(&validity.not_before) {
            return Err(Status::new(Code::Unauthenticated, "Certificate is only valid in the future"));
        }
        if self.now.gt(&validity.not_after) {
            return Err(Status::new(Code::Unauthenticated, "Certificate is expired"));
        }

        let common_name = cert.subject().iter_common_name().next()
            .ok_or_else(|| Status::unauthenticated("Peer certificate is missing common name"))?
            .as_str()
            .map_err(|_| Status::unauthenticated("Error extracting common name from peer certificate"))?;
        self.peer_common_name = Some(common_name.to_string());
        self.tlsa_future = Some(self.resolver.clone().background_tlsa_lookup(tlsa_name(common_name)));

        self.peer_cert_bytes = Some(peer_cert_bytes);

        match hello.random
            .ok_or_else(|| Status::new(Code::InvalidArgument, "Got Hello message with no random"))?
            .as_slice().try_into()
        {
            Ok(array) => Ok(array),
            Err(_) => Err(Status::new(Code::InvalidArgument, "Got Hello message with the wrong amount of random")),
        }
    }

    pub fn accept_server_hello(&mut self, hello: Hello) -> Result<(), Status> {
        match self.accept_hello(hello) {
            Ok(server_random) => {
                self.server_random = server_random;
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    pub fn accept_client_hello(&mut self, hello: Hello) -> Result<(), Status> {
        match self.accept_hello(hello) {
            Ok(client_random) => {
                self.client_random = client_random;
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    pub fn gen_key_exchange(&mut self) -> Result<KeyExchange, Status> {
        let p = SignedParams {
            named_curve: Some(NamedCurve::Secp256k1 as i32),
            ec_public_key: Some(EncodedPoint::from(self.ecdhe_secret.public_key()).as_bytes().to_vec()),
            identity_username: Some(self.local_username.clone()),
            application_protocols: self.application_protocols.clone(),
            rpc_versions: self.rpc_versions.take(),
        };

        let mut signed_params_bytes = Vec::new();
        signed_params_bytes.reserve(p.encoded_len());
        p.encode(&mut signed_params_bytes).unwrap();

        let signed_payload = [
            self.client_random.to_vec(),
            self.server_random.to_vec(),
            signed_params_bytes.clone(),
        ].concat();

        let rng = rand::SystemRandom::new();
        let key_pair = &self.cert_and_key.key;
        let mut signature = vec![0; key_pair.public_modulus_len()];
        key_pair.sign(
            &signature::RSA_PKCS1_SHA256, &rng, &signed_payload, &mut signature)
            .map_err(|_| Status::new(Code::Internal, "Failed to generate signature"))?;

        Ok(KeyExchange {
            signed_params: Some(signed_params_bytes),
            signature: Some(signature),
        })
    }

    pub fn accept_key_exchange(&mut self, kex: KeyExchange) -> Result<(), Status> {
        if self.ecdhe_shared.is_some() {
            return Err(Status::new(
                Code::InvalidArgument,
                "Got duplicate KeyExchange message",
            ));
        }
        let signed_params_bytes = kex.signed_params.unwrap_or_default();
        let signed_payload = [
            self.client_random.to_vec(),
            self.server_random.to_vec(),
            signed_params_bytes.clone(),
        ].concat();

        let peer_public_key = self.peer_public_key.as_ref()
            .ok_or_else(|| Status::new(Code::Internal, "KeyExchange with unknown peer public key (was a Hello sent first?)"))?;
        peer_public_key.verify(&signed_payload, &kex.signature.unwrap_or_default())
            .map_err(|_| Status::new(Code::Unauthenticated, "Signature verification failed"))?;

        let signed_params = SignedParams::decode(Cursor::new(signed_params_bytes))
            .map_err(|err| Status::new(Code::Internal, format!("KeyExchange.signed_params decode failure: {}", err)))?;
        let named_curve = signed_params.named_curve
            .ok_or_else(|| Status::new(Code::InvalidArgument, "SignedParams.named_curve is unset"))?;
        if named_curve != NamedCurve::Secp256k1 as i32 {
            return Err(Status::new(Code::InvalidArgument, format!("SignedParams.named_curve {} is not supported", named_curve)));
        }
        let peer_ec_public_key = PublicKey::from_sec1_bytes(&signed_params.ec_public_key
            .ok_or_else(|| Status::new(Code::Internal, "SignedParams.ec_public_key is unset"))?
        ).map_err(|err| Status::new(Code::Internal, format!("Error decoding peer ECDH public key: {}", err)))?;
        self.ecdhe_shared = Some(self.ecdhe_secret.diffie_hellman(&peer_ec_public_key));

        self.peer_rpc_versions = signed_params.rpc_versions;
        self.peer_username = signed_params.identity_username;
        let peer_protocols: HashSet<String> = signed_params.application_protocols.into_iter().collect();
        // Narrow down our set of supported protocols to only the ones the
        // peer also supports, and then take the first one.
        self.application_protocols = std::mem::take(&mut self.application_protocols)
            .into_iter()
            .filter(|ap| peer_protocols.get(ap).is_some())
            .take(1)
            .collect();

        Ok(())
    }

    pub async fn result(&mut self) -> Result<Option<HandshakerResult>, Status> {
        Ok(match &self.ecdhe_shared {
            None => None,
            Some(shared_secret) => {
                let peer_username = self.peer_username.as_ref()
                    .ok_or_else(|| Status::unauthenticated("missing remote username"))?;
                let peer_hostname = self.peer_common_name.as_ref()
                    .ok_or_else(|| Status::unauthenticated("missing remote common name"))?;
                let peer_identity = format!("{}@{}", peer_username, peer_hostname);

                // Zero target_identities means all peer identities are acceptable.
                if !self.target_identities.is_empty() {
                    self.target_identities.iter()
                        .find(|i| match &i.identity_oneof {
                            Some(IdentityOneof::ServiceAccount(requested_identity)) => *requested_identity == peer_identity,
                            _ => false,
                        })
                        .ok_or_else(|| Status::unauthenticated(format!("Remote identity {} not among requested remte identities", peer_identity)))?;
                }

                let hkdf = shared_secret.extract::<Sha256>(None);
                let mut okm = [0u8; SUPPORTED_RECORD_PROTOCOL_KEY_SIZE];
                hkdf.expand(&[], &mut okm)
                    .map_err(|_| Status::new(Code::Internal, "Error extracting shared key"))?;
                check_tlsa(&self.tlsa_future.take().unwrap().await?,
                           self.peer_cert_bytes.as_ref().unwrap_or(&vec![]),
                           self.peer_public_key_bytes.as_ref().unwrap_or(&vec![]))?;
                Some(HandshakerResult {
                    application_protocol: self.application_protocols
                        .get(0).unwrap_or(&String::new()).to_string(),
                    record_protocol: String::from(SUPPORTED_RECORD_PROTOCOL),
                    key_data: okm.to_vec(),
                    peer_identity: Some(Identity {
                        identity_oneof: Some(IdentityOneof::ServiceAccount(peer_identity)),
                    }),
                    local_identity: Some(Identity {
                        identity_oneof: Some(IdentityOneof::ServiceAccount(
                            format!("{}@{}", self.local_username, self.cert_and_key.common_name)
                        )),
                    }),
                    keep_channel_open: false,
                    peer_rpc_versions: self.peer_rpc_versions.take(),
                })
            }
        })
    }
}
