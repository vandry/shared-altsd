use async_stream::stream;
use futures::Stream;
use prost::Message;
use std::io::{BufRead, Cursor};
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::StreamExt;
use tonic::{Code, Request, Response, Status, Streaming};
use tonic::transport::server::UdsConnectInfo;
use users::get_user_by_uid;
use x509_parser::time::ASN1Time;

use crate::config::{CertAndKey, Config};
use crate::exchange::{Exchange, record_protocol_supported};
use crate::tlsa::TLSAProvider;

use crate::grpc::gcp::handshaker_service_server::HandshakerService;
use crate::grpc::gcp::{HandshakerReq, HandshakerResp, HandshakerStatus};
use crate::grpc::gcp::{HandshakeProtocol::Alts, StartClientHandshakeReq, StartServerHandshakeReq};
use crate::grpc::gcp::handshaker_req::ReqOneof::{ClientStart, ServerStart, Next};
use crate::grpc::gcp::identity::IdentityOneof;
use crate::shared_alts_pb::AltsMessage;

fn frame_message(m: AltsMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.reserve(m.encoded_len());
    m.encode(&mut buf).unwrap();
    let len = buf.len() as u32;
    [len.to_be_bytes().to_vec(), buf].concat()
}

fn check_client_start(cs: &StartClientHandshakeReq) -> Result<(), Status> {
    if cs.handshake_security_protocol != Alts as i32 {
        return Err(Status::new(Code::InvalidArgument, "handshake_security_protocol must be ALTS"));
    }
    if !record_protocol_supported(&cs.record_protocols) {
        return Err(Status::new(Code::InvalidArgument, "unsupported record_protocol"));
    }
    Ok(())
}

fn check_server_start(ss: &StartServerHandshakeReq) -> Result<(), Status> {
    match ss.handshake_parameters.get(&(Alts as i32)) {
        Some(shp) => {
            if record_protocol_supported(&shp.record_protocols) {
                Ok(())
            } else {
                Err(Status::new(Code::InvalidArgument, "unsupported record_protocol"))
            }
        }
        None => Err(Status::new(Code::InvalidArgument, "handshake_parameters for ALTS must be given")),
    }
}

enum HandshakeProcessorTalker {
    NotStarted,
    Client,
    Server,
}

pub struct HandshakeProcessor<T: TLSAProvider> {
    available_bytes: Vec<u8>,
    exchange: Exchange<T>,
    talker: HandshakeProcessorTalker,
}

impl<T: TLSAProvider> HandshakeProcessor<T> {
    pub fn new(username: &str, cert_and_key: Arc<CertAndKey>, now: ASN1Time, resolver: Arc<T>) -> Self {
        Self {
            available_bytes: Vec::new(),
            exchange: Exchange::new(username, cert_and_key, now, resolver),
            talker: HandshakeProcessorTalker::NotStarted,
        }
    }

    fn run(mut self, mut in_stream: Streaming<HandshakerReq>) -> impl Stream<Item = Result<HandshakerResp, Status>> {
        stream! {
            while let Some(req) = in_stream.next().await {
                let r = match self.step(req).await {
                    Ok(r) => r,
                    Err(status) => HandshakerResp {
                        bytes_consumed: 0,
                        out_frames: Vec::new(),
                        result: None,
                        status: Some(HandshakerStatus {
                            code: status.code() as u32,
                            details: status.message().to_string(),
                        }),
                    }
                };
                let is_last_message = {
                    if let Some(ref result) = r.result {
                        if let Some(sa) = match &result.peer_identity {
                            None => None,
                            Some(i) => match &i.identity_oneof {
                                Some(IdentityOneof::ServiceAccount(sa)) => Some(sa),
                                _ => None,
                            },
                        } {
                            log::info!("Handshake completed successfully, peer is {}", sa);
                        } else {
                            log::info!("Handshake completed successfully but peer is unknown");
                        }
                        true
                    } else if let Some(ref s) = r.status {
                        if s.code == Code::Ok as u32 {
                            false
                        } else {
                            log::info!("Handshake failed with status {} and message {}", Code::from_i32(s.code.try_into().unwrap_or(Code::Unknown as i32)), s.details);
                            true
                        }
                    } else {
                        false
                    }
                };
                yield Ok(r);
                if is_last_message {
                    break;
                }
            }
        }
    }

    fn client_accept_message(&mut self, m: AltsMessage) -> Result<Option<AltsMessage>, Status> {
        if let Some(hello) = m.hello {
            self.exchange.accept_server_hello(hello)?;
        }
        if let Some(kex) = m.key_exchange {
            self.exchange.accept_key_exchange(kex)?;
        }
        Ok(Some(AltsMessage {
            hello: None,
            key_exchange: Some(self.exchange.gen_key_exchange()?),
        }))
    }

    fn server_accept_message(&mut self, m: AltsMessage) -> Result<Option<AltsMessage>, Status> {
        let mut output = None;
        if let Some(hello) = m.hello {
            self.exchange.accept_client_hello(hello)?;
            output = Some(AltsMessage {
                hello: Some(self.exchange.gen_server_hello()),
                key_exchange: Some(self.exchange.gen_key_exchange()?),
            })
        }
        if let Some(kex) = m.key_exchange {
            self.exchange.accept_key_exchange(kex)?;
        }
        Ok(output)
    }

    pub async fn step(&mut self, req: Result<HandshakerReq, Status>) -> Result<HandshakerResp, Status> {
        let hr = req?;
        let mut output = None;
        let mut in_bytes = match hr.req_oneof {
            Some(ClientStart(r)) => {
                match self.talker {
                    HandshakeProcessorTalker::NotStarted => (),
                    _ => {
                        return Err(Status::new(Code::InvalidArgument, "StartClientHandshakeReq after handshake already started"));
                    }
                };
                check_client_start(&r)?;
                self.exchange.set_start_parameters(r.application_protocols, r.rpc_versions, r.target_identities);
                output = Some(AltsMessage {
                    hello: Some(self.exchange.gen_client_hello()),
                    key_exchange: None,
                });
                self.talker = HandshakeProcessorTalker::Client;
                Vec::new()
            }
            Some(ServerStart(mut r)) => {
                match self.talker {
                    HandshakeProcessorTalker::NotStarted => (),
                    _ => {
                        return Err(Status::new(Code::InvalidArgument, "StartServerHandshakeReq after handshake already started"));
                    }
                };
                check_server_start(&r)?;
                self.exchange.set_start_parameters(r.application_protocols, r.rpc_versions, Vec::new());
                self.talker = HandshakeProcessorTalker::Server;
                std::mem::take(&mut r.in_bytes)
            }
            Some(Next(r)) => {
                if let HandshakeProcessorTalker::NotStarted = self.talker {
                    return Err(Status::new(Code::InvalidArgument, "next before client_start or server_start"));
                }
                r.in_bytes
            }
            None => {
                return Err(Status::new(Code::InvalidArgument, "HandshakerReq with no fields set"));
            }
        };
        let got_bytes = in_bytes.len();
        self.available_bytes.append(&mut in_bytes);
        while let Some(m_or) = self.consume_message() {
            match m_or {
                Ok(m) => {
                    let feed_out = match &mut self.talker {
                        HandshakeProcessorTalker::Client => self.client_accept_message(m),
                        HandshakeProcessorTalker::Server => self.server_accept_message(m),
                        HandshakeProcessorTalker::NotStarted => panic!("Always set above"),
                    }?;
                    match feed_out {
                        Some(o) => {
                            output = Some(o);
                        }
                        None => (),
                    }
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }
        Ok(HandshakerResp {
            bytes_consumed: got_bytes as u32,
            out_frames: match output {
                Some(o) => frame_message(o),
                None => Vec::new(),
            },
            result: self.exchange.result().await?,
            status: Some(HandshakerStatus::default()),
        })
    }

    fn consume_message(&mut self) -> Option<Result<AltsMessage, Status>> {
        if self.available_bytes.len() < 4 {
            return None;
        }
        let header: [u8; 4] = self.available_bytes[0..4].try_into().unwrap();
        let msglen = u32::from_be_bytes(header) as usize;
        if self.available_bytes.len() < 4 + msglen {
            return None;
        }
        let frame_bytes: Vec<u8> = self.available_bytes.drain(0..msglen+4).collect();
        let mut c = Cursor::new(frame_bytes);
        c.consume(4);
        match AltsMessage::decode(&mut c) {
            Ok(m) => Some(Ok(m)),
            Err(err) => Some(Err(Status::new(Code::InvalidArgument, format!("error decoding TLSA_ALTS_Message: {}", err)))),
        }
    }
}

pub struct Handshaker<T: TLSAProvider> {
    config: Config,
    resolver: Arc<T>,
}

impl<T: TLSAProvider> Handshaker<T> {
    pub fn new(config: Config, resolver: Arc<T>) -> Self {
        Self { config, resolver }
    }
}

#[tonic::async_trait]
impl<T: TLSAProvider> HandshakerService for Handshaker<T> {
    type DoHandshakeStream = Pin<Box<dyn Stream<Item = Result<HandshakerResp, Status>> + Send>>;

    async fn do_handshake(
        &self,
        req: Request<Streaming<HandshakerReq>>,
    ) -> Result<Response<Self::DoHandshakeStream>, Status> {
        let peer_cred = match req.extensions().get::<UdsConnectInfo>() {
            Some(conn_info) => conn_info.peer_cred,
            None => None,
        }.ok_or_else(|| Status::new(Code::Unauthenticated, "No credentials from UNIX socket"))?;
        let username = match get_user_by_uid(peer_cred.uid()) {
            Some(user) => String::from(user.name().to_string_lossy()),
            None => {
                return Err(Status::new(Code::Unauthenticated, "Peer uid corresponds to no user"));
            }
        };
        log::info!("Starting handshake from {:?}", peer_cred);
        let p = HandshakeProcessor::new(&username, self.config.get(), ASN1Time::now(), self.resolver.clone());
        Ok(Response::new(Box::pin(p.run(req.into_inner()))))
    }
}
