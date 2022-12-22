use futures::future::ready;
use hex_literal::hex;
use prost::Message;
use std::collections::HashMap;
use std::io::{BufRead, Cursor};
use std::sync::Arc;
use tonic::{Code, Status};
use trust_dns_proto::rr::rdata::tlsa::{CertUsage, Matching, Selector, TLSA};
use x509_parser::{parse_x509_certificate, time::ASN1Time};

use crate::config::Config;
use crate::server::HandshakeProcessor;
use crate::tlsa::{TLSAFuture, TLSAProvider, check_tlsa};

use crate::grpc::gcp::{HandshakerReq, NextHandshakeMessageReq, StartClientHandshakeReq, StartServerHandshakeReq};
use crate::grpc::gcp::{HandshakerResp, HandshakerStatus, ServerHandshakeParameters};
use crate::grpc::gcp::handshaker_req::ReqOneof::{ClientStart, ServerStart, Next};
use crate::grpc::gcp::HandshakeProtocol::{Alts, Tls};
use crate::shared_alts_pb::AltsMessage;

const TIME_WHEN_CERT_IS_VALID: i64 = 1671478511;

fn test1_config() -> Config {
    Config::new_from_string("
-----BEGIN CERTIFICATE-----
MIIFDzCCAvegAwIBAgIUXceiuZYjto57m9MBh1fttdwVJxEwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMdGVzdDEuZG9tYWluMB4XDTIyMTIxODExNDQzM1oXDTIy
MTIyODExNDQzM1owFzEVMBMGA1UEAwwMdGVzdDEuZG9tYWluMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEAlUCm6gXvEbRkeXVgrrYZ2rkMujqL9cnD6p+C
MlS0TkzozOpsi8ilvVWIFPxR0pnsoJm3PENn4igI1/4syLxg1LUHClkeK2PvaFt1
yi6fth2O9LFRzT1/BF3Mb1m+qhP3kebJCdnCCne9Xfii3oSYZQjvEZ0MKSlTCsXT
lV8X/Lx3ezEeJDFpnL1Z3VlghNFOGpwdjK/7hWWi25JIQHHAwddRu5WdTRC2usu3
mqfusQqE/mtqRU9rLT0yvyMwSfY0kNiBQVuLfFv/U+2+I+L/5/dM+BduRb/+tfnp
IMrqX74bPQkbHBm5apnWEYywrhOyxikj6xFIA8+7yrhcsUhYat5+TJQnKUBScqLb
udQIblzf+g/p4bQZ7jhKpxTE73AgQ2OWQ/E0p1TnP0cFY/gbWFi7+jYzm7vIPrIX
wBSgqeYTKqjrERQio12+UjUeL/rahSrlLza02Mv/PHgcF5lgH9fICmhRwp9hn1zs
olLd71a1Rd4HxufalNBPDK3YlY42jaEj78MTd+WRgOLexPjEe9RUQPXId5YWQzuQ
7PMjaZsf7bVNKMFQ3MISvODK0nOnA4LyCl+/7/n1kghwQIlzfrBWIbUUbwnP3tWn
pRdMYnlegndLI9DKRjJvpfnlkVxWZBdMT37ZkK9GDnoqYxP26TxW3oGLCP4rRmAt
XIDTtScCAwEAAaNTMFEwHQYDVR0OBBYEFPnhCuChvvtVl6b6J+JlnV++MHJPMB8G
A1UdIwQYMBaAFPnhCuChvvtVl6b6J+JlnV++MHJPMA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQELBQADggIBACrtiJ4TOM1IKHFY3UmwZbgPyhTVZlb/q9yi5YVQ
sM51vclYN/3ojv3k2C90MrpAWpbgCll02QanGDHBtLwr65L+LKJp1AzqZ9BrFwDv
MUbog2zFGOS0TILv+ey1ObQbihf8axPkD2qPeIKRAm6TIXwJfLRJDTCWCcd2w3vg
P/PfyVafAMj00h9lu+dt5dGSR2HxTmhzHILctGFDEwUQi8czfCFXy80/lOEWa0yi
7pdGEzgEKFUI7BDcYkP2jc70tWE9LbR0rA0uifyrf113Ebi/2br3FlJqQvcm8QVk
I6/a+rO2i14/F5ZcwybDuDgrrsnrtaIDoBVIODcd16IFRrBGmtVYsIDbR5bjf5ii
tKxACDEucMl/VXUVBg69WrNp9nPSZi1T8ybQGE9/b+H3a+4MINpbGyog6kKseWFK
wy7jGDz+t4M+z1YncIrCQm4vlhb6SPvRWiBwNefVk7DzSt1NvS5OJmyZXpaluYpV
XTkwkuVMMZnPxhgF9gHsEYi4YaFhOP4DiagUXmhYoElPBJFpLAYUPT/QXTNRsKuR
aCuDz2GT+XnKIbLWarkYBYXwyrX1RcBHxbGUzlRZwnfrKpFrHUnjkkwZbWiZ1PUj
gpDzNT7XPUkDBSpdcndDSxqEMUB5nLyPg6dy4hEHd147Ps1q5bLcoTxnJeBPpC2Y
qOVz
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIJQQIBADANBgkqhkiG9w0BAQEFAASCCSswggknAgEAAoICAQCVQKbqBe8RtGR5
dWCuthnauQy6Oov1ycPqn4IyVLROTOjM6myLyKW9VYgU/FHSmeygmbc8Q2fiKAjX
/izIvGDUtQcKWR4rY+9oW3XKLp+2HY70sVHNPX8EXcxvWb6qE/eR5skJ2cIKd71d
+KLehJhlCO8RnQwpKVMKxdOVXxf8vHd7MR4kMWmcvVndWWCE0U4anB2Mr/uFZaLb
kkhAccDB11G7lZ1NELa6y7eap+6xCoT+a2pFT2stPTK/IzBJ9jSQ2IFBW4t8W/9T
7b4j4v/n90z4F25Fv/61+ekgyupfvhs9CRscGblqmdYRjLCuE7LGKSPrEUgDz7vK
uFyxSFhq3n5MlCcpQFJyotu51AhuXN/6D+nhtBnuOEqnFMTvcCBDY5ZD8TSnVOc/
RwVj+BtYWLv6NjObu8g+shfAFKCp5hMqqOsRFCKjXb5SNR4v+tqFKuUvNrTYy/88
eBwXmWAf18gKaFHCn2GfXOyiUt3vVrVF3gfG59qU0E8MrdiVjjaNoSPvwxN35ZGA
4t7E+MR71FRA9ch3lhZDO5Ds8yNpmx/ttU0owVDcwhK84MrSc6cDgvIKX7/v+fWS
CHBAiXN+sFYhtRRvCc/e1aelF0xieV6Cd0sj0MpGMm+l+eWRXFZkF0xPftmQr0YO
eipjE/bpPFbegYsI/itGYC1cgNO1JwIDAQABAoICABc+SSA4igQhqeSzumRK+K4e
077BdQrIf/8ZwH69FpKmbeTSUdLXuF6gI3/9JshGRLBixUNDI2T4I3RxDCFmG4BU
rC2Di8Fpyp61C5wlHvs6EYlwKeiYE0qnSY9CadZ2eJTGB6NF6xmSjzDuEn3WfB3T
7S3liBTK743wbqRxpDyC+ep7T5HcXhxU7Vny3CdNqeer+KVwbJpYJdYjAFHaRTtg
IHA2+xca1hIzZ+WpEcY2zgJfJl7NNkgxInuGFomWKEExw7iyxyoNRlntiYcbiAs5
xfNRltCRogWjT0KA8fdfauzaQ64LIDHb65ddEntxluLpr5h2iawKSFkS1WCd1HhH
PmboGoNa6dNGZ30lxNsHve8r2a6cGIMuiXzIzC1miEu5s4AjGdw0tbAu962X+qGv
76J5pF8zyFVi2h3b2sthyzSXIxqCpYOk6iPwJU1F8bw6J4XfCCHqTDl0G3QQmo2S
eHaok24L7nkNrPiv2zvUO7ZCnY77J4vG6PnyTucP+2USYwb7vegdKpn861FrPANx
lfVd+eL+brZtRnTfCEGyN7NA6hITzifZAekCn8hmPsVZB5kx09dzDYt1GjDtLg76
PWYrwAb0kWruQh91Usj/0VzjZPLzqv3cy9VRlZWYghP40ueksSNXClDWAmu0nWcJ
ypLUVVC1PzhOXk/fGt7BAoIBAQDLE24cVMncvLtKiEneyx5zCYsqaqNTsQbBbEkJ
toNBp4JCdJA4v98dtS4eJtEBGcBQAVwErAHr6xqBqnblG7mpxfyiv8b2waH3apoq
sMK4MYO93jDzs8xbikXyAmdk+e8H07VQ48gZxoQ422rLjQtQey+BitrgcOfi1cjk
e9SqHR1t3c+wdyFUoNQu7St0l87MIIvA3tjhhmrjvbTY/KrnYtqPk2ZlMnr3El1H
mM+Lf0iwDOMm94+T2kacCZfK1YMGlLNHad0at9LmK3C5tmouWMtbf5A/1up/V8/W
svSZ5K8ytO4h3Wkk3M0zGRx59urK4RjmoBZ0tUqFpWoVG2/BAoIBAQC8Jk0bxQZ/
RIKE12a2b6M7a6p6VpxDYKHkPP4oINuS0KNqJo0fsXQ8hAtzCv+domzfhbQjYwRl
1EqOoCT80ZtNf26ambraEYPFDcEBPsqZooRw0SGbN17+MluC/yAaJaGdFM6qz2fg
211Sj9nrX6FwQE3LacXhhB1US2mnkjRDORqjxKRy/X8Ain3RfOW1Wed7I2rt+Mqp
1XMM5JXalpAWEwwM2y6u772hPHaT4PjgjyX4ZklpYC31uAD5SazYPmv1w5QD+G9H
kqF+/tjyvTzGa8W2gIpqmJydfembqR/ZQ+W9eCUFDupnsUq76wCWBHelq+KacRXd
WBASiLGESV7nAoIBADYD/Q3cH7VvHgI9LijsrjS7HSEzLC5esAVS4DqNKWyVObij
eJkfsCEeyB2NBZrdVqHxOqCjf/9YkbxbszRNo5zc5M4FZM7Nwl8lI8ynJ6QGx5wB
NdQcxwaySNiOeyIIuOPEFD5n2BnDC/hzpHxwD8pgecpjPMTmQ0e6xazAo1h8Vg+b
KFsv1NXF0aqJuz1QA9mX7pRmshmKv3PESg5NZsgVKz11X48bVknRwK4Cn3HjcVoi
k2kSAEa7kHyAsLdrA2cEtosQRZeNvbMrath7BNM/GxhDXgMdD1K/8LCS+SzV/yPl
rFGlqwn7ETm+PCzU2K8OIKl3e4GflyrlTMpAegECggEAAsU5m3ASQWt71ILrc0I/
kA9syjJeSKuylo7DW0nokcfasCRzLYVKZd234XDHBMYwfjYUyfSaSvmOQ31eLg7U
D5cRxNsAoldhrlQehGstRofbFWIu8X8mOe355PrmuRvWvl5hEKjPKcNxI1cU6V9W
HDYGLzmWfVSZrfUSUDJZ7Kd5mfG6TisnZJWldqE1LK9vNiP2Xhyst0V6VTVEc5yF
8J1FLydHD7JeA3LFeDX21C+nannvGMsewiB8ey83iVOZ+Vtw4YIV+WLSV/FetmxM
6csKdT59S0aF/9eryev6mRNj3Z9YRDPNBcvZgtzZ/FuCe4EFbCrAHKtASVWT75O4
/wKCAQA/Twy2fDhzn0mqz4NEsizf2jx+p3pvzLOektSUu09AzltIczexaa5hvktS
WsjyzZy+bS6fQVqbBv6aKiH3nLIf/qUGgsYEEYgOEi8DV30oO1WRTYaXYf7kd0xi
iSfZqn6SyaeMqzJG90KCDpL5gA8MPcgAYunotud5sSm0fDs5eQLcZDgZZygQVnMs
iE090pxo7Hw3mlGr4/heSHLI06CKVISIibtacfglF3q64rE9/6aeKii9PlAwZ4J8
lTd8UpBBWjtd2ltPQEwJW7Dp5ylaednzJM3DM0XOQLYS/9p18VpsOYM6S1/TwZOt
DyPpEZYr0p6psZFOg3/b4OeEjguA
-----END PRIVATE KEY-----
    ").expect("valid key and cert")
}

fn test1_valid_tlsas() -> Vec<TLSA> {
    vec![
        TLSA::new(CertUsage::DomainIssued, Selector::Full, Matching::Sha256,
                  hex!("ef88a99949d171997fd2fdb02a0acba75eb85a9ae0dfdb7b0f670ac247d2ad6e").to_vec()),
        TLSA::new(CertUsage::DomainIssued, Selector::Full, Matching::Sha512,
                  hex!("da26072e33d0490e0b1f44262e4813708
                        d5bdbbbbe3f544273dc7b40f278c9d8dc
                        111bd30dcda9d1073cbac63640b736398
                        29ae62477a5a255144451c76b2534").to_vec()),
        TLSA::new(CertUsage::DomainIssued, Selector::Full, Matching::Raw,
                  test1_config().get().cert_bytes.clone()),
        TLSA::new(CertUsage::DomainIssued, Selector::Spki, Matching::Sha256,
                  hex!("43e1c7ae849bbd3426436aff451de0132a88b12a8fae07ba8c7e46f38b1f6a0a").to_vec()),
    ]
}

fn test2_config() -> Config {
    Config::new_from_string("
-----BEGIN CERTIFICATE-----
MIIFDzCCAvegAwIBAgIUN5Tcxv6BJ8MPieqtH/DGaezUMGowDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMdGVzdDIuZG9tYWluMB4XDTIyMTIxODEyNTkzMloXDTIy
MTIyODEyNTkzMlowFzEVMBMGA1UEAwwMdGVzdDIuZG9tYWluMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEA27jAIeV3B5wchhg1oaFzvzJJTVNB9cDslB4J
wuywr8AcKkX4UqsEKB4mbF23flM+a3YeVqAzLIQZ9JdF/DjhHitTnhi9LAVOiwF1
Y7h55/t5YRVFdcDbI8AIO9E+FtgZ4vU+Fpy+c41vQY0/P/OAQnt/QbQ1MMEh55uG
v5msw2g1h2qi/ixYqdb4HtlduPr1mfp2qGONICf9iJqoGkGrGvU+uSTlGFNo2sRt
2R864xZJ+Bklk+AxtXafOAInjnXf9LIrMPQ6Dv7ZWjyu3zLH/D4Re0GxGWOloH1t
2hogGPb6sA9k2W755BgaWhkCGXLRK7ojEyCyLIelHLpMUDIOPJbDA57IIvQkNOUF
2BWoK9GjHUMC5kFn9iAoL0eDxK3cbuw9CXXsW/Kt9mdlidA2DzG9eJZQ+gNFG5mo
bEii2E7iQ7NZ37ENY/8IVsg75GzRLZyf1TXJdWIDo54rexBrb4RorzkZ2e3moC41
BJtmGbasjEDsnQGAMlsVPycOfvFsTvlx+AY/ufsLwevKkrrLULq7RrWxcfvIX7c4
s4gwtn+S33aDmm5UO8gTG92K9egy1joaSDLgxDg301hmyhv3EMZ8OMDrH3kzsYLI
VG4+CBTgd9TwsqSJ/7AI3wbr80CS0OQOya8zrOm7KvgDVTqpRuWXb2qKY/Q+i/I8
SllfVacCAwEAAaNTMFEwHQYDVR0OBBYEFBBt+kBFHfx0+Uxuj5SBZHD5LmqfMB8G
A1UdIwQYMBaAFBBt+kBFHfx0+Uxuj5SBZHD5LmqfMA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQELBQADggIBABG33Oa5D0V3Py4ysQYdNBpAH3npSvAnAPTqLU1L
w6ak42LNZ0V8UY3sgglztqFNBvPRAXYnTNwzcoySVFxku2v/U4xsvwSE9z/UT9DO
0QwctXD5s0YgL/pOC0Z+7JdI9mSz6i41pESsT1MsQfBSDgagQbnjMycKmFLEon3F
sfxIJsxmSRkomZfLHMNKvT6fROlqbUL1kbQOgFYUdvQenRq0JH5knpiTDLt6Yz1f
sjdBxvMiIf3YW5R05sR0VDj5cVsv6+PlUiigssQ+jNVQ6eVbZ6nvf5iywixjvoW1
0YdDOVuzslH5t9RW6ua9rUETxVX9a2RG90fxeFKnLVrXt7M9vSrymnDaSwhJCGRS
xdvZ1Konc1LD1I4vGTSp3hI7N1VzHXH53PI9ZAnDPg9J+zoeeQr1KgBHROdpcdhT
9e5cguryVVQF6X8hr+Q9k99CHKyFe6FRpTpz6XqEY5iXPHHPEL5UjdDuTXM1JNPC
PYMihIrD845IplrleFY6Q7+RVE60QXrZsr4SKovA26zD3ydDuZlSqU3+npOKk6FQ
ECgpAjFsk1xMdr4WFdm/sl7nkSt3GZbgKCLmTEpRqDFGf8jq5E94rydlf6E1nRiu
aa35bCJhkGchqRG/UadSP4vWN8UlCFfHpcEG1fgShUnBf4kBaZeyV986WxhnKx9L
sjRm
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
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
SPOKGkn7sXYozFvSfYngf+gO2OgZ1ofN
-----END PRIVATE KEY-----
    ").expect("valid key and cert")
}

fn test2_valid_tlsas() -> Vec<TLSA> {
    vec![
        TLSA::new(CertUsage::DomainIssued, Selector::Full, Matching::Sha256,
                  hex!("c58d1e48682eeb14eb3bb9b4cc47f667713cd10ef3e7756a03ec1be743d0ce13").to_vec()),
        TLSA::new(CertUsage::DomainIssued, Selector::Spki, Matching::Sha256,
                  hex!("594677314cd904e97b90fbcad5b2988ca567ea3d16f9cf60d4574bce859ae8f0").to_vec()),
    ]
}

enum MockTLSAProvider {
    GoodFull,
    GoodSpki,
    Error,
}

impl TLSAProvider for MockTLSAProvider {
    fn background_tlsa_lookup(self: Arc<Self>, name: String) -> TLSAFuture {
        let tlsas = match name.as_str() {
            "_shared-alts.test1.domain." => test1_valid_tlsas(),
            "_shared-alts.test2.domain." => test2_valid_tlsas(),
            _ => vec![],
        };
        let result = match *self {
            MockTLSAProvider::GoodFull => Ok(tlsas.into_iter().filter(|t| t.selector() == Selector::Full).collect()),
            MockTLSAProvider::GoodSpki => Ok(tlsas.into_iter().filter(|t| t.selector() == Selector::Spki).collect()),
            MockTLSAProvider::Error => Err(Status::unavailable("oops")),
        };
        Box::pin(ready(result))
    }
}

fn make_client(tlsa: MockTLSAProvider) -> HandshakeProcessor<MockTLSAProvider> {
    HandshakeProcessor::new(
        "test-client-user", test1_config().get(),
        ASN1Time::from_timestamp(TIME_WHEN_CERT_IS_VALID).expect("time"),
        Arc::new(tlsa))
}

fn make_server(tlsa: MockTLSAProvider) -> HandshakeProcessor<MockTLSAProvider> {
    HandshakeProcessor::new(
        "test-server-user", test2_config().get(),
        ASN1Time::from_timestamp(TIME_WHEN_CERT_IS_VALID).expect("time"),
        Arc::new(tlsa))
}

fn unframe_message(r: &HandshakerResp) -> Option<AltsMessage> {
    if r.out_frames.len() == 0 {
        return None;
    } else if r.out_frames.len() < 4 {
        panic!("out_frames must be at least 4 bytes");
    }
    let header: [u8; 4] = r.out_frames[0..4].try_into().unwrap();
    let msglen = u32::from_be_bytes(header) as usize;
    if r.out_frames.len() != 4 + msglen {
        panic!("out_frames length must be 4 + payload size");
    }
    let mut c = Cursor::new(r.out_frames.clone());
    c.consume(4);
    Some(AltsMessage::decode(&mut c).expect("AltsMessage decode error"))
}

#[tokio::test]
async fn test_client_rejects_wrong_handshake_protocol() {
    let mut client = make_client(MockTLSAProvider::GoodFull);

    let status = client.step(Ok(HandshakerReq {
        req_oneof: Some(ClientStart(StartClientHandshakeReq {
            handshake_security_protocol: Tls as i32,
            record_protocols: vec![String::from("ALTSRP_GCM_AES128_REKEY")],
            ..StartClientHandshakeReq::default()
        })),
    })).await.expect_err("StartClientHandshakeReq rejected due to wrong handshake_security_protocol");
    assert!(status.message().contains("handshake_security_protocol"));
}

#[tokio::test]
async fn test_server_rejects_wrong_handshake_protocol() {
    let mut server = make_server(MockTLSAProvider::GoodFull);

    let status = server.step(Ok(HandshakerReq {
        req_oneof: Some(ServerStart(StartServerHandshakeReq {
            handshake_parameters: HashMap::from([(Tls as i32, ServerHandshakeParameters {
                record_protocols: vec![String::from("ALTSRP_GCM_AES128_REKEY")],
                ..ServerHandshakeParameters::default()
            })]),
            ..StartServerHandshakeReq::default()
        })),
    })).await.expect_err("StartServerHandshakeReq rejected due to wrong handshake_security_protocol");
    assert!(status.message().contains("handshake_parameters"));
}

#[tokio::test]
async fn test_client_rejects_wrong_record_protocol() {
    let mut client = make_client(MockTLSAProvider::GoodFull);

    let status = client.step(Ok(HandshakerReq {
        req_oneof: Some(ClientStart(StartClientHandshakeReq {
            handshake_security_protocol: Alts as i32,
            record_protocols: vec![String::from("ridiculous")],
            ..StartClientHandshakeReq::default()
        })),
    })).await.expect_err("StartClientHandshakeReq rejected due to wrong record_protocols");
    assert!(status.message().contains("record_protocol"));
}

#[tokio::test]
async fn test_server_rejects_wrong_record_protocol() {
    let mut server = make_server(MockTLSAProvider::GoodFull);

    let status = server.step(Ok(HandshakerReq {
        req_oneof: Some(ServerStart(StartServerHandshakeReq {
            handshake_parameters: HashMap::from([(Alts as i32, ServerHandshakeParameters {
                record_protocols: vec![String::from("ridiculous")],
                ..ServerHandshakeParameters::default()
            })]),
            ..StartServerHandshakeReq::default()
        })),
    })).await.expect_err("StartServerHandshakeReq rejected due to wrong record_protocols");
    assert!(status.message().contains("record_protocol"));
}

async fn do_handshake_except_last(client: &mut HandshakeProcessor<MockTLSAProvider>, server: &mut HandshakeProcessor<MockTLSAProvider>) -> Result<HandshakerResp, Status> {
    let c1 = client.step(Ok(HandshakerReq {
        req_oneof: Some(ClientStart(StartClientHandshakeReq {
            handshake_security_protocol: Alts as i32,
            application_protocols: vec![
                String::from("not_supported_by_server"),
                String::from("fancy"),
            ],
            record_protocols: vec![String::from("ALTSRP_GCM_AES128_REKEY")],
            // rpc_versions:
            ..StartClientHandshakeReq::default()
        })),
    })).await.expect("first HandshakerResp from client");
    assert_eq!(c1.status, Some(HandshakerStatus::default()));
    assert_eq!(c1.result, None);
    let client_hello = unframe_message(&c1).unwrap();
    assert!(client_hello.hello.is_some());
    assert!(client_hello.key_exchange.is_none());

    let s1 = server.step(Ok(HandshakerReq {
        req_oneof: Some(ServerStart(StartServerHandshakeReq {
            handshake_parameters: HashMap::from([(Alts as i32, ServerHandshakeParameters {
                record_protocols: vec![String::from("ALTSRP_GCM_AES128_REKEY")],
                ..ServerHandshakeParameters::default()
            })]),
            application_protocols: vec![
                String::from("not_supported_by_client"),
                String::from("fancy"),
            ],
            // rpc_versions:
            ..StartServerHandshakeReq::default()
        })),
    })).await.expect("first HandshakerResp from server");
    assert_eq!(s1.status, Some(HandshakerStatus::default()));
    assert_eq!(s1.result, None);
    assert_eq!(unframe_message(&s1), None);

    let s2 = server.step(Ok(HandshakerReq {
        req_oneof: Some(Next(NextHandshakeMessageReq {
            in_bytes: c1.out_frames,
        })),
    })).await.expect("second HandshakerResp from server");
    assert_eq!(s2.status, Some(HandshakerStatus::default()));
    assert_eq!(s2.result, None);
    let server_hello = unframe_message(&s2).unwrap();
    assert!(server_hello.hello.is_some());
    assert!(server_hello.key_exchange.is_some());

    client.step(Ok(HandshakerReq {
        req_oneof: Some(Next(NextHandshakeMessageReq {
            in_bytes: s2.out_frames,
        })),
    })).await
}

async fn do_handshake(client: &mut HandshakeProcessor<MockTLSAProvider>, server: &mut HandshakeProcessor<MockTLSAProvider>) {
    let c2 = do_handshake_except_last(client, server)
        .await
        .expect("second HandshakerResp from client");
    assert_eq!(c2.status, Some(HandshakerStatus::default()));
    let client_result = c2.result.as_ref().expect("Client should have finished");
    let client_kex = unframe_message(&c2).unwrap();
    assert!(client_kex.hello.is_none());
    assert!(client_kex.key_exchange.is_some());

    let s3 = server.step(Ok(HandshakerReq {
        req_oneof: Some(Next(NextHandshakeMessageReq {
            in_bytes: c2.out_frames,
        })),
    })).await.expect("third HandshakerResp from server");
    assert_eq!(s3.status, Some(HandshakerStatus::default()));
    let server_result = s3.result.as_ref().expect("Server should have finished");
    assert_eq!(unframe_message(&s3), None);

    assert_eq!(client_result.application_protocol, "fancy");
    assert_eq!(server_result.application_protocol, "fancy");
    assert_eq!(client_result.key_data, server_result.key_data);
}

#[tokio::test]
async fn test_handshake_with_full_tlsa() {
    let mut client = make_client(MockTLSAProvider::GoodFull);
    let mut server = make_server(MockTLSAProvider::GoodFull);
    do_handshake(&mut client, &mut server).await
}

#[tokio::test]
async fn test_handshake_with_spki_tlsa() {
    let mut client = make_client(MockTLSAProvider::GoodSpki);
    let mut server = make_server(MockTLSAProvider::GoodSpki);
    do_handshake(&mut client, &mut server).await
}

#[tokio::test]
async fn test_handshake_fails_on_tlsa_error() {
    let mut client = make_client(MockTLSAProvider::Error);
    let mut server = make_server(MockTLSAProvider::Error);

    let c2 = do_handshake_except_last(&mut client, &mut server).await;

    assert_eq!(c2
        .expect_err("Client should have experienced TLSA fetch error")
        .code(),
        Code::Unavailable);
}

#[tokio::test]
async fn test_rejects_certificate_outside_validity() {
    for clock_adjust_seconds in [-10000000, 0, 10000000] {
        let mut client = HandshakeProcessor::new(
            "test-client-user", test2_config().get(),
            ASN1Time::from_timestamp(TIME_WHEN_CERT_IS_VALID+clock_adjust_seconds).expect("time"),
            Arc::new(MockTLSAProvider::GoodFull));
        let mut server = HandshakeProcessor::new(
            "test-server-user", test2_config().get(),
            ASN1Time::from_timestamp(TIME_WHEN_CERT_IS_VALID+clock_adjust_seconds).expect("time"),
            Arc::new(MockTLSAProvider::GoodFull));

        let c1 = client.step(Ok(HandshakerReq {
            req_oneof: Some(ClientStart(StartClientHandshakeReq {
                handshake_security_protocol: Alts as i32,
                record_protocols: vec![String::from("ALTSRP_GCM_AES128_REKEY")],
                ..StartClientHandshakeReq::default()
            })),
        })).await.expect("first HandshakerResp from client");

        let s1 = server.step(Ok(HandshakerReq {
            req_oneof: Some(ServerStart(StartServerHandshakeReq {
                handshake_parameters: HashMap::from([(Alts as i32, ServerHandshakeParameters {
                    record_protocols: vec![String::from("ALTSRP_GCM_AES128_REKEY")],
                    ..ServerHandshakeParameters::default()
                })]),
                in_bytes: c1.out_frames,
                ..StartServerHandshakeReq::default()
            })),
        })).await;

        if clock_adjust_seconds == 0 {
            s1.expect("Certificate should be valid now");
        } else {
            assert_eq!(s1
                .expect_err("Certificate should be rejected too early or too late")
                .code(),
                Code::Unauthenticated);
        }
    }
}

fn get_cert_public_key(cert_bytes: &[u8]) -> Vec<u8> {
    let (_rem, cert) = parse_x509_certificate(cert_bytes).expect("parseable cert");
    cert.public_key().raw.to_vec()
}

#[tokio::test]
async fn test_accepts_valid_tlsas() {
    let cert_bytes = &test1_config().get().cert_bytes;
    let pk_bytes = get_cert_public_key(cert_bytes);
    for record in test1_valid_tlsas() {
        let test_tlsas = vec![record];
        check_tlsa(&test_tlsas, cert_bytes, &pk_bytes)
            .map_err(|e| format!("Validating {:?}: {}", &test_tlsas, e))
            .expect("Validation success");
    }
}

#[tokio::test]
async fn test_accepts_wrong_tlsa_followed_by_valid_one() {
    let cert_bytes = &test1_config().get().cert_bytes;
    let pk_bytes = get_cert_public_key(cert_bytes);
    let good = test1_valid_tlsas().into_iter().next().unwrap();
    let bad = test2_valid_tlsas().into_iter().next().unwrap();
    let test_tlsas = vec![bad, good];
    check_tlsa(&test_tlsas, cert_bytes, &pk_bytes)
        .map_err(|e| format!("Validating {:?}: {}", &test_tlsas, e))
        .expect("Validation success");
}

// TODO(vandry): Test that delivering wrong or duplicated messages.
