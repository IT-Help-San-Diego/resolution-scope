//! Loopback DNS stub for the egress / identity / preflight tests.
//!
//! Binds 127.0.0.1:0 (the OS picks the port) on UDP and TCP, answers every
//! query it has no canned answer for with REFUSED (so a scan completes in
//! milliseconds and no lookup ever leaves the machine), and records every
//! question it saw. A stub that answers is the POSITIVE control for "the
//! ledger saw the socket"; an unreachable port is the negative one.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// A canned answer: answer records + AUTHORITY records + response code for
/// one (owner name, type).
///
/// The authority section is what carries the SOA on a negative answer, and it
/// is the whole subject of the NXDOMAIN-existence work: an NXDOMAIN's SOA
/// names the closest enclosing zone THAT EXISTS, which says nothing about
/// whether the queried name's own domain exists. Without an authority section
/// the stub could only emit a bare NXDOMAIN and could not reproduce that shape
/// end to end.
#[derive(Clone)]
pub struct Canned {
    pub records: Vec<Record>,
    pub authority: Vec<Record>,
    pub code: ResponseCode,
}

impl Canned {
    pub fn ok(records: Vec<Record>) -> Self {
        Self {
            records,
            authority: Vec::new(),
            code: ResponseCode::NoError,
        }
    }

    /// A response code with no answers and no authority — e.g. a bare
    /// NXDOMAIN, or the NODATA shape (`NoError` + nothing).
    pub fn code(code: ResponseCode) -> Self {
        Self {
            records: Vec::new(),
            authority: Vec::new(),
            code,
        }
    }

    /// A negative answer carrying an SOA in the AUTHORITY section — the shape
    /// a real resolver returns for NXDOMAIN and NODATA.
    pub fn with_soa(code: ResponseCode, zone: &str) -> Self {
        use hickory_proto::rr::{rdata::SOA, Name, RData};
        let owner = Name::from_ascii(if zone.ends_with('.') {
            zone.to_string()
        } else {
            format!("{zone}.")
        })
        .unwrap();
        let soa = SOA::new(
            Name::from_ascii("ns1.invalid.").unwrap(),
            Name::from_ascii("hostmaster.invalid.").unwrap(),
            1,
            3600,
            600,
            86400,
            3600,
        );
        Self {
            records: Vec::new(),
            authority: vec![Record::from_rdata(owner, 3600, RData::SOA(soa))],
            code,
        }
    }
}

type Answers = Arc<Mutex<HashMap<(String, RecordType), Canned>>>;
type Seen = Arc<Mutex<Vec<(String, RecordType, &'static str)>>>;

pub struct Stub {
    pub addr: SocketAddr,
    /// (name, type, "udp" | "tcp") for every question seen.
    pub seen: Seen,
    answers: Answers,
    _udp: tokio::task::JoinHandle<()>,
    _tcp: tokio::task::JoinHandle<()>,
}

fn answer(req: &[u8], answers: &Answers, seen: &Seen, via: &'static str) -> Option<Vec<u8>> {
    let req = Message::from_vec(req).ok()?;
    let q = req.queries.first().cloned()?;
    let key = (q.name().to_lowercase().to_ascii(), q.query_type());
    seen.lock().unwrap().push((key.0.clone(), key.1, via));
    let canned = answers.lock().unwrap().get(&key).cloned();
    let mut resp = Message::response(req.metadata.id, OpCode::Query);
    resp.metadata.message_type = MessageType::Response;
    resp.metadata.recursion_desired = req.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.add_query(q);
    match canned {
        Some(c) => {
            resp.metadata.response_code = c.code;
            resp.add_answers(c.records);
            resp.add_authorities(c.authority);
        }
        None => resp.metadata.response_code = ResponseCode::Refused,
    }
    if let Some(edns) = req.edns.as_ref() {
        let mut e = hickory_proto::op::Edns::new();
        e.set_max_payload(4096)
            .set_dnssec_ok(edns.flags().dnssec_ok);
        resp.edns = Some(e);
    }
    resp.to_vec().ok()
}

impl Stub {
    /// Start a stub that answers REFUSED to everything not canned.
    pub async fn start() -> Self {
        Self::start_with(HashMap::new()).await
    }

    pub async fn start_with(canned: HashMap<(String, RecordType), Canned>) -> Self {
        // One port for both transports: bind TCP on an OS-chosen port, then
        // UDP on the same number (retry if the UDP side is taken).
        let (tcp, udp) = loop {
            let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
            let port = tcp.local_addr().unwrap().port();
            if let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)).await {
                break (tcp, udp);
            }
        };
        let addr = udp.local_addr().unwrap();
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let answers: Answers = Arc::new(Mutex::new(canned));

        let (s1, a1) = (seen.clone(), answers.clone());
        let udp_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                    break;
                };
                if let Some(bytes) = answer(&buf[..n], &a1, &s1, "udp") {
                    let _ = udp.send_to(&bytes, from).await;
                }
            }
        });
        let (s2, a2) = (seen.clone(), answers.clone());
        let tcp_task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = tcp.accept().await else {
                    break;
                };
                let (a, s) = (a2.clone(), s2.clone());
                tokio::spawn(async move {
                    while let Ok(len) = stream.read_u16().await {
                        let mut buf = vec![0u8; len as usize];
                        if stream.read_exact(&mut buf).await.is_err() {
                            break;
                        }
                        if let Some(bytes) = answer(&buf, &a, &s, "tcp") {
                            if stream.write_u16(bytes.len() as u16).await.is_err()
                                || stream.write_all(&bytes).await.is_err()
                            {
                                break;
                            }
                        }
                    }
                });
            }
        });
        Self {
            addr,
            seen,
            answers,
            _udp: udp_task,
            _tcp: tcp_task,
        }
    }

    /// The `--resolver` spelling of this stub over plain 53.
    pub fn choice_plain(&self) -> String {
        format!("127.0.0.1#{}", self.addr.port())
    }

    pub fn saw(&self, name: &str, rt: RecordType) -> bool {
        let want = key(name, rt).0;
        self.seen
            .lock()
            .unwrap()
            .iter()
            .any(|(n, t, _)| *n == want && *t == rt)
    }

    pub fn seen_count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    pub fn seen_via(&self, via: &str) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, _, v)| *v == via)
            .count()
    }
}

/// Key for a canned answer — always the FQDN spelling (trailing dot), which
/// is what hickory puts on the wire.
pub fn key(name: &str, rt: RecordType) -> (String, RecordType) {
    let fqdn = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    };
    (
        Name::from_ascii(fqdn).unwrap().to_lowercase().to_ascii(),
        rt,
    )
}
