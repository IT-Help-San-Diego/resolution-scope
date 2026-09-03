// egress.rs — the socket-layer egress ledger
//
// Every number a surface prints about "what left this machine" comes from
// here, and from nowhere else. The ledger sits UNDER hickory: a
// `RuntimeProvider` that delegates every socket to tokio and records the
// destination the kernel was asked to reach — a UDP datagram only when the
// inner `poll_send_to` returned `Ready(Ok(n))`, a TCP connection only when the
// connect completed, a QUIC socket only when quinn was handed one. A mode flag
// says what the instrument INTENDED; this ledger says what the socket DID.
// (Doctrine: measure, do not derive — a count taken from a mode flag is
// testimony; a count taken at the socket layer is a measurement.)
//
// What the ledger cannot see is said out loud, never guessed: QUIC/H3
// datagrams travel through quinn's own socket (the binder hands it over;
// datagrams never pass through `DnsUdpSocket`), so a QUIC/H3 run reports
// connections and NO datagram count. Names carried over TCP (truncation
// fallback) are not decoded either.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use hickory_proto::op::Message;
use hickory_resolver::config::{ConnectionConfig, ProtocolConfig};
use hickory_resolver::net::runtime::{
    DnsUdpSocket, QuicSocketBinder, RuntimeProvider, TokioHandle, TokioRuntimeProvider, TokioTime,
};
use hickory_resolver::net::NetError;
use hickory_resolver::{ConnectionProvider, PoolContext, Resolver};

/// The resolver type every scan path holds: hickory's `Resolver` over the
/// recording provider. Replaces `TokioResolver` at every construction and
/// lookup site so no lookup can bypass the ledger.
pub type ScopeResolver = Resolver<RecordingProvider>;

/// Which layer an egress event was measured at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer {
    /// hickory asked the provider for a connection (intent, one per pool
    /// connection). `protocol` is the wire word: udp, tcp, tls, https, quic, h3.
    Connection { protocol: &'static str, port: u16 },
    /// A UDP socket was bound for this destination.
    UdpBind,
    /// A UDP datagram left: the kernel accepted `bytes`. `qnames` is decoded
    /// from OUR OWN outbound buffer (plain DNS only) — the names that were
    /// readable on the wire. `decoded` is false when the buffer was not a
    /// parseable DNS message (counted, reported, never dropped).
    UdpSend {
        bytes: usize,
        qnames: Vec<String>,
        decoded: bool,
    },
    /// A TCP connection completed (the kernel's handshake, not TLS).
    TcpConnect,
    /// quinn was handed a UDP socket for this destination (DoQ / DoH3).
    QuicBind,
}

/// One recorded egress event.
#[derive(Debug, Clone)]
pub struct EgressEntry {
    pub dest: SocketAddr,
    pub layer: Layer,
    pub at: SystemTime,
}

/// The outcome of one HTTPS fetch (the MTA-STS policy), as observed.
///
/// The failure variants are classified from the `std::error::Error::source()`
/// chain, never from `Display`: reqwest 0.12's `Display` prints only the kind
/// and the URL ("error sending request for url (…)"), so a substring test on
/// it never sees the layer that failed — a closed port and a wrong
/// certificate print byte-identical text (E8, engine/tests/egress_ledger.rs).
/// hyper-util's connect stage runs DNS → TCP → TLS and names the first two in
/// its chain ("dns error", "tcp connect error", …); a connect-stage failure
/// that names neither is the TLS handshake. Each variant carries the chain
/// verbatim so a surface prints what the library said, joined by " -> ".
///
/// The SNI claim a surface may make follows the stage: `Unresolved` and
/// `ConnectError` — no ClientHello left, the name was NOT sent; `TlsError`
/// and `RequestFailed` — the TCP connection completed and the ClientHello
/// (which carries the name in the clear) was the next thing out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// HTTP status and body bytes read.
    Status(u16, usize),
    /// A 3xx with its Location — recorded, never followed (RFC 8461 §3.3).
    Redirect(u16, String),
    /// The policy host could not be resolved through the vantage: no HTTPS
    /// packet left.
    Unresolved(String),
    /// The TCP connect failed (refused, unreachable, or timed out at the
    /// socket): the SYNs are what left; no TLS handshake began.
    ConnectError(String),
    /// The TCP connection completed and the TLS handshake failed (bad
    /// certificate, alert, EOF): the ClientHello carried the name (SNI).
    TlsError(String),
    /// The TLS session was established and the request failed afterwards
    /// (protocol error, body read): the name was sent, the request left.
    RequestFailed(String),
    /// The 10 s client timeout elapsed. The timeout wraps the whole request
    /// (resolution included), so the stage reached is NOT recorded here.
    Timeout,
    /// The fetch was recorded but has not completed.
    NotAttempted,
}

/// The `source()` chain of an error below its top-level `Display`, joined by
/// " -> " — the text a surface prints verbatim so the user can match it
/// against what the library actually said.
pub fn error_chain(e: &dyn std::error::Error) -> String {
    chain_segments(e).join(" -> ")
}

fn chain_segments(e: &dyn std::error::Error) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = e.source();
    while let Some(s) = cur {
        parts.push(s.to_string());
        cur = s.source();
    }
    parts
}

impl FetchOutcome {
    /// Classify a failed `send()` by the layer that failed, from the typed
    /// source chain (see the enum doc). Order matters: the stage words are
    /// read BEFORE `is_timeout()`, because a TCP connect that timed out at
    /// the socket carries `io::ErrorKind::TimedOut` in its chain and is
    /// still a connect-stage failure (no ClientHello left).
    ///
    /// hyper-util 0.1.20 `ConnectError`'s `Display` is exactly its stage word
    /// (`connect/http.rs`: "dns error"; "tcp connect error", "tcp open
    /// error", "tcp bind local error", … — every socket-stage word begins
    /// with "tcp "). The type is public but its message is not, so the word
    /// is matched on the segment's `Display`, whole, never as a substring of
    /// a longer message.
    pub fn classify(e: &reqwest::Error) -> FetchOutcome {
        let segments = chain_segments(e);
        let chain = segments.join(" -> ");
        let has_dns_stage = segments.iter().any(|s| s == "dns error");
        let has_socket_stage = segments.iter().any(|s| s.starts_with("tcp "));
        if e.is_connect() {
            if has_dns_stage {
                FetchOutcome::Unresolved(chain)
            } else if has_socket_stage {
                FetchOutcome::ConnectError(chain)
            } else if e.is_timeout() {
                FetchOutcome::Timeout
            } else {
                FetchOutcome::TlsError(chain)
            }
        } else if e.is_timeout() {
            FetchOutcome::Timeout
        } else {
            FetchOutcome::RequestFailed(chain)
        }
    }
}

/// One HTTPS fetch: where it went, which addresses were handed to the HTTP
/// client (resolved through the vantage — a lookup result, labelled so), the
/// peer the response actually came from (hyper-util's `getpeername` on the
/// socket the response arrived over — the ONE measured destination; `None`
/// when no response arrived, because reqwest's socket is outside the ledger
/// and a failed connect leaves no peer to read), and what came back.
#[derive(Debug, Clone)]
pub struct FetchEntry {
    pub url: String,
    pub host: String,
    /// Resolved through the vantage — NOT the address connected to.
    pub addrs: Vec<IpAddr>,
    /// The socket peer of the response, when there was a response.
    pub peer: Option<SocketAddr>,
    pub via: String,
    pub outcome: FetchOutcome,
}

#[derive(Default)]
struct Ledger {
    dns: Vec<EgressEntry>,
    fetches: Vec<FetchEntry>,
}

/// The shared ledger. Cloning shares the same underlying record.
#[derive(Clone, Default)]
pub struct EgressLedger(Arc<Mutex<Ledger>>);

impl EgressLedger {
    pub fn new() -> Self {
        Self::default()
    }

    fn record(&self, dest: SocketAddr, layer: Layer) {
        let mut l = self.0.lock().unwrap_or_else(|e| e.into_inner());
        l.dns.push(EgressEntry {
            dest,
            layer,
            at: SystemTime::now(),
        });
    }

    /// Record (or replace, matched by URL) a fetch entry.
    pub fn record_fetch(&self, entry: FetchEntry) {
        let mut l = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = l.fetches.iter_mut().find(|f| f.url == entry.url) {
            *existing = entry;
        } else {
            l.fetches.push(entry);
        }
    }

    /// Take everything recorded so far and reset. Called after the preflight
    /// and after each domain, so every printed block is exact for its scope.
    pub fn drain(&self) -> EgressSnapshot {
        let (dns, fetches) = {
            let mut l = self.0.lock().unwrap_or_else(|e| e.into_inner());
            (std::mem::take(&mut l.dns), std::mem::take(&mut l.fetches))
        };
        EgressSnapshot::from_entries(dns, fetches)
    }

    /// A look at the record without resetting it.
    pub fn peek(&self) -> EgressSnapshot {
        let l = self.0.lock().unwrap_or_else(|e| e.into_inner());
        EgressSnapshot::from_entries(l.dns.clone(), l.fetches.clone())
    }
}

/// Per-destination totals: the wire word hickory used for that connection,
/// datagrams the kernel accepted, TCP connections completed, QUIC sockets
/// handed to quinn.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DestinationTotals {
    pub protocol: &'static str,
    pub datagrams: usize,
    pub tcp_connects: usize,
    pub quic_binds: usize,
}

/// Everything a surface may print about egress, measured at the socket.
#[derive(Debug, Clone, Default)]
pub struct EgressSnapshot {
    /// Distinct socket addresses actually sent to / connected to, in
    /// first-seen order.
    pub per_destination: Vec<(SocketAddr, DestinationTotals)>,
    pub datagrams_sent: usize,
    pub datagram_bytes: usize,
    pub undecoded_datagrams: usize,
    pub tcp_connects: usize,
    pub quic_connections: usize,
    /// Every question name decoded from the datagrams that left, deduplicated,
    /// first-seen order, with the trailing dot hickory writes.
    pub cleartext_qnames: Vec<String>,
    pub fetches: Vec<FetchEntry>,
    /// The raw entries, for tests and for anyone who wants the timeline.
    pub entries: Vec<EgressEntry>,
}

impl EgressSnapshot {
    fn from_entries(entries: Vec<EgressEntry>, fetches: Vec<FetchEntry>) -> Self {
        let mut order: Vec<SocketAddr> = Vec::new();
        let mut totals: BTreeMap<SocketAddr, DestinationTotals> = BTreeMap::new();
        let mut snap = Self {
            fetches,
            ..Default::default()
        };
        let mut seen_names = std::collections::HashSet::new();
        for e in &entries {
            let t = totals.entry(e.dest).or_default();
            match &e.layer {
                Layer::Connection { protocol, .. } => {
                    // Intent only: the destination is listed once something
                    // actually reached it (below), but the wire word is
                    // remembered so the block can name it.
                    if t.protocol.is_empty() {
                        t.protocol = protocol;
                    }
                }
                Layer::UdpBind => {}
                Layer::UdpSend {
                    bytes,
                    qnames,
                    decoded,
                } => {
                    if !order.contains(&e.dest) {
                        order.push(e.dest);
                    }
                    t.datagrams += 1;
                    if t.protocol.is_empty() {
                        t.protocol = "udp";
                    }
                    snap.datagrams_sent += 1;
                    snap.datagram_bytes += bytes;
                    if !decoded {
                        snap.undecoded_datagrams += 1;
                    }
                    for q in qnames {
                        if seen_names.insert(q.clone()) {
                            snap.cleartext_qnames.push(q.clone());
                        }
                    }
                }
                Layer::TcpConnect => {
                    if !order.contains(&e.dest) {
                        order.push(e.dest);
                    }
                    t.tcp_connects += 1;
                    if t.protocol.is_empty() {
                        t.protocol = "tcp";
                    }
                    snap.tcp_connects += 1;
                }
                Layer::QuicBind => {
                    if !order.contains(&e.dest) {
                        order.push(e.dest);
                    }
                    t.quic_binds += 1;
                    if t.protocol.is_empty() {
                        t.protocol = "quic";
                    }
                    snap.quic_connections += 1;
                }
            }
        }
        snap.per_destination = order
            .into_iter()
            .map(|d| (d, totals.remove(&d).unwrap_or_default()))
            .collect();
        snap.entries = entries;
        snap
    }

    /// The set of destinations something was actually sent to.
    pub fn destinations(&self) -> std::collections::BTreeSet<SocketAddr> {
        self.per_destination.iter().map(|(d, _)| *d).collect()
    }

    /// True when nothing at all left through the DNS ledger.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The wire word for a hickory connection protocol. Every arm is spelled by
/// hand; the wildcard exists only for a build with the encrypted transports
/// compiled out (then hickory has no such variants and the arm is unreachable
/// in practice).
pub fn protocol_word(p: &ProtocolConfig) -> &'static str {
    #[cfg(feature = "encrypted-transport")]
    {
        match p {
            ProtocolConfig::Udp => "udp",
            ProtocolConfig::Tcp => "tcp",
            ProtocolConfig::Tls { .. } => "tls",
            ProtocolConfig::Https { .. } => "https",
            ProtocolConfig::Quic { .. } => "quic",
            ProtocolConfig::H3 { .. } => "h3",
        }
    }
    #[cfg(not(feature = "encrypted-transport"))]
    {
        match p {
            ProtocolConfig::Udp => "udp",
            ProtocolConfig::Tcp => "tcp",
            _ => "other",
        }
    }
}

// =============================================================================
// The recording runtime — every socket delegated to tokio, every event recorded
// =============================================================================

/// hickory's `RuntimeProvider`, wrapped: sockets come from tokio, events go to
/// the ledger.
#[derive(Clone)]
pub struct RecordingRuntime {
    inner: TokioRuntimeProvider,
    ledger: EgressLedger,
    #[cfg(feature = "encrypted-transport")]
    quic: Arc<RecordingQuicBinder>,
}

impl RecordingRuntime {
    pub fn new(ledger: EgressLedger) -> Self {
        Self {
            inner: TokioRuntimeProvider::default(),
            #[cfg(feature = "encrypted-transport")]
            quic: Arc::new(RecordingQuicBinder {
                ledger: ledger.clone(),
            }),
            ledger,
        }
    }

    pub fn ledger(&self) -> &EgressLedger {
        &self.ledger
    }
}

/// A UDP socket that records each datagram the kernel accepted.
pub struct RecordingUdp {
    inner: tokio::net::UdpSocket,
    ledger: EgressLedger,
}

impl RecordingUdp {
    /// Wrap an already-bound tokio socket (the test seam for the failed-send
    /// control, which needs a socket the kernel will refuse).
    pub fn wrap(inner: tokio::net::UdpSocket, ledger: EgressLedger) -> Self {
        Self { inner, ledger }
    }
}

/// Decode the question names from an outbound DNS datagram — our own buffer,
/// so this is a decode of what we sent, not a guess about it.
pub fn decode_qnames(buf: &[u8]) -> Option<Vec<String>> {
    let m = Message::from_vec(buf).ok()?;
    Some(
        m.queries
            .iter()
            .map(|q| q.name().to_lowercase().to_ascii())
            .collect(),
    )
}

/// Record one accepted UDP send. Pure over the ledger: the tests feed it an
/// `Ok(n)` and an `Err` and assert the ledger's shape.
pub fn record_udp_send(
    ledger: &EgressLedger,
    target: SocketAddr,
    buf: &[u8],
    sent: &io::Result<usize>,
) {
    if let Ok(n) = sent {
        let (qnames, decoded) = match decode_qnames(buf) {
            Some(q) => (q, true),
            None => (Vec::new(), false),
        };
        ledger.record(
            target,
            Layer::UdpSend {
                bytes: *n,
                qnames,
                decoded,
            },
        );
    }
}

impl DnsUdpSocket for RecordingUdp {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        <tokio::net::UdpSocket as DnsUdpSocket>::poll_recv_from(&self.inner, cx, buf)
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let r = <tokio::net::UdpSocket as DnsUdpSocket>::poll_send_to(&self.inner, cx, buf, target);
        if let Poll::Ready(sent) = &r {
            record_udp_send(&self.ledger, target, buf, sent);
        }
        r
    }
}

impl RuntimeProvider for RecordingRuntime {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = RecordingUdp;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;

    fn create_handle(&self) -> Self::Handle {
        self.inner.create_handle()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
        let fut = self.inner.connect_tcp(server_addr, bind_addr, timeout);
        let ledger = self.ledger.clone();
        Box::pin(async move {
            let r = fut.await;
            if r.is_ok() {
                ledger.record(server_addr, Layer::TcpConnect);
            }
            r
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Udp, io::Error>>>> {
        let fut = self.inner.bind_udp(local_addr, server_addr);
        let ledger = self.ledger.clone();
        Box::pin(async move {
            let sock = fut.await?;
            ledger.record(server_addr, Layer::UdpBind);
            Ok(RecordingUdp {
                inner: sock,
                ledger,
            })
        })
    }

    #[cfg(feature = "encrypted-transport")]
    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        Some(&*self.quic)
    }
}

/// The QUIC socket binder, wrapped: quinn gets tokio's socket, the ledger
/// gets the destination. Datagrams through that socket are quinn's and are
/// NOT counted here — the surfaces say so.
#[cfg(feature = "encrypted-transport")]
pub struct RecordingQuicBinder {
    ledger: EgressLedger,
}

#[cfg(feature = "encrypted-transport")]
impl QuicSocketBinder for RecordingQuicBinder {
    fn bind_quic(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Result<Arc<dyn quinn::AsyncUdpSocket>, io::Error> {
        let inner = TokioRuntimeProvider::default();
        let binder = inner
            .quic_binder()
            .ok_or_else(|| io::Error::other("tokio runtime provides no QUIC binder"))?;
        let r = binder.bind_quic(local_addr, server_addr);
        if r.is_ok() {
            self.ledger.record(server_addr, Layer::QuicBind);
        }
        r
    }
}

// =============================================================================
// The connection provider — records intent, delegates to hickory's blanket impl
// =============================================================================

/// hickory's `ConnectionProvider`, wrapped: records every `new_connection`
/// (destination, protocol word, port) and hands the work to the blanket
/// implementation over `RecordingRuntime`.
#[derive(Clone)]
pub struct RecordingProvider {
    runtime: RecordingRuntime,
}

impl RecordingProvider {
    pub fn new(ledger: EgressLedger) -> Self {
        Self {
            runtime: RecordingRuntime::new(ledger),
        }
    }

    pub fn ledger(&self) -> &EgressLedger {
        self.runtime.ledger()
    }
}

impl ConnectionProvider for RecordingProvider {
    type Conn = <RecordingRuntime as ConnectionProvider>::Conn;
    type FutureConn = <RecordingRuntime as ConnectionProvider>::FutureConn;
    type RuntimeProvider = RecordingRuntime;

    fn new_connection(
        &self,
        ip: IpAddr,
        config: &ConnectionConfig,
        cx: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        self.runtime.ledger.record(
            SocketAddr::new(ip, config.port),
            Layer::Connection {
                protocol: protocol_word(&config.protocol),
                port: config.port,
            },
        );
        self.runtime.new_connection(ip, config, cx)
    }

    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        &self.runtime
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};

    fn dest(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn query_bytes(name: &str) -> Vec<u8> {
        let mut m = Message::query();
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        m.to_vec().unwrap()
    }

    /// E3 — the ledger claims only what the kernel accepted: an `Err` from
    /// the inner socket leaves the ledger empty; an `Ok(n)` records one
    /// datagram with its decoded names.
    #[test]
    fn failed_send_is_never_recorded() {
        let ledger = EgressLedger::new();
        let buf = query_bytes("example.com");
        record_udp_send(
            &ledger,
            dest(53),
            &buf,
            &Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        );
        assert!(
            ledger.peek().is_empty(),
            "a refused send must not be counted"
        );

        record_udp_send(&ledger, dest(53), &buf, &Ok(buf.len()));
        let snap = ledger.drain();
        assert_eq!(snap.datagrams_sent, 1);
        assert_eq!(snap.datagram_bytes, buf.len());
        assert_eq!(snap.cleartext_qnames, vec!["example.com.".to_string()]);
        assert_eq!(snap.undecoded_datagrams, 0);
        assert_eq!(snap.per_destination[0].0, dest(53));
        assert_eq!(snap.per_destination[0].1.datagrams, 1);
    }

    /// An outbound buffer that is not a DNS message is COUNTED and marked
    /// undecoded — never dropped, never guessed.
    #[test]
    fn undecodable_datagram_is_counted_and_marked() {
        let ledger = EgressLedger::new();
        record_udp_send(&ledger, dest(53), b"not dns", &Ok(7));
        let snap = ledger.drain();
        assert_eq!(snap.datagrams_sent, 1);
        assert_eq!(snap.undecoded_datagrams, 1);
        assert!(snap.cleartext_qnames.is_empty());
    }

    /// drain() resets; a second drain is empty; names dedupe in first-seen order.
    #[test]
    fn drain_resets_and_names_dedupe() {
        let ledger = EgressLedger::new();
        for n in ["b.example.", "a.example.", "b.example."] {
            let buf = query_bytes(n);
            record_udp_send(&ledger, dest(53), &buf, &Ok(buf.len()));
        }
        let snap = ledger.drain();
        assert_eq!(snap.datagrams_sent, 3);
        assert_eq!(snap.cleartext_qnames, ["b.example.", "a.example."]);
        assert!(ledger.drain().is_empty());
    }

    /// A TCP connect and a QUIC bind are connections, never datagrams: a
    /// snapshot holding only those has `datagrams_sent == 0`.
    #[test]
    fn connections_are_not_datagrams() {
        let ledger = EgressLedger::new();
        ledger.record(dest(853), Layer::TcpConnect);
        ledger.record(dest(853), Layer::QuicBind);
        let snap = ledger.drain();
        assert_eq!(snap.datagrams_sent, 0);
        assert_eq!(snap.tcp_connects, 1);
        assert_eq!(snap.quic_connections, 1);
        assert_eq!(snap.destinations().len(), 1);
    }

    /// The protocol word is the wire word hickory used — spelled by hand.
    #[test]
    fn protocol_words_are_pinned() {
        assert_eq!(protocol_word(&ProtocolConfig::Udp), "udp");
        assert_eq!(protocol_word(&ProtocolConfig::Tcp), "tcp");
        #[cfg(feature = "encrypted-transport")]
        {
            assert_eq!(
                protocol_word(&ProtocolConfig::Tls {
                    server_name: Arc::from("x")
                }),
                "tls"
            );
            assert_eq!(
                protocol_word(&ProtocolConfig::Https {
                    server_name: Arc::from("x"),
                    path: Arc::from("/dns-query")
                }),
                "https"
            );
            assert_eq!(
                protocol_word(&ProtocolConfig::Quic {
                    server_name: Arc::from("x")
                }),
                "quic"
            );
            assert_eq!(
                protocol_word(&ProtocolConfig::H3 {
                    server_name: Arc::from("x"),
                    path: Arc::from("/dns-query"),
                    disable_grease: false
                }),
                "h3"
            );
        }
    }
}
