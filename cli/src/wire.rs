//! The wire copy — every line about what left this machine.
//!
//! Pure formatters over the engine's socket-layer snapshot and the resolver
//! choice. Every number printed here was measured at the socket
//! (`EgressSnapshot`); every configured fact is labelled "(configured)"; no
//! line prints a TLS version or cipher (hickory does not expose them); a
//! QUIC/H3 run prints no digit before "datagrams" (quinn's sockets are
//! outside the ledger). The user can check each line with tcpdump or lsof,
//! and the line says so before they look.

use std::fmt::Write as _;

use resolution_scope_engine::egress::{EgressSnapshot, FetchOutcome};
use resolution_scope_engine::preflight::{Mode, PreflightRefusal, VantageReceipt};
use resolution_scope_engine::resolver::{ResolverChoice, Target, Transport};

fn addrs_list(ips: &[std::net::IpAddr]) -> String {
    ips.iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The transport phrase of the vantage line: protocol, layer 4, port.
fn transport_phrase(c: &ResolverChoice) -> String {
    let port = c.port();
    match c.transport {
        Transport::Plain => format!("plain DNS on port {port}"),
        Transport::Tcp => format!("plain DNS on TCP port {port}"),
        Transport::Tls => format!("DNS over TLS on TCP port {port}"),
        Transport::Https => format!("DNS over HTTPS on TCP port {port}"),
        Transport::Quic => format!("DNS over QUIC on UDP port {port}"),
        Transport::H3 => format!("DNS over HTTP/3 on UDP port {port}"),
    }
}

fn encryption_sentence(c: &ResolverChoice) -> &'static str {
    if c.transport.is_encrypted() {
        "encrypted: the path sees endpoints and sizes, not the DNS names"
    } else {
        "not encrypted: the names you scan are readable between this machine and the resolver"
    }
}

fn system_conf_source() -> &'static str {
    if cfg!(target_vendor = "apple") {
        "scutil --dns"
    } else if cfg!(unix) {
        "/etc/resolv.conf"
    } else {
        "the operating system"
    }
}

/// The egress summary for the receipt or a wire line: "6 datagrams →
/// 1.1.1.1:53 ×3, 1.0.0.1:53 ×3" / "2 TCP connections → …" / "2 QUIC
/// connections → … (datagrams not counted here)". Zero events → no count.
fn egress_summary(s: &EgressSnapshot) -> String {
    let mut parts = Vec::new();
    if s.datagrams_sent > 0 {
        let dests: Vec<String> = s
            .per_destination
            .iter()
            .filter(|(_, t)| t.datagrams > 0)
            .map(|(d, t)| format!("{d} ×{}", t.datagrams))
            .collect();
        parts.push(format!(
            "{} datagram{} → {}",
            s.datagrams_sent,
            if s.datagrams_sent == 1 { "" } else { "s" },
            dests.join(", ")
        ));
    }
    if s.tcp_connects > 0 {
        let dests: Vec<String> = s
            .per_destination
            .iter()
            .filter(|(_, t)| t.tcp_connects > 0)
            .map(|(d, t)| format!("{d} ×{}", t.tcp_connects))
            .collect();
        parts.push(format!(
            "{} TCP connection{} → {}",
            s.tcp_connects,
            if s.tcp_connects == 1 { "" } else { "s" },
            dests.join(", ")
        ));
    }
    if s.quic_connections > 0 {
        let dests: Vec<String> = s
            .per_destination
            .iter()
            .filter(|(_, t)| t.quic_binds > 0)
            .map(|(d, t)| format!("{d} ×{}", t.quic_binds))
            .collect();
        parts.push(format!(
            "{} QUIC connection{} → {} (datagrams not counted here)",
            s.quic_connections,
            if s.quic_connections == 1 { "" } else { "s" },
            dests.join(", ")
        ));
    }
    if s.undecoded_datagrams > 0 {
        parts.push(format!(
            "{} datagrams could not be decoded",
            s.undecoded_datagrams
        ));
    }
    if parts.is_empty() {
        "nothing left the socket".to_string()
    } else {
        parts.join(" · ")
    }
}

/// The once-per-process vantage block, printed after the preflight passed.
pub fn vantage_line(r: &VantageReceipt, c: &ResolverChoice) -> String {
    let configured = c.configured_addresses();
    let mut s = String::new();
    let first = match &c.target {
        Target::System => format!(
            "vantage {} — this computer's own resolver, {} to {} (configured, read from {}; printed here, never sealed — the seal says \"system\") — {}",
            r.identity,
            transport_phrase(c),
            addrs_list(&configured),
            system_conf_source(),
            encryption_sentence(c)
        ),
        _ => {
            let mut line = format!(
                "vantage {} — {}, {} to {} (configured{})",
                r.identity,
                c.operator(),
                transport_phrase(c),
                addrs_list(&configured),
                if configured.len() >= 2 {
                    "; two asked per lookup"
                } else {
                    ""
                }
            );
            if let Some(name) = c.server_name() {
                let _ = write!(
                    line,
                    ", certificate for {name} checked against the bundled roots{}",
                    if c.transport == Transport::Tls {
                        ", no SNI sent"
                    } else {
                        ""
                    }
                );
            }
            let _ = write!(line, " — {}", encryption_sentence(c));
            line
        }
    };
    s.push_str(&first);
    s.push('\n');
    s.push_str(
        "        DNSSEC is validated here against the root keys (KSK 20326, 38696), never taken on the resolver's word.\n",
    );
    let negative = match (&r.warning, r.mode) {
        (Some(w), _) => w.clone(),
        (None, Mode::UpstreamAndLocal) => format!(
            "dnssec-failed.org → {} (pass: {})",
            r.negative.1,
            r.mode.describe()
        ),
        (None, Mode::LocalOnly) => format!(
            "dnssec-failed.org → {} (pass: {})",
            r.negative.1,
            r.mode.describe()
        ),
    };
    let _ = writeln!(
        s,
        "        controls: root DNSKEY → {} (pass) · {} · {} · {}",
        r.positive.1,
        negative,
        r.at_utc,
        egress_summary(&r.egress)
    );
    s.push_str(
        "        those two control names left this machine for this check; it cannot be skipped.\n",
    );
    s
}

/// The per-domain progress line.
pub fn progress_line(domain: &str, c: &ResolverChoice, controls: usize) -> String {
    let how = match c.transport {
        Transport::Plain => "plain DNS 53".to_string(),
        Transport::Tcp => format!("plain DNS, TCP {}", c.port()),
        Transport::Tls => format!("DNS over TLS {}", c.port()),
        Transport::Https => format!("DNS over HTTPS {}", c.port()),
        Transport::Quic => format!("DNS over QUIC {}", c.port()),
        Transport::H3 => format!("DNS over HTTP/3 {}", c.port()),
    };
    format!(
        "measuring {domain} — {controls} controls · asking {} over {how} · validating here …",
        c.identity()
    )
}

/// What a wire block needs to know beyond the snapshot: facts the CLI
/// measured elsewhere, named so the formatter cannot invent them.
pub struct WireFacts<'a> {
    pub domain: &'a str,
    /// The `_mta-sts` hint was ABSENT (from the disposition, analysis.rs
    /// hint lookup) — the only ground on which "HTTPS none" is printed.
    pub mta_sts_hint_absent: bool,
    /// At least one lookup returned an answer (from the receipts).
    pub answered: bool,
    /// `--store-url` / `RS_STORE_URL`, when set.
    pub store_url: Option<&'a str>,
}

fn tcpdump_filter(c: &ResolverChoice) -> String {
    let p = c.port();
    match c.transport {
        Transport::Plain => format!("udp port {p} or tcp port {p} or tcp port 443"),
        Transport::Tcp => format!("tcp port {p} or tcp port 443"),
        Transport::Tls => format!("tcp port {p} or tcp port 443"),
        Transport::Https => {
            if p == 443 {
                "tcp port 443".to_string()
            } else {
                format!("tcp port {p} or tcp port 443")
            }
        }
        Transport::Quic => format!("udp port {p} or tcp port 443"),
        Transport::H3 => {
            if p == 443 {
                "udp port 443 or tcp port 443".to_string()
            } else {
                format!("udp port {p} or tcp port 443")
            }
        }
    }
}

/// Compress the cleartext name list: the DKIM selector sweep collapses to a
/// count; everything else is listed as it left.
fn cleartext_names(names: &[String], domain: &str) -> String {
    let dk_suffix = format!("._domainkey.{domain}.");
    let dk = names.iter().filter(|n| n.ends_with(&dk_suffix)).count();
    let mut rest: Vec<String> = names
        .iter()
        .filter(|n| !n.ends_with(&dk_suffix))
        .map(|n| n.trim_end_matches('.').to_string())
        .map(|n| if n.is_empty() { ".".to_string() } else { n })
        .collect();
    if dk > 0 {
        rest.push(format!(
            "{dk} <selector>._domainkey.{domain} name{}",
            if dk == 1 { "" } else { "s" }
        ));
    }
    rest.join(", ")
}

/// The per-domain wire block.
pub fn render(s: &EgressSnapshot, c: &ResolverChoice, f: &WireFacts<'_>) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "wire    what left this machine for {}, counted at the socket (this process only):",
        f.domain
    );
    let identity = c.identity();
    let l4 = c.transport.l4();
    let port = c.port();
    let dests: Vec<String> = s
        .per_destination
        .iter()
        .map(|(d, t)| {
            let n = t.datagrams.max(t.tcp_connects).max(t.quic_binds);
            format!("{} ×{n}", d.ip())
        })
        .collect();
    let arrow = if dests.is_empty() {
        "→ (nothing left the socket)".to_string()
    } else {
        format!("→ {}", dests.join(", "))
    };
    match c.transport {
        Transport::Plain | Transport::Tcp => {
            let mut line = format!(
                "        DNS    {identity} — {l4} {port} {arrow} · {} datagram{}, {} TCP connection{}",
                s.datagrams_sent,
                if s.datagrams_sent == 1 { "" } else { "s" },
                s.tcp_connects,
                if s.tcp_connects == 1 { "" } else { "s" }
            );
            if s.tcp_connects > 0 {
                let tcp_dests: Vec<String> = s
                    .per_destination
                    .iter()
                    .filter(|(_, t)| t.tcp_connects > 0)
                    .map(|(d, _)| d.to_string())
                    .collect();
                let _ = write!(
                    line,
                    " → {} (names carried over TCP were not decoded)",
                    tcp_dests.join(", ")
                );
            }
            if s.undecoded_datagrams > 0 {
                let _ = write!(
                    line,
                    " · {} datagrams could not be decoded",
                    s.undecoded_datagrams
                );
            }
            out.push_str(&line);
            out.push('\n');
            if !s.cleartext_qnames.is_empty() {
                let _ = writeln!(
                    out,
                    "               in the clear on the path (decoded from the datagrams sent): {}",
                    cleartext_names(&s.cleartext_qnames, f.domain)
                );
            }
            if let Target::System = c.target {
                let first = s
                    .per_destination
                    .first()
                    .map(|(d, _)| d.ip().to_string())
                    .unwrap_or_else(|| "the resolver".to_string());
                let _ = writeln!(
                    out,
                    "               plain DNS; if {first} forwards elsewhere, tcpdump on this machine shows only the first hop (systemd-resolved's 127.0.0.53 and VPN split-DNS are such first hops)"
                );
            }
        }
        Transport::Tls | Transport::Https => {
            let mut line = format!(
                "        DNS    {identity} — {l4} {port} {arrow} · {} connection{}, {} datagrams",
                s.tcp_connects,
                if s.tcp_connects == 1 { "" } else { "s" },
                s.datagrams_sent
            );
            if f.answered && s.tcp_connects > 0 {
                let _ = write!(
                    line,
                    " · answers arrived over TLS, so the handshake completed with the certificate for {} verified (this build holds no plain fallback)",
                    c.server_name().unwrap_or_default()
                );
                if c.transport == Transport::Tls {
                    line.push_str("; no SNI is sent on 853");
                }
            }
            out.push_str(&line);
            out.push('\n');
            out.push_str(
                "               encrypted: the path sees endpoints and sizes, not the DNS names — the HTTPS line below is the one place the domain is visible (SNI)\n",
            );
        }
        Transport::Quic | Transport::H3 => {
            let _ = writeln!(
                out,
                "        DNS    {identity} — {l4} {port} {arrow} · {} connection{} · datagrams not counted here (QUIC sockets are opened by quinn, outside the ledger) — tcpdump udp port {port}",
                s.quic_connections,
                if s.quic_connections == 1 { "" } else { "s" }
            );
            out.push_str(
                "               encrypted: the path sees endpoints and sizes, not the DNS names — the HTTPS line below is the one place the domain is visible (SNI)\n",
            );
        }
    }

    // HTTPS: the MTA-STS policy fetch. "none" ONLY from the hint-absent fact.
    if f.mta_sts_hint_absent {
        let _ = writeln!(
            out,
            "        HTTPS  none — {} publishes no _mta-sts record; nothing was fetched",
            f.domain
        );
    } else if let Some(fe) = s.fetches.first() {
        let addrs = if fe.addrs.is_empty() {
            "(address unresolved)".to_string()
        } else {
            addrs_list(&fe.addrs)
        };
        let outcome = match &fe.outcome {
            FetchOutcome::Status(code, bytes) if (200..300).contains(code) => format!(
                "{code}, {bytes} bytes, policy read — the name {} is visible in that TLS handshake (SNI); redirects are never followed (RFC 8461 §3.3)",
                fe.host
            ),
            FetchOutcome::Status(code, bytes) => format!(
                "{code}, {bytes} bytes — not a policy; the name {} was visible in that TLS handshake (SNI)",
                fe.host
            ),
            FetchOutcome::Redirect(code, location) => format!(
                "{code} to {location} — not followed (RFC 8461 §3.3): the policy is not servable from the domain"
            ),
            FetchOutcome::ConnectError(e) => {
                format!("{e} — the connection attempt is what left; nothing further was sent")
            }
            FetchOutcome::TlsError(e) => {
                format!("{e} — the name {} was visible in that attempt (SNI)", fe.host)
            }
            FetchOutcome::Timeout => "timed out after 10 s".to_string(),
            FetchOutcome::NotAttempted => "not attempted".to_string(),
        };
        let _ = writeln!(
            out,
            "        HTTPS  {} → {addrs} (address via {}) · TCP 443 · {outcome}",
            fe.host, fe.via
        );
    } else {
        let _ = writeln!(
            out,
            "        HTTPS  the _mta-sts hint could not be measured for {}; no policy fetch was attempted",
            f.domain
        );
    }
    if let Some(url) = f.store_url {
        let _ = writeln!(
            out,
            "        store  {} (the sealed-history database you configured — configured, not counted at the socket)",
            store_host(url)
        );
    }
    let _ = writeln!(
        out,
        "        check it yourself: sudo tcpdump -ni any '{}' · lsof -nP -i -a -p <pid>",
        tcpdump_filter(c)
    );
    out
}

/// The host:port of a store DSN, never its credentials.
fn store_host(url: &str) -> String {
    let after = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let after = after.rsplit_once('@').map(|(_, r)| r).unwrap_or(after);
    after.split('/').next().unwrap_or(after).to_string()
}

/// The refusal block (exit 3, nothing sealed).
pub fn refusal(r: &PreflightRefusal, c: &ResolverChoice) -> String {
    let identity = c.identity();
    let configured = c.configured_addresses();
    let mut s = String::new();
    match r {
        PreflightRefusal::CannotValidate { positive } => {
            let who = match &c.target {
                Target::System => format!("system ({})", addrs_list(&configured)),
                _ => identity.clone(),
            };
            let _ = writeln!(
                s,
                "vantage refused: {who} cannot validate DNSSEC — the root DNSKEY came back {positive}, not Secure. The answer carried no DNSSEC signatures (a forwarder on the path strips them, or the resolver never asked for them), so every domain would read \"broken chain\", falsely. Nothing was sealed."
            );
            if cfg!(unix) {
                let _ = writeln!(
                    s,
                    "                 check: dig +dnssec . DNSKEY @{}   (an honest resolver returns RRSIG records)",
                    configured
                        .first()
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "<resolver>".into())
                );
            }
            s.push_str("                 try:   --resolver cloudflare   or, to encrypt the questions: --resolver tls://quad9\n");
        }
        PreflightRefusal::NegativeNotRefused { negative } => {
            let _ = writeln!(
                s,
                "vantage refused: {identity} accepted a known-bad signature — dnssec-failed.org came back {negative}; this vantage cannot tell a broken chain from a good one. Nothing was sealed."
            );
            s.push_str("                 try:   --resolver cloudflare   or, to encrypt the questions: --resolver tls://quad9\n");
        }
        PreflightRefusal::NegativeUnreachable { negative } => {
            let _ = writeln!(
                s,
                "vantage refused: {identity} — the negative control dnssec-failed.org could not be reached ({negative}); an unnamed vantage must prove it rejects a bad signature before anything is sealed. Nothing was sealed."
            );
        }
        PreflightRefusal::Transport { display, debug } => {
            let lib = match c.transport {
                Transport::Plain | Transport::Tcp => "hickory-resolver 0.26.1".to_string(),
                Transport::Tls => "hickory-resolver 0.26.1, tls-ring".to_string(),
                Transport::Https => "hickory-resolver 0.26.1, https-ring".to_string(),
                Transport::Quic => "hickory-resolver 0.26.1, quic-ring".to_string(),
                Transport::H3 => "hickory-resolver 0.26.1, h3-ring".to_string(),
            };
            let _ = write!(
                s,
                "vantage refused: {identity} — no answer over {} from {} ({lib}: \"{display}\" / Debug: {debug}). Not falling back to plain DNS.",
                transport_phrase(c),
                addrs_list(&configured)
            );
            match c.transport {
                Transport::Tls => s.push_str(" hickory sends no SNI on 853; a resolver that requires SNI answers over https://. hickory reports a failed certificate or SNI check only as this string (measured 2026-09-03)."),
                Transport::Quic => s.push_str(" When measured 2026-09-03 only Quad9 answered DoQ; try h3://cloudflare or quic://quad9."),
                Transport::H3 => s.push_str(" When measured 2026-09-03 Cloudflare and Google answered DoH3; try https:// for the others."),
                _ => {}
            }
            s.push_str(" Nothing was sealed.\n");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use resolution_scope_engine::egress::{EgressLedger, FetchEntry};
    use resolution_scope_engine::preflight::ControlOutcome;
    use std::net::SocketAddr;

    fn choice(s: &str) -> ResolverChoice {
        s.parse().unwrap()
    }

    /// A snapshot with N udp datagrams to `dest`, built through the ledger's
    /// own recording path (never hand-assembled).
    fn udp_snapshot(dest: SocketAddr, names: &[&str]) -> EgressSnapshot {
        use hickory_resolver::proto::op::{Message, Query};
        use hickory_resolver::proto::rr::{Name, RecordType};
        let ledger = EgressLedger::new();
        for n in names {
            let mut m = Message::query();
            m.add_query(Query::query(Name::from_ascii(n).unwrap(), RecordType::A));
            let buf = m.to_vec().unwrap();
            resolution_scope_engine::egress::record_udp_send(&ledger, dest, &buf, &Ok(buf.len()));
        }
        ledger.drain()
    }

    fn facts<'a>(domain: &'a str, hint_absent: bool, answered: bool) -> WireFacts<'a> {
        WireFacts {
            domain,
            mta_sts_hint_absent: hint_absent,
            answered,
            store_url: None,
        }
    }

    /// W1 — the wire lines are pinned.
    #[test]
    fn wire_lines_are_pinned() {
        let dest: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let snap = udp_snapshot(
            dest,
            &[
                "example.com.",
                "_dmarc.example.com.",
                "s1._domainkey.example.com.",
                "s2._domainkey.example.com.",
            ],
        );
        let text = render(
            &snap,
            &choice("cloudflare"),
            &facts("example.com", true, true),
        );
        assert_eq!(
            text,
            "wire    what left this machine for example.com, counted at the socket (this process only):\n\
             \x20       DNS    cloudflare — UDP 53 → 1.1.1.1 ×4 · 4 datagrams, 0 TCP connections\n\
             \x20              in the clear on the path (decoded from the datagrams sent): example.com, _dmarc.example.com, 2 <selector>._domainkey.example.com names\n\
             \x20       HTTPS  none — example.com publishes no _mta-sts record; nothing was fetched\n\
             \x20       check it yourself: sudo tcpdump -ni any 'udp port 53 or tcp port 53 or tcp port 443' · lsof -nP -i -a -p <pid>\n"
        );

        // A fetch that read a policy.
        let mut with_fetch = snap.clone();
        with_fetch.fetches.push(FetchEntry {
            url: "https://mta-sts.example.com/.well-known/mta-sts.txt".into(),
            host: "mta-sts.example.com".into(),
            addrs: vec!["203.0.113.7".parse().unwrap()],
            via: "cloudflare".into(),
            outcome: FetchOutcome::Status(200, 143),
        });
        let text = render(
            &with_fetch,
            &choice("cloudflare"),
            &facts("example.com", false, true),
        );
        assert!(text.contains("        HTTPS  mta-sts.example.com → 203.0.113.7 (address via cloudflare) · TCP 443 · 200, 143 bytes, policy read — the name mta-sts.example.com is visible in that TLS handshake (SNI); redirects are never followed (RFC 8461 §3.3)\n"), "{text}");

        // A redirect is recorded, never followed.
        with_fetch.fetches[0].outcome =
            FetchOutcome::Redirect(301, "https://policy.example.net/x".into());
        let text = render(
            &with_fetch,
            &choice("cloudflare"),
            &facts("example.com", false, true),
        );
        assert!(text.contains("· TCP 443 · 301 to https://policy.example.net/x — not followed (RFC 8461 §3.3): the policy is not servable from the domain\n"), "{text}");

        // A refused connection.
        with_fetch.fetches[0].outcome = FetchOutcome::ConnectError("connection refused".into());
        let text = render(
            &with_fetch,
            &choice("cloudflare"),
            &facts("example.com", false, true),
        );
        assert!(text.contains("· TCP 443 · connection refused — the connection attempt is what left; nothing further was sent\n"), "{text}");

        // The store line only when configured, host only, never credentials.
        let f = WireFacts {
            store_url: Some("postgres://u:hunter2@localhost:5435/resolution_scope"),
            ..facts("example.com", true, true)
        };
        let text = render(&snap, &choice("cloudflare"), &f);
        assert!(text.contains("        store  localhost:5435 (the sealed-history database you configured — configured, not counted at the socket)\n"), "{text}");
        assert!(!text.contains("hunter2"));
    }

    /// A TLS vantage: connections, "0 datagrams", the TLS sentence only when answered.
    #[test]
    fn tls_lines_count_connections_and_never_print_a_tls_version() {
        let ledger = EgressLedger::new();
        let snap = {
            // Two completed TCP connects to 9.9.9.9:853, recorded through the runtime path.
            let dest: SocketAddr = "9.9.9.9:853".parse().unwrap();
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                use hickory_resolver::net::runtime::RuntimeProvider;
                let p = resolution_scope_engine::egress::RecordingRuntime::new(ledger.clone());
                // A closed local port: the connect fails, so nothing is recorded — the negative.
                let closed: SocketAddr = "127.0.0.1:1".parse().unwrap();
                let r = p
                    .connect_tcp(closed, None, Some(std::time::Duration::from_millis(200)))
                    .await;
                assert!(r.is_err(), "port 1 on loopback is closed");
                assert!(
                    ledger.peek().is_empty(),
                    "a failed connect is never recorded"
                );
            });
            let _ = dest;
            // The positive: an accepted connect through the same path.
            let rt2 = tokio::runtime::Runtime::new().unwrap();
            rt2.block_on(async {
                use hickory_resolver::net::runtime::RuntimeProvider;
                let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = l.local_addr().unwrap();
                let p = resolution_scope_engine::egress::RecordingRuntime::new(ledger.clone());
                let s = p
                    .connect_tcp(addr, None, Some(std::time::Duration::from_secs(2)))
                    .await;
                assert!(s.is_ok());
                let s2 = p
                    .connect_tcp(addr, None, Some(std::time::Duration::from_secs(2)))
                    .await;
                assert!(s2.is_ok());
            });
            ledger.drain()
        };
        assert_eq!(snap.tcp_connects, 2);
        let c: ResolverChoice = format!("tls://{}/dns.quad9.net", snap.per_destination[0].0.ip())
            .parse()
            .unwrap();
        // The identity of a loopback address under tls carries its port when non-default.
        let text = render(&snap, &c, &facts("example.com", true, true));
        assert!(text.contains(" · 2 connections, 0 datagrams · answers arrived over TLS, so the handshake completed with the certificate for dns.quad9.net verified (this build holds no plain fallback); no SNI is sent on 853\n"), "{text}");
        assert!(
            !text.to_lowercase().contains("tls 1."),
            "no TLS version is ever printed"
        );
        assert!(!text.contains("cipher"));
        // Not answered → no TLS sentence.
        let text = render(&snap, &c, &facts("example.com", true, false));
        assert!(!text.contains("answers arrived over TLS"), "{text}");
    }

    /// A QUIC/H3 snapshot never prints a digit before "datagrams".
    #[test]
    fn quic_lines_never_count_datagrams() {
        let snap = EgressSnapshot::default();
        for c in [choice("quic://quad9"), choice("h3://cloudflare")] {
            let text = render(&snap, &c, &facts("example.com", true, true));
            let dns_line = text.lines().nth(1).unwrap();
            assert!(dns_line.contains("datagrams not counted here (QUIC sockets are opened by quinn, outside the ledger)"), "{dns_line}");
            let before = dns_line.split("datagrams").next().unwrap();
            let last_token = before.trim_end().rsplit(' ').next().unwrap();
            assert!(
                !last_token.chars().all(|ch| ch.is_ascii_digit()),
                "a digit before 'datagrams' on a QUIC line: {dns_line}"
            );
        }
    }

    /// Zero events → no count on the vantage receipt.
    #[test]
    fn empty_snapshot_prints_no_count() {
        assert_eq!(
            egress_summary(&EgressSnapshot::default()),
            "nothing left the socket"
        );
        let dest: SocketAddr = "1.1.1.1:53".parse().unwrap();
        assert_eq!(
            egress_summary(&udp_snapshot(dest, &["a.", "b.", "c."])),
            "3 datagrams → 1.1.1.1:53 ×3"
        );
    }

    fn receipt(
        identity: &str,
        mode: Mode,
        negative: ControlOutcome,
        warning: Option<String>,
    ) -> VantageReceipt {
        VantageReceipt {
            identity: identity.into(),
            mode,
            positive: (".", ControlOutcome::Secure),
            negative: ("dnssec-failed.org", negative),
            at_utc: "2026-09-03T05:13:35Z".into(),
            warning,
            egress: udp_snapshot("1.1.1.1:53".parse().unwrap(), &[".", "dnssec-failed.org."]),
        }
    }

    #[test]
    fn vantage_lines_are_pinned() {
        let r = receipt(
            "cloudflare",
            Mode::UpstreamAndLocal,
            ControlOutcome::ServFail,
            None,
        );
        let text = vantage_line(&r, &choice("cloudflare"));
        assert_eq!(
            text,
            "vantage cloudflare — Cloudflare, plain DNS on port 53 to 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001 (configured; two asked per lookup) — not encrypted: the names you scan are readable between this machine and the resolver\n\
             \x20       DNSSEC is validated here against the root keys (KSK 20326, 38696), never taken on the resolver's word.\n\
             \x20       controls: root DNSKEY → Secure (pass) · dnssec-failed.org → SERVFAIL (pass: the resolver validates too) · 2026-09-03T05:13:35Z · 2 datagrams → 1.1.1.1:53 ×2\n\
             \x20       those two control names left this machine for this check; it cannot be skipped.\n"
        );
        let r = receipt(
            "quad9/tls",
            Mode::UpstreamAndLocal,
            ControlOutcome::ServFail,
            None,
        );
        let text = vantage_line(&r, &choice("tls://quad9"));
        assert!(text.starts_with("vantage quad9/tls — Quad9, DNS over TLS on TCP port 853 to 9.9.9.9, 149.112.112.112, 2620:fe::fe, 2620:fe::9 (configured; two asked per lookup), certificate for dns.quad9.net checked against the bundled roots, no SNI sent — encrypted: the path sees endpoints and sizes, not the DNS names\n"), "{text}");
        let w = "dnssec-failed.org → unreachable: request timed out (warning: the negative control could not be exercised; DNSSEC verdicts stand on the root-key check alone)".to_string();
        let r = receipt(
            "quad9",
            Mode::LocalOnly,
            ControlOutcome::Timeout("request timed out".into()),
            Some(w.clone()),
        );
        let text = vantage_line(&r, &choice("quad9"));
        assert!(
            text.contains(&format!(
                "controls: root DNSKEY → Secure (pass) · {w} · 2026-09-03T05:13:35Z"
            )),
            "{text}"
        );
        let r = receipt("system", Mode::LocalOnly, ControlOutcome::Bogus, None);
        let text = vantage_line(&r, &choice("system"));
        assert!(
            text.starts_with(
                "vantage system — this computer's own resolver, plain DNS on port 53 to "
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "printed here, never sealed — the seal says \"system\") — not encrypted:"
            ),
            "{text}"
        );
        assert!(text.contains("dnssec-failed.org → Bogus (pass: validation is local only; this resolver does not validate)"), "{text}");
    }

    #[test]
    fn refusals_name_the_fix() {
        let r = PreflightRefusal::CannotValidate {
            positive: ControlOutcome::Bogus,
        };
        let text = refusal(&r, &choice("192.168.1.1"));
        assert!(text.starts_with("vantage refused: 192.168.1.1 cannot validate DNSSEC — the root DNSKEY came back Bogus, not Secure. The answer carried no DNSSEC signatures"), "{text}");
        assert!(text.contains(
            "try:   --resolver cloudflare   or, to encrypt the questions: --resolver tls://quad9"
        ));
        let r = PreflightRefusal::Transport {
            display: "request timed out".into(),
            debug: "Timeout".into(),
        };
        let text = refusal(&r, &choice("quic://cloudflare"));
        assert!(text.starts_with("vantage refused: cloudflare/quic — no answer over DNS over QUIC on UDP port 853 from 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001 (hickory-resolver 0.26.1, quic-ring: \"request timed out\" / Debug: Timeout). Not falling back to plain DNS."), "{text}");
        assert!(text.contains("try h3://cloudflare or quic://quad9"));
        let r = PreflightRefusal::Transport {
            display: "no connections available".into(),
            debug: "NoConnections".into(),
        };
        let text = refusal(&r, &choice("tls://94.140.14.140/dns.adguard-dns.com"));
        assert!(text.starts_with("vantage refused: 94.140.14.140/tls/dns.adguard-dns.com — no answer over DNS over TLS on TCP port 853 from 94.140.14.140 (hickory-resolver 0.26.1, tls-ring: \"no connections available\" / Debug: NoConnections). Not falling back to plain DNS. hickory sends no SNI on 853; a resolver that requires SNI answers over https://."), "{text}");
    }

    #[test]
    fn progress_line_names_the_transport() {
        assert_eq!(
            progress_line("example.com", &choice("cloudflare"), 10),
            "measuring example.com — 10 controls · asking cloudflare over plain DNS 53 · validating here …"
        );
        assert_eq!(
            progress_line("example.com", &choice("tls://quad9"), 10),
            "measuring example.com — 10 controls · asking quad9/tls over DNS over TLS 853 · validating here …"
        );
    }
}
