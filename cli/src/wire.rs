//! The wire copy — every line about what left this machine.
//!
//! Pure formatters over the engine's socket-layer snapshot and the resolver
//! choice. Every number printed here was measured at the socket
//! (`EgressSnapshot`); every configured fact is labelled "(configured)"; no
//! line prints a TLS version or cipher (hickory does not expose them); a
//! QUIC/H3 run prints no digit before "datagrams" and counts sockets
//! opened, never connections (quinn's handshake and datagrams are outside
//! the ledger; the bind is what it sees). The user can check each line with tcpdump or lsof,
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

/// Where the system choice's addresses were read from — named so the user
/// can read the same source. On macOS hickory-resolver 0.26.1 reads
/// `State:/Network/Global/DNS` from the System Configuration store: the
/// GLOBAL resolver only, the first block of `scutil --dns`; a VPN's scoped
/// or per-domain resolvers are not read and never asked.
fn system_conf_source() -> &'static str {
    if cfg!(target_vendor = "apple") {
        "the global resolver only — the first block of scutil --dns; a VPN's scoped or per-domain resolvers are not read and never asked"
    } else if cfg!(unix) {
        "/etc/resolv.conf"
    } else {
        "the operating system"
    }
}

/// The egress summary for the receipt or a wire line: "6 datagrams →
/// 1.1.1.1:53 ×3, 1.0.0.1:53 ×3" / "2 TCP connections → …" / "2 QUIC
/// sockets opened → … (connections and datagrams not counted here)". Zero
/// events → no count. A QUIC count is SOCKETS handed to quinn (what lsof
/// shows), never connections: the ledger does not see quinn's handshake,
/// and a fully timed-out DoQ run opens sockets all the same.
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
    if s.quic_sockets > 0 {
        let dests: Vec<String> = s
            .per_destination
            .iter()
            .filter(|(_, t)| t.quic_binds > 0)
            .map(|(d, t)| format!("{d} ×{}", t.quic_binds))
            .collect();
        parts.push(format!(
            "{} QUIC socket{} opened → {} (connections and datagrams not counted here)",
            s.quic_sockets,
            if s.quic_sockets == 1 { "" } else { "s" },
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
                "        DNS    {identity} — {l4} {port} {arrow} · {} QUIC socket{} opened · connections and datagrams not counted here (quinn owns the socket; the ledger sees the bind, not the handshake) — tcpdump udp port {port}",
                s.quic_sockets,
                if s.quic_sockets == 1 { "" } else { "s" }
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
        // Behind the arrow sits ONLY the socket peer (hyper-util's
        // getpeername on the socket the response came over). The resolved
        // set is a lookup result: hyper-util connects to one address (the
        // next only on error), so the set is listed as "resolved", never as
        // where the bytes went. No response → no peer, and the line says so
        // rather than promoting the lookup to a measurement.
        let destination = match &fe.peer {
            Some(peer) => format!("{peer} (socket peer)"),
            None => "peer not recorded (no response; reqwest's socket is outside the ledger)"
                .to_string(),
        };
        let resolved = if fe.addrs.is_empty() {
            format!("resolved via {}: no address", fe.via)
        } else {
            format!("resolved via {}: {}", fe.via, addrs_list(&fe.addrs))
        };
        let outcome = match &fe.outcome {
            FetchOutcome::Status(code, bytes) if (200..300).contains(code) => format!(
                "{code}, {bytes} bytes, policy read — the name {} is visible in that TLS handshake (SNI); redirects are never followed",
                fe.host
            ),
            FetchOutcome::Status(code, bytes) => format!(
                "{code}, {bytes} bytes — not a policy; the name {} was visible in that TLS handshake (SNI)",
                fe.host
            ),
            FetchOutcome::Redirect(code, location) => format!(
                "{code} to {location} — not followed: the policy is not servable from the domain"
            ),
            FetchOutcome::Unresolved(e) => format!(
                "no HTTPS packet left: {} could not be resolved through {} ({e})",
                fe.host, fe.via
            ),
            FetchOutcome::ConnectError(e) => format!(
                "TCP connect on port 443 failed ({e}) — the SYNs are what left; no TLS handshake began, so the name {} was not sent",
                fe.host
            ),
            FetchOutcome::TlsError(e) => format!(
                "the TCP connection completed and the TLS handshake failed ({e}) — the ClientHello that opens it carries the name {} in the clear (SNI)",
                fe.host
            ),
            FetchOutcome::RequestFailed(e) => format!(
                "the TLS session was established (the name {} was visible, SNI) and the request failed afterwards ({e})",
                fe.host
            ),
            FetchOutcome::Timeout => {
                "timed out after 10 s — the stage reached was not recorded".to_string()
            }
            FetchOutcome::NotAttempted => "not attempted".to_string(),
        };
        let _ = writeln!(
            out,
            "        HTTPS  {} → {destination} · {resolved} · {} · {outcome}",
            fe.host,
            connection_claim(&fe.outcome)
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

/// The transport/port token of the HTTPS line, printed ONLY when a
/// connection was attempted. `Unresolved` never reached the socket (the
/// name did not resolve, so no SYN left for :443) and `NotAttempted` never
/// started; both say "no connection attempted" rather than name a port no
/// packet went to. `Timeout` wraps the whole request and the stage reached
/// was not recorded, so the line does not claim a connect either way.
/// `ConnectError` and every later stage attempted the connect: "TCP 443".
fn connection_claim(outcome: &FetchOutcome) -> &'static str {
    match outcome {
        FetchOutcome::Unresolved(_) | FetchOutcome::NotAttempted => "no connection attempted",
        FetchOutcome::Timeout => "connection attempt not recorded",
        FetchOutcome::Status(..)
        | FetchOutcome::Redirect(..)
        | FetchOutcome::ConnectError(_)
        | FetchOutcome::TlsError(_)
        | FetchOutcome::RequestFailed(_) => "TCP 443",
    }
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
    use resolution_scope_engine::egress::{DestinationTotals, EgressLedger, FetchEntry};
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

        // A fetch that read a policy: two addresses resolved, ONE peer
        // measured (the socket the response came over). The peer sits
        // behind the arrow; the resolved set is labelled a lookup result.
        let mut with_fetch = snap.clone();
        with_fetch.fetches.push(FetchEntry {
            url: "https://mta-sts.example.com/.well-known/mta-sts.txt".into(),
            host: "mta-sts.example.com".into(),
            addrs: vec![
                "203.0.113.7".parse().unwrap(),
                "2001:db8::7".parse().unwrap(),
            ],
            peer: Some("[2001:db8::7]:443".parse().unwrap()),
            via: "cloudflare".into(),
            outcome: FetchOutcome::Status(200, 143),
        });
        let text = render(
            &with_fetch,
            &choice("cloudflare"),
            &facts("example.com", false, true),
        );
        assert!(text.contains("        HTTPS  mta-sts.example.com → [2001:db8::7]:443 (socket peer) · resolved via cloudflare: 203.0.113.7, 2001:db8::7 · TCP 443 · 200, 143 bytes, policy read — the name mta-sts.example.com is visible in that TLS handshake (SNI); redirects are never followed\n"), "{text}");
        // Negative control on the arrow: the unconnected address is never
        // printed behind it (mutant: put `addrs` behind the arrow → fails).
        let https_line = text.lines().find(|l| l.contains("HTTPS  mta-sts")).unwrap();
        let behind_arrow = https_line.split('→').nth(1).unwrap();
        let behind_arrow = behind_arrow.split('·').next().unwrap();
        assert!(
            !behind_arrow.contains("203.0.113.7"),
            "a lookup result behind the measured-destination arrow: {https_line}"
        );

        // A redirect is recorded, never followed.
        with_fetch.fetches[0].outcome =
            FetchOutcome::Redirect(301, "https://policy.example.net/x".into());
        let text = render(
            &with_fetch,
            &choice("cloudflare"),
            &facts("example.com", false, true),
        );
        assert!(text.contains("· TCP 443 · 301 to https://policy.example.net/x — not followed: the policy is not servable from the domain\n"), "{text}");

        // A refused connection: no response, so no peer — said so, never
        // filled in from the lookup. The chain text is what reqwest 0.12.28
        // / hyper-util 0.1.20 yield for a closed loopback port (E8).
        with_fetch.fetches[0].peer = None;
        with_fetch.fetches[0].outcome = FetchOutcome::ConnectError(
            "client error (Connect) -> tcp connect error -> Connection refused (os error 61)"
                .into(),
        );
        let text = render(
            &with_fetch,
            &choice("cloudflare"),
            &facts("example.com", false, true),
        );
        assert!(text.contains("        HTTPS  mta-sts.example.com → peer not recorded (no response; reqwest's socket is outside the ledger) · resolved via cloudflare: 203.0.113.7, 2001:db8::7 · TCP 443 · TCP connect on port 443 failed (client error (Connect) -> tcp connect error -> Connection refused (os error 61)) — the SYNs are what left; no TLS handshake began, so the name mta-sts.example.com was not sent\n"), "{text}");

        // A TLS failure: the handshake began, so the name left in the
        // ClientHello — the opposite SNI claim from the connect failure.
        with_fetch.fetches[0].outcome = FetchOutcome::TlsError(
            "client error (Connect) -> invalid peer certificate: UnknownIssuer".into(),
        );
        let text = render(
            &with_fetch,
            &choice("cloudflare"),
            &facts("example.com", false, true),
        );
        assert!(text.contains("· TCP 443 · the TCP connection completed and the TLS handshake failed (client error (Connect) -> invalid peer certificate: UnknownIssuer) — the ClientHello that opens it carries the name mta-sts.example.com in the clear (SNI)\n"), "{text}");

        // Unresolved: no address, no packet — and so no port claimed. The
        // NEGATIVE control for `connection_claim`: the name never resolved,
        // no SYN left for :443, and the line must not print "TCP 443"
        // (mutant: `connection_claim` returns "TCP 443" for every arm →
        // the `!contains` fails). The POSITIVE is the ConnectError line
        // above, where the SYNs did leave and "· TCP 443 ·" is printed.
        with_fetch.fetches[0].addrs.clear();
        with_fetch.fetches[0].outcome = FetchOutcome::Unresolved(
            "client error (Connect) -> dns error -> no record found for Query { name: Name(\"mta-sts.example.com.\"), query_type: A, query_class: IN }".into(),
        );
        let text = render(
            &with_fetch,
            &choice("cloudflare"),
            &facts("example.com", false, true),
        );
        assert!(text.contains("        HTTPS  mta-sts.example.com → peer not recorded (no response; reqwest's socket is outside the ledger) · resolved via cloudflare: no address · no connection attempted · no HTTPS packet left: mta-sts.example.com could not be resolved through cloudflare (client error (Connect) -> dns error -> "), "{text}");
        let https_line = text.lines().find(|l| l.contains("HTTPS  mta-sts")).unwrap();
        assert!(
            !https_line.contains("443"),
            "a port no packet went to, printed on the Unresolved line: {https_line}"
        );

        // NotAttempted: the entry recorded before the fetch began and never
        // updated — nothing was connected, so nothing is claimed.
        with_fetch.fetches[0].outcome = FetchOutcome::NotAttempted;
        let text = render(
            &with_fetch,
            &choice("cloudflare"),
            &facts("example.com", false, true),
        );
        assert!(
            text.contains(
                "· resolved via cloudflare: no address · no connection attempted · not attempted\n"
            ),
            "{text}"
        );

        // The timeout wraps the whole request: no stage claim, no SNI
        // claim, no connect claim — the stage reached was not recorded.
        with_fetch.fetches[0].outcome = FetchOutcome::Timeout;
        let text = render(
            &with_fetch,
            &choice("cloudflare"),
            &facts("example.com", false, true),
        );
        assert!(
            text.contains(
                "· connection attempt not recorded · timed out after 10 s — the stage reached was not recorded\n"
            ),
            "{text}"
        );
        assert!(!text.contains("SNI)\n"), "{text}");
        assert!(!text.contains("TCP 443"), "{text}");

        // Every arm of `connection_claim`, pinned: the port is printed for
        // ConnectError and every later stage, and for nothing earlier.
        for (outcome, claim) in [
            (
                FetchOutcome::Unresolved("x".into()),
                "no connection attempted",
            ),
            (FetchOutcome::NotAttempted, "no connection attempted"),
            (FetchOutcome::Timeout, "connection attempt not recorded"),
            (FetchOutcome::ConnectError("x".into()), "TCP 443"),
            (FetchOutcome::TlsError("x".into()), "TCP 443"),
            (FetchOutcome::RequestFailed("x".into()), "TCP 443"),
            (FetchOutcome::Redirect(301, "x".into()), "TCP 443"),
            (FetchOutcome::Status(200, 1), "TCP 443"),
        ] {
            assert_eq!(connection_claim(&outcome), claim, "{outcome:?}");
        }

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

    /// A QUIC/H3 snapshot never prints a digit before "datagrams", and never
    /// calls a socket a connection: `quic_sockets` counts UDP sockets handed
    /// to quinn (the bind), and a DoQ run that timed out on every one still
    /// opened them. NEGATIVE — two sockets, zero answers: the line says "2
    /// QUIC sockets opened" and the word "connection" never follows a digit
    /// (mutant: print "{} connection{}" from `quic_sockets` → fails).
    /// POSITIVE — one socket prints the singular, and the count is the
    /// measured one.
    #[test]
    fn quic_lines_count_sockets_never_connections() {
        let mut snap = EgressSnapshot::default();
        for c in [choice("quic://quad9"), choice("h3://cloudflare")] {
            let text = render(&snap, &c, &facts("example.com", true, true));
            let dns_line = text.lines().nth(1).unwrap();
            assert!(dns_line.contains(" · 0 QUIC sockets opened · connections and datagrams not counted here (quinn owns the socket; the ledger sees the bind, not the handshake)"), "{dns_line}");
            let before = dns_line.split("datagrams").next().unwrap();
            let last_token = before.trim_end().rsplit(' ').next().unwrap();
            assert!(
                !last_token.chars().all(|ch| ch.is_ascii_digit()),
                "a digit before 'datagrams' on a QUIC line: {dns_line}"
            );
        }
        // Two sockets opened, nothing answered (a fully timed-out DoQ run).
        let dest: std::net::SocketAddr = "9.9.9.9:853".parse().unwrap();
        snap.quic_sockets = 2;
        snap.per_destination.push((
            dest,
            DestinationTotals {
                protocol: "quic",
                datagrams: 0,
                tcp_connects: 0,
                quic_binds: 2,
            },
        ));
        let text = render(
            &snap,
            &choice("quic://quad9"),
            &facts("example.com", true, false),
        );
        let dns_line = text.lines().nth(1).unwrap();
        assert!(
            dns_line
                .contains(" · 2 QUIC sockets opened · connections and datagrams not counted here"),
            "{dns_line}"
        );
        for (i, word) in dns_line.split(' ').enumerate() {
            if word.starts_with("connection") {
                let prev = dns_line.split(' ').nth(i - 1).unwrap();
                assert!(
                    !prev.chars().all(|ch| ch.is_ascii_digit()),
                    "a socket count printed as connections: {dns_line}"
                );
            }
        }
        assert_eq!(
            egress_summary(&snap),
            "2 QUIC sockets opened → 9.9.9.9:853 ×2 (connections and datagrams not counted here)"
        );
        snap.quic_sockets = 1;
        snap.per_destination[0].1.quic_binds = 1;
        assert_eq!(
            egress_summary(&snap),
            "1 QUIC socket opened → 9.9.9.9:853 ×1 (connections and datagrams not counted here)"
        );
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
        // The source clause is honest about WHAT was read: hickory-resolver
        // 0.26.1 (system_conf/apple.rs) reads State:/Network/Global/DNS —
        // the global resolver only — so a VPN's scoped resolvers are named
        // as unread. NEGATIVE: the old clause "read from scutil --dns;"
        // (which lists scoped resolvers too) never appears. POSITIVE: the
        // macOS line names the global resolver and the VPN consequence.
        assert!(!text.contains("read from scutil --dns;"), "{text}");
        if cfg!(target_vendor = "apple") {
            assert!(
                text.contains("(configured, read from the global resolver only — the first block of scutil --dns; a VPN's scoped or per-domain resolvers are not read and never asked; printed here, never sealed"),
                "{text}"
            );
        } else if cfg!(unix) {
            assert!(
                text.contains(
                    "(configured, read from /etc/resolv.conf; printed here, never sealed"
                ),
                "{text}"
            );
        }
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
