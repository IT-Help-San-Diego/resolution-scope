// resolver.rs — the resolver choice: one type, one identity, one vantage
//
// THE PROPERTY (Science, two-gaps-closed-and-the-vantage-collision.md):
// the sealed `resolver_identity` must be a pure function of the RESOLVER
// CHOICE (destination + transport), never of which function the caller
// invoked. Before this module, `analyse_domain` sealed the literal "default"
// while the CLI sealed "cloudflare" for the SAME resolver — two seals in the
// archive that disagree about the vantage of identical measurements.
//
// So: `ResolverChoice::identity()` is the ONLY producer of that string. No
// entry point takes a label. The default choice spells exactly "cloudflare",
// so every CLI seal ever minted stays reproducible (preimage line 4 unchanged,
// engine/src/seal.rs preimage_header).
//
// Transport is a vantage axis (mandate M3): it is written into the identity
// as a `/suffix` for every NON-default transport; plain 53 (UDP, TCP on
// truncation) carries no suffix — the rule every existing seal already obeys.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;

use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts, ServerGroup, CLOUDFLARE,
    GOOGLE, QUAD9,
};
use hickory_resolver::Resolver;

use crate::egress::{EgressLedger, RecordingProvider, ScopeResolver};

// =============================================================================
// Presets — the five public resolvers by name
// =============================================================================

/// DNS4EU unfiltered (86.54.11.100, certificate unfiltered.joindns4.eu).
/// hickory ships no such preset; the address and name were probed 2026-09-03
/// (DoT and DoH answered). IPv6 excluded until measured.
pub const DNS4EU: ServerGroup<'static> = ServerGroup {
    ips: &[IpAddr::V4(Ipv4Addr::new(86, 54, 11, 100))],
    server_name: "unfiltered.joindns4.eu",
    path: "/dns-query",
};

/// OpenDNS (208.67.222.222, certificate dns.opendns.com). Probed 2026-09-03
/// (DoT and DoH answered). The second anycast address 208.67.220.220 ships
/// only once measured from this binary; IPv6 excluded until measured.
pub const OPENDNS: ServerGroup<'static> = ServerGroup {
    ips: &[IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222))],
    server_name: "dns.opendns.com",
    path: "/dns-query",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Preset {
    Cloudflare,
    Quad9,
    Google,
    Dns4eu,
    OpenDns,
}

impl Preset {
    pub const ALL: [Preset; 5] = [
        Preset::Cloudflare,
        Preset::Quad9,
        Preset::Google,
        Preset::Dns4eu,
        Preset::OpenDns,
    ];

    /// The sealed label — hand-pinned, never derived from a Debug repr.
    pub fn label(self) -> &'static str {
        match self {
            Preset::Cloudflare => "cloudflare",
            Preset::Quad9 => "quad9",
            Preset::Google => "google",
            Preset::Dns4eu => "dns4eu",
            Preset::OpenDns => "opendns",
        }
    }

    /// The family name the copy uses (the operator, with its first address).
    pub fn operator(self) -> &'static str {
        match self {
            Preset::Cloudflare => "Cloudflare",
            Preset::Quad9 => "Quad9",
            Preset::Google => "Google",
            Preset::Dns4eu => "DNS4EU",
            Preset::OpenDns => "OpenDNS",
        }
    }

    pub fn group(self) -> ServerGroup<'static> {
        match self {
            Preset::Cloudflare => CLOUDFLARE,
            Preset::Quad9 => QUAD9,
            Preset::Google => GOOGLE,
            Preset::Dns4eu => DNS4EU,
            Preset::OpenDns => OPENDNS,
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Preset::ALL.into_iter().find(|p| p.label() == s)
    }
}

// =============================================================================
// Transport
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Transport {
    /// UDP 53, TCP 53 on truncation — the absence of a scheme.
    #[default]
    Plain,
    /// TCP 53 only.
    Tcp,
    /// DNS over TLS, TCP 853.
    Tls,
    /// DNS over HTTPS, TCP 443 (HTTP/2).
    Https,
    /// DNS over QUIC, UDP 853.
    Quic,
    /// DNS over HTTP/3, UDP 443.
    H3,
}

impl Transport {
    pub const ALL: [Transport; 6] = [
        Transport::Plain,
        Transport::Tcp,
        Transport::Tls,
        Transport::Https,
        Transport::Quic,
        Transport::H3,
    ];

    /// The identity suffix; `None` for plain 53 (no suffix, by rule).
    pub fn suffix(self) -> Option<&'static str> {
        match self {
            Transport::Plain => None,
            Transport::Tcp => Some("tcp"),
            Transport::Tls => Some("tls"),
            Transport::Https => Some("https"),
            Transport::Quic => Some("quic"),
            Transport::H3 => Some("h3"),
        }
    }

    /// The port the transport uses when none is given.
    pub fn default_port(self) -> u16 {
        match self {
            Transport::Plain | Transport::Tcp => 53,
            Transport::Tls | Transport::Quic => 853,
            Transport::Https | Transport::H3 => 443,
        }
    }

    /// Whether the transport carries a certificate (and therefore a name).
    pub fn is_encrypted(self) -> bool {
        matches!(
            self,
            Transport::Tls | Transport::Https | Transport::Quic | Transport::H3
        )
    }

    /// The layer-4 word tcpdump shows.
    pub fn l4(self) -> &'static str {
        match self {
            Transport::Plain => "UDP",
            Transport::Tcp | Transport::Tls | Transport::Https => "TCP",
            Transport::Quic | Transport::H3 => "UDP",
        }
    }

    /// The protocol name for prose.
    pub fn name(self) -> &'static str {
        match self {
            Transport::Plain => "plain DNS",
            Transport::Tcp => "plain DNS, TCP only",
            Transport::Tls => "DNS over TLS",
            Transport::Https => "DNS over HTTPS",
            Transport::Quic => "DNS over QUIC",
            Transport::H3 => "DNS over HTTP/3",
        }
    }

    /// Scheme word → transport. Aliases are accepted, never emitted.
    fn from_scheme(s: &str) -> Result<Self, ChoiceError> {
        Ok(match s {
            "plain" | "udp" | "do53" => Transport::Plain,
            "tcp" => Transport::Tcp,
            "tls" | "dot" => Transport::Tls,
            "https" | "doh" => Transport::Https,
            "quic" | "doq" => Transport::Quic,
            "h3" | "doh3" => Transport::H3,
            "http" => {
                return Err(ChoiceError::Refused(
                    "DNS over http does not exist; did you mean `https://`?".into(),
                ))
            }
            other => {
                return Err(ChoiceError::Refused(format!(
                    "`{other}://` is not a transport this instrument speaks; the transports are \
                     tcp://, tls://, https://, quic://, h3:// (plain 53 is the absence of a scheme)"
                )))
            }
        })
    }

    /// Identity suffix word → transport (the strict set, no aliases).
    fn from_suffix(s: &str) -> Option<Self> {
        Transport::ALL.into_iter().find(|t| t.suffix() == Some(s))
    }
}

// =============================================================================
// Target and choice
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Target {
    Preset(Preset),
    /// The operating system's resolver(s). Sealed as the word, never an address.
    System,
    /// A resolver by address. `port` is `Some` only when it differs from the
    /// transport's default; `server_name` only under an encrypted transport.
    Address {
        ip: IpAddr,
        port: Option<u16>,
        server_name: Option<String>,
    },
}

/// The resolver choice: where the questions go, and how they travel.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolverChoice {
    pub target: Target,
    pub transport: Transport,
}

impl Default for ResolverChoice {
    /// Cloudflare over plain 53 — exactly what every scan path built before
    /// this module existed (cli/src/main.rs `udp_and_tcp(&CLOUDFLARE)`).
    fn default() -> Self {
        Self {
            target: Target::Preset(Preset::Cloudflare),
            transport: Transport::Plain,
        }
    }
}

/// Why a choice was refused, or could not be built. Every message names the
/// fix; the CLI prints it verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChoiceError {
    Refused(String),
    /// The encrypted transports were compiled out of this build.
    NotCompiled,
    /// `system` was chosen and the OS lists no resolver.
    NoSystemResolver(String),
    /// hickory refused to build the resolver.
    Build(String),
}

impl fmt::Display for ChoiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChoiceError::Refused(m) => f.write_str(m),
            ChoiceError::NotCompiled => f.write_str(
                "this build of resolution-scope was compiled without the engine's \
                 `encrypted-transport` feature (hickory-resolver tls-ring/https-ring/quic-ring/h3-ring). \
                 Nothing was sent. Rebuild with it, or drop the transport.",
            ),
            ChoiceError::NoSystemResolver(m) => f.write_str(m),
            ChoiceError::Build(m) => write!(f, "hickory-resolver could not build the resolver: {m}"),
        }
    }
}

impl std::error::Error for ChoiceError {}

const PRESET_LIST: &str = "cloudflare | quad9 | google | dns4eu | opendns";
const SYSTEM_IS_PLAIN: &str =
    "your system resolver is plain DNS by definition — the OS hands out addresses, \
                               not certificates; to encrypt, name a resolver: `tls://quad9`";

/// Parse a port: decimal, no leading zeros, 1..=65535.
fn parse_port(s: &str) -> Result<u16, ChoiceError> {
    let bad = || {
        ChoiceError::Refused(format!(
            "`{s}` is not a port: 1..65535, decimal, no leading zeros"
        ))
    };
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(bad());
    }
    let p: u32 = s.parse().map_err(|_| bad())?;
    if p == 0 || p > 65535 {
        return Err(bad());
    }
    Ok(p as u16)
}

/// Validate a certificate name under the input-boundary rules (cli/src/input.rs
/// canonical_domain): one trailing dot dropped, lowercase ASCII, ≤253, label rules.
fn canonical_server_name(raw: &str) -> Result<String, ChoiceError> {
    let bad = |why: &str| ChoiceError::Refused(format!("`{raw}` is not a certificate name: {why}"));
    if raw.is_empty() {
        return Err(bad("empty"));
    }
    let no_dot = raw.strip_suffix('.').unwrap_or(raw);
    let lower = no_dot.to_ascii_lowercase();
    if lower.is_empty() {
        return Err(bad("the root is not a name"));
    }
    if lower.len() > 253 {
        return Err(bad("longer than 253 characters"));
    }
    if lower.parse::<IpAddr>().is_ok() {
        return Err(bad("an address is not the name on a certificate"));
    }
    for label in lower.split('.') {
        let ok_len = !label.is_empty() && label.len() <= 63;
        let ok_chars = label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        let ok_edges = !label.starts_with('-') && !label.ends_with('-');
        if !(ok_len && ok_chars && ok_edges) {
            return Err(bad(&format!("label `{label}` is malformed")));
        }
    }
    Ok(lower)
}

/// Parse the TARGET part (no scheme, no `/` segments): preset, system, or an
/// address with an optional port. Returns `(target, explicit_port)`.
fn parse_target(s: &str) -> Result<(Target, Option<u16>), ChoiceError> {
    if s.is_empty() {
        return Err(ChoiceError::Refused(format!(
            "a resolver is required: {PRESET_LIST} | system | an address"
        )));
    }
    if s == "system" {
        return Ok((Target::System, None));
    }
    if let Some(p) = Preset::parse(s) {
        return Ok((Target::Preset(p), None));
    }
    // Bracketed IPv6, with an optional #port / :port.
    if let Some(rest) = s.strip_prefix('[') {
        let (inner, after) = rest.split_once(']').ok_or_else(|| {
            ChoiceError::Refused(format!(
                "`{s}`: an IPv6 address in brackets needs its closing `]`"
            ))
        })?;
        let ip: Ipv6Addr = inner
            .parse()
            .map_err(|_| ChoiceError::Refused(format!("`{inner}` is not an IPv6 address")))?;
        let port = match after {
            "" => None,
            p => Some(parse_port(
                p.strip_prefix('#')
                    .or_else(|| p.strip_prefix(':'))
                    .ok_or_else(|| {
                        ChoiceError::Refused(format!("`{s}`: after `]` only `#port` is understood"))
                    })?,
            )?),
        };
        return Ok((address(IpAddr::V6(ip)), port));
    }
    // Bare IPv6 (no port possible).
    if let Ok(ip) = s.parse::<Ipv6Addr>() {
        return Ok((address(IpAddr::V6(ip)), None));
    }
    // IPv4 with an optional #port / :port.
    let (host, port) = match s.split_once('#').or_else(|| s.split_once(':')) {
        Some((h, p)) => (h, Some(p)),
        None => (s, None),
    };
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        let port = port.map(parse_port).transpose()?;
        return Ok((address(IpAddr::V4(ip)), port));
    }
    if host == "system" {
        return Err(ChoiceError::Refused(SYSTEM_IS_PLAIN.into()));
    }
    // Not an address. Name the fix.
    match s {
        "default" | "test" | "unknown" => Err(ChoiceError::Refused(format!(
            "`{s}` is the engine's old label for the same vantage — the default is spelled `cloudflare`; write that or nothing"
        ))),
        _ if s.contains('.') => {
            Err(ChoiceError::Refused(format!(
                "`{s}` looks like a hostname; give the address and the certificate name: \
                 `tls://9.9.9.9/dns.quad9.net` — the instrument never looks up a resolver's address through another resolver. \
                 By name, the resolvers are {PRESET_LIST}"
            )))
        }
        _ if port.is_some() => Err(ChoiceError::Refused(format!(
            "`{s}`: a port goes with an address (`9.9.9.9#5353`); the named resolvers ({PRESET_LIST}) and `system` take none"
        ))),
        _ => Err(ChoiceError::Refused(format!(
            "`{s}` is not a resolver this instrument knows: {PRESET_LIST} | system | an address such as 9.9.9.9 or [2620:fe::fe]"
        ))),
    }
}

fn address(ip: IpAddr) -> Target {
    Target::Address {
        ip,
        port: None,
        server_name: None,
    }
}

impl FromStr for ResolverChoice {
    type Err = ChoiceError;

    /// Accepts the CHOICE form (`[transport://]target[/name]`) and the
    /// IDENTITY form (`label[/transport[/name]]`, exactly what a report
    /// prints after "resolver"), and refuses everything else with the fix
    /// named. Runs before any network.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if raw.is_empty() {
            return Err(ChoiceError::Refused(format!(
                "a resolver is required: {PRESET_LIST} | system | an address"
            )));
        }
        if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(ChoiceError::Refused(format!(
                "{raw:?} contains whitespace or a control character; a resolver is one token such as `quad9` or `tls://9.9.9.9/dns.quad9.net`"
            )));
        }
        if !raw.is_ascii() {
            return Err(ChoiceError::Refused(format!(
                "{raw:?} is not ASCII; write the resolver as {PRESET_LIST}, system, or an address"
            )));
        }
        if raw.contains('=') || raw.contains(',') {
            return Err(ChoiceError::Refused(format!(
                "`{raw}`: `=` and `,` are reserved for the vantage vocabulary (class=/network=/operator= prefixes); \
                 write the resolver as {PRESET_LIST}, system, or an address"
            )));
        }
        let s = raw.to_ascii_lowercase();

        // Scheme, if any.
        let (scheme, rest) = match s.split_once("://") {
            Some((sch, rest)) => (Some(Transport::from_scheme(sch)?), rest),
            None => (None, s.as_str()),
        };
        if rest.contains("://") {
            return Err(ChoiceError::Refused(format!("`{raw}`: one transport only")));
        }
        let segments: Vec<&str> = rest.split('/').collect();
        if segments.len() > 3 {
            return Err(ChoiceError::Refused(format!(
                "`{raw}`: at most `target/transport/certificate-name`"
            )));
        }
        let (target, explicit_port) = parse_target(segments[0])?;

        // Work out transport and certificate name from the remaining segments.
        let (transport, name_seg): (Transport, Option<&str>) = match (scheme, &segments[1..]) {
            (Some(t), []) => (t, None),
            (Some(t), [name]) => (t, Some(name)),
            (Some(_), [_, _]) => {
                return Err(ChoiceError::Refused(format!(
                    "`{raw}`: with a scheme the form is `transport://target[/certificate-name]`"
                )))
            }
            (None, []) => (Transport::Plain, None),
            (None, [seg]) => match Transport::from_suffix(seg) {
                Some(t) => (t, None),
                None => {
                    return Err(match &target {
                        Target::System => ChoiceError::Refused(SYSTEM_IS_PLAIN.into()),
                        Target::Preset(p) => ChoiceError::Refused(format!(
                            "`{raw}`: {} already carries its certificate name {}; write `tls://{}`",
                            p.label(),
                            p.group().server_name,
                            p.label()
                        )),
                        _ => ChoiceError::Refused(format!(
                            "`{raw}`: a certificate name needs tls://, https://, quic:// or h3://; plain 53 has no certificate"
                        )),
                    })
                }
            },
            (None, [seg, name]) => match Transport::from_suffix(seg) {
                Some(t) => (t, Some(name)),
                None => {
                    return Err(ChoiceError::Refused(format!(
                        "`{raw}`: `{seg}` is not a transport; the identity form is `label/transport/certificate-name`"
                    )))
                }
            },
            _ => unreachable!("segments capped at three"),
        };

        // Semantics.
        let target = match target {
            Target::System => {
                if transport != Transport::Plain || explicit_port.is_some() || name_seg.is_some() {
                    return Err(ChoiceError::Refused(SYSTEM_IS_PLAIN.into()));
                }
                Target::System
            }
            Target::Preset(p) => {
                if let Some(n) = name_seg {
                    return Err(ChoiceError::Refused(format!(
                        "`{raw}`: {} already carries its certificate name {}; drop `/{n}`",
                        p.label(),
                        p.group().server_name
                    )));
                }
                Target::Preset(p)
            }
            Target::Address { ip, .. } => {
                let server_name = match (transport.is_encrypted(), name_seg) {
                    (true, Some(n)) => Some(canonical_server_name(n)?),
                    (true, None) => {
                        return Err(ChoiceError::Refused(format!(
                            "an encrypted transport to a bare address needs the name on its certificate: \
                             `{}://{}/dns.quad9.net`",
                            transport.suffix().unwrap_or("tls"),
                            display_ip(ip)
                        )))
                    }
                    (false, Some(_)) => {
                        return Err(ChoiceError::Refused(format!(
                            "`{raw}`: a certificate name needs tls://, https://, quic:// or h3://; plain 53 has no certificate"
                        )))
                    }
                    (false, None) => None,
                };
                // A port equal to the transport default is the default: never stored, never written.
                let port = explicit_port.filter(|p| *p != transport.default_port());
                Target::Address {
                    ip,
                    port,
                    server_name,
                }
            }
        };
        Ok(ResolverChoice { target, transport })
    }
}

fn display_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

impl fmt::Display for ResolverChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.identity())
    }
}

impl ResolverChoice {
    /// The sealed identity — preimage line 4. The ONLY producer of that string.
    ///
    /// `LABEL [ "/" TSUFFIX [ "/" SERVER_NAME ] ]`; the port is written only
    /// when it differs from the transport's default; plain 53 has no suffix.
    pub fn identity(&self) -> String {
        let mut s = match &self.target {
            Target::Preset(p) => p.label().to_string(),
            Target::System => "system".to_string(),
            Target::Address { ip, .. } => match self.written_port() {
                Some(p) => format!("{}#{p}", display_ip(*ip)),
                None => display_ip(*ip),
            },
        };
        if let Some(suffix) = self.transport.suffix() {
            s.push('/');
            s.push_str(suffix);
            if let Target::Address {
                server_name: Some(n),
                ..
            } = &self.target
            {
                s.push('/');
                s.push_str(n);
            }
        }
        s
    }

    /// The port the identity writes: an address's port ONLY when it differs
    /// from the transport's default. The parser never stores a default port
    /// (`from_str`), but the fields are `pub`, so a value built as
    /// `Target::Address { port: Some(853), .. }` under `Transport::Tls` is
    /// the same choice as `port: None` and must seal the same bytes —
    /// identity is a pure function of destination + transport, never of
    /// how the value was constructed.
    fn written_port(&self) -> Option<u16> {
        match &self.target {
            Target::Address { port: Some(p), .. } if *p != self.transport.default_port() => {
                Some(*p)
            }
            _ => None,
        }
    }

    /// The exact inverse of [`identity`](Self::identity). `None` for a legacy
    /// opaque label (`default`, `test`, …) that no choice produces.
    pub fn parse_identity(s: &str) -> Option<Self> {
        let c = s.parse::<ResolverChoice>().ok()?;
        (c.identity() == s).then_some(c)
    }

    /// The human gloss of a choice — a pure function of the choice (vocabulary,
    /// not wire), so it stays true for a seal re-read in ten years.
    pub fn gloss(&self) -> String {
        let t = self.transport;
        let mut s = match &self.target {
            Target::Preset(p) => format!("{} ({})", p.operator(), first_address(p.group().ips)),
            Target::System => "this machine's own system resolver (address not sealed)".to_string(),
            Target::Address { ip, .. } => match self.written_port() {
                Some(port) => format!("{} port {port}", display_ip(*ip)),
                None => display_ip(*ip),
            },
        };
        match t {
            Transport::Plain => s.push_str(" over plain DNS, port 53"),
            Transport::Tcp => s.push_str(" over plain DNS, TCP only, port 53"),
            Transport::Tls => s.push_str(" over DNS-over-TLS, port 853"),
            Transport::Https => s.push_str(" over DNS-over-HTTPS, port 443"),
            Transport::Quic => s.push_str(" over DNS-over-QUIC, port 853"),
            Transport::H3 => s.push_str(" over DNS-over-HTTP/3, port 443"),
        }
        if self.written_port().is_some() {
            // The port already appears with the address; do not print the default one twice.
            s = s
                .replace(", port 53", "")
                .replace(", port 853", "")
                .replace(", port 443", "");
        }
        if let Some(name) = self.server_name() {
            s.push_str(&format!(", certificate {name}"));
        }
        s.push_str(" — DNSSEC validated by the instrument against the root keys, not by the resolver's word");
        s
    }

    /// The gloss for a sealed identity string, including legacy labels.
    pub fn gloss_of_identity(identity: &str) -> String {
        match Self::parse_identity(identity) {
            Some(c) => c.gloss(),
            None if identity == "default" => {
                "unstructured label \"default\" — sealed before cc/resolver-choice; the engine binary \
                 measured through Cloudflare over plain DNS (ledger f7ad6d0)"
                    .to_string()
            }
            None => format!("unstructured label {identity:?} — sealed before cc/resolver-choice"),
        }
    }

    /// The certificate name this choice verifies, if the transport carries one.
    pub fn server_name(&self) -> Option<String> {
        if !self.transport.is_encrypted() {
            return None;
        }
        match &self.target {
            Target::Preset(p) => Some(p.group().server_name.to_string()),
            Target::System => None,
            Target::Address { server_name, .. } => server_name.clone(),
        }
    }

    /// The port the questions go to.
    pub fn port(&self) -> u16 {
        match &self.target {
            Target::Address { port: Some(p), .. } => *p,
            _ => self.transport.default_port(),
        }
    }

    /// The options every branch builds with: `ResolverOpts::default()` plus
    /// `validate = true`, nothing else — the real constructor input.
    pub fn options(&self) -> ResolverOpts {
        let mut opts = ResolverOpts::default();
        opts.validate = true;
        opts
    }

    /// The hickory configuration for this choice. Construction never connects.
    pub fn config(&self) -> Result<ResolverConfig, ChoiceError> {
        let t = self.transport;
        if t.is_encrypted() && !cfg!(feature = "encrypted-transport") {
            return Err(ChoiceError::NotCompiled);
        }
        let name_servers: Vec<NameServerConfig> = match &self.target {
            Target::Preset(p) => {
                let g = p.group();
                match t {
                    Transport::Plain => g.udp_and_tcp().collect(),
                    Transport::Tcp => g.tcp().collect(),
                    #[cfg(feature = "encrypted-transport")]
                    Transport::Tls => g.tls().collect(),
                    #[cfg(feature = "encrypted-transport")]
                    Transport::Https => g.https().collect(),
                    #[cfg(feature = "encrypted-transport")]
                    Transport::Quic => g.quic().collect(),
                    #[cfg(feature = "encrypted-transport")]
                    Transport::H3 => g.h3().collect(),
                    #[cfg(not(feature = "encrypted-transport"))]
                    _ => return Err(ChoiceError::NotCompiled),
                }
            }
            Target::System => {
                let (config, _system_opts) = read_system_config()?;
                if config.name_servers.is_empty() {
                    return Err(ChoiceError::NoSystemResolver(system_conf_missing()));
                }
                // The OS hands out addresses; the transport is plain by definition.
                config.name_servers.to_vec()
            }
            Target::Address {
                ip,
                port,
                server_name,
            } => {
                let mut conns: Vec<ConnectionConfig> = match t {
                    Transport::Plain => vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
                    Transport::Tcp => vec![ConnectionConfig::tcp()],
                    #[cfg(feature = "encrypted-transport")]
                    Transport::Tls => vec![ConnectionConfig::tls(Arc::from(
                        server_name.as_deref().unwrap_or_default(),
                    ))],
                    #[cfg(feature = "encrypted-transport")]
                    Transport::Https => vec![ConnectionConfig::https(
                        Arc::from(server_name.as_deref().unwrap_or_default()),
                        None,
                    )],
                    #[cfg(feature = "encrypted-transport")]
                    Transport::Quic => vec![ConnectionConfig::quic(Arc::from(
                        server_name.as_deref().unwrap_or_default(),
                    ))],
                    #[cfg(feature = "encrypted-transport")]
                    Transport::H3 => vec![ConnectionConfig::h3(
                        Arc::from(server_name.as_deref().unwrap_or_default()),
                        None,
                    )],
                    #[cfg(not(feature = "encrypted-transport"))]
                    _ => return Err(ChoiceError::NotCompiled),
                };
                if let Some(p) = port {
                    for c in conns.iter_mut() {
                        c.port = *p;
                    }
                }
                vec![NameServerConfig::new(*ip, true, conns)]
            }
        };
        Ok(ResolverConfig::from_parts(None, vec![], name_servers))
    }

    /// The addresses this choice is CONFIGURED with (the preset table, the
    /// typed address, or what the OS lists). Printed as "(configured)", never
    /// sealed for `system`; the addresses actually SENT TO come from the ledger.
    pub fn configured_addresses(&self) -> Vec<IpAddr> {
        match &self.target {
            Target::Preset(p) => p.group().ips.to_vec(),
            Target::Address { ip, .. } => vec![*ip],
            Target::System => read_system_config()
                .map(|(c, _)| c.name_servers.iter().map(|ns| ns.ip).collect())
                .unwrap_or_default(),
        }
    }

    /// The stderr warning for a private / loopback / link-local address: it is
    /// sealed as typed and printed on any report the user shares.
    pub fn private_address_warning(&self) -> Option<String> {
        let Target::Address { ip, .. } = &self.target else {
            return None;
        };
        let private = match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
            }
        };
        private.then(|| {
            format!(
                "warning: {} is a private address; it is sealed into the verdict as \"{}\" and printed on any report you share. --resolver system seals the word instead.",
                ip,
                self.identity()
            )
        })
    }

    /// The target class the preflight tiers its refusals by.
    pub fn target_class(&self) -> TargetClass {
        match &self.target {
            Target::Preset(_) => TargetClass::Preset,
            Target::System => TargetClass::System,
            Target::Address { .. } => TargetClass::Address,
        }
    }

    /// The operator word for the console ("Cloudflare", "Quad9", "this
    /// computer's own resolver", or the address).
    pub fn operator(&self) -> String {
        match &self.target {
            Target::Preset(p) => p.operator().to_string(),
            Target::System => "this computer's own resolver".to_string(),
            Target::Address { ip, .. } => display_ip(*ip),
        }
    }
}

/// The three kinds of vantage the preflight distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetClass {
    Preset,
    System,
    Address,
}

fn first_address(ips: &[IpAddr]) -> String {
    ips.first().map(|ip| ip.to_string()).unwrap_or_default()
}

fn system_conf_missing() -> String {
    if cfg!(target_vendor = "apple") {
        "this machine lists no DNS resolver (macOS: `scutil --dns` shows none); name one: --resolver cloudflare".into()
    } else if cfg!(unix) {
        "this machine lists no DNS resolver (/etc/resolv.conf has no nameserver line); name one: --resolver cloudflare".into()
    } else {
        "this machine lists no DNS resolver; name one: --resolver cloudflare".into()
    }
}

/// hickory's system configuration read — the CONFIG only. The options it
/// returns are discarded: `Resolver::builder(provider)` would overwrite the
/// builder's options with the system's and `validate` would silently drop.
fn read_system_config() -> Result<(ResolverConfig, ResolverOpts), ChoiceError> {
    hickory_resolver::system_conf::read_system_conf().map_err(|e| {
        ChoiceError::NoSystemResolver(format!(
            "{} (hickory-resolver read_system_conf: {e})",
            system_conf_missing()
        ))
    })
}

// =============================================================================
// Vantage — the choice, the resolver built from it, and its ledger
// =============================================================================

/// A resolver choice, the resolver built from it, and the socket-layer ledger
/// under that resolver. Every entry point takes one of these; the identity
/// it seals comes from the choice and from nowhere else.
#[derive(Clone)]
pub struct Vantage {
    choice: ResolverChoice,
    resolver: ScopeResolver,
    ledger: EgressLedger,
    fetch_overrides: Vec<(String, SocketAddr)>,
}

impl Deref for Vantage {
    type Target = ScopeResolver;
    fn deref(&self) -> &ScopeResolver {
        &self.resolver
    }
}

impl Vantage {
    /// Build the resolver for a choice. Construction never connects; a refused
    /// choice or a compiled-out transport errors here, before any network.
    pub fn build(choice: ResolverChoice) -> Result<Self, ChoiceError> {
        Self::build_with_options(choice, None)
    }

    /// TEST SEAM, never a production path: build with `validate = false`.
    /// A loopback stub cannot serve a DNSSEC chain, and hickory's validator
    /// propagates the chain-walk's REFUSED as the lookup's own error, so a
    /// canned positive answer is unreachable under validation. The egress
    /// ledger and the HTTPS fetch hook are what those tests measure; the
    /// identity, config and ledger wiring are identical to `build`.
    #[doc(hidden)]
    pub fn build_unvalidating_for_tests(choice: ResolverChoice) -> Result<Self, ChoiceError> {
        let mut opts = choice.options();
        opts.validate = false;
        Self::build_with_options(choice, Some(opts))
    }

    fn build_with_options(
        choice: ResolverChoice,
        opts: Option<ResolverOpts>,
    ) -> Result<Self, ChoiceError> {
        let identity = choice.identity();
        if identity
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        {
            // A newline would inject a preimage line (seal.rs is newline-terminated).
            return Err(ChoiceError::Refused(format!(
                "identity {identity:?} carries whitespace or a control character"
            )));
        }
        let config = choice.config()?;
        let ledger = EgressLedger::new();
        let resolver =
            Resolver::builder_with_config(config, RecordingProvider::new(ledger.clone()))
                .with_options(opts.unwrap_or_else(|| choice.options()))
                .build()
                .map_err(|e| ChoiceError::Build(e.to_string()))?;
        Ok(Self {
            choice,
            resolver,
            ledger,
            fetch_overrides: Vec::new(),
        })
    }

    pub fn choice(&self) -> &ResolverChoice {
        &self.choice
    }

    /// The sealed identity of this vantage — `ResolverChoice::identity()`.
    pub fn identity(&self) -> String {
        self.choice.identity()
    }

    pub fn ledger(&self) -> &EgressLedger {
        &self.ledger
    }

    pub fn resolver(&self) -> &ScopeResolver {
        &self.resolver
    }

    /// Test seam: pin `host` to `addr` for the HTTPS client (reqwest's
    /// `.resolve()` override, applied on top of the vantage resolver).
    #[doc(hidden)]
    pub fn with_fetch_override(mut self, host: &str, addr: SocketAddr) -> Self {
        self.fetch_overrides.push((host.to_ascii_lowercase(), addr));
        self
    }

    /// The HTTPS client for the MTA-STS policy fetch: names resolved THROUGH
    /// THIS VANTAGE (never libc's getaddrinfo — that was a cleartext leak to
    /// the system stub under every choice), redirects never followed (RFC 8461
    /// §3.3: "HTTP 3xx redirects MUST NOT be followed"), environment proxies
    /// ignored (the destination printed must be the destination reached).
    pub fn http_client(&self) -> reqwest::Result<reqwest::Client> {
        let mut b = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .dns_resolver(Arc::new(VantageResolve {
                resolver: self.resolver.clone(),
            }));
        for (host, addr) in &self.fetch_overrides {
            b = b.resolve(host, *addr);
        }
        b.build()
    }
}

/// reqwest's DNS hook over the vantage resolver. Returns socket addresses
/// with port 0 so hyper substitutes the URL's port (hyper-util set_port).
pub struct VantageResolve {
    resolver: ScopeResolver,
}

impl VantageResolve {
    pub fn new(resolver: ScopeResolver) -> Self {
        Self { resolver }
    }
}

impl reqwest::dns::Resolve for VantageResolve {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let resolver = self.resolver.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let ips = resolver.lookup_ip(host.as_str()).await?;
            let addrs: Vec<SocketAddr> = ips.iter().map(|ip| SocketAddr::new(ip, 0)).collect();
            let boxed: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(boxed)
        })
    }
}

// =============================================================================
// Tests — T1, T3, T4, T5, T6, T7, T8
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::ProtocolConfig;

    fn parse(s: &str) -> ResolverChoice {
        s.parse::<ResolverChoice>()
            .unwrap_or_else(|e| panic!("{s:?} should parse: {e}"))
    }

    fn refused(s: &str) -> String {
        match s.parse::<ResolverChoice>() {
            Err(e) => e.to_string(),
            Ok(c) => panic!("{s:?} should be refused, parsed as {c:?}"),
        }
    }

    /// Every (target, transport) pair over the presets and system, plus a
    /// representative address set — the grid the exhaustive tests walk.
    fn grid() -> Vec<ResolverChoice> {
        let mut v = Vec::new();
        for t in Transport::ALL {
            for p in Preset::ALL {
                v.push(ResolverChoice {
                    target: Target::Preset(p),
                    transport: t,
                });
            }
            let name = t.is_encrypted().then(|| "dns.quad9.net".to_string());
            for (ip, port) in [
                ("9.9.9.9", None),
                ("9.9.9.9", Some(5353)),
                ("2620:fe::fe", None),
                ("2620:fe::fe", Some(8443)),
            ] {
                v.push(ResolverChoice {
                    target: Target::Address {
                        ip: ip.parse().unwrap(),
                        port,
                        server_name: name.clone(),
                    },
                    transport: t,
                });
            }
        }
        v.push(ResolverChoice {
            target: Target::System,
            transport: Transport::Plain,
        });
        v
    }

    /// T1 — the default seals the literal "cloudflare"; every spelling of the
    /// default parses to it; every OTHER pair seals something else. The match
    /// has no wildcard arm: a new variant without a pinned spelling is a
    /// compile error here.
    #[test]
    fn default_choice_identity_is_the_literal_cloudflare() {
        assert_eq!(ResolverChoice::default().identity(), "cloudflare");
        for s in [
            "cloudflare",
            "CLOUDFLARE",
            "udp://cloudflare",
            "plain://cloudflare",
            "do53://cloudflare",
        ] {
            assert_eq!(parse(s), ResolverChoice::default(), "{s}");
            assert_eq!(parse(s).identity(), "cloudflare", "{s}");
        }
        for p in Preset::ALL {
            for t in Transport::ALL {
                let c = ResolverChoice {
                    target: Target::Preset(p),
                    transport: t,
                };
                let is_default = match (p, t) {
                    (Preset::Cloudflare, Transport::Plain) => true,
                    (Preset::Cloudflare, Transport::Tcp)
                    | (Preset::Cloudflare, Transport::Tls)
                    | (Preset::Cloudflare, Transport::Https)
                    | (Preset::Cloudflare, Transport::Quic)
                    | (Preset::Cloudflare, Transport::H3)
                    | (Preset::Quad9, _)
                    | (Preset::Google, _)
                    | (Preset::Dns4eu, _)
                    | (Preset::OpenDns, _) => false,
                };
                assert_eq!(c.identity() == "cloudflare", is_default, "{c:?}");
            }
        }
        assert_ne!(
            ResolverChoice {
                target: Target::System,
                transport: Transport::Plain
            }
            .identity(),
            "cloudflare"
        );
    }

    /// T3 — the default's built config is `udp_and_tcp(&CLOUDFLARE)` name
    /// server for name server, and `validate` is on.
    #[test]
    fn default_choice_config_is_udp_and_tcp_cloudflare_with_validate() {
        let got = ResolverChoice::default().config().unwrap();
        let want = ResolverConfig::udp_and_tcp(&CLOUDFLARE);
        assert_eq!(got.name_servers.len(), want.name_servers.len());
        assert_eq!(got.name_servers.len(), 4);
        for (g, w) in got.name_servers.iter().zip(want.name_servers.iter()) {
            assert_eq!(g.ip, w.ip);
            assert_eq!(g.trust_negative_responses, w.trust_negative_responses);
            assert_eq!(g.connections.len(), w.connections.len());
            for (gc, wc) in g.connections.iter().zip(w.connections.iter()) {
                assert_eq!(gc.port, wc.port);
                assert_eq!(gc.protocol, wc.protocol);
                assert_eq!(gc.bind_addr, wc.bind_addr);
            }
        }
        assert!(got.domain.is_none());
        assert!(got.search.is_empty());
        assert!(ResolverChoice::default().options().validate);
        assert!(
            !ResolverOpts::default().validate,
            "sanity: hickory's default is off"
        );
    }

    /// T4 — flag and identity round-trip: `parse(identity(c)) == c` for every
    /// grid choice; every accepted spelling has one canonical identity; every
    /// must-fail row refuses with the fix named.
    #[test]
    fn flag_and_identity_round_trip() {
        for c in grid() {
            let id = c.identity();
            assert_eq!(id.parse::<ResolverChoice>().unwrap(), c, "{id}");
            assert_eq!(ResolverChoice::parse_identity(&id), Some(c.clone()), "{id}");
        }
        let canonical = [
            ("quad9", "quad9"),
            ("QUAD9", "quad9"),
            ("google", "google"),
            ("dns4eu", "dns4eu"),
            ("opendns", "opendns"),
            ("tcp://quad9", "quad9/tcp"),
            ("tls://quad9", "quad9/tls"),
            ("dot://quad9", "quad9/tls"),
            ("https://quad9", "quad9/https"),
            ("doh://quad9", "quad9/https"),
            ("quic://quad9", "quad9/quic"),
            ("doq://quad9", "quad9/quic"),
            ("h3://cloudflare", "cloudflare/h3"),
            ("doh3://cloudflare", "cloudflare/h3"),
            ("tcp://cloudflare", "cloudflare/tcp"),
            ("system", "system"),
            ("9.9.9.9", "9.9.9.9"),
            ("9.9.9.9#53", "9.9.9.9"),
            ("9.9.9.9:53", "9.9.9.9"),
            ("9.9.9.9#5353", "9.9.9.9#5353"),
            ("9.9.9.9:5353", "9.9.9.9#5353"),
            ("1.1.1.1:5353", "1.1.1.1#5353"),
            ("[2620:fe::fe]", "[2620:fe::fe]"),
            ("2620:fe::fe", "[2620:fe::fe]"),
            ("[2620:00fe::00fe]", "[2620:fe::fe]"),
            ("[2620:fe::fe]#5353", "[2620:fe::fe]#5353"),
            ("[2620:fe::fe]:5353", "[2620:fe::fe]#5353"),
            ("tls://9.9.9.9/dns.quad9.net", "9.9.9.9/tls/dns.quad9.net"),
            ("tls://9.9.9.9/DNS.Quad9.NET.", "9.9.9.9/tls/dns.quad9.net"),
            (
                "tls://9.9.9.9#853/dns.quad9.net",
                "9.9.9.9/tls/dns.quad9.net",
            ),
            (
                "https://[2620:fe::fe]#8443/dns.quad9.net",
                "[2620:fe::fe]#8443/https/dns.quad9.net",
            ),
            (
                "https://9.9.9.9#443/dns.quad9.net",
                "9.9.9.9/https/dns.quad9.net",
            ),
            ("quad9/tls", "quad9/tls"),
            ("9.9.9.9/tls/dns.quad9.net", "9.9.9.9/tls/dns.quad9.net"),
            ("9.9.9.9#5353", "9.9.9.9#5353"),
        ];
        for (input, want) in canonical {
            assert_eq!(parse(input).identity(), want, "{input}");
            assert_eq!(
                parse(want).identity(),
                want,
                "canonical form is stable: {want}"
            );
        }
        let must_fail = [
            ("default", "spelled `cloudflare`"),
            ("test", "spelled `cloudflare`"),
            ("unknown", "spelled `cloudflare`"),
            ("class=instrument:x", "reserved for the vantage vocabulary"),
            ("network=residential:x", "reserved"),
            ("tls://dns.quad9.net", "tls://9.9.9.9/dns.quad9.net"),
            ("dns.quad9.net", "tls://9.9.9.9/dns.quad9.net"),
            ("tls://9.9.9.9", "tls://9.9.9.9/dns.quad9.net"),
            ("tls://system", "name a resolver: `tls://quad9`"),
            ("system#5353", "name a resolver: `tls://quad9`"),
            ("system/x", "name a resolver: `tls://quad9`"),
            ("9.9.9.9/dns.quad9.net", "plain 53 has no certificate"),
            (
                "quad9/dns.quad9.net",
                "already carries its certificate name dns.quad9.net",
            ),
            (
                "tls://quad9/dns.quad9.net",
                "already carries its certificate name dns.quad9.net",
            ),
            ("http://quad9", "did you mean `https://`"),
            ("a b", "whitespace"),
            ("x\ny", "control character"),
            ("9.9.9.9#0", "not a port"),
            ("9.9.9.9#65536", "not a port"),
            ("9.9.9.9#053", "not a port"),
            ("quad9#853", "a port goes with an address"),
            ("ftp://quad9", "not a transport"),
            ("quäd9", "not ASCII"),
            ("", "a resolver is required"),
            ("[2620:fe::fe", "closing `]`"),
            ("tls://9.9.9.9/9.9.9.9", "not the name on a certificate"),
            ("nine", "not a resolver this instrument knows"),
        ];
        for (input, fix) in must_fail {
            let msg = refused(input);
            assert!(msg.contains(fix), "{input:?} → {msg:?} should name {fix:?}");
        }
    }

    /// T5 — every emitted identity obeys the legality rules: ASCII, lowercase,
    /// no whitespace/control, no `=`/`,`, `:` only inside brackets, at most
    /// two `/`, the closed alphabet.
    #[test]
    fn identity_strings_obey_the_legality_rules() {
        for c in grid() {
            let id = c.identity();
            assert!(!id.is_empty());
            assert!(id.is_ascii(), "{id}");
            assert_eq!(id, id.to_ascii_lowercase(), "{id}");
            assert!(
                !id.chars().any(|ch| ch.is_whitespace() || ch.is_control()),
                "{id}"
            );
            assert!(!id.contains('=') && !id.contains(','), "{id}");
            assert!(id.matches('/').count() <= 2, "{id}");
            let mut depth = 0i32;
            for ch in id.chars() {
                match ch {
                    '[' => depth += 1,
                    ']' => depth -= 1,
                    ':' => assert!(depth > 0, "`:` outside brackets in {id}"),
                    'a'..='z' | '0'..='9' | '.' | '-' | '#' | '/' => {}
                    other => panic!("{other:?} is outside the identity alphabet: {id}"),
                }
            }
            assert!(id.len() <= 253 + 6 + 6 + 6, "{id}");
        }
    }

    /// T6 — every grid choice builds offline with `validate` on and only its
    /// own protocol(s): Plain → {Udp, Tcp}; every other transport exactly one
    /// connection config, never a plain fallback.
    #[test]
    fn every_choice_builds_with_validate_true_and_only_its_protocol() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        for c in grid() {
            if c.target == Target::System {
                continue; // depends on the host; covered by T7 and the live tests
            }
            assert!(c.options().validate, "{c:?}");
            let cfg = c.config().unwrap_or_else(|e| panic!("{c:?}: {e}"));
            assert!(!cfg.name_servers.is_empty(), "{c:?}");
            for ns in &cfg.name_servers {
                let protocols: Vec<&ProtocolConfig> =
                    ns.connections.iter().map(|x| &x.protocol).collect();
                match c.transport {
                    Transport::Plain => {
                        assert_eq!(protocols.len(), 2, "{c:?}");
                        assert!(matches!(protocols[0], ProtocolConfig::Udp), "{c:?}");
                        assert!(matches!(protocols[1], ProtocolConfig::Tcp), "{c:?}");
                    }
                    Transport::Tcp => {
                        assert_eq!(protocols.len(), 1, "{c:?}");
                        assert!(matches!(protocols[0], ProtocolConfig::Tcp), "{c:?}");
                    }
                    #[cfg(feature = "encrypted-transport")]
                    Transport::Tls => {
                        assert_eq!(protocols.len(), 1, "{c:?}");
                        assert!(matches!(protocols[0], ProtocolConfig::Tls { .. }), "{c:?}");
                    }
                    #[cfg(feature = "encrypted-transport")]
                    Transport::Https => {
                        assert_eq!(protocols.len(), 1, "{c:?}");
                        assert!(
                            matches!(protocols[0], ProtocolConfig::Https { .. }),
                            "{c:?}"
                        );
                    }
                    #[cfg(feature = "encrypted-transport")]
                    Transport::Quic => {
                        assert_eq!(protocols.len(), 1, "{c:?}");
                        assert!(matches!(protocols[0], ProtocolConfig::Quic { .. }), "{c:?}");
                    }
                    #[cfg(feature = "encrypted-transport")]
                    Transport::H3 => {
                        assert_eq!(protocols.len(), 1, "{c:?}");
                        assert!(matches!(protocols[0], ProtocolConfig::H3 { .. }), "{c:?}");
                    }
                    #[cfg(not(feature = "encrypted-transport"))]
                    _ => unreachable!("config() refuses encrypted transports when compiled out"),
                }
                for conn in &ns.connections {
                    assert_eq!(conn.port, c.port(), "{c:?}");
                }
            }
            let v = Vantage::build(c.clone()).unwrap_or_else(|e| panic!("{c:?}: {e}"));
            assert_eq!(v.identity(), c.identity());
        }
    }

    /// T9 — identity is a pure function of destination + transport: a port
    /// written explicitly through the `pub` fields that equals the
    /// transport default yields the SAME string as the port omitted, for
    /// every transport and both address families. Negative control: a
    /// port that differs from the default is still written.
    /// Mutant: `identity()` reads `port` directly instead of
    /// `written_port()` → "9.9.9.9#853/tls/dns.quad9.net" != "9.9.9.9/tls/dns.quad9.net".
    #[test]
    fn identity_omits_a_port_equal_to_the_transport_default_however_it_was_built() {
        for t in Transport::ALL {
            let name = t.is_encrypted().then(|| "dns.quad9.net".to_string());
            for ip in ["9.9.9.9", "2620:fe::fe"] {
                let ip: IpAddr = ip.parse().unwrap();
                let omitted = ResolverChoice {
                    target: Target::Address {
                        ip,
                        port: None,
                        server_name: name.clone(),
                    },
                    transport: t,
                };
                let explicit_default = ResolverChoice {
                    target: Target::Address {
                        ip,
                        port: Some(t.default_port()),
                        server_name: name.clone(),
                    },
                    transport: t,
                };
                assert_eq!(
                    explicit_default.identity(),
                    omitted.identity(),
                    "{t:?} {ip}: an explicit default port is the same choice"
                );
                assert!(!omitted.identity().contains('#'), "{}", omitted.identity());
                assert_eq!(explicit_default.gloss(), omitted.gloss());
                assert_eq!(explicit_default.port(), omitted.port());
                // Negative: a non-default port is written, and moves the identity.
                let other = ResolverChoice {
                    target: Target::Address {
                        ip,
                        port: Some(t.default_port() + 1),
                        server_name: name.clone(),
                    },
                    transport: t,
                };
                assert!(
                    other
                        .identity()
                        .contains(&format!("#{}", t.default_port() + 1)),
                    "{}",
                    other.identity()
                );
                assert_ne!(other.identity(), omitted.identity());
            }
        }
    }

    /// T7 — `system` seals the word, never an address, without consulting the OS.
    #[test]
    fn system_choice_never_seals_an_address() {
        let c = ResolverChoice {
            target: Target::System,
            transport: Transport::Plain,
        };
        assert_eq!(c.identity(), "system");
        let back = ResolverChoice::parse_identity("system").unwrap();
        assert_eq!(back.target, Target::System);
        assert!(!c.identity().contains(|ch: char| ch.is_ascii_digit()));
    }

    /// T8 — a private / loopback / link-local address is warned, not refused.
    #[test]
    fn private_address_is_warned_not_refused() {
        for s in [
            "192.168.1.1",
            "10.0.0.53",
            "127.0.0.1#5353",
            "fe80::1",
            "[::1]",
            "fd00::53",
        ] {
            let c = parse(s);
            let w = c
                .private_address_warning()
                .unwrap_or_else(|| panic!("{s} should warn"));
            assert!(w.contains("private address"), "{w}");
            assert!(w.contains(&c.identity()), "{w}");
        }
        assert!(parse("9.9.9.9").private_address_warning().is_none());
        assert!(parse("quad9").private_address_warning().is_none());
        assert!(parse("system").private_address_warning().is_none());
    }

    /// The gloss is a pure function of the identity string; legacy labels get
    /// the legacy sentence.
    #[test]
    fn gloss_covers_every_target_and_legacy_labels() {
        assert_eq!(
            ResolverChoice::gloss_of_identity("cloudflare"),
            "Cloudflare (1.1.1.1) over plain DNS, port 53 — DNSSEC validated by the instrument against the root keys, not by the resolver's word"
        );
        assert_eq!(
            ResolverChoice::gloss_of_identity("quad9/tls"),
            "Quad9 (9.9.9.9) over DNS-over-TLS, port 853, certificate dns.quad9.net — DNSSEC validated by the instrument against the root keys, not by the resolver's word"
        );
        assert!(ResolverChoice::gloss_of_identity("quad9/tcp")
            .starts_with("Quad9 (9.9.9.9) over plain DNS, TCP only, port 53 —"));
        assert!(ResolverChoice::gloss_of_identity("system").starts_with(
            "this machine's own system resolver (address not sealed) over plain DNS, port 53 —"
        ));
        assert!(
            ResolverChoice::gloss_of_identity("9.9.9.9/tls/dns.quad9.net")
                .starts_with("9.9.9.9 over DNS-over-TLS, port 853, certificate dns.quad9.net —")
        );
        assert!(ResolverChoice::gloss_of_identity("9.9.9.9#5353")
            .starts_with("9.9.9.9 port 5353 over plain DNS —"));
        assert!(ResolverChoice::gloss_of_identity("default").starts_with("unstructured label \"default\" — sealed before cc/resolver-choice; the engine binary measured through Cloudflare over plain DNS (ledger f7ad6d0)"));
        assert_eq!(
            ResolverChoice::gloss_of_identity("test"),
            "unstructured label \"test\" — sealed before cc/resolver-choice"
        );
        assert_eq!(ResolverChoice::parse_identity("default"), None);
        assert_eq!(
            ResolverChoice::parse_identity("9.9.9.9#53"),
            None,
            "non-canonical spellings are not identities"
        );
    }

    /// The two hand-typed presets carry the addresses and names the probe measured.
    #[test]
    fn extra_presets_are_pinned() {
        assert_eq!(DNS4EU.ips, &[IpAddr::V4(Ipv4Addr::new(86, 54, 11, 100))]);
        assert_eq!(DNS4EU.server_name, "unfiltered.joindns4.eu");
        assert_eq!(OPENDNS.ips, &[IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222))]);
        assert_eq!(OPENDNS.server_name, "dns.opendns.com");
        assert_eq!(
            parse("tls://dns4eu").server_name().as_deref(),
            Some("unfiltered.joindns4.eu")
        );
        assert_eq!(
            parse("https://opendns").server_name().as_deref(),
            Some("dns.opendns.com")
        );
        assert_eq!(
            parse("quad9").server_name(),
            None,
            "plain 53 has no certificate"
        );
    }
}
