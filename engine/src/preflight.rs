// preflight.rs — both controls, once per process, before any seal
//
// A guard needs BOTH controls: a positive case that must pass and a negative
// case that must fail, both exercised. The DNSSEC verdict is a guard, so
// before the first scan the vantage proves it can validate at all:
//
//   positive  `.` DNSKEY must come back Proof::Secure — validated directly
//             against hickory's compiled-in root anchors (20326, 38696);
//             adds no third-party name to the wire (the validator fetches
//             it in any chain walk anyway).
//   negative  `dnssec-failed.org` A must be REFUSED — SERVFAIL from a
//             validating upstream (Mode::UpstreamAndLocal), or an answer the
//             local validator marks Bogus (Mode::LocalOnly).
//
// The hazard this closes was measured 2026-09-03 (scratchpad/wf/dot-probe/
// strip_opt_proxy.py): a DO/OPT-stripping forwarder on the path makes EVERY
// zone read Bogus → "broken chain", falsely, on every scan. Pre-registered
// H4 ("Indeterminate") was refuted both ways: not a validation bypass, but a
// false-BrokenChain hazard. The preflight is the guard; a refusal seals
// nothing and exits 3. There is no way to skip it — skipping would be a
// silent downgrade.

use std::fmt;

use hickory_proto::dnssec::Proof;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use hickory_resolver::net::{DnsError, NetError};

use crate::egress::EgressSnapshot;
use crate::resolver::{TargetClass, Vantage};

pub const POSITIVE_CONTROL: &str = ".";
pub const NEGATIVE_CONTROL: &str = "dnssec-failed.org";

/// What one control lookup came back as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlOutcome {
    /// Every answer record carried Proof::Secure.
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
    /// The resolver refused with SERVFAIL (a validating upstream's "bogus").
    ServFail,
    NxDomain,
    /// NOERROR with no answers.
    NoRecords,
    /// hickory's timeout elapsed.
    Timeout(String),
    /// A connection could not be made (Io / NoConnections), with hickory's
    /// exact Display and Debug text.
    Transport {
        display: String,
        debug: String,
    },
    Other {
        display: String,
        debug: String,
    },
}

impl fmt::Display for ControlOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlOutcome::Secure => f.write_str("Secure"),
            ControlOutcome::Insecure => f.write_str("Insecure"),
            ControlOutcome::Bogus => f.write_str("Bogus"),
            ControlOutcome::Indeterminate => f.write_str("Indeterminate"),
            ControlOutcome::ServFail => f.write_str("SERVFAIL"),
            ControlOutcome::NxDomain => f.write_str("NXDOMAIN"),
            ControlOutcome::NoRecords => f.write_str("NOERROR, no records"),
            ControlOutcome::Timeout(d) => write!(f, "unreachable: {d}"),
            ControlOutcome::Transport { display, .. } => write!(f, "unreachable: {display}"),
            ControlOutcome::Other { display, .. } => write!(f, "error: {display}"),
        }
    }
}

/// Where validation happens for this vantage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The resolver validates too (it SERVFAILed the bogus fixture) and the
    /// instrument validates locally.
    UpstreamAndLocal,
    /// The resolver hands signatures through without validating; only the
    /// instrument's local validation stands.
    LocalOnly,
}

impl Mode {
    pub fn describe(self) -> &'static str {
        match self {
            Mode::UpstreamAndLocal => "the resolver validates too",
            Mode::LocalOnly => "validation is local only; this resolver does not validate",
        }
    }
}

/// Why a vantage was refused. Nothing was sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightRefusal {
    /// The root DNSKEY did not come back Secure.
    CannotValidate { positive: ControlOutcome },
    /// The bogus fixture was accepted as Secure or Insecure.
    NegativeNotRefused { negative: ControlOutcome },
    /// The bogus fixture could not be reached from an unnamed vantage.
    NegativeUnreachable { negative: ControlOutcome },
    /// The vantage could not be reached at all.
    Transport { display: String, debug: String },
}

impl fmt::Display for PreflightRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PreflightRefusal::CannotValidate { positive } => write!(
                f,
                "cannot validate DNSSEC — the root DNSKEY came back {positive}, not Secure"
            ),
            PreflightRefusal::NegativeNotRefused { negative } => write!(
                f,
                "accepted a known-bad signature — {NEGATIVE_CONTROL} came back {negative}; this vantage cannot tell a broken chain from a good one"
            ),
            PreflightRefusal::NegativeUnreachable { negative } => write!(
                f,
                "the negative control {NEGATIVE_CONTROL} could not be reached ({negative}); an unnamed vantage must prove it rejects a bad signature before anything is sealed"
            ),
            PreflightRefusal::Transport { display, debug } => {
                write!(f, "no answer ({display} / Debug: {debug})")
            }
        }
    }
}

impl std::error::Error for PreflightRefusal {}

/// The pure decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Pass {
        mode: Mode,
        /// Set when the negative control could not be exercised at a preset.
        warning: Option<String>,
    },
    Refuse(PreflightRefusal),
}

/// The truth table (P1). Positive first: a transport failure or anything but
/// Secure refuses. Then the negative: SERVFAIL / Bogus pass (two modes);
/// Secure / Insecure refuse (the vantage validates nothing); unreachable
/// refuses an unnamed vantage and warns at a preset (a third party's fixture
/// outage must not disable a measured vantage).
pub fn verdict(
    positive: &ControlOutcome,
    negative: &ControlOutcome,
    class: TargetClass,
) -> Outcome {
    match positive {
        ControlOutcome::Secure => {}
        ControlOutcome::Transport { display, debug } | ControlOutcome::Other { display, debug } => {
            return Outcome::Refuse(PreflightRefusal::Transport {
                display: display.clone(),
                debug: debug.clone(),
            })
        }
        ControlOutcome::Timeout(d) => {
            return Outcome::Refuse(PreflightRefusal::Transport {
                display: d.clone(),
                debug: "Timeout".to_string(),
            })
        }
        other => {
            return Outcome::Refuse(PreflightRefusal::CannotValidate {
                positive: other.clone(),
            })
        }
    }
    match negative {
        ControlOutcome::ServFail => Outcome::Pass {
            mode: Mode::UpstreamAndLocal,
            warning: None,
        },
        ControlOutcome::Bogus => Outcome::Pass {
            mode: Mode::LocalOnly,
            warning: None,
        },
        ControlOutcome::Secure | ControlOutcome::Insecure => {
            Outcome::Refuse(PreflightRefusal::NegativeNotRefused {
                negative: negative.clone(),
            })
        }
        unreachable => match class {
            TargetClass::Preset => Outcome::Pass {
                // The mode is unknown when the negative did not run; report
                // the more conservative one and say why.
                mode: Mode::LocalOnly,
                warning: Some(format!(
                    "{NEGATIVE_CONTROL} → {unreachable} (warning: the negative control could not be exercised; DNSSEC verdicts stand on the root-key check alone)"
                )),
            },
            TargetClass::System | TargetClass::Address => {
                Outcome::Refuse(PreflightRefusal::NegativeUnreachable {
                    negative: unreachable.clone(),
                })
            }
        },
    }
}

/// The receipt of a passed preflight — printed beside the seal, never sealed,
/// never persisted.
#[derive(Debug, Clone)]
pub struct VantageReceipt {
    pub identity: String,
    pub mode: Mode,
    pub positive: (&'static str, ControlOutcome),
    pub negative: (&'static str, ControlOutcome),
    /// UTC to the second, e.g. `2026-09-03T05:13:35Z`.
    pub at_utc: String,
    pub warning: Option<String>,
    /// What the two control lookups sent, measured at the socket.
    pub egress: EgressSnapshot,
}

/// Classify a lookup result into a control outcome. Every answer record must
/// be Secure for `Secure`; the worst proof present otherwise.
pub fn classify(result: &Result<hickory_resolver::lookup::Lookup, NetError>) -> ControlOutcome {
    match result {
        Ok(l) => {
            let answers = l.answers();
            if answers.is_empty() {
                return ControlOutcome::NoRecords;
            }
            let mut worst = Proof::Secure;
            for r in answers {
                worst = worst_of(worst, r.proof);
            }
            proof_outcome(worst)
        }
        Err(e) => classify_err(e),
    }
}

fn worst_of(a: Proof, b: Proof) -> Proof {
    // Bogus < Indeterminate < Insecure < Secure, by how much the answer can be trusted.
    fn rank(p: Proof) -> u8 {
        match p {
            Proof::Bogus => 0,
            Proof::Indeterminate => 1,
            Proof::Insecure => 2,
            Proof::Secure => 3,
        }
    }
    if rank(b) < rank(a) {
        b
    } else {
        a
    }
}

fn proof_outcome(p: Proof) -> ControlOutcome {
    match p {
        Proof::Secure => ControlOutcome::Secure,
        Proof::Insecure => ControlOutcome::Insecure,
        Proof::Bogus => ControlOutcome::Bogus,
        Proof::Indeterminate => ControlOutcome::Indeterminate,
    }
}

pub fn classify_err(e: &NetError) -> ControlOutcome {
    match e {
        NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail)) => ControlOutcome::ServFail,
        NetError::Dns(DnsError::NoRecordsFound(nr)) => match nr.response_code {
            ResponseCode::NXDomain => ControlOutcome::NxDomain,
            ResponseCode::ServFail => ControlOutcome::ServFail,
            _ => ControlOutcome::NoRecords,
        },
        NetError::Dns(DnsError::Nsec { proof, .. }) => proof_outcome(*proof),
        NetError::Timeout => ControlOutcome::Timeout(e.to_string()),
        NetError::Io(_) | NetError::NoConnections => ControlOutcome::Transport {
            display: e.to_string(),
            debug: format!("{e:?}"),
        },
        other => ControlOutcome::Other {
            display: other.to_string(),
            debug: format!("{other:?}"),
        },
    }
}

/// UTC to the second, RFC 3339 `Z`, from the system clock (no chrono needed:
/// the civil-date arithmetic is the proleptic-Gregorian algorithm).
pub fn utc_now_to_the_second() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    utc_from_epoch(secs)
}

pub fn utc_from_epoch(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil_from_days.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

impl Vantage {
    /// Run both controls through this vantage. `Ok` carries the receipt;
    /// `Err` is the refusal (nothing sealed, exit 3 at the CLI).
    pub async fn preflight(&self) -> Result<VantageReceipt, PreflightRefusal> {
        let at_utc = utc_now_to_the_second();
        let positive = classify(&self.lookup(POSITIVE_CONTROL, RecordType::DNSKEY).await);
        // Do not spend the negative lookup on a vantage that already failed.
        let negative = if positive == ControlOutcome::Secure {
            classify(&self.lookup(NEGATIVE_CONTROL, RecordType::A).await)
        } else {
            ControlOutcome::Other {
                display: "not attempted: the positive control failed first".into(),
                debug: "NotAttempted".into(),
            }
        };
        let egress = self.ledger().drain();
        match verdict(&positive, &negative, self.choice().target_class()) {
            Outcome::Pass { mode, warning } => Ok(VantageReceipt {
                identity: self.identity(),
                mode,
                positive: (POSITIVE_CONTROL, positive),
                negative: (NEGATIVE_CONTROL, negative),
                at_utc,
                warning,
                egress,
            }),
            Outcome::Refuse(r) => Err(r),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport() -> ControlOutcome {
        ControlOutcome::Transport {
            display: "no connections available".into(),
            debug: "NoConnections".into(),
        }
    }

    /// P1 — the full positive × negative × target-class table.
    #[test]
    fn preflight_decision_truth_table() {
        use ControlOutcome as C;
        use TargetClass as T;
        let classes = [T::Preset, T::System, T::Address];
        let timeout = C::Timeout("request timed out".into());

        // Positive Secure + negative SERVFAIL → UpstreamAndLocal, every class.
        for c in classes {
            assert_eq!(
                verdict(&C::Secure, &C::ServFail, c),
                Outcome::Pass {
                    mode: Mode::UpstreamAndLocal,
                    warning: None
                }
            );
            // Positive Secure + negative Bogus → LocalOnly.
            assert_eq!(
                verdict(&C::Secure, &C::Bogus, c),
                Outcome::Pass {
                    mode: Mode::LocalOnly,
                    warning: None
                }
            );
            // Positive not Secure → CannotValidate, whatever the negative says.
            for p in [
                C::Bogus,
                C::Insecure,
                C::Indeterminate,
                C::NoRecords,
                C::NxDomain,
                C::ServFail,
            ] {
                assert_eq!(
                    verdict(&p, &C::ServFail, c),
                    Outcome::Refuse(PreflightRefusal::CannotValidate {
                        positive: p.clone()
                    }),
                    "{p:?} {c:?}"
                );
            }
            // Positive transport / timeout → Transport refusal.
            assert!(matches!(
                verdict(&transport(), &C::ServFail, c),
                Outcome::Refuse(PreflightRefusal::Transport { .. })
            ));
            assert!(matches!(
                verdict(&timeout, &C::ServFail, c),
                Outcome::Refuse(PreflightRefusal::Transport { .. })
            ));
            // Negative accepted → NegativeNotRefused.
            for n in [C::Secure, C::Insecure] {
                assert_eq!(
                    verdict(&C::Secure, &n, c),
                    Outcome::Refuse(PreflightRefusal::NegativeNotRefused {
                        negative: n.clone()
                    })
                );
            }
        }
        // Negative unreachable: a preset passes with a warning; system and
        // an address refuse.
        for n in [
            C::NxDomain,
            timeout.clone(),
            transport(),
            C::NoRecords,
            C::Indeterminate,
        ] {
            match verdict(&C::Secure, &n, T::Preset) {
                Outcome::Pass {
                    mode: Mode::LocalOnly,
                    warning: Some(w),
                } => assert!(w.contains("could not be exercised"), "{w}"),
                other => panic!("preset with {n:?} → {other:?}"),
            }
            for c in [T::System, T::Address] {
                assert_eq!(
                    verdict(&C::Secure, &n, c),
                    Outcome::Refuse(PreflightRefusal::NegativeUnreachable {
                        negative: n.clone()
                    }),
                    "{n:?} {c:?}"
                );
            }
        }
    }

    /// Every refusal names what happened; the CannotValidate one names the
    /// proof that came back.
    #[test]
    fn refusals_name_the_outcome() {
        let r = PreflightRefusal::CannotValidate {
            positive: ControlOutcome::Bogus,
        };
        assert!(r.to_string().contains("came back Bogus, not Secure"));
        let r = PreflightRefusal::NegativeNotRefused {
            negative: ControlOutcome::Secure,
        };
        assert!(r
            .to_string()
            .contains("cannot tell a broken chain from a good one"));
    }

    #[test]
    fn utc_formatting_is_rfc3339_to_the_second() {
        assert_eq!(utc_from_epoch(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_from_epoch(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(utc_from_epoch(1_788_364_509), "2026-09-02T15:55:09Z");
    }

    #[test]
    fn classify_maps_errors_to_outcomes() {
        assert_eq!(
            classify_err(&NetError::Dns(DnsError::ResponseCode(
                ResponseCode::ServFail
            ))),
            ControlOutcome::ServFail
        );
        assert!(matches!(
            classify_err(&NetError::Timeout),
            ControlOutcome::Timeout(_)
        ));
        assert!(matches!(
            classify_err(&NetError::NoConnections),
            ControlOutcome::Transport { .. }
        ));
    }
}
