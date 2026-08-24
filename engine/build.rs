//! Build-time provenance: stamp the engine with the git describe string so a
//! seal can name the exact commit that produced it — the load-bearing fix for
//! "two builds emitting different verdicts must stamp different versions".
//!
//! Falls back to a VISIBLY-distinct marker (never a silent default) when git
//! or the .git dir is absent (tarball / vendored build). Re-runs when HEAD
//! moves so cargo cannot cache a stale stamp across commits.

use std::process::Command;

fn main() {
    let git = Command::new("git")
        .args(["describe", "--always", "--dirty", "--tags"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "untracked".to_string());

    println!("cargo:rustc-env=RESOLUTION_SCOPE_GIT_VERSION={git}");

    // Staleness guard: rebuild the stamp when the checked-out commit changes.
    // (The Rust twin of the parent's "plain go build stamps dev into prod"
    // defect — without these, cargo caches the version across commits.)
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
    println!("cargo:rerun-if-changed=.git/packed-refs");
}
