// ffi.rs — the store compartment's C ABI (the Rust↔Microkit seam)
//
// Under Option B the store compartment runs inside seL4 (via the Microkit
// framework), while the engine that produces verdicts runs OUTSIDE (std Rust on
// the Linux host). The boundary between them is this C ABI:
//
//   engine (std)  ──JSON + claimed seal + engine version──▶  store (no_std)
//
// `rs_store_report` is the store's single entry point. It receives the
// serialised `ScoredAnalysis` + the engine's claimed seal + the producing
// engine version, and:
//
//   1. deserialises the verdict (serde_json, alloc-only — the same wire format
//      the engine already emits);
//   2. re-derives the SHA3-512 seal over (verdict, engine version);
//   3. compares to the claimed seal — TAMPER-EVIDENCE at the boundary;
//   4. on match, renders the report and returns it; on mismatch/parse-failure,
//      returns NULL (the store must never persist an unverifiable verdict).
//
// The returned pointer is a NUL-terminated UTF-8 string on the compartment
// heap; the caller frees it with `rs_store_free`. This is the exact ABI both
// wiring paths need:
//
//   (a) a C shim (store.c) that receives over the channel and calls this; or
//   (b) the no_std Rust bin linking libmicrokitco directly and calling this.
//
// No network, no resolver, no tokio. The functions are `#[no_mangle] pub
// extern "C"` so they are globally visible symbols the Microkit toolchain can
// link against.
//
// ── HARDENING TRACK (SciSpace second-opinion 2026-08-22, tracked not done) ──
//   1A (Low):     monotonic u64 attempt-counter for forensics — a static
//                 AtomicU64 bumped on each tamper/parse failure, exposed over a
//                 second query message type or a read-only memory_region. Not a
//                 soundness fix; NULL + caller-logged is already correct.
//   1B (Stage 3): migrate the wire format serde_json → postcard. The seal is
//                 computed over canonical_input (NOT the wire bytes), so JSON
//                 cannot cause a silent integrity failure — only a liveness
//                 failure (false NULL on malformed input). postcard shrinks the
//                 TCB (parser LOC) inside the compartment; it is a DoS-surface
//                 reduction, not a correctness fix. Do NOT block Stage 2 on it.
//   1C (now-done): allocator strategy — bump allocator, see main_native.rs.
//                 INVARIANT: dealloc is a no-op; the heap is sized (64 KiB) for
//                 the demo's single-verdict-per-boot model and does NOT reset
//                 within an epoch. A store receiving many verdicts per boot
//                 needs a proper allocator (linked_list_allocator/dlmalloc) or
//                 per-verdict heap reset — Stage 3.
//   3  (Stage 2):  SEAL_SCHEME version exchange — the engine sends produced_by
//                 (engine version) but NOT the seal scheme constant. If the
//                 engine bumps resolution-scope-sha3-512-v2 → v3 while the store
//                 still holds v2, every verdict fails verification (NULL) with no
//                 diagnostic distinguishing version-skew from tamper. Fix (option
//                 a, SciSpace): carry the scheme over the boundary and assert it
//                 matches before re-deriving, so skew is a distinct failure class.

use alloc::ffi::CString;
use alloc::string::String;
use core::ffi::{c_char, CStr};

use crate::report::render_text;
use crate::seal::seal_versioned;
use resolution_scope_types::ScoredAnalysis;

/// Read a NUL-terminated C string into an owned String (empty on null pointer).
unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

/// The store compartment's single entry point (C ABI).
///
/// Returns a NUL-terminated rendered report on successful seal verification,
/// or NULL when the verdict cannot be deserialised OR the re-derived seal does
/// not match `claimed_seal` (tamper detected — never persist).
///
/// # Safety
/// `json` must point to `json_len` valid bytes. `claimed_seal` and `produced_by`
/// must be valid NUL-terminated C strings, or null.
#[no_mangle]
pub unsafe extern "C" fn rs_store_report(
    json: *const u8,
    json_len: usize,
    claimed_seal: *const c_char,
    produced_by: *const c_char,
) -> *mut c_char {
    if json.is_null() {
        return core::ptr::null_mut();
    }
    let slice = unsafe { core::slice::from_raw_parts(json, json_len) };
    let analysis: ScoredAnalysis = match serde_json::from_slice(slice) {
        Ok(a) => a,
        Err(_) => return core::ptr::null_mut(),
    };
    let claimed = unsafe { cstr_to_string(claimed_seal) };
    let produced = unsafe { cstr_to_string(produced_by) };

    // Tamper-evidence: the store persists nothing whose seal does not match what
    // the engine claimed crossed the boundary.
    if seal_versioned(&analysis, &produced) != claimed {
        return core::ptr::null_mut();
    }

    let report = render_text(&analysis, &produced);
    match CString::new(report) {
        Ok(c) => c.into_raw(),
        Err(_) => core::ptr::null_mut(),
    }
}

/// Free a report pointer returned by [`rs_store_report`].
///
/// # Safety
/// `ptr` must be a pointer previously returned by [`rs_store_report`] and not
/// already freed, or null.
#[no_mangle]
pub unsafe extern "C" fn rs_store_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { drop(CString::from_raw(ptr)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::ffi::CString;
    use alloc::format;
    use core::ffi::CStr;

    /// The golden seal for the demo verdict, produced by "0.1.0" — the drift-pin
    /// from seal.rs. Used here to prove the FFI round-trip returns a report that
    /// carries exactly this seal.
    const GOLDEN_SEAL: &str = "9a0b7790ff865f24df52ae0449284809cd7f61c5d4ea267f292de8650adcdb2bfdee735e15d4a9bf7ea84052c5b3f6c49cbd0062e30c1f13d4f37ebd70203a35";

    /// Serialise the demo verdict, seal it, and run it through the FFI entry —
    /// the report must come back non-null and carry the golden seal.
    #[test]
    fn ffi_roundtrip_returns_golden_seal() {
        let a = crate::fixtures::demo_verdict();
        let json = serde_json::to_vec(&a).expect("serialise verdict");
        let claimed = CString::new(GOLDEN_SEAL).expect("seal has no NUL");
        let produced = CString::new("0.1.0").expect("version has no NUL");

        let ptr = unsafe {
            rs_store_report(
                json.as_ptr(),
                json.len(),
                claimed.as_ptr(),
                produced.as_ptr(),
            )
        };
        assert!(
            !ptr.is_null(),
            "seal round-trip must succeed for a valid verdict"
        );

        let report = unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        assert!(
            report.contains(&format!("Seal      : {GOLDEN_SEAL}")),
            "the returned report must carry the golden seal — got:\n{report}"
        );

        unsafe { rs_store_free(ptr) };
    }

    /// A tampered claimed seal must fail closed: NULL, never a rendered report.
    #[test]
    fn ffi_rejects_tampered_seal() {
        let a = crate::fixtures::demo_verdict();
        let json = serde_json::to_vec(&a).expect("serialise verdict");
        let bogus = CString::new("deadbeef").expect("no NUL");
        let produced = CString::new("0.1.0").expect("no NUL");

        let ptr = unsafe {
            rs_store_report(json.as_ptr(), json.len(), bogus.as_ptr(), produced.as_ptr())
        };
        assert!(
            ptr.is_null(),
            "a mismatched seal must be rejected (NULL), never rendered"
        );
    }

    /// A parse failure (garbage bytes) must fail closed too.
    #[test]
    fn ffi_rejects_garbage_json() {
        let garbage = b"not json";
        let claimed = CString::new(GOLDEN_SEAL).expect("no NUL");
        let produced = CString::new("0.1.0").expect("no NUL");
        let ptr = unsafe {
            rs_store_report(
                garbage.as_ptr(),
                garbage.len(),
                claimed.as_ptr(),
                produced.as_ptr(),
            )
        };
        assert!(ptr.is_null(), "unparseable input must be rejected (NULL)");
    }
}
