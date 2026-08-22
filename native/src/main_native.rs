//! main_native.rs — Phase 2 bare-metal entry point (Option B: report/store receiver)
//!
//! Under Option B the no_std compartment RECEIVES a ScoredAnalysis (produced by
//! the std engine), re-derives the verdict seal, verifies it, renders the
//! report, and writes it through a granted capability. No network, no resolver.
//!
//! ```text
//!   seL4 root task
//!     └─ capability grants: ep_results_in (R), cap_local_report (W), clock (R)
//!           │
//!           ▼
//!   main_native.rs   ← you are here
//!     ├─ receive ScoredAnalysis + engine version over ep_results_in   [STUB]
//!     ├─ verify_seal()   — re-derive SHA3-512, compare to claimed     [REAL]
//!     ├─ render_text()   — render the report                          [REAL]
//!     └─ write via cap_local_report                                   [STUB]
//! ```
//!
//! The seal verification and rendering are REAL and host-tested (see seal.rs
//! tests); the IPC receive and capability write are STUBs until the LionsOS
//! runtime crate is wired (`sel4-runtime` / `sel4::BootInfo`).
//!
//! Build (bare-metal, no host OS):
//! ```sh
//! cargo build --target aarch64-unknown-none --release
//! ```

#![no_std]
#![no_main]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

use resolution_scope_native::{demo_verdict, render_text, seal_versioned, verify_seal};

// ─── Global allocator (bump over a static heap) ──────────────────────────────
// The seal/render path allocates Strings. Until the seL4 runtime provides a
// capability-granted memory frame, a static bump heap is the honest spike
// allocator: sufficient for a single verdict, never reused, panic-adjacent on
// exhaustion.

const HEAP_SIZE: usize = 64 * 1024;

#[repr(align(16))]
struct Heap([u8; HEAP_SIZE]);
static HEAP: Heap = Heap([0; HEAP_SIZE]);
static HEAP_POS: AtomicUsize = AtomicUsize::new(0);

struct BumpAllocator;

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pos = HEAP_POS.load(Ordering::Relaxed);
        let align = layout.align();
        let aligned = (pos + align - 1) & !(align - 1);
        let next = aligned + layout.size();
        if next > HEAP_SIZE {
            return core::ptr::null_mut();
        }
        HEAP_POS.store(next, Ordering::Relaxed);
        HEAP.0.as_ptr().add(aligned) as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator: no reuse. Intentional for the spike.
    }
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

// NOTE: no `#[alloc_error_handler]` — that attribute is nightly-only. On stable
// the `alloc` crate's default `handle_alloc_error` aborts, which is the correct
// failure mode for a store that cannot allocate (there is no recovery path).

// ─── Panic handler (bare-metal: panic = abort) ───────────────────────────────

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    // STUB: in production, write info to the IPC log endpoint before halting.
    let _ = info;
    loop {
        core::hint::spin_loop();
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Bare-metal entry. The LionsOS runtime (or `_start` trampoline below) calls
/// `main`; `#[no_mangle]` keeps the symbol stable for the linker.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    main();
    loop {
        core::hint::spin_loop();
    }
}

/// The store compartment's job, end to end. Ends in a diverging spin halt so it
/// never returns; the trailing loop in `_start` is the halt if it ever did.
#[no_mangle]
pub fn main() {
    // ── Receive ──────────────────────────────────────────────────────────────
    // STUB: receive the ScoredAnalysis + producing engine version over
    // ep_results_in. In the spike, embed a demo verdict to prove the
    // seal-verify + render path compiles and links bare-metal. Replace with
    // actual IPC receive (sel4-runtime) when wired.
    let a = demo_verdict();
    let produced_by: &str = "0.1.0";

    // ── Verify ───────────────────────────────────────────────────────────────
    // Re-derive the seal and confirm it matches the claimed value (tamper
    // evidence). For the demo, the "claimed" seal is the freshly re-derived one
    // (the real IPC carries the engine's seal alongside the verdict).
    let claimed = seal_versioned(&a, produced_by);
    let verified = verify_seal(&a, produced_by, &claimed);
    // In the spike, the verify is expected to hold; a broken seal re-derivation
    // is a panic (correct: the store must never persist an unverifiable verdict).
    assert!(
        verified,
        "seal re-derivation failed — verdict altered in transit"
    );

    // ── Render ───────────────────────────────────────────────────────────────
    let report = render_text(&a, produced_by);

    // ── Write ────────────────────────────────────────────────────────────────
    // STUB: write `report` via cap_local_report. In the spike there is no file
    // capability yet; the report is held and the thread suspends.
    let _ = &report;

    // In seL4, a finished thread suspends its own TCB (seL4_TCB_Suspend).
    loop {
        core::hint::spin_loop();
    }
}
