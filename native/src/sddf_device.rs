//! sddf_device.rs — sDDF-to-smoltcp Device trait adapter (stub)
//!
//! # Purpose
//! Bridges the seL4 Device Driver Framework (sDDF) DMA ring buffer interface
//! to smoltcp's `Device` trait so the Phase 2 native DNS engine can send and
//! receive raw Ethernet frames without a Linux network stack.
//!
//! # Architecture position
//! ```text
//!   LionsOS network driver (sDDF)
//!         │  capability-granted DMA memory
//!         │  RX ring  ──►  SddfDevice::receive()
//!         │  TX ring  ◄──  SddfDevice::transmit()
//!         ▼
//!   SddfDevice  (this file — implements smoltcp::phy::Device)
//!         │
//!         ▼
//!   smoltcp Interface  (EthernetInterface)
//!         │
//!         ▼
//!   smoltcp DnsSocket / TcpSocket
//!         │
//!         ▼
//!   hickory-proto (sync DNS wire format)
//!         │
//!         ▼
//!   ScoredAnalysis  (analysis.rs)
//! ```
//!
//! # seL4 capability model
//! The DMA buffers are mapped into this compartment's VSpace via capability
//! grants from the root task (see dns_sovereign_compartment.cdl, slot 2:
//! dma_frame_cap).  No shared-memory mapping exists outside this grant.
//! The network driver communicates only through the sDDF ring buffers;
//! it cannot read this compartment's heap.
//!
//! # TODO markers indicate integration work required before Phase 2 milestone
//! Search for `TODO(sddf)` to find every gap.

// NOTE: this module does not declare #![no_std] — the crate root (lib.rs)
// owns that decision. The native lib is currently std (host-testable); the
// no_std transition is gated on the hickory __dnssec fix
// (docs/UPSTREAM-NOSTD-DNSSEC-SCOPE.md).
extern crate alloc;

use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

// ─── Ring buffer descriptors ──────────────────────────────────────────────────

/// One slot in an sDDF receive ring.
///
/// In the real sDDF interface each descriptor holds a physical address and a
/// length.  The DMA region is pre-mapped; we index into it by slot number.
/// TODO(sddf): replace with the actual sDDF ring descriptor type from the
///             LionsOS Rust support crate when it is available.
#[derive(Debug)]
pub struct SddfRxDescriptor {
    /// Offset into the shared DMA region (bytes).
    pub offset: usize,
    /// Byte length of the received frame.
    pub len: usize,
}

/// One slot in an sDDF transmit ring.
#[derive(Debug)]
pub struct SddfTxDescriptor {
    /// Offset into the shared DMA region (bytes) where caller writes the frame.
    pub offset: usize,
    /// Maximum usable bytes at this offset.
    pub capacity: usize,
}

// ─── DMA region ───────────────────────────────────────────────────────────────

/// A contiguous region of capability-granted DMA memory shared with the sDDF
/// network driver.
///
/// The seL4 capability that backs this mapping is `dma_frame_cap` (slot 2 in
/// dns_sovereign_compartment.cdl).  All frame data lives here; no heap copying
/// is performed on the fast path.
///
/// TODO(sddf): in the real implementation this is a `*mut u8` obtained from
///             `seL4_Map` on the capability grant, not a heap-allocated Vec.
pub struct SddfDmaRegion {
    /// Base pointer into the DMA mapping.
    /// SAFETY invariant: must point to a region at least `len` bytes long,
    /// mapped with RW permissions from the capability grant.
    ptr: *mut u8,
    /// Total mapped size in bytes.
    len: usize,
}

// SAFETY: sDDF DMA memory is not accessed concurrently from multiple threads
// within this compartment (single-core seL4 cooperative model assumed for
// Phase 2 spike).  Revise before enabling SMP.
unsafe impl Send for SddfDmaRegion {}
unsafe impl Sync for SddfDmaRegion {}

impl SddfDmaRegion {
    /// Construct from a raw capability-granted mapping.
    ///
    /// # Safety
    /// `ptr` must be valid for `len` bytes for the entire lifetime of `self`.
    /// It must have been obtained from an seL4 capability grant, not from the
    /// Rust allocator.
    pub unsafe fn from_raw(ptr: *mut u8, len: usize) -> Self {
        Self { ptr, len }
    }

    /// Construct a heap-backed stub for unit tests.
    ///
    /// This is the only path that uses the Rust allocator; production code
    /// must use `from_raw`.
    #[cfg(test)]
    pub fn for_test(len: usize) -> Self {
        let mut buf = alloc::vec![0u8; len];
        let ptr = buf.as_mut_ptr();
        core::mem::forget(buf); // keep allocation alive; intentional leak in test
        Self { ptr, len }
    }

    /// Return a mutable byte slice for the given offset + length.
    ///
    /// # Panics
    /// Panics in debug builds if the range is out of bounds.
    pub fn slice_mut(&mut self, offset: usize, len: usize) -> &mut [u8] {
        assert!(
            offset + len <= self.len,
            "SddfDmaRegion: offset {} + len {} exceeds mapped size {}",
            offset, len, self.len
        );
        // SAFETY: bounds checked above; no other mutable alias exists while
        // this borrow is live (single-threaded cooperative model).
        unsafe { core::slice::from_raw_parts_mut(self.ptr.add(offset), len) }
    }

    /// Return an immutable byte slice.
    pub fn slice(&self, offset: usize, len: usize) -> &[u8] {
        assert!(
            offset + len <= self.len,
            "SddfDmaRegion: offset {} + len {} exceeds mapped size {}",
            offset, len, self.len
        );
        unsafe { core::slice::from_raw_parts(self.ptr.add(offset), len) }
    }
}

// ─── Ring handles ─────────────────────────────────────────────────────────────

/// Handle to the sDDF receive ring.
///
/// TODO(sddf): replace with the LionsOS `sddf_rx_ring_handle_t` equivalent.
pub struct SddfRxRing {
    /// Index of the next slot to dequeue from the driver.
    pub head: usize,
    /// Total ring capacity (number of slots).
    pub capacity: usize,
    /// Slot size in bytes (maximum Ethernet frame size, typically 1514 or 2048).
    pub slot_size: usize,
}

impl SddfRxRing {
    /// Attempt to dequeue one received frame descriptor.
    ///
    /// Returns `None` when the ring is empty (driver has no new frames).
    ///
    /// TODO(sddf): implement the actual sDDF ring protocol:
    ///   1. Read the used-ring tail pointer via memory-mapped register or shared counter.
    ///   2. Memory barrier before reading the descriptor.
    ///   3. Return the descriptor and advance `head`.
    ///   4. Post a return descriptor to the free ring so the driver can reuse the slot.
    pub fn dequeue(&mut self) -> Option<SddfRxDescriptor> {
        // TODO(sddf): ring empty check against driver-written tail pointer
        let _ = self.head;
        None // stub: always empty until DMA integration is wired
    }
}

/// Handle to the sDDF transmit ring.
///
/// TODO(sddf): replace with LionsOS `sddf_tx_ring_handle_t` equivalent.
pub struct SddfTxRing {
    /// Index of the next free slot.
    pub tail: usize,
    /// Total ring capacity.
    pub capacity: usize,
    /// Slot size in bytes.
    pub slot_size: usize,
}

impl SddfTxRing {
    /// Acquire one transmit slot.
    ///
    /// Returns `None` when the ring is full (driver has not yet consumed
    /// previously submitted frames).
    ///
    /// TODO(sddf): implement the actual sDDF tx protocol:
    ///   1. Check free-ring head against tail.
    ///   2. Dequeue a free slot descriptor.
    ///   3. Return its offset so the caller can write the frame.
    ///   4. On commit: enqueue the used descriptor and notify the driver
    ///      via seL4_Signal on the tx notification capability.
    pub fn acquire(&mut self) -> Option<SddfTxDescriptor> {
        // TODO(sddf): free-slot check
        let _ = self.tail;
        None // stub: no slots available until DMA integration is wired
    }

    /// Commit a previously acquired transmit slot.
    ///
    /// `desc` must have been returned by the most recent `acquire()` call.
    /// `len` is the number of valid bytes written into the slot.
    ///
    /// TODO(sddf): enqueue used descriptor to driver tx ring; signal driver.
    pub fn commit(&mut self, desc: SddfTxDescriptor, len: usize) {
        // TODO(sddf): signal the sDDF network driver via seL4_Signal on the
        //             tx notification endpoint (capDL slot 3: net_tx_ntfn_cap).
        let _ = (desc, len);
    }
}

// ─── smoltcp Device implementation ───────────────────────────────────────────

/// smoltcp `Device` implementation backed by sDDF DMA ring buffers.
///
/// # Capability requirements (see dns_sovereign_compartment.cdl)
/// - Slot 2 (`dma_frame_cap`): READ + WRITE on DMA region
/// - Slot 3 (`net_tx_ntfn_cap`): SIGNAL on transmit notification endpoint
/// - No capability grants the network driver access to this compartment's heap.
pub struct SddfDevice {
    rx: SddfRxRing,
    tx: SddfTxRing,
    dma: SddfDmaRegion,
    /// Cached capabilities reported to smoltcp.
    caps: DeviceCapabilities,
}

impl SddfDevice {
    /// Construct from pre-initialised ring handles and a capability-granted DMA region.
    ///
    /// Call this once from the seL4 root task initialisation path after mapping
    /// the DMA capability and initialising both ring handles.
    pub fn new(rx: SddfRxRing, tx: SddfTxRing, dma: SddfDmaRegion) -> Self {
        let mut caps = DeviceCapabilities::default();
        // Standard Ethernet MTU; sDDF drivers may expose larger jumbo frames —
        // adjust to match the hardware capability when known.
        caps.max_transmission_unit = 1514;
        // sDDF provides raw Ethernet frames (no IP offload in Phase 2 spike).
        caps.medium = Medium::Ethernet;
        // TODO(sddf): query driver for hardware checksum offload capability and
        //             set caps.checksum accordingly to avoid redundant computation.
        Self { rx, tx, dma, caps }
    }
}

// ─── RxToken ─────────────────────────────────────────────────────────────────

/// Token representing one received Ethernet frame in DMA memory.
pub struct SddfRxToken {
    /// Offset into the DMA region where the frame data begins.
    offset: usize,
    /// Valid byte count for this frame.
    len: usize,
    // NOTE: a production implementation would hold a mutable borrow of the
    // DMA region here and return the slot to the free ring on drop.
    // For the stub we use raw pointer arithmetic to avoid lifetime complexity.
    dma_ptr: *mut u8,
    dma_len: usize,
}

impl phy::RxToken for SddfRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // SAFETY: bounds were checked when the token was constructed in
        // `SddfDevice::receive()`.  No other mutable alias exists while
        // this token is live (smoltcp's single-threaded poll model).
        let buf = unsafe {
            assert!(
                self.offset + self.len <= self.dma_len,
                "SddfRxToken: frame range out of DMA bounds"
            );
            core::slice::from_raw_parts_mut(self.dma_ptr.add(self.offset), self.len)
        };
        f(buf)
        // TODO(sddf): after f() returns, post a return descriptor to the
        //             sDDF free ring so the driver can reuse this slot.
    }
}

// ─── TxToken ─────────────────────────────────────────────────────────────────

/// Token representing one reserved transmit slot in DMA memory.
pub struct SddfTxToken {
    desc: SddfTxDescriptor,
    dma_ptr: *mut u8,
    dma_len: usize,
    // TODO(sddf): hold a reference to SddfTxRing so `commit()` can be called
    // in `consume()` without unsafety.  For the stub we skip the commit.
}

impl phy::TxToken for SddfTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // SAFETY: bounds checked against DMA region size in `transmit()`.
        let buf = unsafe {
            assert!(
                self.desc.offset + len <= self.dma_len,
                "SddfTxToken: frame write would exceed DMA bounds"
            );
            core::slice::from_raw_parts_mut(self.dma_ptr.add(self.desc.offset), len)
        };
        let result = f(buf);
        // TODO(sddf): call tx_ring.commit(self.desc, len) and signal the driver
        //             via seL4_Signal on net_tx_ntfn_cap (capDL slot 3).
        //             The stub discards the write; no frame is transmitted yet.
        let _ = self.desc;
        result
    }
}

// ─── Device trait ─────────────────────────────────────────────────────────────

impl phy::Device for SddfDevice {
    type RxToken<'a> = SddfRxToken where Self: 'a;
    type TxToken<'a> = SddfTxToken where Self: 'a;

    /// Poll the sDDF receive ring for an available frame.
    ///
    /// Returns `Some((rx_token, tx_token))` if both a received frame and a free
    /// transmit slot are available simultaneously (required by smoltcp's Device
    /// contract for devices that need to send acknowledgements while processing
    /// incoming frames, e.g. TCP ACKs).
    ///
    /// Returns `None` when either the RX ring is empty or the TX ring is full.
    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let rx_desc = self.rx.dequeue()?;
        let tx_desc = self.tx.acquire()?;

        // Validate RX bounds before constructing the token.
        assert!(
            rx_desc.offset + rx_desc.len <= self.dma.len,
            "SddfDevice::receive: RX descriptor out of DMA bounds"
        );

        // Validate TX bounds.
        assert!(
            tx_desc.offset + tx_desc.capacity <= self.dma.len,
            "SddfDevice::receive: TX descriptor out of DMA bounds"
        );

        let dma_ptr = self.dma.ptr;
        let dma_len = self.dma.len;

        let rx_token = SddfRxToken {
            offset: rx_desc.offset,
            len: rx_desc.len,
            dma_ptr,
            dma_len,
        };
        let tx_token = SddfTxToken {
            desc: tx_desc,
            dma_ptr,
            dma_len,
        };
        Some((rx_token, tx_token))
    }

    /// Acquire a transmit slot for an outgoing frame.
    ///
    /// Returns `None` when the TX ring is full.
    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let tx_desc = self.tx.acquire()?;
        assert!(
            tx_desc.offset + tx_desc.capacity <= self.dma.len,
            "SddfDevice::transmit: TX descriptor out of DMA bounds"
        );
        let dma_ptr = self.dma.ptr;
        let dma_len = self.dma.len;
        Some(SddfTxToken { desc: tx_desc, dma_ptr, dma_len })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that DmaRegion slice bounds-checking panics on out-of-bounds access.
    #[test]
    #[should_panic(expected = "exceeds mapped size")]
    fn dma_region_oob_panics() {
        let mut region = SddfDmaRegion::for_test(64);
        let _ = region.slice_mut(60, 10); // 60+10 = 70 > 64 — must panic
    }

    /// Verify that DmaRegion allows a valid slice.
    #[test]
    fn dma_region_valid_slice() {
        let mut region = SddfDmaRegion::for_test(128);
        let buf = region.slice_mut(0, 64);
        assert_eq!(buf.len(), 64);
        buf[0] = 0xde;
        buf[63] = 0xad;
        assert_eq!(region.slice(0, 64)[0], 0xde);
        assert_eq!(region.slice(0, 64)[63], 0xad);
    }

    /// Verify that an empty RX ring returns None from dequeue().
    #[test]
    fn rx_ring_empty_returns_none() {
        let mut ring = SddfRxRing { head: 0, capacity: 32, slot_size: 1514 };
        assert!(ring.dequeue().is_none());
    }

    /// Verify that an empty TX ring returns None from acquire().
    #[test]
    fn tx_ring_full_returns_none() {
        let mut ring = SddfTxRing { tail: 0, capacity: 32, slot_size: 1514 };
        assert!(ring.acquire().is_none());
    }

    // TODO(sddf): add integration tests once sDDF ring protocol is implemented:
    //   - enqueue one RX descriptor, call dequeue(), verify offset/len match
    //   - acquire one TX slot, write frame bytes, call commit(), verify driver sees frame
    //   - throughput: 64-byte frames at line rate within 2× smoltcp loopback baseline (R4 gate)
}
