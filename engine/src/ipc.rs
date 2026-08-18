// ipc.rs — IPC payload serialisation for the seL4 compartment boundary
//
// This module owns the wire format that crosses the seL4 IPC endpoint.
// RULE: no raw DNS data, no resolver IP addresses, no query timing crosses
// this boundary.  Only ScoredAnalysis fields (see analysis.rs) are permitted.
//
// Full capDL capability wiring is described in:
//   native/capdl/dns_sovereign_compartment.cdl
//
// Stub: serialise ScoredAnalysis to a fixed-size byte buffer for the IPC call.
// Real implementation replaces this with seL4 IPC message registers or a
// shared memory frame once the LionsOS demo integration begins.

use crate::analysis::ScoredAnalysis;
use anyhow::Result;

/// Serialise a ScoredAnalysis to a JSON byte vector for the IPC channel.
/// The seL4 compartment deserialises this from the shared frame.
pub fn encode(analysis: &ScoredAnalysis) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(analysis)?)
}

/// Deserialise a ScoredAnalysis from the IPC channel byte slice.
pub fn decode(bytes: &[u8]) -> Result<ScoredAnalysis> {
    Ok(serde_json::from_slice(bytes)?)
}
