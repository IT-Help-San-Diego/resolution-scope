/*
 * store.c — Resolution Scope store compartment (seL4 Microkit, Option B)
 *
 * Copyright 2026, IT Help San Diego Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This is the C shim that proves the store PD boots and receives on the
 * channel with NO network capability. It is the seL4-side stand-in for the
 * no_std Rust compartment (native/src/main_native.rs, which links bare-metal
 * but is not yet wired through the Microkit Rust binding — the C init()/
 * notified() template is the proven path from the SDK hello/passive_server
 * examples, and is the honest first cut).
 *
 * The Rust compartment does the real work (receive ScoredAnalysis, re-derive
 * the SHA3-512 seal, verify, render, write). This C shim proves the SYSTEM
 * shape — one passive PD, one channel, zero network — boots and receives.
 */

#include <microkit.h>

/* The channel id this PD receives on (matches the .system <end pd="store" id="0">). */
#define CH_RESULTS 0

void init(void)
{
    microkit_dbg_puts("store: init (passive, no network, no irq)\n");
    /* The store is passive: it is notified/PPC'd by the engine. Nothing to do
     * at init except announce; the receive happens in notified(). */
}

/* Called when the engine PPCs/sends on the channel. Under Option B the real
 * receiver deserialises the ScoredAnalysis here, re-derives the seal, verifies
 * it, renders, and writes via cap_local_report. The shim just acknowledges that
 * a message arrived on the sealed channel. */
void notified(microkit_channel ch)
{
    if (ch == CH_RESULTS) {
        microkit_dbg_puts("store: received verdict on channel (sealed)\n");
    }
}
