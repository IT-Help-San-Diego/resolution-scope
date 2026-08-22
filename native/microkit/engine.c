/*
 * engine.c — Resolution Scope engine stub (seL4 Microkit, Option B)
 *
 * Copyright 2026, IT Help San Diego Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Under Option B the real engine is the std Rust binary (Phase 1) running on
 * the Linux host, OUTSIDE seL4. This C stub exists only to prove the seL4-side
 * system shape: it is an active PD that sends one message over the channel to
 * the passive store PD, exercising the exact IPC surface the real system uses.
 * It is NOT the DNSSEC engine and holds no verdict logic.
 */

#include <microkit.h>

#define CH_RESULTS 0

void init(void)
{
    microkit_dbg_puts("engine: init (stub, sends one verdict)\n");
    /* Notify the store PD that a verdict is available on the channel. */
    microkit_notify(CH_RESULTS);
}

void notified(microkit_channel ch)
{
    (void)ch;
    /* The stub engine receives nothing; under Option B the engine is outside. */
}
