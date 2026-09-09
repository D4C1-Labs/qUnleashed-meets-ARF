#pragma once

// Multi-threaded Hitag2Hell key recovery for Fiat V1 captures.
//
// Given one or more Fiat V1 captures (each: uid, button, counter, hop), this
// partitions the layer-0 sweep [l0_start, l0_end) across the available CPUs,
// runs hitag2_hell_recover on each sub-range, inverts every state31 candidate
// with hitag2_fiat_invert_init, and cross-validates it against ALL supplied
// captures using hitag2_fiat_full_auth. Only a key that reproduces every
// capture is accepted.

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// One captured Fiat V1 authenticator.
typedef struct {
    uint32_t uid;
    uint8_t button;
    uint16_t counter;
    uint32_t hop; // the 32-bit authenticator
} Hitag2Capture;

// Progress callback: pct 0..100 over the whole sweep, slots_done = total
// layer-0 slots completed across all threads. Return false to abort. May be NULL.
typedef bool (*Hitag2ProgressFn)(uint8_t pct, uint64_t slots_done, void* ctx);

// Recover the 48-bit key.
//   caps        : capture_count captures (>= 1). caps[0] is the primary target.
//   l0_start/l0_end : layer-0 sweep range; (0,0) means full 2^20.
//   out_key     : 6 bytes, filled on success.
//   cancel      : if non-NULL and *cancel != 0, aborts.
// Returns true if a cross-validated key was found.
bool hitag2_threaded_recover(
    const Hitag2Capture* caps,
    uint32_t capture_count,
    uint32_t l0_start,
    uint32_t l0_end,
    uint8_t out_key[6],
    Hitag2ProgressFn progress,
    void* progress_ctx,
    volatile int32_t* cancel);

#ifdef __cplusplus
}
#endif
