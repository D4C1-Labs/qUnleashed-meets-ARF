#pragma once

// Multi-threaded Hitag2Hell key recovery for Fiat V1 / Fiat V2 / Renault V1
// captures.
//
// Given one or more captures, this partitions the layer-0 sweep
// [l0_start, l0_end) across the available CPUs, runs hitag2_hell_recover on each
// sub-range, inverts every state31 candidate with hitag2_fiat_invert_init, and
// cross-validates it against ALL supplied captures. Only a key that reproduces
// every capture is accepted.
//
// The extra "combo/slice" dimensions of Fiat V2 and Renault V1 are handled in
// the validation loop (and, for Renault V1, an extra kernel run per hop slice):
//   * Fiat V1 (proto 0): one hop; a single fixed IV; verify all captures.
//   * Fiat V2 (proto 1): one hop; 4 IV combos; ONE combo must validate ALL.
//   * Renault V1 (proto 2): 3 hop slices x 4 IV combos; ONE (slice, combo)
//     must validate ALL captures.

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Protocol / normalization type of a capture set.
typedef enum {
    HITAG2_PROTO_FIAT_V1 = 0,
    HITAG2_PROTO_FIAT_V2 = 1,
    HITAG2_PROTO_RENAULT_V1 = 2,
} Hitag2Proto;

// One captured authenticator. The active fields depend on `proto`:
//   * Fiat V1    : uid, button, counter, hop.
//   * Fiat V2    : uid, hop, raw[14] (uid/hop/counter/IV re-derived from raw).
//   * Renault V1 : uid, button, counter, payload42 (hop re-derived per slice).
// `proto` is set on every capture and must be identical across a set.
typedef struct {
    uint32_t uid;
    uint8_t button;
    uint16_t counter;
    uint32_t hop; // the 32-bit authenticator (Fiat V1 / Fiat V2)

    uint8_t proto;         // Hitag2Proto
    uint8_t raw[14];       // Fiat V2: verbatim frame bytes 0..13
    uint64_t payload42;    // Renault V1: low 42 bits
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
