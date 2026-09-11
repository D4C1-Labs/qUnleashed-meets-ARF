#pragma once

// KeeLoq manufacturer-key brute-force, ported from the arf-android-companion
// native engine (app/src/main/cpp/keeloq_bruteforce.c). Recovers the device
// key by brute-forcing the "magic serial" manufacturer-key learning schemes
// (types 6/7/8) against two captured hop codes, cross-validating the counter
// difference. Only the pure crypto + threading is retained (no JNI) so it can
// be driven from Dart via FFI, mirroring psa_tea.c.

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// A recovered candidate device key.
typedef struct {
    uint64_t mfkey;     // recovered manufacturer/device key (same value here)
    uint64_t devkey;    // device key used to decrypt
    uint32_t counter;   // counter from the first hop
    uint8_t learn_type; // 6, 7 or 8
} KeeloqCandidate;

// Progress callback: pct 0..100 over the searched keyspace, keys_tested =
// cumulative. Return false to abort. May be NULL.
typedef bool (*KeeloqProgressFn)(uint8_t pct, uint64_t keys_tested, void* ctx);

// Run the KeeLoq brute-force, multi-threaded.
//   learning_type : 6, 7 or 8 (a single scheme). Use the "auto" driver on the
//                   Dart side to try 6 -> 7 -> 8 in sequence.
//   serial, fix   : the captured FIX/serial words.
//   hop1, hop2    : two captured rolling codes (hop2 may equal hop1 if only one
//                   was captured, but two distinct hops are needed to validate).
//   out           : caller array of at least `max_candidates` entries.
//   max_candidates: capacity of `out`.
//   cancel        : if non-NULL and *cancel != 0, aborts.
// Returns the number of candidates written to `out` (0 if none / cancelled).
int keeloq_bruteforce_run(
    int learning_type,
    uint32_t serial,
    uint32_t fix,
    uint32_t hop1,
    uint32_t hop2,
    KeeloqCandidate* out,
    int max_candidates,
    KeeloqProgressFn progress,
    void* progress_ctx,
    volatile int32_t* cancel);

#ifdef __cplusplus
}
#endif
