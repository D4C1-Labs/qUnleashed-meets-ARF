//-----------------------------------------------------------------------------
// qUnleashed host-side Sub-GHz crypto bridge.
//
// Three Dart FFI entry points for offline Sub-GHz key recovery:
//   qunleashed_psa_bruteforce     - PSA TEA bruteforce (BF1 + BF2, multithread)
//   qunleashed_keeloq_decrypt/enc - KeeLoq block cipher (cheap, single-shot)
//   qunleashed_hitag2hell_recover - Hitag2Hell Fiat V1 attack (heavy, multithread)
//
// Crypto ported from the Flipper-ARF firmware (psa.c, keeloq_common.c) and from
// the verified /tmp/opencode/hitag2hell core (Fiat V1 + bitsliced Hell kernel).
//-----------------------------------------------------------------------------
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "psa/psa_tea.h"
#include "keeloq/keeloq.h"
#include "keeloq/keeloq_bruteforce.h"
#include "hitag2/hitag2_threaded.h"
#include "hitag2/fiat_v2_ref.h"

#if defined(_WIN32)
#define QUNLEASHED_EXPORT __declspec(dllexport)
#else
#define QUNLEASHED_EXPORT __attribute__((visibility("default")))
#endif

// ---------------------------------------------------------------------------
// Progress reporting model (IMPORTANT)
// ---------------------------------------------------------------------------
// We do NOT call back into Dart from the native worker threads. Dart FFI
// callbacks created with Pointer.fromFunction may only be invoked from the
// thread of the isolate that created them; calling them from our pthread
// workers crashes the app. Instead the bridge writes progress into a shared
// `uint64_t* progress_out` cell (packed as (pct << 56) | slots) that the Dart
// side polls with a Timer. Cancellation stays as a shared `volatile int32_t*`
// flag the workers read. This keeps all Dart<->native crossings on plain
// memory, safe from any thread.

// ---------------------------------------------------------------------------
// PSA bruteforce
// ---------------------------------------------------------------------------
typedef struct {
    volatile uint64_t* progress_out; // packed (pct<<56)|keys, may be NULL
    volatile int32_t* cancel;        // set by Dart to request abort, may be NULL
} PsaBridgeCtx;

static bool psa_bridge_progress(uint8_t pct, uint64_t keys_tested, void* raw) {
    PsaBridgeCtx* b = (PsaBridgeCtx*)raw;
    if(b->progress_out) {
        *b->progress_out =
            (((uint64_t)pct & 0xFFULL) << 56) | (keys_tested & 0x00FFFFFFFFFFFFFFULL);
    }
    if(b->cancel && *b->cancel) return false;
    return true;
}

// Run the PSA TEA bruteforce. Returns 0 on success (fields written to the out
// params, *found=1), -2 on bad args, -10 when no key was found (*found=0).
// progress_out: optional shared cell the bridge writes packed progress into.
QUNLEASHED_EXPORT int qunleashed_psa_bruteforce(
    const uint8_t* key1,
    const uint8_t* key2,
    uint64_t* out_serial,
    uint32_t* out_cnt,
    uint8_t* out_btn,
    uint8_t* out_type,
    int32_t* found,
    uint64_t* progress_out,
    volatile int32_t* cancel) {
    if(found) *found = 0;
    if(!key1 || !key2) return -2;

    PsaBridgeCtx bctx = {progress_out, cancel};
    PsaResult res;
    memset(&res, 0, sizeof(res));

    bool ok = psa_bruteforce_run(
        key1, key2, &res, psa_bridge_progress, &bctx, cancel);

    if(!ok) {
        if(found) *found = 0;
        return -10;
    }
    if(out_serial) *out_serial = res.serial;
    if(out_cnt) *out_cnt = res.counter;
    if(out_btn) *out_btn = res.button;
    if(out_type) *out_type = res.type;
    if(found) *found = 1;
    return 0;
}

// BLE offload variant. The Flipper firmware sends the raw TEA plaintext words
// (w0, w1) and expects (counter, dec_v0, dec_v1) back. Returns 0 on success
// (*found=1, out_counter/out_dec_v0/out_dec_v1 filled), -2 on bad args, -10 when
// no key was found (*found=0). Same shared-memory progress/cancel model.
QUNLEASHED_EXPORT int qunleashed_psa_bruteforce_offload(
    uint32_t w0,
    uint32_t w1,
    uint32_t* out_counter,
    uint32_t* out_dec_v0,
    uint32_t* out_dec_v1,
    int32_t* found,
    uint64_t* progress_out,
    volatile int32_t* cancel) {
    if(found) *found = 0;

    PsaBridgeCtx bctx = {progress_out, cancel};
    PsaResult res;
    memset(&res, 0, sizeof(res));

    bool ok = psa_bruteforce_run_words(
        w0, w1, &res, psa_bridge_progress, &bctx, cancel);

    if(!ok) {
        if(found) *found = 0;
        return -10;
    }
    if(out_counter) *out_counter = res.bf_counter;
    if(out_dec_v0) *out_dec_v0 = res.dec_v0;
    if(out_dec_v1) *out_dec_v1 = res.dec_v1;
    if(found) *found = 1;
    return 0;
}

// ---------------------------------------------------------------------------
// KeeLoq (single-shot, no threads)
// ---------------------------------------------------------------------------
QUNLEASHED_EXPORT uint32_t qunleashed_keeloq_decrypt(uint32_t hop, uint64_t key) {
    return subghz_protocol_keeloq_common_decrypt(hop, key);
}

QUNLEASHED_EXPORT uint32_t qunleashed_keeloq_encrypt(uint32_t data, uint64_t key) {
    return subghz_protocol_keeloq_common_encrypt(data, key);
}

// ---------------------------------------------------------------------------
// KeeLoq manufacturer-key brute-force (heavy, multithread)
// ---------------------------------------------------------------------------
// Same shared-memory progress model as PSA. On return, up to max_candidates
// entries are written to the caller-provided flat arrays (parallel arrays, one
// slot per candidate). Returns the number of candidates found. cancel/progress
// as usual. learning_type 6/7/8; the Dart side runs the 6->7->8 "auto" sequence
// as three calls when the firmware requests learning_type 0.
typedef struct {
    volatile uint64_t* progress_out;
    volatile int32_t* cancel;
} KeeloqBridgeCtx;

static bool keeloq_bridge_progress(uint8_t pct, uint64_t keys_tested, void* raw) {
    KeeloqBridgeCtx* b = (KeeloqBridgeCtx*)raw;
    if(b->progress_out) {
        *b->progress_out =
            (((uint64_t)pct & 0xFFULL) << 56) | (keys_tested & 0x00FFFFFFFFFFFFFFULL);
    }
    if(b->cancel && *b->cancel) return false;
    return true;
}

QUNLEASHED_EXPORT int qunleashed_keeloq_bruteforce(
    int learning_type,
    uint32_t serial,
    uint32_t fix,
    uint32_t hop1,
    uint32_t hop2,
    int max_candidates,
    uint64_t* out_mfkeys, // [max_candidates]
    uint64_t* out_devkeys, // [max_candidates]
    uint32_t* out_counters, // [max_candidates]
    uint8_t* out_learn_types, // [max_candidates]
    uint64_t* progress_out,
    volatile int32_t* cancel) {
    if(!out_mfkeys || !out_devkeys || !out_counters || !out_learn_types ||
       max_candidates <= 0) {
        return -2;
    }

    KeeloqCandidate* cands =
        (KeeloqCandidate*)calloc((size_t)max_candidates, sizeof(KeeloqCandidate));
    if(!cands) return -2;

    KeeloqBridgeCtx bctx = {progress_out, cancel};
    int found = keeloq_bruteforce_run(
        learning_type,
        serial,
        fix,
        hop1,
        hop2,
        cands,
        max_candidates,
        keeloq_bridge_progress,
        &bctx,
        cancel);

    for(int i = 0; i < found && i < max_candidates; i++) {
        out_mfkeys[i] = cands[i].mfkey;
        out_devkeys[i] = cands[i].devkey;
        out_counters[i] = cands[i].counter;
        out_learn_types[i] = cands[i].learn_type;
    }

    free(cands);
    return found;
}

// ---------------------------------------------------------------------------
// Hitag2Hell (heavy, multithread)
// ---------------------------------------------------------------------------
// Same shared-memory progress model as PSA: write packed (pct<<56)|slots into
// progress_out; never call back into Dart from worker threads.
typedef struct {
    volatile uint64_t* progress_out; // packed (pct<<56)|slots, may be NULL
    volatile int32_t* cancel;        // set by Dart to request abort, may be NULL
} Hitag2BridgeCtx;

static bool hitag2_bridge_progress(uint8_t pct, uint64_t slots_done, void* raw) {
    Hitag2BridgeCtx* b = (Hitag2BridgeCtx*)raw;
    if(b->progress_out) {
        *b->progress_out =
            (((uint64_t)pct & 0xFFULL) << 56) | (slots_done & 0x00FFFFFFFFFFFFFFULL);
    }
    if(b->cancel && *b->cancel) return false;
    return true;
}

// Recover a Fiat V1 / Fiat V2 / Renault V1 48-bit key from one or more captures.
//
// `proto` selects the wire/normalization:
//   0 = Fiat V1    : uses uids/btns/cnts/hops (raws/payload42 ignored/NULL).
//   1 = Fiat V2    : uses `raws` (14 bytes per capture); uid/hop are re-derived
//                    from each raw frame on the native side (uids/btns/cnts/hops
//                    may be NULL). The 4 IV combos are searched in validation.
//   2 = Renault V1 : uses uids (uid = serial & 0xFFFFFF, shared header value),
//                    `payload42s`, `btns`, `cnts` (counter is 8-bit here). The 3
//                    hop slices x 4 IV combos are searched.
//
// The parallel arrays each hold `capture_count` entries (raws holds
// capture_count*14 bytes). Returns 0 on success (out_key filled, *found=1), -2
// on bad args, -10 when no cross-validated key was found (*found=0).
// progress_out: optional shared packed-progress cell. epoch is 0 for all.
QUNLEASHED_EXPORT int qunleashed_hitag2hell_recover(
    int32_t proto,
    const uint32_t* uids,
    const uint8_t* btns,
    const uint16_t* cnts,
    const uint32_t* hops,
    const uint8_t* raws,        // Fiat V2: capture_count*14 bytes, else NULL
    const uint64_t* payload42s, // Renault V1: capture_count entries, else NULL
    uint32_t capture_count,
    uint32_t l0_start,
    uint32_t l0_end,
    uint8_t* out_key,
    int32_t* found,
    uint64_t* progress_out,
    volatile int32_t* cancel) {
    if(found) *found = 0;
    if(!out_key || capture_count == 0) return -2;

    // Per-proto required inputs.
    if(proto == (int32_t)HITAG2_PROTO_FIAT_V1) {
        if(!uids || !btns || !cnts || !hops) return -2;
    } else if(proto == (int32_t)HITAG2_PROTO_FIAT_V2) {
        if(!raws) return -2;
    } else if(proto == (int32_t)HITAG2_PROTO_RENAULT_V1) {
        if(!uids || !btns || !cnts || !payload42s) return -2;
    } else {
        return -2;
    }

    Hitag2Capture* caps =
        (Hitag2Capture*)calloc((size_t)capture_count, sizeof(Hitag2Capture));
    if(!caps) return -2;
    for(uint32_t i = 0; i < capture_count; i++) {
        caps[i].proto = (uint8_t)proto;
        if(proto == (int32_t)HITAG2_PROTO_FIAT_V1) {
            caps[i].uid = uids[i];
            caps[i].button = btns[i];
            caps[i].counter = cnts[i];
            caps[i].hop = hops[i];
        } else if(proto == (int32_t)HITAG2_PROTO_FIAT_V2) {
            const uint8_t* r = &raws[(size_t)i * FIAT_V2_WIRE_BYTES];
            memcpy(caps[i].raw, r, FIAT_V2_WIRE_BYTES);
            caps[i].uid = fiat_v2_uid(r);
            caps[i].hop = fiat_v2_hop(r);
        } else { // Renault V1
            caps[i].uid = uids[i];
            caps[i].button = btns[i];
            caps[i].counter = cnts[i]; // 8-bit counter carried in the 16-bit field
            caps[i].payload42 = payload42s[i];
        }
    }

    Hitag2BridgeCtx bctx = {progress_out, cancel};
    uint8_t key[6];
    bool ok = hitag2_threaded_recover(
        caps,
        capture_count,
        l0_start,
        l0_end,
        key,
        hitag2_bridge_progress,
        &bctx,
        cancel);

    free(caps);

    if(!ok) {
        if(found) *found = 0;
        return -10;
    }
    memcpy(out_key, key, 6);
    if(found) *found = 1;
    return 0;
}
