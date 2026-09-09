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
#include "hitag2/hitag2_threaded.h"

#if defined(_WIN32)
#define QUNLEASHED_EXPORT __declspec(dllexport)
#else
#define QUNLEASHED_EXPORT __attribute__((visibility("default")))
#endif

// ---------------------------------------------------------------------------
// PSA bruteforce
// ---------------------------------------------------------------------------
// Adapter: the Dart callback signature is (pct, keys_tested, ctx) with no bool
// return; cancellation is via the shared *cancel flag instead. The internal
// PsaProgressFn must return bool, so we bridge through a small context.
typedef struct {
    void (*progress)(uint32_t pct, uint64_t keys_tested, void* ctx);
    void* ctx;
    volatile int32_t* cancel;
} PsaBridgeCtx;

static bool psa_bridge_progress(uint8_t pct, uint64_t keys_tested, void* raw) {
    PsaBridgeCtx* b = (PsaBridgeCtx*)raw;
    if(b->progress) b->progress((uint32_t)pct, keys_tested, b->ctx);
    if(b->cancel && *b->cancel) return false;
    return true;
}

// Run the PSA TEA bruteforce. Returns 0 on success (fields written to the out
// params, *found=1), -2 on bad args, -10 when no key was found (*found=0).
QUNLEASHED_EXPORT int qunleashed_psa_bruteforce(
    const uint8_t* key1,
    const uint8_t* key2,
    uint64_t* out_serial,
    uint32_t* out_cnt,
    uint8_t* out_btn,
    uint8_t* out_type,
    int32_t* found,
    void (*progress)(uint32_t pct, uint64_t keys_tested, void* ctx),
    void* ctx,
    volatile int32_t* cancel) {
    if(found) *found = 0;
    if(!key1 || !key2) return -2;

    PsaBridgeCtx bctx = {progress, ctx, cancel};
    PsaResult res;
    memset(&res, 0, sizeof(res));

    bool ok = psa_bruteforce_run(
        key1, key2, &res, progress ? psa_bridge_progress : NULL, &bctx, cancel);

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
// Hitag2Hell (heavy, multithread)
// ---------------------------------------------------------------------------
// The Dart progress callback is void-returning; cancellation goes through the
// shared *cancel flag. Bridge it to the bool-returning Hitag2ProgressFn.
typedef struct {
    void (*progress)(uint8_t pct, uint64_t slots_done, void* ctx);
    void* ctx;
    volatile int32_t* cancel;
} Hitag2BridgeCtx;

static bool hitag2_bridge_progress(uint8_t pct, uint64_t slots_done, void* raw) {
    Hitag2BridgeCtx* b = (Hitag2BridgeCtx*)raw;
    if(b->progress) b->progress(pct, slots_done, b->ctx);
    if(b->cancel && *b->cancel) return false;
    return true;
}

// Recover a Fiat V1 48-bit key from one or more captures. The parallel arrays
// uids/btns/cnts/hops each hold `capture_count` entries. Returns 0 on success
// (out_key filled, *found=1), -2 on bad args, -10 when no cross-validated key
// was found (*found=0).
QUNLEASHED_EXPORT int qunleashed_hitag2hell_recover(
    const uint32_t* uids,
    const uint8_t* btns,
    const uint16_t* cnts,
    const uint32_t* hops,
    uint32_t capture_count,
    uint32_t l0_start,
    uint32_t l0_end,
    uint8_t* out_key,
    int32_t* found,
    void (*progress)(uint8_t pct, uint64_t slots_done, void* ctx),
    void* ctx,
    volatile int32_t* cancel) {
    if(found) *found = 0;
    if(!uids || !btns || !cnts || !hops || !out_key || capture_count == 0) {
        return -2;
    }

    Hitag2Capture* caps =
        (Hitag2Capture*)calloc((size_t)capture_count, sizeof(Hitag2Capture));
    if(!caps) return -2;
    for(uint32_t i = 0; i < capture_count; i++) {
        caps[i].uid = uids[i];
        caps[i].button = btns[i];
        caps[i].counter = cnts[i];
        caps[i].hop = hops[i];
    }

    Hitag2BridgeCtx bctx = {progress, ctx, cancel};
    uint8_t key[6];
    bool ok = hitag2_threaded_recover(
        caps,
        capture_count,
        l0_start,
        l0_end,
        key,
        progress ? hitag2_bridge_progress : NULL,
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
