// Multi-threaded Hitag2Hell recovery, adapted from crack_threaded.c into a
// reusable (no main()) entry point. Uniform partition of the layer-0 sweep
// (mobile: we do not know big.LITTLE topology, so split evenly); atomic
// found-flag; per-candidate cross-validation against every capture.

#define _POSIX_C_SOURCE 200809L

#include "hitag2_threaded.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) && !defined(__MINGW32__)
#include "../pthread_shim.h"
#else
#include <pthread.h>
#endif

#include "subghz_hitag2_core.h"
#include "subghz_hitag2_hell.h"
#include "../subghz_util.h"

// ---------------------------------------------------------------------------
// Shared coordination
// ---------------------------------------------------------------------------
typedef struct {
    const Hitag2Capture* caps;
    uint32_t capture_count;

    uint32_t total_slots; // l0_end - l0_start (for pct)

    // Work-stealing cursor over [l0_base, l0_limit). Every worker atomically
    // grabs the next WORK_CHUNK slots from here, so fast (big) cores naturally
    // process more chunks than slow (little) cores and no core sits idle at the
    // end — the fix for the uniform-split big.LITTLE stall.
    uint32_t l0_base;
    uint32_t l0_limit;
    atomic_uint_least32_t next_slot;

    atomic_int found;                // 1 once the real key is committed
    atomic_uint_least64_t slots_done; // cumulative across workers
    volatile int32_t* cancel;         // external cancel (may be NULL)

    uint8_t found_key[6];
    pthread_mutex_t found_lock;

    // Progress: only the leader worker calls the user callback.
    Hitag2ProgressFn progress;
    void* progress_ctx;
    atomic_int abort_all; // set when progress cb returns false / cancel seen
} Hitag2Shared;

typedef struct {
    Hitag2Shared* sh;
    uint32_t l0_start;
    uint32_t l0_end;
    int is_leader;
    uint64_t last_slots; // for incremental slots accounting
} Hitag2Worker;

// Validate a state31 candidate: invert to a key, self-check against the primary
// capture, then cross-check against every other capture. Returns true only if
// the key reproduces ALL captures.
static bool hitag2_validate_candidate(
    Hitag2Shared* sh,
    uint64_t state31,
    uint8_t out_key[6]) {
    const Hitag2Capture* primary = &sh->caps[0];
    if(!hitag2_fiat_invert_init(
           state31, primary->uid, primary->button, primary->counter, 0, out_key)) {
        return false;
    }
    // Self-check (should always hold for a genuine candidate).
    for(uint32_t i = 0; i < sh->capture_count; i++) {
        const Hitag2Capture* c = &sh->caps[i];
        uint32_t exp = hitag2_fiat_full_auth(c->uid, c->button, c->counter, out_key, 0);
        if(exp != c->hop) return false;
    }
    return true;
}

static bool hitag2_worker_progress_cb(uint8_t pct, uint64_t states_tested, void* ctx) {
    (void)pct;
    (void)states_tested;
    Hitag2Worker* w = (Hitag2Worker*)ctx;
    Hitag2Shared* sh = w->sh;

    if(atomic_load_explicit(&sh->abort_all, memory_order_relaxed)) return false;
    if(atomic_load_explicit(&sh->found, memory_order_relaxed)) return false;
    if(sh->cancel && *sh->cancel) {
        atomic_store_explicit(&sh->abort_all, 1, memory_order_relaxed);
        return false;
    }
    return true;
}

// Slots grabbed per atomic fetch. Small enough that big/little cores stay
// balanced and cancel stays responsive; large enough that the atomic and the
// per-call kernel setup are amortized over real work.
#define HITAG2_WORK_CHUNK 64U

static void* hitag2_worker_main(void* arg) {
    Hitag2Worker* w = (Hitag2Worker*)arg;
    Hitag2Shared* sh = w->sh;

    for(;;) {
        if(atomic_load_explicit(&sh->found, memory_order_relaxed)) break;
        if(atomic_load_explicit(&sh->abort_all, memory_order_relaxed)) break;
        if(sh->cancel && *sh->cancel) {
            atomic_store_explicit(&sh->abort_all, 1, memory_order_relaxed);
            break;
        }

        // Grab the next chunk of the L0 space. Whoever is free takes the next
        // work, so throughput follows real per-core speed automatically.
        uint32_t base = atomic_fetch_add_explicit(
            &sh->next_slot, HITAG2_WORK_CHUNK, memory_order_relaxed);
        if(base >= sh->l0_limit) break;
        uint32_t end = base + HITAG2_WORK_CHUNK;
        if(end > sh->l0_limit) end = sh->l0_limit;

        Hitag2HellConfig cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.progress_cb = hitag2_worker_progress_cb;
        cfg.progress_ctx = w;
        cfg.l0_start = base;
        cfg.l0_end = end;

        Hitag2HellResult r;
        memset(&r, 0, sizeof(r));

        // Primary capture's hop is what the kernel searches for.
        if(hitag2_hell_recover(sh->caps[0].hop, &cfg, &r)) {
            for(uint32_t i = 0; i < r.candidate_count; i++) {
                uint8_t key[6];
                if(hitag2_validate_candidate(sh, r.candidates[i], key)) {
                    pthread_mutex_lock(&sh->found_lock);
                    if(!atomic_load(&sh->found)) {
                        memcpy(sh->found_key, key, 6);
                        atomic_store(&sh->found, 1);
                    }
                    pthread_mutex_unlock(&sh->found_lock);
                    break;
                }
            }
        }

        // Account slots and (leader only) push progress.
        uint64_t done_delta = (end - base);
        uint64_t total = atomic_fetch_add_explicit(
                             &sh->slots_done, done_delta, memory_order_relaxed) +
                         done_delta;
        if(w->is_leader && sh->progress) {
            uint8_t pct = sh->total_slots
                              ? (uint8_t)((total * 100U) / sh->total_slots)
                              : 100U;
            if(pct > 100) pct = 100;
            if(!sh->progress(pct, total, sh->progress_ctx)) {
                atomic_store_explicit(&sh->abort_all, 1, memory_order_relaxed);
                break;
            }
        }
    }
    return NULL;
}

bool hitag2_threaded_recover(
    const Hitag2Capture* caps,
    uint32_t capture_count,
    uint32_t l0_start,
    uint32_t l0_end,
    uint8_t out_key[6],
    Hitag2ProgressFn progress,
    void* progress_ctx,
    volatile int32_t* cancel) {
    if(!caps || capture_count == 0 || !out_key) return false;

    // (0,0) => full 2^20 sweep.
    if(l0_start == 0 && l0_end == 0) {
        l0_end = 1U << 20;
    }
    if(l0_end <= l0_start) return false;

    int n = subghz_num_cpus();
    if(n < 1) n = 1;
    uint32_t span = l0_end - l0_start;
    if((uint32_t)n > span) n = (int)span;

    Hitag2Shared sh;
    memset(&sh, 0, sizeof(sh));
    sh.caps = caps;
    sh.capture_count = capture_count;
    sh.total_slots = span;
    sh.l0_base = l0_start;
    sh.l0_limit = l0_end;
    atomic_init(&sh.next_slot, l0_start);
    atomic_init(&sh.found, 0);
    atomic_init(&sh.slots_done, 0);
    atomic_init(&sh.abort_all, 0);
    sh.cancel = cancel;
    sh.progress = progress;
    sh.progress_ctx = progress_ctx;
    pthread_mutex_init(&sh.found_lock, NULL);

    Hitag2Worker* workers = (Hitag2Worker*)calloc((size_t)n, sizeof(Hitag2Worker));
    pthread_t* tids = (pthread_t*)calloc((size_t)n, sizeof(pthread_t));
    if(!workers || !tids) {
        free(workers);
        free(tids);
        pthread_mutex_destroy(&sh.found_lock);
        return false;
    }

    // Work-stealing: all workers are identical and pull chunks from the shared
    // cursor. No fixed per-thread range, so a fast core simply grabs more.
    for(int i = 0; i < n; i++) {
        workers[i].sh = &sh;
        workers[i].l0_start = l0_start;
        workers[i].l0_end = l0_end;
        workers[i].is_leader = (i == 0);
        workers[i].last_slots = 0;
    }

    for(int i = 0; i < n; i++) {
        pthread_create(&tids[i], NULL, hitag2_worker_main, &workers[i]);
    }
    for(int i = 0; i < n; i++) {
        pthread_join(tids[i], NULL);
    }

    bool found = atomic_load(&sh.found) != 0;
    if(found) memcpy(out_key, sh.found_key, 6);

    pthread_mutex_destroy(&sh.found_lock);
    free(workers);
    free(tids);
    return found;
}
