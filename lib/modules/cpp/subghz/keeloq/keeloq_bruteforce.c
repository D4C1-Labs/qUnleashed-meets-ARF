// KeeLoq manufacturer-key brute-force. Crypto ported verbatim from the
// arf-android-companion native engine (keeloq_bruteforce.c: keeloq_decrypt,
// validate_hop, brute_type6/7/8). The threading wrapper follows psa_tea.c
// (host-side pthreads + shared-memory progress/cancel), replacing the JNI /
// big-core-pinning glue of the original.

#include "keeloq_bruteforce.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) && !defined(__MINGW32__)
#include "../pthread_shim.h"
#else
#include <pthread.h>
#endif

#include "../subghz_util.h"

// ---------------------------------------------------------------------------
// KeeLoq NLFSR block cipher (from arf keeloq_bruteforce.c)
// ---------------------------------------------------------------------------
#define KLQ_NLF 0x3A5C742EU
#define klq_bit(x, n) (((x) >> (n)) & 1)
#define klq_g5(x, a, b, c, d, e) \
    (klq_bit(x, a) + klq_bit(x, b) * 2 + klq_bit(x, c) * 4 + klq_bit(x, d) * 8 + \
     klq_bit(x, e) * 16)

static uint32_t keeloq_decrypt(uint32_t data, uint64_t key) {
    uint32_t x = data;
    for(int r = 0; r < 528; r++) {
        x = (x << 1) ^ klq_bit(x, 31) ^ klq_bit(x, 15) ^
            (uint32_t)klq_bit(key, (15 - r) & 63) ^
            klq_bit(KLQ_NLF, klq_g5(x, 0, 8, 19, 25, 30));
    }
    return x;
}

static inline bool
    validate_hop(uint32_t dec, uint8_t expected_btn, uint16_t expected_disc) {
    if((dec >> 28) != expected_btn) return false;
    uint16_t disc = (dec >> 16) & 0x3FF;
    if(disc == expected_disc) return true;
    if((disc & 0xFF) == (expected_disc & 0xFF)) return true;
    return false;
}

// Total searched keyspace is 2^32 per learning type (the low/high 32 bits).
#define KLQ_TOTAL_KEYS 0x100000000ULL
#define KLQ_MAX_THREADS 16

// ---------------------------------------------------------------------------
// Shared candidate store (thread-safe append)
// ---------------------------------------------------------------------------
typedef struct {
    KeeloqCandidate* out;
    int max_candidates;
    _Atomic int count;
} KlCandidateStore;

static void klq_store_candidate(
    KlCandidateStore* store,
    uint64_t mfkey,
    uint64_t devkey,
    uint32_t cnt,
    uint8_t learn_type) {
    int idx = atomic_fetch_add_explicit(&store->count, 1, memory_order_relaxed);
    if(idx < store->max_candidates) {
        store->out[idx].mfkey = mfkey;
        store->out[idx].devkey = devkey;
        store->out[idx].counter = cnt;
        store->out[idx].learn_type = learn_type;
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------
typedef struct {
    int learning_type;
    uint32_t serial, fix, hop1, hop2;
    uint8_t btn;
    uint16_t disc;
    uint64_t off_start, off_end; // sub-range of the 2^32 offset space

    KlCandidateStore* store;
    volatile int32_t* cancel;
    _Atomic uint64_t* keys_done;

    int is_leader;
    KeeloqProgressFn progress;
    void* progress_ctx;
} KlWorker;

// Build the device key for a given learning type and search offset.
static inline uint64_t klq_build_devkey(const KlWorker* w, uint64_t off) {
    switch(w->learning_type) {
    case 6: {
        // Upper 40 bits fixed from serial; low 32 bits searched.
        uint64_t upper = ((uint64_t)(w->serial & 0x00FFFFFF) << 40) |
                         ((uint64_t)(((w->serial & 0xFF) + ((w->serial >> 8) & 0xFF)) &
                                     0xFF)
                          << 32);
        return upper | (uint32_t)off;
    }
    case 7: {
        // Upper 4 bytes taken from fix; low 32 bits searched.
        uint8_t s0 = w->fix & 0xFF;
        uint8_t s1 = (w->fix >> 8) & 0xFF;
        uint8_t s2 = (w->fix >> 16) & 0xFF;
        uint8_t s3 = (w->fix >> 24) & 0xFF;
        uint64_t man = (uint32_t)off;
        uint8_t* m = (uint8_t*)&man;
        m[4] = s3;
        m[5] = s2;
        m[6] = s1;
        m[7] = s0;
        return man;
    }
    case 8:
    default: {
        // Low 24 bits fixed from serial; upper 40 bits searched.
        uint32_t serial_lo24 = w->serial & 0xFFFFFF;
        return (off << 24) | serial_lo24;
    }
    }
}

static inline void klq_poll_progress(KlWorker* w, uint64_t delta) {
    uint64_t total =
        atomic_fetch_add_explicit(w->keys_done, delta, memory_order_relaxed) + delta;
    if(w->is_leader && w->progress) {
        uint8_t pct = (uint8_t)((total * 100U) / KLQ_TOTAL_KEYS);
        if(pct > 100) pct = 100;
        w->progress(pct, total, w->progress_ctx);
    }
}

static void* klq_worker_main(void* arg) {
    KlWorker* w = (KlWorker*)arg;
    const uint64_t CHUNK = 0x10000; // report cadence

    for(uint64_t off = w->off_start; off < w->off_end;) {
        uint64_t end = off + CHUNK;
        if(end > w->off_end) end = w->off_end;

        for(uint64_t o = off; o < end; o++) {
            if(w->cancel && *w->cancel) return NULL;

            uint64_t devkey = klq_build_devkey(w, o);
            uint32_t dec1 = keeloq_decrypt(w->hop1, devkey);
            if(!validate_hop(dec1, w->btn, w->disc)) continue;

            uint32_t dec2 = keeloq_decrypt(w->hop2, devkey);
            if(validate_hop(dec2, w->btn, w->disc)) {
                uint16_t cnt1 = dec1 & 0xFFFF;
                uint16_t cnt2 = dec2 & 0xFFFF;
                int diff = (int)cnt2 - (int)cnt1;
                if(diff >= 1 && diff <= 256) {
                    klq_store_candidate(
                        w->store, devkey, devkey, cnt1, (uint8_t)w->learning_type);
                }
            }
        }

        klq_poll_progress(w, end - off);
        if(w->cancel && *w->cancel) return NULL;
        off = end;
    }
    return NULL;
}

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
    volatile int32_t* cancel) {
    if(!out || max_candidates <= 0) return 0;
    if(learning_type != 6 && learning_type != 7 && learning_type != 8) return 0;
    if(hop2 == 0) hop2 = hop1; // reuse the single captured hop if only one

    uint8_t btn = (uint8_t)(fix >> 28);
    uint16_t disc = (uint16_t)(serial & 0x3FF);

    int n = subghz_num_cpus();
    if(n < 1) n = 1;
    if(n > KLQ_MAX_THREADS) n = KLQ_MAX_THREADS;

    KlWorker* workers = (KlWorker*)calloc((size_t)n, sizeof(KlWorker));
    pthread_t* tids = (pthread_t*)calloc((size_t)n, sizeof(pthread_t));
    if(!workers || !tids) {
        free(workers);
        free(tids);
        return 0;
    }

    KlCandidateStore store;
    store.out = out;
    store.max_candidates = max_candidates;
    atomic_init(&store.count, 0);

    _Atomic uint64_t keys_done;
    atomic_init(&keys_done, 0);

    uint64_t per = KLQ_TOTAL_KEYS / (uint64_t)n;
    uint64_t cursor = 0;
    for(int i = 0; i < n; i++) {
        workers[i].learning_type = learning_type;
        workers[i].serial = serial;
        workers[i].fix = fix;
        workers[i].hop1 = hop1;
        workers[i].hop2 = hop2;
        workers[i].btn = btn;
        workers[i].disc = disc;
        workers[i].off_start = cursor;
        workers[i].off_end = (i == n - 1) ? KLQ_TOTAL_KEYS : (cursor + per);
        cursor = workers[i].off_end;
        workers[i].store = &store;
        workers[i].cancel = cancel;
        workers[i].keys_done = &keys_done;
        workers[i].is_leader = (i == 0);
        workers[i].progress = progress;
        workers[i].progress_ctx = progress_ctx;
    }

    for(int i = 0; i < n; i++) {
        pthread_create(&tids[i], NULL, klq_worker_main, &workers[i]);
    }
    for(int i = 0; i < n; i++) {
        pthread_join(tids[i], NULL);
    }

    free(workers);
    free(tids);

    int found = atomic_load(&store.count);
    if(found > max_candidates) found = max_candidates;
    return found;
}
