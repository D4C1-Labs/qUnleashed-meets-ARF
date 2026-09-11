// PSA TEA bruteforce. Crypto ported verbatim from the Flipper firmware
// lib/subghz/protocols/psa.c; the threading wrapper is new (host-side).

#include "psa_tea.h"

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
// Constants (from psa.c)
// ---------------------------------------------------------------------------
#define TEA_DELTA 0x9E3779B9U
#define TEA_ROUNDS 32

#define PSA_BF1_CONST_U4 0x0E0F5C41U
#define PSA_BF1_CONST_U5 0x0F5C4123U

static const uint32_t PSA_BF1_KEY_SCHEDULE[4] = {
    0x4A434915U,
    0xD6743C2BU,
    0x1F29D308U,
    0xE6B79A64U,
};

static const uint32_t PSA_BF2_KEY_SCHEDULE[4] = {
    0x4039C240U,
    0xEDA92CABU,
    0x4306C02AU,
    0x02192A04U,
};

#define PSA_BF1_START 0x23000000U
#define PSA_BF1_END 0x24000000U
#define PSA_BF2_START 0xF3000000U
#define PSA_BF2_END 0xF4000000U

// Total keyspace = (BF1 span) + (BF2 span) = 16M + 16M = 32M.
#define PSA_BF_SPAN (PSA_BF1_END - PSA_BF1_START) // == PSA_BF2_END - PSA_BF2_START
#define PSA_TOTAL_KEYS ((uint64_t)PSA_BF_SPAN * 2U)

// ---------------------------------------------------------------------------
// TEA primitives (from psa.c)
// ---------------------------------------------------------------------------
static inline void
    psa_tea_encrypt(uint32_t* v0, uint32_t* v1, const uint32_t* key) {
    uint32_t a = *v0, b = *v1;
    uint32_t sum = 0;
    for(int i = 0; i < TEA_ROUNDS; i++) {
        uint32_t temp = key[sum & 3] + sum;
        sum += TEA_DELTA;
        a += (temp ^ (((b >> 5) ^ (b << 4)) + b));
        temp = key[(sum >> 11) & 3] + sum;
        b += (temp ^ (((a >> 5) ^ (a << 4)) + a));
    }
    *v0 = a;
    *v1 = b;
}

static inline void
    psa_tea_decrypt(uint32_t* v0, uint32_t* v1, const uint32_t* key) {
    uint32_t a = *v0, b = *v1;
    uint32_t sum = TEA_DELTA * TEA_ROUNDS;
    for(int i = 0; i < TEA_ROUNDS; i++) {
        uint32_t temp = key[(sum >> 11) & 3] + sum;
        sum -= TEA_DELTA;
        b -= (temp ^ (((a >> 5) ^ (a << 4)) + a));
        temp = key[sum & 3] + sum;
        a -= (temp ^ (((b >> 5) ^ (b << 4)) + b));
    }
    *v0 = a;
    *v1 = b;
}

typedef struct {
    uint32_t s0[TEA_ROUNDS];
    uint32_t s1[TEA_ROUNDS];
} PsaTeaSchedule;

static void psa_tea_build_schedule(const uint32_t* key, PsaTeaSchedule* out) {
    for(int i = 0; i < TEA_ROUNDS; i++) {
        uint32_t sum0 = (uint32_t)((uint64_t)i * TEA_DELTA);
        uint32_t sum1 = (uint32_t)((uint64_t)(i + 1) * TEA_DELTA);
        out->s0[i] = key[sum0 & 3] + sum0;
        out->s1[i] = key[(sum1 >> 11) & 3] + sum1;
    }
}

static inline void psa_tea_encrypt_with_schedule(
    uint32_t* v0,
    uint32_t* v1,
    const PsaTeaSchedule* sched) {
    uint32_t a = *v0, b = *v1;
    for(int i = 0; i < TEA_ROUNDS; i++) {
        a += (sched->s0[i] ^ (((b >> 5) ^ (b << 4)) + b));
        b += (sched->s1[i] ^ (((a >> 5) ^ (a << 4)) + a));
    }
    *v0 = a;
    *v1 = b;
}

// ---------------------------------------------------------------------------
// Buffer / field helpers (from psa.c)
// ---------------------------------------------------------------------------
static void psa_setup_byte_buffer(
    uint8_t* buffer,
    uint32_t key1_low,
    uint32_t key1_high,
    uint32_t key2_low) {
    for(int i = 0; i < 8; i++) {
        int shift = i * 8;
        uint8_t byte_val;
        if(shift < 32) {
            byte_val = (uint8_t)((key1_low >> shift) & 0xFF);
        } else {
            byte_val = (uint8_t)((key1_high >> (shift - 32)) & 0xFF);
        }
        buffer[7 - i] = byte_val;
    }
    buffer[9] = (uint8_t)(key2_low & 0xFF);
    buffer[8] = (uint8_t)((key2_low >> 8) & 0xFF);
}

static void psa_prepare_tea_data(const uint8_t* buffer, uint32_t* w0, uint32_t* w1) {
    *w0 = ((uint32_t)buffer[3] << 16) | ((uint32_t)buffer[2] << 24) |
          ((uint32_t)buffer[4] << 8) | (uint32_t)buffer[5];
    *w1 = ((uint32_t)buffer[7] << 16) | ((uint32_t)buffer[6] << 24) |
          ((uint32_t)buffer[8] << 8) | (uint32_t)buffer[9];
}

static uint8_t psa_calculate_tea_crc(uint32_t v0, uint32_t v1) {
    uint32_t crc = ((v0 >> 24) & 0xFF) + ((v0 >> 16) & 0xFF) + ((v0 >> 8) & 0xFF) +
                   (v0 & 0xFF);
    crc += ((v1 >> 24) & 0xFF) + ((v1 >> 16) & 0xFF) + ((v1 >> 8) & 0xFF);
    return (uint8_t)(crc & 0xFF);
}

static const uint16_t psa_crc16_table[256] = {
    0x0000, 0x8005, 0x800F, 0x000A, 0x801B, 0x001E, 0x0014, 0x8011, 0x8033, 0x0036,
    0x003C, 0x8039, 0x0028, 0x802D, 0x8027, 0x0022, 0x8063, 0x0066, 0x006C, 0x8069,
    0x0078, 0x807D, 0x8077, 0x0072, 0x0050, 0x8055, 0x805F, 0x005A, 0x804B, 0x004E,
    0x0044, 0x8041, 0x80C3, 0x00C6, 0x00CC, 0x80C9, 0x00D8, 0x80DD, 0x80D7, 0x00D2,
    0x00F0, 0x80F5, 0x80FF, 0x00FA, 0x80EB, 0x00EE, 0x00E4, 0x80E1, 0x00A0, 0x80A5,
    0x80AF, 0x00AA, 0x80BB, 0x00BE, 0x00B4, 0x80B1, 0x8093, 0x0096, 0x009C, 0x8099,
    0x0088, 0x808D, 0x8087, 0x0082, 0x8183, 0x0186, 0x018C, 0x8189, 0x0198, 0x819D,
    0x8197, 0x0192, 0x01B0, 0x81B5, 0x81BF, 0x01BA, 0x81AB, 0x01AE, 0x01A4, 0x81A1,
    0x01E0, 0x81E5, 0x81EF, 0x01EA, 0x81FB, 0x01FE, 0x01F4, 0x81F1, 0x81D3, 0x01D6,
    0x01DC, 0x81D9, 0x01C8, 0x81CD, 0x81C7, 0x01C2, 0x0140, 0x8145, 0x814F, 0x014A,
    0x815B, 0x015E, 0x0154, 0x8151, 0x8173, 0x0176, 0x017C, 0x8179, 0x0168, 0x816D,
    0x8167, 0x0162, 0x8123, 0x0126, 0x012C, 0x8129, 0x0138, 0x813D, 0x8137, 0x0132,
    0x0110, 0x8115, 0x811F, 0x011A, 0x810B, 0x010E, 0x0104, 0x8101, 0x8303, 0x0306,
    0x030C, 0x8309, 0x0318, 0x831D, 0x8317, 0x0312, 0x0330, 0x8335, 0x833F, 0x033A,
    0x832B, 0x032E, 0x0324, 0x8321, 0x0360, 0x8365, 0x836F, 0x036A, 0x837B, 0x037E,
    0x0374, 0x8371, 0x8353, 0x0356, 0x035C, 0x8359, 0x0348, 0x834D, 0x8347, 0x0342,
    0x03C0, 0x83C5, 0x83CF, 0x03CA, 0x83DB, 0x03DE, 0x03D4, 0x83D1, 0x83F3, 0x03F6,
    0x03FC, 0x83F9, 0x03E8, 0x83ED, 0x83E7, 0x03E2, 0x83A3, 0x03A6, 0x03AC, 0x83A9,
    0x03B8, 0x83BD, 0x83B7, 0x03B2, 0x0390, 0x8395, 0x839F, 0x039A, 0x838B, 0x038E,
    0x0384, 0x8381, 0x0280, 0x8285, 0x828F, 0x028A, 0x829B, 0x029E, 0x0294, 0x8291,
    0x82B3, 0x02B6, 0x02BC, 0x82B9, 0x02A8, 0x82AD, 0x82A7, 0x02A2, 0x82E3, 0x02E6,
    0x02EC, 0x82E9, 0x02F8, 0x82FD, 0x82F7, 0x02F2, 0x02D0, 0x82D5, 0x82DF, 0x02DA,
    0x82CB, 0x02CE, 0x02C4, 0x82C1, 0x8243, 0x0246, 0x024C, 0x8249, 0x0258, 0x825D,
    0x8257, 0x0252, 0x0270, 0x8275, 0x827F, 0x027A, 0x826B, 0x026E, 0x0264, 0x8261,
    0x0220, 0x8225, 0x822F, 0x022A, 0x823B, 0x023E, 0x0234, 0x8231, 0x8213, 0x0216,
    0x021C, 0x8219, 0x0208, 0x820D, 0x8207, 0x0202,
};

static uint16_t psa_calculate_crc16_bf2(const uint8_t* buffer, int length) {
    uint16_t crc = 0;
    for(int i = 0; i < length; i++) {
        crc = (crc << 8) ^ psa_crc16_table[((crc >> 8) ^ buffer[i]) & 0xFF];
    }
    return crc;
}

static void psa_unpack_tea_result_to_buffer(uint8_t* buffer, uint32_t v0, uint32_t v1) {
    buffer[2] = (uint8_t)((v0 >> 24) & 0xFF);
    buffer[3] = (uint8_t)((v0 >> 16) & 0xFF);
    buffer[4] = (uint8_t)((v0 >> 8) & 0xFF);
    buffer[5] = (uint8_t)(v0 & 0xFF);
    buffer[6] = (uint8_t)((v1 >> 24) & 0xFF);
    buffer[7] = (uint8_t)((v1 >> 16) & 0xFF);
    buffer[8] = (uint8_t)((v1 >> 8) & 0xFF);
    buffer[9] = (uint8_t)(v1 & 0xFF);
}

static void psa_extract_fields_mode36(const uint8_t* buffer, PsaResult* out) {
    out->button = (buffer[5] >> 4) & 0xF;
    out->serial = ((uint32_t)buffer[3] << 8) | ((uint32_t)buffer[2] << 16) | (uint32_t)buffer[4];
    out->counter = ((uint32_t)buffer[7] << 8) | ((uint32_t)buffer[6] << 16) |
                   (uint32_t)buffer[8] | (((uint32_t)buffer[5] & 0xF) << 24);
    out->type = 0x36;
}

// ---------------------------------------------------------------------------
// Threaded bruteforce
// ---------------------------------------------------------------------------
typedef struct {
    // Immutable target inputs
    uint32_t w0, w1;
    // Sub-range of the [0, PSA_BF_SPAN) offset space this worker sweeps.
    uint32_t off_start, off_end;

    // Shared coordination (pointers to the caller-owned state).
    volatile int32_t* found;      // set to 1 when any worker wins
    volatile int32_t* cancel;     // external cancel
    _Atomic uint64_t* keys_done;  // cumulative keys tested across threads
    PsaResult* out;               // written by the winner
    pthread_mutex_t* out_lock;

    // Progress plumbing (only the "leader" thread invokes the callback).
    int is_leader;
    PsaProgressFn progress;
    void* progress_ctx;
} PsaWorker;

// Try one BF1 counter value. Returns true on hit (out filled).
static inline int psa_try_bf1(
    uint32_t counter,
    const PsaTeaSchedule* bf1_sched,
    uint32_t w0,
    uint32_t w1,
    PsaResult* out) {
    uint32_t wk2 = PSA_BF1_CONST_U4;
    uint32_t wk3 = counter;
    psa_tea_encrypt_with_schedule(&wk2, &wk3, bf1_sched);

    uint32_t wk0 = (counter << 8) | 0x0E;
    uint32_t wk1 = PSA_BF1_CONST_U5;
    psa_tea_encrypt_with_schedule(&wk0, &wk1, bf1_sched);

    uint32_t working_key[4] = {wk0, wk1, wk2, wk3};
    uint32_t dec_v0 = w0, dec_v1 = w1;
    psa_tea_decrypt(&dec_v0, &dec_v1, working_key);

    if((counter & 0xFFFFFF) == (dec_v0 >> 8)) {
        uint8_t crc = psa_calculate_tea_crc(dec_v0, dec_v1);
        if(crc == (dec_v1 & 0xFF)) {
            uint8_t buffer[48] = {0};
            psa_unpack_tea_result_to_buffer(buffer, dec_v0, dec_v1);
            psa_extract_fields_mode36(buffer, out);
            out->serial = counter;
            // Raw hit values for the BLE offload reply.
            out->bf_counter = counter;
            out->dec_v0 = dec_v0;
            out->dec_v1 = dec_v1;
            return 1;
        }
    }
    return 0;
}

// Try one BF2 counter value. Returns true on hit (out filled).
static inline int psa_try_bf2(uint32_t counter, uint32_t w0, uint32_t w1, PsaResult* out) {
    uint32_t working_key[4] = {
        PSA_BF2_KEY_SCHEDULE[0] ^ counter,
        PSA_BF2_KEY_SCHEDULE[1] ^ counter,
        PSA_BF2_KEY_SCHEDULE[2] ^ counter,
        PSA_BF2_KEY_SCHEDULE[3] ^ counter,
    };
    uint32_t dec_v0 = w0, dec_v1 = w1;
    psa_tea_decrypt(&dec_v0, &dec_v1, working_key);

    if((counter & 0xFFFFFF) == (dec_v0 >> 8)) {
        uint8_t buffer[48] = {0};
        psa_unpack_tea_result_to_buffer(buffer, dec_v0, dec_v1);
        uint8_t crc_buffer[6] = {
            (uint8_t)((dec_v0 >> 24) & 0xFF),
            (uint8_t)((dec_v0 >> 8) & 0xFF),
            (uint8_t)((dec_v0 >> 16) & 0xFF),
            (uint8_t)(dec_v0 & 0xFF),
            (uint8_t)((dec_v1 >> 24) & 0xFF),
            (uint8_t)((dec_v1 >> 16) & 0xFF),
        };
        uint16_t crc16 = psa_calculate_crc16_bf2(crc_buffer, 6);
        uint16_t expected_crc = (((dec_v1 >> 16) & 0xFF) << 8) | (dec_v1 & 0xFF);
        if(crc16 == expected_crc) {
            psa_extract_fields_mode36(buffer, out);
            out->serial = counter;
            // Raw hit values for the BLE offload reply.
            out->bf_counter = counter;
            out->dec_v0 = dec_v0;
            out->dec_v1 = dec_v1;
            return 1;
        }
    }
    return 0;
}

static void psa_win(PsaWorker* w, const PsaResult* r) {
    pthread_mutex_lock(w->out_lock);
    if(*w->found == 0) {
        *w->out = *r;
        *w->found = 1;
    }
    pthread_mutex_unlock(w->out_lock);
}

// Poll cancel/found + push progress. Returns 1 if the sweep should stop.
static inline int psa_poll(PsaWorker* w, uint64_t local_done_delta) {
    uint64_t total = atomic_fetch_add_explicit(
                         w->keys_done, local_done_delta, memory_order_relaxed) +
                     local_done_delta;
    if(*w->found) return 1;
    if(w->cancel && *w->cancel) return 1;
    if(w->is_leader && w->progress) {
        uint8_t pct = (uint8_t)((total * 100U) / PSA_TOTAL_KEYS);
        if(pct > 100) pct = 100;
        if(!w->progress(pct, total, w->progress_ctx)) return 1;
    }
    return 0;
}

static void* psa_worker_main(void* arg) {
    PsaWorker* w = (PsaWorker*)arg;

    PsaTeaSchedule bf1_sched;
    psa_tea_build_schedule(PSA_BF1_KEY_SCHEDULE, &bf1_sched);

    const uint32_t CHUNK = 0x10000; // report cadence

    // --- BF1 pass over this worker's offset sub-range ---
    for(uint32_t off = w->off_start; off < w->off_end;) {
        uint32_t end = off + CHUNK;
        if(end > w->off_end) end = w->off_end;
        for(uint32_t o = off; o < end; o++) {
            PsaResult r;
            if(psa_try_bf1(PSA_BF1_START + o, &bf1_sched, w->w0, w->w1, &r)) {
                psa_win(w, &r);
                return NULL;
            }
        }
        if(psa_poll(w, end - off)) return NULL;
        off = end;
    }

    // --- BF2 pass over this worker's offset sub-range ---
    for(uint32_t off = w->off_start; off < w->off_end;) {
        uint32_t end = off + CHUNK;
        if(end > w->off_end) end = w->off_end;
        for(uint32_t o = off; o < end; o++) {
            PsaResult r;
            if(psa_try_bf2(PSA_BF2_START + o, w->w0, w->w1, &r)) {
                psa_win(w, &r);
                return NULL;
            }
        }
        if(psa_poll(w, end - off)) return NULL;
        off = end;
    }
    return NULL;
}

// Core sweep: brute-force the TEA plaintext words (w0, w1) across BF1+BF2,
// multi-threaded. Both the key-based entry point and the BLE offload entry
// point funnel through here so the threading/progress/cancel logic lives once.
static bool psa_bruteforce_run_core(
    uint32_t w0,
    uint32_t w1,
    PsaResult* out,
    PsaProgressFn progress,
    void* progress_ctx,
    volatile int32_t* cancel) {
    if(!out) return false;

    int n = subghz_num_cpus();
    if(n < 1) n = 1;
    if((uint32_t)n > PSA_BF_SPAN) n = 1;

    PsaWorker* workers = (PsaWorker*)calloc((size_t)n, sizeof(PsaWorker));
    pthread_t* tids = (pthread_t*)calloc((size_t)n, sizeof(pthread_t));
    if(!workers || !tids) {
        free(workers);
        free(tids);
        return false;
    }

    volatile int32_t found = 0;
    _Atomic uint64_t keys_done = 0;
    pthread_mutex_t out_lock;
    pthread_mutex_init(&out_lock, NULL);

    uint32_t per = PSA_BF_SPAN / (uint32_t)n;
    uint32_t cursor = 0;
    for(int i = 0; i < n; i++) {
        workers[i].w0 = w0;
        workers[i].w1 = w1;
        workers[i].off_start = cursor;
        workers[i].off_end = (i == n - 1) ? PSA_BF_SPAN : (cursor + per);
        cursor = workers[i].off_end;
        workers[i].found = &found;
        workers[i].cancel = cancel;
        workers[i].keys_done = &keys_done;
        workers[i].out = out;
        workers[i].out_lock = &out_lock;
        workers[i].is_leader = (i == 0);
        workers[i].progress = progress;
        workers[i].progress_ctx = progress_ctx;
    }

    for(int i = 0; i < n; i++) {
        pthread_create(&tids[i], NULL, psa_worker_main, &workers[i]);
    }
    for(int i = 0; i < n; i++) {
        pthread_join(tids[i], NULL);
    }

    pthread_mutex_destroy(&out_lock);
    free(workers);
    free(tids);
    return found != 0;
}

bool psa_bruteforce_run(
    const uint8_t key1[8],
    const uint8_t key2[8],
    PsaResult* out,
    PsaProgressFn progress,
    void* progress_ctx,
    volatile int32_t* cancel) {
    if(!key1 || !key2 || !out) return false;

    // Reconstruct the (key1_low, key1_high, key2_low) triple the firmware uses.
    // key1[] is the 8-byte little-endian key1 value; key2[] the 8-byte key2,
    // of which only the low 16 bits feed the buffer.
    uint32_t key1_low = (uint32_t)key1[0] | ((uint32_t)key1[1] << 8) |
                        ((uint32_t)key1[2] << 16) | ((uint32_t)key1[3] << 24);
    uint32_t key1_high = (uint32_t)key1[4] | ((uint32_t)key1[5] << 8) |
                         ((uint32_t)key1[6] << 16) | ((uint32_t)key1[7] << 24);
    uint32_t key2_low = (uint32_t)key2[0] | ((uint32_t)key2[1] << 8);

    uint8_t buffer[48] = {0};
    psa_setup_byte_buffer(buffer, key1_low, key1_high, key2_low);
    uint32_t w0, w1;
    psa_prepare_tea_data(buffer, &w0, &w1);

    return psa_bruteforce_run_core(w0, w1, out, progress, progress_ctx, cancel);
}

bool psa_bruteforce_run_words(
    uint32_t w0,
    uint32_t w1,
    PsaResult* out,
    PsaProgressFn progress,
    void* progress_ctx,
    volatile int32_t* cancel) {
    return psa_bruteforce_run_core(w0, w1, out, progress, progress_ctx, cancel);
}
