#pragma once

// PSA TEA bruteforce, crypto ported from the Flipper firmware
// lib/subghz/protocols/psa.c (psa_tea_encrypt/decrypt, the two key schedules,
// and psa_brute_force_decrypt_bf1/bf2 + psa_extract_fields_mode36). Only the
// pure cryptographic logic is retained - no FlipperFormat / subghz deps.
//
// The full bruteforce runs BF1 then BF2, each sweeping 2^24 = 16M counter
// values (32M total). psa_bruteforce_run partitions the counter space across
// multiple threads.

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Decrypted PSA mode-0x36 fields, on a successful bruteforce hit.
typedef struct {
    uint64_t serial;  // decrypted_serial
    uint32_t counter; // decrypted_counter
    uint8_t button;   // decrypted_button
    uint8_t type;     // decrypted_type (0x36)
    // Raw brute-force hit values, needed by the BLE offload path which reports
    // (counter, dec_v0, dec_v1) straight back to the Flipper firmware instead
    // of the extracted mode-0x36 fields. bf_counter is the winning counter (the
    // same value stored in `serial` by the sweep); dec_v0/dec_v1 are the TEA
    // plaintext words after decryption with the winning working key.
    uint32_t bf_counter;
    uint32_t dec_v0;
    uint32_t dec_v1;
} PsaResult;

// Progress callback. pct 0..100 over the 32M keyspace, keys_tested = cumulative.
// Return false to abort. May be NULL.
typedef bool (*PsaProgressFn)(uint8_t pct, uint64_t keys_tested, void* ctx);

// Run the full PSA TEA bruteforce (BF1 + BF2), multi-threaded.
//   key1 : 8 bytes (the 64-bit "key1" field of the capture)
//   key2 : 8 bytes (the "key2" field; only the low 2 bytes are used)
//   out  : filled on success
//   cancel : if non-NULL and *cancel != 0, aborts.
// Returns true if a key was found.
bool psa_bruteforce_run(
    const uint8_t key1[8],
    const uint8_t key2[8],
    PsaResult* out,
    PsaProgressFn progress,
    void* progress_ctx,
    volatile int32_t* cancel);

// BLE offload variant: brute-force the raw TEA plaintext words (w0, w1) sent by
// the Flipper firmware directly, instead of deriving them from key1/key2. On a
// hit, out->bf_counter / out->dec_v0 / out->dec_v1 carry the values the firmware
// expects back (see the PSA offload BLE protocol). Returns true if found.
bool psa_bruteforce_run_words(
    uint32_t w0,
    uint32_t w1,
    PsaResult* out,
    PsaProgressFn progress,
    void* progress_ctx,
    volatile int32_t* cancel);

#ifdef __cplusplus
}
#endif
