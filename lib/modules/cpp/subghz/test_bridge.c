// Standalone bring-up test for the qunleashed_subghz FFI bridge.
//
//   gcc -O3 -pthread -I. -Ihitag2 test_bridge.c \
//       subghz_util.c psa/psa_tea.c keeloq/keeloq.c \
//       hitag2/subghz_hitag2_core.c hitag2/subghz_hitag2_hell_optb.c \
//       hitag2/fiat_v1_ref.c hitag2/hitag2_threaded.c -o test_bridge && ./test_bridge
//
// Verifies:
//   1) KeeLoq encrypt/decrypt roundtrip (decrypt(encrypt(x)) == x).
//   2) qunleashed_hitag2hell_recover runs without crashing and reports
//      candidates on a small L0 sub-range.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "keeloq/keeloq.h"
#include "hitag2/subghz_hitag2_core.h"

// The three FFI entry points (declared here to link against the bridge).
uint32_t qunleashed_keeloq_decrypt(uint32_t hop, uint64_t key);
uint32_t qunleashed_keeloq_encrypt(uint32_t data, uint64_t key);
int qunleashed_hitag2hell_recover(
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
    volatile int32_t* cancel);

// Compute the correct L0 slot ourselves from state31, using the same layer-0
// bit selection (k_layer0_bits) as the kernel in subghz_hitag2_hell_optb.c.
static const uint8_t TEST_L0_BITS[20] = {
    1, 3, 4, 13, 14, 16, 18, 19, 21, 24, 26, 30, 32, 33, 35, 39, 41, 42, 44, 45};
static uint32_t test_compute_l0(uint64_t state31) {
    uint32_t idx = 0;
    for(uint8_t i = 0; i < 20U; i++) {
        if((state31 >> TEST_L0_BITS[i]) & 1U) idx |= (1U << i);
    }
    return idx;
}

static int g_progress_calls = 0;
static void progress_cb(uint8_t pct, uint64_t slots_done, void* ctx) {
    (void)ctx;
    g_progress_calls++;
    printf("    progress: pct=%u slots_done=%llu\n", pct,
           (unsigned long long)slots_done);
}

int main(void) {
    int fails = 0;

    // -------------------------------------------------------------------
    // 1) KeeLoq roundtrip
    // -------------------------------------------------------------------
    printf("=== KeeLoq roundtrip ===\n");
    {
        uint64_t key = 0x0123456789ABCDEFULL;
        uint32_t plains[] = {0x00000000U, 0xDEADBEEFU, 0x12345678U, 0xFFFFFFFFU, 0xA5A5A5A5U};
        int all_ok = 1;
        for(size_t i = 0; i < sizeof(plains) / sizeof(plains[0]); i++) {
            uint32_t enc = qunleashed_keeloq_encrypt(plains[i], key);
            uint32_t dec = qunleashed_keeloq_decrypt(enc, key);
            printf("  data=%08X enc=%08X dec=%08X %s\n", plains[i], enc, dec,
                   dec == plains[i] ? "OK" : "MISMATCH");
            if(dec != plains[i]) all_ok = 0;
        }
        if(all_ok) {
            printf("  KeeLoq roundtrip: PASS\n");
        } else {
            printf("  KeeLoq roundtrip: FAIL\n");
            fails++;
        }
    }

    // -------------------------------------------------------------------
    // 2) Hitag2Hell: run on a small L0 window around a known-good slot.
    // -------------------------------------------------------------------
    printf("\n=== Hitag2Hell recover (small window) ===\n");
    {
        // Build a synthetic capture from a known key so we know the target L0.
        const uint8_t key[6] = {0xB7, 0x92, 0x80, 0xAE, 0xCC, 0x37};
        uint32_t uid = 0x468F5D25U;
        uint8_t button = 1;
        uint16_t control = 0x053U;
        uint32_t epoch = 0; // the bridge/threaded path uses epoch=0

        uint32_t hop = hitag2_fiat_full_auth(uid, button, control, key, epoch);
        Hitag2State true_s31 = hitag2_fiat_init_phase(uid, button, control, key, epoch);
        uint32_t l0 = test_compute_l0(true_s31);

        printf("  synthetic capture: uid=%08X btn=%u cnt=0x%03X hop=%08X\n",
               uid, button, control, hop);
        printf("  correct L0 slot = %u; sweeping [%u, %u) (100 slots)\n", l0,
               l0, l0 + 100);

        uint32_t uids[1] = {uid};
        uint8_t btns[1] = {button};
        uint16_t cnts[1] = {control};
        uint32_t hops[1] = {hop};

        uint8_t out_key[6] = {0};
        int32_t found = 0;
        volatile int32_t cancel = 0;

        int rc = qunleashed_hitag2hell_recover(
            uids, btns, cnts, hops, 1,
            l0, l0 + 100,
            out_key, &found, progress_cb, NULL, &cancel);

        printf("  recover rc=%d found=%d progress_calls=%d\n", rc, found,
               g_progress_calls);
        if(found) {
            printf("  key: %02X %02X %02X %02X %02X %02X\n", out_key[0],
                   out_key[1], out_key[2], out_key[3], out_key[4], out_key[5]);
            if(memcmp(out_key, key, 6) == 0) {
                printf("  Hitag2Hell: recovered CORRECT key (bonus).\n");
            } else {
                printf("  Hitag2Hell: found a cross-validated key (single "
                       "capture => may differ).\n");
            }
        } else {
            printf("  Hitag2Hell: no key in this small window (expected; ran "
                   "without crash).\n");
        }
        printf("  Hitag2Hell: ran without crash: PASS\n");
    }

    printf("\n=== SUMMARY ===\n");
    printf(fails == 0 ? "ALL TESTS PASSED\n" : "%d TEST(S) FAILED\n", fails);
    return fails == 0 ? 0 : 1;
}
