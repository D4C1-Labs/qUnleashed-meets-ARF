// Reference implementation of the Fiat V1 Hitag2 variant, extracted from
// standalone_test.c so multiple runners can link against it.

#include <stdint.h>
#include <stdbool.h>

static uint8_t ref_truth(uint32_t table, uint8_t index) { return (uint8_t)((table >> index) & 1U); }
static uint8_t ref_fi(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (uint8_t)((a << 3U) | (b << 2U) | (c << 1U) | d);
}
static uint8_t ref_bb(uint8_t byte, uint8_t bit) { return (uint8_t)((byte >> bit) & 1U); }

static uint8_t ref_filter(const uint8_t state[6]) {
    uint8_t g = 0U;
    g |= ref_truth(0x2C79U, ref_fi(ref_bb(state[0],1U), ref_bb(state[0],2U), ref_bb(state[0],4U), ref_bb(state[0],5U)));
    g |= (uint8_t)(ref_truth(0x6671U, ref_fi(ref_bb(state[1],0U), ref_bb(state[1],1U), ref_bb(state[1],3U), ref_bb(state[1],7U))) << 1U);
    g |= (uint8_t)(ref_truth(0x6671U, ref_fi(ref_bb(state[3],5U), ref_bb(state[2],0U), ref_bb(state[2],2U), ref_bb(state[2],6U))) << 2U);
    g |= (uint8_t)(ref_truth(0x6671U, ref_fi(ref_bb(state[4],6U), ref_bb(state[3],0U), ref_bb(state[3],2U), ref_bb(state[3],3U))) << 3U);
    g |= (uint8_t)(ref_truth(0x2C79U, ref_fi(ref_bb(state[5],1U), ref_bb(state[5],3U), ref_bb(state[5],4U), ref_bb(state[4],5U))) << 4U);
    return ref_truth(0x7907287BUL, g);
}

static uint8_t ref_parity8(uint8_t v) {
    v ^= (uint8_t)(v >> 4U); v ^= (uint8_t)(v >> 2U); v ^= (uint8_t)(v >> 1U);
    return v & 1U;
}

static uint8_t ref_feedback(const uint8_t state[6]) {
    static const uint8_t masks[6] = {0xB3U, 0x80U, 0x83U, 0x22U, 0x00U, 0x73U};
    uint8_t fb = 0U;
    for(uint8_t i = 0U; i < 6U; i++) fb ^= ref_parity8((uint8_t)(state[i] & masks[i]));
    return fb & 1U;
}

static void ref_shift(uint8_t state[6], uint8_t input) {
    for(uint8_t i = 0U; i < 5U; i++)
        state[i] = (uint8_t)((state[i] << 1U) | (state[i+1U] >> 7U));
    state[5] = (uint8_t)((state[5] << 1U) | (input & 1U));
}

static uint8_t ref_iv_bit(uint32_t v, uint8_t i) { return (uint8_t)((v >> (31U - i)) & 1U); }
static uint8_t ref_key_bit(const uint8_t* b, uint8_t i) { return (uint8_t)((b[i>>3U] >> (7U - (i & 7U))) & 1U); }

uint32_t subghz_protocol_fiat_v1_compute_auth(
    uint32_t uid, uint8_t button, uint16_t control, const uint8_t key[6], uint32_t epoch) {
    uint8_t state[6] = {(uint8_t)(uid>>24U),(uint8_t)(uid>>16U),(uint8_t)(uid>>8U),(uint8_t)uid,key[4],key[5]};
    const uint32_t iv = ((epoch & 0x3FFFFUL) << 14U) | (((uint32_t)control & 0x3FFUL) << 4U) | ((uint32_t)button & 0xFUL);
    for(uint8_t i = 0U; i < 32U; i++) {
        const uint8_t inp = (uint8_t)(ref_iv_bit(iv,i) ^ ref_key_bit(key,i) ^ ref_filter(state));
        ref_shift(state, inp);
    }
    uint32_t auth = 0U;
    for(uint8_t i = 0U; i < 32U; i++) {
        auth = (auth << 1U) | ref_filter(state);
        ref_shift(state, ref_feedback(state));
    }
    return auth;
}

bool subghz_protocol_fiat_v1_verify_key(
    uint32_t uid, uint8_t button, uint16_t control, uint32_t hop, const uint8_t key[6], uint32_t epoch) {
    return subghz_protocol_fiat_v1_compute_auth(uid, button, control, key, epoch) == hop;
}
