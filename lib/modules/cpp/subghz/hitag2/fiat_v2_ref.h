#pragma once

// Fiat V2 IV combo derivation from a 14-byte raw frame.
//
// The Flipper offloads a verbatim 14-byte Fiat V2 frame (bytes 0..13). From it
// we derive: the 4-byte UID, the 32-bit hop (authenticator), the rolling
// counter, and — for each of the 4 IV "combos" — the (button, control) pair fed
// into the Fiat V1 cipher (the underlying cipher is identical; only the IV
// derivation differs between V1 and V2).
//
// Mirrors the firmware EXACTLY. Uses the shared cipher from fiat_v1_ref.h.

#include <stdint.h>
#include <stdbool.h>

#include "fiat_v1_ref.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FIAT_V2_WIRE_BYTES 14U
#define FIAT_V2_BTN_SHIFT 6U
#define FIAT_V2_CNT_SHIFT 3U
#define FIAT_V2_FCA_TYPE_NIBBLE 0xD0U
#define FIAT_V2_BUTTON_TRUNK 0x1U
#define FIAT_V2_BUTTON_LOCK 0x2U
#define FIAT_V2_BUTTON_UNLOCK 0x3U
#define FIAT_V2_IV_COMBO_COUNT 4U

static inline uint32_t fiat_v2_uid(const uint8_t r[14]) {
    return ((uint32_t)r[2] << 24) | ((uint32_t)r[3] << 16) | ((uint32_t)r[4] << 8) | r[5];
}

static inline bool fiat_v2_is_fca(const uint8_t r[14]) {
    return (r[6] & 0xF0U) == FIAT_V2_FCA_TYPE_NIBBLE;
}

static inline uint32_t fiat_v2_hop(const uint8_t r[14]) {
    if(fiat_v2_is_fca(r))
        return ((uint32_t)r[10] << 24) | ((uint32_t)r[11] << 16) | ((uint32_t)r[12] << 8) |
               r[13];
    return ((uint32_t)r[9] << 24) | ((uint32_t)r[10] << 16) | ((uint32_t)r[11] << 8) | r[12];
}

static inline uint32_t fiat_v2_counter(const uint8_t r[14]) {
    if(fiat_v2_is_fca(r)) {
        uint32_t rc = ((uint32_t)r[8] << 6) | ((uint32_t)(r[9] >> 2));
        return (~rc) & 0x3FFFU;
    }
    uint32_t rc = ((uint32_t)(r[7] & 0x3FU) << 5) | ((uint32_t)(r[8] >> FIAT_V2_CNT_SHIFT));
    return (~rc) & 0x7FFU;
}

// Derived IV button for the given combo (combo bit0 selects the mapping).
uint8_t fiat_v2_iv_button(const uint8_t r[14], uint8_t combo);

// Derived IV control for the given combo (combo bit1 selects inversion).
uint16_t fiat_v2_iv_control(const uint8_t r[14], uint8_t combo);

#ifdef __cplusplus
}
#endif
