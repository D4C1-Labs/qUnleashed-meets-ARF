// Fiat V2 IV combo derivation. Mirrors the firmware EXACTLY. The cipher itself
// is the shared Fiat V1 core (fiat_v1_ref.h); only the (button, control) IV
// derivation differs. See fiat_v2_ref.h for the inline extractors.

#include "fiat_v2_ref.h"

uint8_t fiat_v2_iv_button(const uint8_t r[14], uint8_t combo) { // combo bit0
    uint8_t sel = (uint8_t)((r[7] >> FIAT_V2_BTN_SHIFT) & 0x0FU);
    if((combo & 0x01U) == 0U) return sel;
    switch(sel) {
    case FIAT_V2_BUTTON_TRUNK:
        return 0x2U;
    case FIAT_V2_BUTTON_LOCK:
        return 0x4U;
    case FIAT_V2_BUTTON_UNLOCK:
        return 0x8U;
    default:
        return 0x0U;
    }
}

uint16_t fiat_v2_iv_control(const uint8_t r[14], uint8_t combo) { // combo bit1
    uint16_t cnt = (uint16_t)(fiat_v2_counter(r) & 0x3FFU);
    if((combo & 0x02U) == 0U) return cnt;
    return (uint16_t)((~cnt) & 0x3FFU);
}
