// Renault V1 hop-slice + IV combo derivation. Mirrors the firmware EXACTLY. The
// cipher itself is the shared Fiat V1 core (fiat_v1_ref.h). See
// renault_v1_ref.h for the API.

#include "renault_v1_ref.h"

static const uint8_t renault_v1_hop_slice_starts[3] = {0U, 5U, 10U};

uint32_t renault_v1_candidate_hop(uint64_t payload42, uint8_t slice) {
    if(slice >= RENAULT_V1_HOP_SLICE_COUNT) return 0U;
    uint8_t start = renault_v1_hop_slice_starts[slice];
    uint8_t shift = (uint8_t)(42U - 32U - start);
    return (uint32_t)((payload42 >> shift) & 0xFFFFFFFFULL);
}

uint8_t renault_v1_iv_button(uint8_t button, uint8_t combo) { // combo bit0
    uint8_t ln = (uint8_t)(button & 0x0FU);
    if((combo & 0x01U) == 0U) return ln;
    if(ln >= 0x04U && ln <= 0x07U) return 0x2U;
    if(ln >= 0x08U && ln <= 0x0BU) return 0x4U;
    return 0x1U;
}

uint16_t renault_v1_iv_control(uint8_t counter, uint8_t combo) { // combo bit1
    uint16_t cnt = (uint16_t)((uint16_t)counter & 0x3FFU);
    if((combo & 0x02U) == 0U) return cnt;
    return (uint16_t)((~cnt) & 0x3FFU);
}
