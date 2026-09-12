#pragma once

// Renault V1 hop-slice + IV combo derivation.
//
// The Flipper offloads a 42-bit payload plus a button + counter for each
// capture. The 32-bit hop (authenticator) fed to the Hell kernel is one of
// three "slices" of that 42-bit payload; and the (button, control) IV has 4
// "combos". The underlying cipher is the shared Fiat V1 core (fiat_v1_ref.h);
// the UID is supplied separately (uid = serial & 0xFFFFFF, sent in the header).
//
// Mirrors the firmware EXACTLY.

#include <stdint.h>
#include <stdbool.h>

#include "fiat_v1_ref.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RENAULT_V1_HOP_SLICE_COUNT 3U
#define RENAULT_V1_IV_COMBO_COUNT 4U

// Candidate 32-bit hop for slice 0..2 of the 42-bit payload. Returns 0 for an
// out-of-range slice.
uint32_t renault_v1_candidate_hop(uint64_t payload42, uint8_t slice);

// Derived IV button for the given combo (combo bit0 selects the mapping).
uint8_t renault_v1_iv_button(uint8_t button, uint8_t combo);

// Derived IV control for the given combo (combo bit1 selects inversion).
uint16_t renault_v1_iv_control(uint8_t counter, uint8_t combo);

#ifdef __cplusplus
}
#endif
