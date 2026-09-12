#pragma once

// Reference Fiat V1 Hitag2 cipher (the authenticator generator + a key
// verifier). Defined in fiat_v1_ref.c. Extracted into a header so the new
// per-proto reference files (fiat_v2_ref.c, renault_v1_ref.c) and the threaded
// recovery can reuse the cipher WITHOUT reimplementing it.
//
// IV layout (see subghz_protocol_fiat_v1_compute_auth):
//   iv = ((epoch & 0x3FFFF) << 14) | ((control & 0x3FF) << 4) | (button & 0xF)

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Generate the 32-bit Fiat V1 authenticator for the given public inputs + key.
uint32_t subghz_protocol_fiat_v1_compute_auth(
    uint32_t uid,
    uint8_t button,
    uint16_t control,
    const uint8_t key[6],
    uint32_t epoch);

// True iff compute_auth(uid, button, control, key, epoch) == hop.
bool subghz_protocol_fiat_v1_verify_key(
    uint32_t uid,
    uint8_t button,
    uint16_t control,
    uint32_t hop,
    const uint8_t key[6],
    uint32_t epoch);

#ifdef __cplusplus
}
#endif
