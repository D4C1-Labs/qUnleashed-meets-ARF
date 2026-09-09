#pragma once

// KeeLoq block cipher (pure crypto), ported from the Flipper firmware's
// lib/subghz/protocols/keeloq_common.c. No FlipperFormat/subghz dependencies:
// just the 528-round NLFSR encrypt/decrypt primitive.

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Non-linear feedback function selector, as in the firmware.
#define KEELOQ_NLF 0x3A5C742E

/** Simple Learning Encrypt.
 *  data - 0xBSSSCCCC, B(4bit) key, S(10bit) serial&0x3FF, C(16bit) counter
 *  key  - manufacturer key (64bit)
 *  returns encrypted 32-bit hop code.
 */
uint32_t subghz_protocol_keeloq_common_encrypt(uint32_t data, uint64_t key);

/** Simple Learning Decrypt.
 *  data - encrypted 32-bit hop code
 *  key  - manufacturer key (64bit)
 *  returns 0xBSSSCCCC plaintext.
 */
uint32_t subghz_protocol_keeloq_common_decrypt(uint32_t data, uint64_t key);

#ifdef __cplusplus
}
#endif
