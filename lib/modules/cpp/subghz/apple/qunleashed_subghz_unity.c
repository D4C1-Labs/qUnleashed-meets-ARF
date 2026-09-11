//-----------------------------------------------------------------------------
// Apple (CocoaPods) unity build for qunleashed_subghz.
//
// Podspecs can't reference sources outside their own tree, and Xcode compiles
// each file once, so this forwarder #includes the shared C sources (one level
// up) into a single translation unit - the same approach the hardnested pod
// uses.
//
// The CMake platforms (Windows/Linux/Android) compile the files individually
// instead; this file is Apple-only and not part of the CMake target.
//-----------------------------------------------------------------------------
#include "../qunleashed_subghz_bridge.c"
#include "../subghz_util.c"
#include "../psa/psa_tea.c"
#include "../keeloq/keeloq.c"
#include "../keeloq/keeloq_bruteforce.c"
#include "../hitag2/subghz_hitag2_core.c"
// Both Hitag2Hell kernels are included; the __ARM_NEON guard inside each makes
// exactly one active (NEON on Apple Silicon / iOS arm64, scalar otherwise).
#include "../hitag2/subghz_hitag2_hell_optb.c"
#include "../hitag2/subghz_hitag2_hell_neon.c"
#include "../hitag2/fiat_v1_ref.c"
#include "../hitag2/hitag2_threaded.c"
