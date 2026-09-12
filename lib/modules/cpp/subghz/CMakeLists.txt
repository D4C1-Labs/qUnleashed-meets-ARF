cmake_minimum_required(VERSION 3.13)
project(qunleashed_subghz LANGUAGES C)

# Host-side Sub-GHz crypto: PSA TEA bruteforce, KeeLoq decrypt/encrypt, and the
# Hitag2Hell Fiat V1 attack. Crypto ported from the Flipper-ARF firmware
# (psa.c, keeloq_common.c) and the verified Hitag2Hell core; all threading is
# host-side (pthreads, or the bundled pthread_shim.h on MSVC).

add_library(qunleashed_subghz SHARED
  qunleashed_subghz_bridge.c
  subghz_util.c
  psa/psa_tea.c
  keeloq/keeloq.c
  keeloq/keeloq_bruteforce.c
  hitag2/subghz_hitag2_core.c
  hitag2/subghz_hitag2_hell_optb.c
  hitag2/subghz_hitag2_hell_neon.c
  hitag2/fiat_v1_ref.c
  hitag2/fiat_v2_ref.c
  hitag2/renault_v1_ref.c
  hitag2/hitag2_threaded.c
)

target_include_directories(qunleashed_subghz PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/hitag2"
)

set_target_properties(qunleashed_subghz PROPERTIES
  C_STANDARD 11
  POSITION_INDEPENDENT_CODE ON
  C_VISIBILITY_PRESET hidden
)

# Perf: -O3 on GCC/Clang. MSVC uses its own default optimization.
# The Hitag2Hell kernel exists in two builds selected at compile time by the
# __ARM_NEON macro: subghz_hitag2_hell_neon.c (128-lane uint32x4_t NEON, used on
# Android arm64 / iOS / Apple Silicon) and subghz_hitag2_hell_optb.c (32-lane
# scalar fallback for x86 desktop). The NEON build is ~4x faster than scalar;
# -O3 does NOT auto-vectorize the scalar bitslice chain, so the explicit NEON
# kernel is required for acceptable phone performance.
if(NOT MSVC)
  target_compile_options(qunleashed_subghz PRIVATE -O3)
endif()

# Threads: real pthreads on Linux/Android/macOS/iOS and MinGW (winpthreads);
# clang-cl/MSVC use the bundled pthread_shim.h (Win32 APIs, no extra library).
if(NOT (WIN32 AND NOT MINGW))
  find_package(Threads REQUIRED)
  target_link_libraries(qunleashed_subghz PRIVATE Threads::Threads)
endif()

if(WIN32)
  target_compile_definitions(qunleashed_subghz PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# MSVC does not enable C11 <stdatomic.h> by default: vcruntime_c11_stdatomic.h
# hard-errors with "C atomic support is not enabled" unless this switch is on
# (available since VS 2022 17.5). The threaded Hitag2 and PSA kernels use
# atomic_int / _Atomic, so MSVC needs it explicitly. clang-cl and MinGW support
# C11 atomics natively and must not receive this MSVC-only flag.
if(MSVC)
  target_compile_options(qunleashed_subghz PRIVATE /experimental:c11atomics)
endif()
