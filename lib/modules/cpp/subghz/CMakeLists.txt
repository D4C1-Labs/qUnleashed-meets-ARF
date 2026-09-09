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
  hitag2/subghz_hitag2_core.c
  hitag2/subghz_hitag2_hell_optb.c
  hitag2/fiat_v1_ref.c
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

# Perf: -O3 on GCC/Clang. MSVC uses its own default optimization. The vector /
# NEON / SSE2 code paths in the Hell kernel use the same GCC/Clang vector_size
# pattern as the hardnested engine (auto-vectorized at -O3).
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
