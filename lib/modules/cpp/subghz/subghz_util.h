#pragma once

// Cross-platform logical-CPU count, ported from the hardnested module's util.c
// (num_CPUs). Renamed to subghz_num_cpus so this library can coexist with
// qunleashed_hardnested in a single Apple binary.

#ifdef __cplusplus
extern "C" {
#endif

// Number of logical CPUs (>= 1). Used to size the thread pools.
int subghz_num_cpus(void);

#ifdef __cplusplus
}
#endif
