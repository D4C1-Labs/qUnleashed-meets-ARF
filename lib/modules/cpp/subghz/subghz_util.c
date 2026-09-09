// Cross-platform logical-CPU detection, ported from the hardnested module's
// util.c num_CPUs().

#include "subghz_util.h"

#ifdef _WIN32
#include <windows.h>
#include <sysinfoapi.h>
#else
#include <unistd.h>
#endif

int subghz_num_cpus(void) {
#if defined(_WIN32)
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return (int)sysinfo.dwNumberOfProcessors;
#else
    int count = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if(count <= 0) count = 1;
    return count;
#endif
}
