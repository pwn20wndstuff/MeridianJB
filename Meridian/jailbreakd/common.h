#include <sys/time.h>

struct timeval dl_tv;
#define DEBUGLOG(syslog, fmt, args ...)     \
    gettimeofday(&dl_tv, NULL); \
    fprintf(stdout, "%ld.%d: " fmt "\n", dl_tv.tv_sec, dl_tv.tv_usec, ##args);      \
    fflush(stdout);

#define CACHED_FIND(type, name) \
    type __##name(void);                \
    type name(void) {                   \
        type cached = 0;                \
        if (cached == 0) {              \
            cached = __##name();        \
        }                               \
        return cached;                  \
    }                                   \
    type __##name(void)
