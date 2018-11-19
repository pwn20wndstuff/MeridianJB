#include <stdio.h>
#include <sys/time.h>

#ifdef DEBUG
extern FILE *log_file;
struct timeval dl_tv;
#define DEBUGLOG(fmt, args...)                                      \
do {                                                                \
    if (log_file == NULL) {                                         \
        char *log_path;                                       \
	if (asprintf(&log_path, "/var/log/unrestrict-%d.log", getpid()) == -1) { \
		break;                                              \
	}                                                           \
        log_file = fopen(log_path, "a");                            \
	free(log_path);                                             \
        if (log_file == NULL) break;                                \
    }                                                               \
    gettimeofday(&dl_tv, NULL);                                     \
    fprintf(log_file, "[%ld.%06d] " fmt "\n", dl_tv.tv_sec, dl_tv.tv_usec, \
              ##args);                                     \
    fflush(log_file);                                               \
} while(0)
#else
#define DEBUGLOG(fmt, args...) do {} while (0)
#endif // ifdef DEBUG

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
