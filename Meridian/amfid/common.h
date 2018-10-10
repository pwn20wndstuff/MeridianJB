#define LOG(str, args...) do { NSLog(@"[amfid_payload] " str, ##args); } while(0)
#define ERROR(str, args...) LOG("ERROR: [%s] " str, __func__, ##args)
#define INFO(str, args...)  LOG("INFO: " str, ##args)

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
