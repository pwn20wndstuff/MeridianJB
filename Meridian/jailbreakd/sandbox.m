#include "kmem.h"
#include "kern_utils.h"
#include "sandbox.h"
#include "kexecute.h"
#include "common.h"

typedef uint64_t extension_hdr_t;
typedef uint64_t extension_t;

struct extension_hdr11 {
    /* 0x00 */    extension_hdr_t next;
    /* 0x08 */    uint64_t desc;
    /* 0x10 */    extension_t ext_lst;
    /* 0x18 */
};

struct extension11 {
    /* 0x00 */    extension_t next;
    /* 0x08 */    uint64_t desc; // always 0xffffffffffffffff
    /* 0x10 */    uint64_t ext_lst; // zero, since it's extension and not a header
    /* 0x18 */    uint8_t something[32]; // zeroed from what I've seen
    /* 0x38 */    uint32_t type; // see ext_type enum
    /* 0x3c */    uint32_t subtype; // either 0 or 4 (or whatever unhex gave?..)
    /* 0x40 */    uint64_t data; // a c string, meaning depends on type and hdr which had this extension
    /* 0x48 */    uint64_t data_len; // strlen(data)
    /* 0x50 */    uint64_t unk0; // always 0
    /* 0x58 */    uint64_t unk1; // always 0xdeadbeefdeadbeef
    /* 0x60 */
};

struct extension_hdr12 {
    /* 0x00 */    extension_hdr_t next;
    /* 0x8 */     extension_t ext_lst;
    /* 0x10 */    char desc[];
    /* 0x18 */
};

struct extension12 {
    extension_t next;
    uint64_t desc;              // always 0xffffffffffffffff;
    uint8_t something[20];      // all zero
    uint16_t num;               // one
    uint8_t type;               // see ext_type enum
    uint8_t num3;               // one
    uint32_t subtype;           // either 0 or 4 (or whatever unhex gave?..)
    uint32_t num4;              // another number
    void* data;                 // a c string, meaning depends on type and hdr which had this extension
    uint64_t data_len;          // strlen(data)
    uint16_t num5;              // another one!
    uint8_t something_2[14];    // something v2.0
    uint64_t ptr3;              // it's always 0 for files
    uint64_t ptr4;              // idk
};

uint64_t _smalloc(uint64_t size) {
    return kexecute(offset_smalloc, size, 0, 0, 0, 0, 0, 0);
}

uint64_t smalloc(uint64_t size) {
    uint64_t ret = _smalloc(size);
    
    if (ret != 0) {
        // IOAlloc's of small size go to zalloc
        ret = zm_fix_addr(ret);
    }
    
    return ret;
}

uint64_t sstrdup(const char* s) {
    size_t slen = strlen(s) + 1;
    
    uint64_t ks = smalloc(slen);
    if (ks) {
        kwrite(ks, s, slen);
    }
    
    return ks;
}

// Notice: path should *not* end with '/' !
uint64_t extension_create_file(const char* path, uint64_t nextptr) {
    size_t slen = strlen(path);
    
    if (path[slen - 1] == '/') {
        DEBUGLOG(false, "No traling slash in path pls");
        return 0;
    }
    
    uint64_t ext_p = 0;
    
    if (kCFCoreFoundationVersionNumber >= 1535.12) {
        ext_p = smalloc(sizeof(struct extension12));
    } else {
        ext_p = smalloc(sizeof(struct extension11));
    }
    
    uint64_t ks = sstrdup(path);
    
    if (ext_p && ks) {
        if (kCFCoreFoundationVersionNumber >= 1535.12) {
            struct extension12 ext;
            bzero(&ext, sizeof(ext));
            ext.next = (extension_t)nextptr;
            ext.desc = 0xffffffffffffffff;
            
            ext.type = 0;
            ext.subtype = 0;
            
            ext.data = (void*)ks;
            ext.data_len = slen;
            
            ext.num = 1;
            ext.num3 = 1;
            
            kwrite(ext_p, &ext, sizeof(ext));
        } else {
            struct extension11 ext;
            bzero(&ext, sizeof(ext));
            ext.next = nextptr;
            ext.desc = 0xffffffffffffffff;
            
            ext.data = ks;
            ext.data_len = slen;
            
            kwrite(ext_p, &ext, sizeof(ext));
        }
    } else {
        // XXX oh no a leak
    }
    
    return ext_p;
}

// get 64 higher bits of 64bit int multiplication
// https://stackoverflow.com/a/28904636
// ofc in asm it's done with 1 instruction huh
// XXX there has to be a cleaner way utilizing hardware support
uint64_t mulhi(uint64_t a, uint64_t b) {
    uint64_t    a_lo = (uint32_t)a;
    uint64_t    a_hi = a >> 32;
    uint64_t    b_lo = (uint32_t)b;
    uint64_t    b_hi = b >> 32;
    
    uint64_t    a_x_b_hi =  a_hi * b_hi;
    uint64_t    a_x_b_mid = a_hi * b_lo;
    uint64_t    b_x_a_mid = b_hi * a_lo;
    uint64_t    a_x_b_lo =  a_lo * b_lo;
    
    uint64_t    carry_bit = ((uint64_t)(uint32_t)a_x_b_mid +
                             (uint64_t)(uint32_t)b_x_a_mid +
                             (a_x_b_lo >> 32) ) >> 32;
    
    uint64_t    multhi = a_x_b_hi +
    (a_x_b_mid >> 32) + (b_x_a_mid >> 32) +
    carry_bit;
    
    return multhi;
}

int hashing_magic(const char *desc) {
    if (kCFCoreFoundationVersionNumber >= 1535.12) {
        unsigned int hashed;
        char ch, ch2;
        char *chp;
        
        ch = *desc;
        
        if (*desc) {
            chp = (char *)(desc + 1);
            hashed = 0x1505;
            
            do {
                hashed = 33 * hashed + ch;
                ch2 = *chp++;
                ch = ch2;
            }
            while (ch2);
        }
        else hashed = 0x1505;
        
        return hashed % 9;
    } else {
        // inlined into exception_add
        uint64_t hashed = 0x1505;
        
        // if desc == NULL, then returned value would be 8
        // APPL optimizes it for some reason
        // but meh, desc should never be NULL or you get
        // null dereference in exception_add
        // if (desc == NULL) return 8;
        
        if (desc != NULL) {
            for (const char* dp = desc; *dp != '\0'; ++dp) {
                hashed += hashed << 5;
                hashed += (int64_t) *dp;
            }
        }
        
        uint64_t magic = 0xe38e38e38e38e38f;
        
        uint64_t hi = mulhi(hashed, magic);
        hi >>= 3;
        hi = (hi<<3) + hi;
        
        hashed -= hi;
        
        return hashed;
    }
}

static const char *ent_key = "com.apple.security.exception.files.absolute-path.read-only";

uint64_t make_ext_hdr(const char* key, uint64_t ext_lst) {
    if (kCFCoreFoundationVersionNumber >= 1535.12) {
        struct extension_hdr12 hdr;
        
        uint64_t khdr = smalloc(sizeof(hdr) + strlen(key) + 1);
        if (!khdr) {
            DEBUGLOG(false, "Unable to smalloc");
            return 0;
        }
        
        // we add headers to end
        hdr.next = 0;
        hdr.ext_lst = ext_lst;

        kwrite(khdr, &hdr, sizeof(hdr));
        kwrite(khdr + offsetof(struct extension_hdr12, desc), key, strlen(key) + 1);
        
        return khdr;
    } else {
        struct extension_hdr11 hdr;
        
        uint64_t khdr = smalloc(sizeof(hdr));
        
        if (khdr) {
            // we add headers to end
            hdr.next = 0;
            hdr.desc = sstrdup(key);
            if (hdr.desc == 0) {
                // XXX leak
                return 0;
            }
            
            hdr.ext_lst = ext_lst;
            kwrite(khdr, &hdr, sizeof(hdr));
        }
        
        return khdr;
    }
}

void extension_add(uint64_t ext, uint64_t sb, const char* desc) {
    // XXX patchfinder + kexecute would be way better
    
    int slot = hashing_magic(ent_key);
    
    uint64_t insert_at_p = 0;
    
    if (kCFCoreFoundationVersionNumber >= 1535.12) {
        uint64_t ext_table = rk64(sb + sizeof(void *));
        insert_at_p = ext_table + slot * sizeof(void*);
    } else {
        insert_at_p = sb + sizeof(void*) + slot * sizeof(void*);
    }
    
    uint64_t insert_at = rk64(insert_at_p);
    
    while (insert_at != 0) {
        uint64_t kdsc = 0;
        
        if (kCFCoreFoundationVersionNumber >= 1535.12) {
            kdsc = insert_at + offsetof(struct extension_hdr12, desc);
        } else {
            kdsc = rk64(insert_at + offsetof(struct extension_hdr11, desc));
        }
        
        if (kstrcmp(kdsc, desc) == 0) {
            break;
        }
        
        insert_at_p = insert_at;
        insert_at = rk64(insert_at);
    }
    
    if (insert_at == 0) {
        insert_at = make_ext_hdr(ent_key, ext);
        wk64(insert_at_p, insert_at);
    } else {
        // XXX no duplicate check
        
        uint64_t ext_lst_p = 0;
        
        if (kCFCoreFoundationVersionNumber >= 1535.12) {
            ext_lst_p = insert_at + offsetof(struct extension_hdr12, ext_lst);
        } else {
            ext_lst_p = insert_at + offsetof(struct extension_hdr11, ext_lst);
        }
        
        uint64_t ext_lst = rk64(ext_lst_p);
        
        while (ext_lst != 0) {
            DEBUGLOG(false, "ext_lst_p = 0x%llx ext_lst = 0x%llx", ext_lst_p, ext_lst);
            
            if (kCFCoreFoundationVersionNumber >= 1535.12) {
                ext_lst_p = ext_lst + offsetof(struct extension12, next);
            } else {
                ext_lst_p = ext_lst + offsetof(struct extension11, next);
            }
            
            ext_lst = rk64(ext_lst_p);
        }
        
        DEBUGLOG(false, "ext_lst_p = 0x%llx ext_lst = 0x%llx", ext_lst_p, ext_lst);
        
        wk64(ext_lst_p, ext);
    }
}

// 1 if yes
int has_file_extension(uint64_t sb, const char* path) {
    const char* desc = ent_key;
    int found = 0;
    
    int slot = hashing_magic(ent_key);
    
    uint64_t insert_at_p = 0;
    
    if (kCFCoreFoundationVersionNumber >= 1535.12) {
        uint64_t ext_table = rk64(sb + sizeof(void *));
        insert_at_p = ext_table + slot * sizeof(void*);
    } else {
        insert_at_p = sb + sizeof(void*) + slot * sizeof(void*);
    }
    
    uint64_t insert_at = rk64(insert_at_p);
    
    while (insert_at != 0) {
        uint64_t kdsc = 0;
        
        if (kCFCoreFoundationVersionNumber >= 1535.12) {
            kdsc = insert_at + offsetof(struct extension_hdr12, desc);
        } else {
            kdsc = rk64(insert_at + offsetof(struct extension_hdr11, desc));
        }
        
        if (kstrcmp(kdsc, desc) == 0) {
            break;
        }
        
        insert_at_p = insert_at;
        insert_at = rk64(insert_at);
    }
    
    if (insert_at != 0) {
        uint64_t ext_lst = 0;
        
        if (kCFCoreFoundationVersionNumber >= 1535.12) {
            ext_lst = rk64(insert_at + offsetof(struct extension_hdr12, ext_lst));
        } else {
            ext_lst = rk64(insert_at + offsetof(struct extension_hdr11, ext_lst));
        }
        
        uint64_t plen = strlen(path);
        char *exist = malloc(plen + 1);
        if (!exist) {
            DEBUGLOG(false, "Unable to malloc");
        }
        exist[plen] = '\0';
        
        while (ext_lst != 0) {
            // XXX no type/subtype check
            
            uint64_t data_len = 0;
            
            if (kCFCoreFoundationVersionNumber >= 1535.12) {
                data_len = rk64(ext_lst + offsetof(struct extension12, data_len));
            } else {
                data_len = rk64(ext_lst + offsetof(struct extension11, data_len));
            }
            
            if (data_len == plen) {
                uint64_t data = 0;
                
                if (kCFCoreFoundationVersionNumber >= 1535.12) {
                    data = ext_lst + offsetof(struct extension12, data);
                } else {
                    data = rk64(ext_lst + offsetof(struct extension11, data));
                }
                
                kread(data, exist, plen);
                
                if (strcmp(path, exist) == 0) {
                    found = 1;
                    break;
                }
            }
            
            ext_lst = rk64(ext_lst);
        }
        
        free(exist);
    }
    
    return found;
}
