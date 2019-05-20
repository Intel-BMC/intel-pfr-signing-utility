#ifndef _BLOCKS_H_
#define _BLOCKS_H_
#include <stdint.h>

typedef struct CSK {
    uint32_t magic;
    uint32_t curve_magic;
    int32_t permissions;
    int32_t keyid;
    uint8_t pubkey_x[48];
    uint8_t pubkey_y[48];
    uint8_t reserved1[20];
    uint32_t sig_magic;
    uint8_t sig_r[48];
    uint8_t sig_s[48];
} _CSK;

typedef struct RK {
    uint32_t magic;
    uint32_t curve_magic;
    int32_t permissions;
    int32_t keyid;
    uint8_t pubkey_x[48];
    uint8_t pubkey_y[48];
    uint8_t reserved1[20];
} _RK;

typedef struct BLOCK0_SIG {
    uint32_t magic;
    uint32_t sig_magic;
    uint8_t sig_r[48];
    uint8_t sig_s[48];
} _BLOCK0_SIG;

typedef struct BLOCK_0 {
    uint32_t magic;
    uint32_t pc_length;
    uint32_t pc_type;
    uint8_t reserved1[4];
    uint8_t sha256[32];
    uint8_t sha384[48];
    uint8_t reserved2[32];
} _BLOCK_0;

typedef struct BLOCK_1 {
    uint32_t magic;
    uint8_t reserved1[12];
    struct RK root_key;
    struct CSK cs_key;
    struct BLOCK0_SIG block0_sig;
} _BLOCK_1;

#endif
