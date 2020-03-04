#ifndef _BLOCKS_H_
#define _BLOCKS_H_
#include <stdint.h>

typedef struct _CSK
{
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
} CSK;

typedef struct _RK
{
    uint32_t magic;
    uint32_t curve_magic;
    int32_t permissions;
    int32_t keyid;
    uint8_t pubkey_x[48];
    uint8_t pubkey_y[48];
    uint8_t reserved1[20];
} RK;

typedef struct _BLOCK0_SIG
{
    uint32_t magic;
    uint32_t sig_magic;
    uint8_t sig_r[48];
    uint8_t sig_s[48];
} BLOCK0_SIG;

typedef struct _BLOCK_0
{
    uint32_t magic;
    uint32_t pc_length;
    uint32_t pc_type;
    uint8_t reserved1[4];
    uint8_t sha256[32];
    uint8_t sha384[48];
    uint8_t reserved2[32];
} BLOCK_0;

typedef struct _BLOCK_1
{
    uint32_t magic;
    uint8_t reserved1[12];
    RK root_key;
    CSK cs_key;
    BLOCK0_SIG block0_sig;
} BLOCK_1;

#endif
