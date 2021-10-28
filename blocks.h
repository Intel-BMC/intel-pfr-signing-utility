/*
// Copyright (c) 2020 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
#pragma once
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
