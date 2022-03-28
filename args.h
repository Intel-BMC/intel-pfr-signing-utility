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
#define EXPECT_VERSION 1

#define CANCELLATION_BIT 0x100
#define EC_POINT_MAX 48
#define EC_POINT_384 48
#define EC_POINT_256 32

// CLI Stuff
#define CLI_CONFIG "-c"
#define CLI_OUTPUT "-o"
#define CLI_PARSE "-p"
#define CLI_VERBOSE "-v"

// Hash Algorithms
#define HASH_SHA1_STR "SHA1"
#define HASH_SHA256_STR "SHA256"
#define HASH_SHA384_STR "SHA384"
#define HASH_SHA512_STR "SHA512"

// Element Defs
#define ELEMENT_BLOCKSIGN "BLOCKSIGN"
#define ELEMENT_VERSION "VERSION"
#define ELEMENT_BLOCK1 "BLOCK1"
#define ELEMENT_BLOCK0 "BLOCK0"
#define ELEMENT_B0SIG "B0_SIG"
#define ELEMENT_SIGMAGIC "SIGMAGIC"
#define ELEMENT_MAGIC "MAGIC"
#define ELEMENT_PCTYPE "PCTYPE"
#define ELEMENT_RKEY "RKEY"
#define ELEMENT_CSKEY "CSKEY"
#define ELEMENT_PERMISSIONS "PERMISSIONS"
#define ELEMENT_KEYID "KEYID"
#define ELEMENT_PUBKEY "PUBKEY"
#define ELEMENT_CURVEMAGIC "CURVEMAGIC"
#define ELEMENT_HASHALG "HASHALG"
#define ELEMENT_SIGNKEY "SIGNKEY"
#define ELEMENT_SCRIPT "SCRIPT"
#define ELEMENT_PADDING "PADDING"
#define ELEMENT_BLOCKPAD "BLOCKPAD"
#define ELEMENT_ALIGN "ALIGN"
#define ELEMENT_CPLD "CPLD"
#define ELEMENT_BYTESWAP "SWAPBYTES"
#define ELEMENT_CPLDSVN "SVN"
#define ELEMENT_CPLDOEMDATA "OEMDATA"

#define OEM_DATA_SIZE 16
#define OEM_HEX_MIN_LEN 3
#define OEM_HEX_MAX_LEN 34

// True False Tags
#define TAG_TRUE "TRUE"
#define TAG_FALSE "FALSE"

typedef struct _B1_RK
{
    uint32_t magic;
    uint32_t curve_magic;
    char *pubkey;
    int32_t permissions;
    int32_t keyid;
} B1_RK;

typedef struct _B1_CSK
{
    uint32_t magic;
    uint32_t curve_magic;
    char *script_file;
    char *sign_key;
    char *pubkey;
    uint16_t hashalg;
    uint32_t sig_magic;
    int32_t permissions;
    int32_t keyid;
} B1_CSK;

typedef struct _B0_SIG
{
    uint32_t magic;
    uint32_t sig_magic;
    uint16_t hashalg;
    char *script_file; // script to call for external
    char *sign_key;
} B0_SIG;

typedef struct _B1_ARGUMENTS
{
    uint32_t magic;
    B1_RK root_key;
    B1_CSK cskey;
    B0_SIG b0sig;
} B1_ARGUMENTS;

typedef struct _B0_ARGUMENTS
{
    uint32_t magic;
    uint32_t pctype;
} B0_ARGUMENTS;

typedef struct _ARGUMENTS
{
    uint8_t swapbytes;
    uint32_t svn;
    uint8_t *oemData;
    uint8_t version;
    uint8_t verbose;
    uint8_t parse;
    uint32_t align;
    uint32_t blockpad;
    char *inputBinary;
    char *outputBinary;
    B0_ARGUMENTS b0_args;
    B1_ARGUMENTS b1_args;
} ARGUMENTS;
