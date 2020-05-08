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
#ifndef _BLOCKSIGN_H_
#define _BLOCKSIGN_H_
#include "args.h"
#include "blocks.h"
#define PAD_CPLD 0xff
#define PAD_BLOCK 0x00
#define FILE_CHUNK_SIZE 1024
#define SIG_READ_BUFFER 256
#define ALIGN_TAG "_aligned"
#define FILE_DATA_HASH "data.hsh"
#define FILE_DATA_RAW "data.raw"
#define FILE_SIG_EXPECT "data.sig"
#define CMD_PREFIX "cmd \0"
// TEST BLOCK
#ifdef _WIN32
#ifdef TESTS
#ifdef __cplusplus
extern "C" {
#endif
#ifdef BLOCKSIGN_EXPORTS
#define BLOCKSIGN_API __declspec(dllexport)
#else
#define BLOCKSIGN_API __declspec(dllimport)
#endif
#else
#define BLOCKSIGN_API
#endif
#else
#define BLOCKSIGN_API
#endif
// END TEST BLOCK
BLOCKSIGN_API int doBlocksign(ARGUMENTS *args);
// TEST BLOCK
#endif
#ifdef _WIN32
#ifdef TESTS
#ifdef __cplusplus
}
#endif
#endif
#endif
// END TEST BLOCK
