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
#include "args.h"
// Returns performs input validation and populates structs necessary for
// building blocks. TEST BLOCK
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
BLOCKSIGN_API int parseCli(int argc, char **argv, ARGUMENTS *args);
BLOCKSIGN_API void initContext(ARGUMENTS **args);
BLOCKSIGN_API void destroyContext(ARGUMENTS *args);
// TEST BLOCK
#ifdef _WIN32
#ifdef TESTS
#ifdef __cplusplus
}
#endif
#endif
#endif
// END TEST BLOCK
