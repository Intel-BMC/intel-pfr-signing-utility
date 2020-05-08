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
#ifndef _S_HELPERS_H_
#define _S_HELPERS_H_
#include <stdio.h>
void copy_string(void *dest, int len, const void *src);
void copy_n_string(void *dest, int len, const void *src, int count);
void copy_memory(void *const dest, const int destSize, const void *const src,
                 const int srcSize);
void cat_string(void *dest, int len, const void *src);
int openFile(FILE **fp, const char *filename, const char *mode);
void toUpper(const unsigned char *in, char **out);
#endif
