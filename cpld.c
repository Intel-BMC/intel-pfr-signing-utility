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
#include "cpld.h"

#include <stdio.h>
#include <stdlib.h>

#include "log.h"
void swapBits(uint8_t *in)
{
    uint8_t out = (*in & 0x01) << 7;
    out += (*in & 0x02) << 5;
    out += (*in & 0x04) << 3;
    out += (*in & 0x08) << 1;
    out += (*in & 0x10) >> 1;
    out += (*in & 0x20) >> 3;
    out += (*in & 0x40) >> 5;
    out += (*in & 0x80) >> 7;
    *in = out;
}
int swapBytesAndBits(const uint8_t *in, uint8_t *out)
{
    int ret = 1;
    /*if (sizeof(in) != 4)
    {
        ret = 0;
        fprintf(stderr, "%sCannot swap bytes, input buffer is too small (%lu,
    needs 4)\n", getErr(), sizeof(in));
    }
    if (sizeof(out) != 4)
    {
        ret = 0;
        fprintf(stderr, "%sCannot swap bytes, output buffer is too small (%lu,
    needs 4)\nz", getErr(), sizeof(out));
    }*/
    if (ret)
    {
        out[0] = in[3];
        out[1] = in[2];
        out[2] = in[1];
        out[3] = in[0];
        swapBits(&(out[0]));
        swapBits(&(out[1]));
        swapBits(&(out[2]));
        swapBits(&(out[3]));
    }
    return ret;
}
