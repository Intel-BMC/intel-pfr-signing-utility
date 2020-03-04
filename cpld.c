#include "cpld.h"

#include <stdio.h>
#include <stdlib.h>

#include "log.h"
void swapBits(uint8_t *in)
{
    uint8_t out = (*in & 0b1) << 7;
    out += (*in & 0b10) << 5;
    out += (*in & 0b100) << 3;
    out += (*in & 0b1000) << 1;
    out += (*in & 0b10000) >> 1;
    out += (*in & 0b100000) >> 3;
    out += (*in & 0b1000000) >> 5;
    out += (*in & 0b10000000) >> 7;
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
