#include "s_helpers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void copy_string(void *dest, int len, const void *src)
{
#ifdef _WIN32
    strcpy_s(dest, len, src);
#else
    strncpy(dest, src, len);
#endif
}

void copy_n_string(void *dest, int len, const void *src, int count)
{
#ifdef _WIN32
    strncpy_s(dest, len, src, count);
#else
    strncpy(dest, src, count);
#endif
}

void copy_memory(void *const dest, const int destSize, const void *const src,
                 const int srcSize)
{
#ifdef _WIN32
    memcpy_s(dest, destSize, src, srcSize);
#else
    memcpy(dest, src, srcSize);
#endif
}

void cat_string(void *dest, int len, const void *src)
{
#ifdef _WIN32
    strcat_s(dest, len, src);
#else
    strncat(dest, src, len);
#endif
}

int openFile(FILE **fp, const char *filename, const char *mode)
{
    int ret = 1;
#ifdef _WIN32
    const char *realMode = "rb";
    if (mode == "w")
    {
        realMode = "wb";
    }

    errno_t err = fopen_s(fp, filename, realMode);
    if (err != 0)
    {
        ret = 0;
    }
#else
    *fp = fopen(filename, mode);
    if (fp == NULL)
    {
        ret = 0;
    }
#endif
    return ret;
}

/// Simple toUpper function for element matching
void toUpper(const unsigned char *in, char **out)
{
    if (in != NULL)
    {
        int i;
        *out = malloc(sizeof(char) * strlen((char *)in) + 1);
        int length = strlen((char *)in);
        for (i = 0; i < length; ++i)
        {
            if (in[i] >= 'a' && in[i] <= 'z')
            {
                (*out)[i] = in[i] - ' ';
            }
            else
            {
                (*out)[i] = in[i];
            }
        }
        (*out)[i] = '\0';
    }
}
