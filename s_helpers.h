#ifndef _S_HELPERS_H_
#define _S_HELPERS_H_
#include <stdio.h>
void copy_string(void *dest, int len, const void *src);
void copy_n_string(void *dest, int len, const void *src, int count);
void copy_memory(void *const dest, const int destSize, const void *const src, const int srcSize);
void cat_string(void *dest, int len, const void *src);
int openFile(FILE **fp, const char *filename, const char *mode);
void toUpper(const unsigned char *in, char **out);
#endif
