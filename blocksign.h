#ifndef _BLOCKSIGN_H_
#define _BLOCKSIGN_H_
#include "args.h"
#include "blocks.h"
#define PAD_CPLD 0xff
#define PAD_BLOCK 0x00
#define FILE_CHUNK_SIZE 1024
#define SIG_READ_BUFFER 256
#define ALIGN_TAG "_aligned"
#define FILE_DATA_HASH  "data.hsh"
#define FILE_DATA_RAW  "data.raw"
#define FILE_SIG_EXPECT  "data.sig"
#define CMD_PREFIX "cmd \0"
int doBlocksign(struct ARGUMENTS *args);
#endif
