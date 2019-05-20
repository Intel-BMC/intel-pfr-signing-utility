#ifndef _ARGPARSE_H_
#define _ARGPRASE_H_
#include "args.h"
// Returns performs input validation and populates structs necessary for building blocks.
int parseCli(int argc, char **argv, struct ARGUMENTS *args);
void initContext(struct ARGUMENTS **args);
void destroyContext(struct ARGUMENTS *args);
#endif