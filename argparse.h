#ifndef _ARGPARSE_H_
#define _ARGPRASE_H_
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
#endif
#ifdef _WIN32
#ifdef TESTS
#ifdef __cplusplus
}
#endif
#endif
#endif
// END TEST BLOCK