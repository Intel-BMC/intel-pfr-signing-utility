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
#ifndef TESTS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argparse.h"
#include "blocksign.h"
#include "log.h"
#ifdef _WIN32
#include <crtdbg.h>
#endif
int appMain(int argc, char **argv);
#ifdef _WIN32
#ifdef _DEBUG
// If it's DEBUG, use Windows style memory leak check
int main(int argc, char **argv)
{
    _CrtMemState s1, s2, s3;
    _CrtMemCheckpoint(&s1);
    int ret = appMain(argc, argv);
    _CrtMemCheckpoint(&s2);
    if (_CrtMemDifference(&s3, &s1, &s2))
    {
        printf("******* MEMORY LEAKS DETECTED *******\n");
        printf("******* MEMORY LEAKS DETECTED *******\n");
        printf("******* MEMORY LEAKS DETECTED *******\n");
        printf("******* MEMORY LEAKS DETECTED *******\n");
        printf("******* MEMORY LEAKS DETECTED *******\n");
        _CrtMemDumpStatistics(&s3);
    }
    // Pause on debug
    system("pause");
    return ret;
}
#else
// Otherwise, normal program entry
int main(int argc, char **argv)
{
    return appMain(argc, argv);
}
#endif
#else
// If Linux, normal program entry
int main(int argc, char **argv)
{
    return appMain(argc, argv);
}
#endif

int appMain(int argc, char **argv)
{
    setAnsi();
    int ret = 1;
    ARGUMENTS *args = NULL;
    initContext(&args);
    ret = parseCli(argc, argv, args);
    if (ret)
    {
        ret = doBlocksign(args);
        if (!ret)
        {
            fprintf(stderr, "%sBlocksign operation failed\n", getErr());
        }
    }
    if (args != NULL)
    {
        destroyContext(args);
    }
    return !ret;
}
#endif