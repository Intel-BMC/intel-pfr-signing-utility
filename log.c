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
#include "log.h"

#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <VersionHelpers.h>
#include <windows.h>
#endif
#include "s_helpers.h"
int ansiCapable = 0;
void setAnsi()
{
#ifdef _WIN32
    // Returns TRUE if 10.0.10586 is GREATER/EQUAL than installed version,
    // TRUE=BAD
    if (!IsWindowsVersionOrGreater(10, 0, 10586))
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD consoleMode;
        GetConsoleMode(hConsole, &consoleMode);
        consoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        if (SetConsoleMode(hConsole, consoleMode))
        {
            ansiCapable = 1;
        }
    }
#else
    char *term;
    term = getenv("TERM");
    char *upper = NULL;
    toUpper((const unsigned char *)term, &upper);
    if (upper != NULL &&
        (strcmp(upper, TERM_XTERM_256) == 0 || strcmp(upper, TERM_LINUX) == 0))
    {
        ansiCapable = 1;
        free(upper);
    }
#endif
}

void hexDump(const unsigned char *buf, const int len, const char *pad, FILE *fd,
             const char *tag)
{
    printf("%s%s0000: ", tag, pad);
    int i;
    for (i = 0; i < len; ++i)
    {
        printf("%02X ", buf[i]);
        if ((i + 1) % 8 == 0)
        {
            fprintf(fd, " ");
        }
        if ((i + 1) % 16 == 0 && i + 1 != len)
        {
            fprintf(fd, "\n%s%s%04X: ", tag, pad, i + 1);
        }
        else if (i + 1 == len)
        {
            fprintf(fd, "\n");
        }
    }
}

const char *getNfo()
{
    if (ansiCapable)
    {
        return LOG_NFO_ANSI;
    }
    else
    {
        return LOG_NFO;
    }
}
const char *getWrn()
{
    if (ansiCapable)
    {
        return LOG_WRN_ANSI;
    }
    else
    {
        return LOG_WRN;
    }
}
const char *getErr()
{
    if (ansiCapable)
    {
        return LOG_ERR_ANSI;
    }
    else
    {
        return LOG_ERR;
    }
}

const char *setAttribute(enum Attribute attr)
{
    if (ansiCapable)
    {
        switch (attr)
        {
            case Red:
                return SET_COLOR_RED;
                break;
            case Green:
                return SET_COLOR_GREEN;
                break;
            case Clear:
                return SET_CLEAR;
                break;
            case Bold:
                return SET_BOLD;
                break;
            case Blink:
                return SET_BLINK;
                break;
            default:
                return "";
                break;
        }
    }
    else
    {
        return "";
    }
}
