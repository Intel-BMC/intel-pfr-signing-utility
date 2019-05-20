#include "log.h"
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#include <VersionHelpers.h>
#endif
#include "s_helpers.h"
int ansiCapable = 0;
void setAnsi()
{
#ifdef _WIN32
    // Returns TRUE if 10.0.10586 is GREATER/EQUAL than installed version, TRUE=BAD
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
    toUpper((const unsigned char*)term, &upper);
    if (upper != NULL && (strcmp(upper,TERM_XTERM_256) == 0 || strcmp(upper,TERM_LINUX) == 0))
    {
        ansiCapable = 1;
        free(upper);
    }
#endif
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
        case Red: return SET_COLOR_RED; break;
        case Green: return SET_COLOR_GREEN; break;
        case Clear: return SET_CLEAR; break;
        case Bold: return SET_BOLD; break;
        case Blink: return SET_BLINK; break;
        default: return ""; break;
        }
    }
    else
    {
        return "";
    }
}
