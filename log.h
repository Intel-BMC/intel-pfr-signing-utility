#ifndef _LOG_H_
#define _LOG_H_
// ANSI Compatible terminals
#define TERM_XTERM_256 "XTERM-256COLOR"
#define TERM_LINUX     "LINUX"
#ifdef _WIN32
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#endif
enum Attribute { Red, Green, Clear, Blink, Bold };
extern int ansiCapable;
// ANSI and Normal print tags
#ifdef _WIN32
#define LOG_ERR_ANSI    "[\x1B[91mERR\x1B[0m] "
#define LOG_WRN_ANSI    "[\x1B[93mWRN\x1B[0m] "
#define LOG_NFO_ANSI    "[\x1B[96mNFO\x1B[0m] "
#define SET_COLOR_RED    "\x1B[91m"
#define SET_COLOR_GREEN "\x1B[92m"
#define SET_CLEAR        "\x1B[0m"
#define SET_BLINK        "\x1B[5m"
#define SET_BOLD        "\x1B[1m"
#else
#define LOG_ERR_ANSI    "[\033[91mERR\033[0m] "
#define LOG_WRN_ANSI    "[\033[93mWRN\033[0m] "
#define LOG_NFO_ANSI    "[\033[96mNFO\033[0m] "
#define SET_COLOR_RED    "\033[91m"
#define SET_COLOR_GREEN "\033[92m"
#define SET_CLEAR        "\033[0m"
#define SET_BLINK        "\033[5m"
#define SET_BOLD        "\033[1m"
#endif
#define LOG_ERR         "[ERR] "
#define LOG_WRN         "[WRN] "
#define LOG_NFO         "[NFO] "
void setAnsi();
const char *getNfo();
const char *getWrn();
const char *getErr();
const char *setAttribute(enum Attribute attr);
#endif
