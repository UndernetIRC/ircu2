#ifndef SPRINTF_IRC
#define SPRINTF_IRC

#include <stdarg.h>

/*=============================================================================
 * Proto types
 */

extern char *vsprintf_irc(register char *str, register const char *format,
    register va_list);
extern char *sprintf_irc(register char *str, register const char *format, ...)
    __attribute__ ((format(printf, 2, 3)));

extern const char atoi_tab[4000];

#endif /* SPRINTF_IRC */
