/*
 * sprintf_irc.h
 *
 * $Id$
 */
#ifndef INCLUDED_sprintf_irc_h
#define INCLUDED_sprintf_irc_h
#ifndef INCLUDED_stdarg_h
#include <stdarg.h>
#define INCLUDED_stdarg_h
#endif

/*
 * Proto types
 */

extern char *vsprintf_irc(char *str, const char *format, va_list);
extern char *sprintf_irc(char *str, const char *format, ...); 
extern const char atoi_tab[4000];

#endif /* INCLUDED_sprintf_irc_h */
