/*
 * s_debug.h
 *
 * $Id$
 */
#ifndef INCLUDED_s_debug_h
#define INCLUDED_s_debug_h
#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"       /* Needed for HOSTLEN */
#endif
#ifndef INCLUDED_stdarg_h
#include <stdarg.h>
#define INCLUDED_stdarg_h
#endif

struct Client;
struct StatDesc;

#ifdef DEBUGMODE

/*
 * Macro's
 */

#define Debug(x) debug x
#define LOGFILE LPATH

/*
 * defined debugging levels
 */
#define DEBUG_FATAL   0
#define DEBUG_ERROR   1  /* report_error() and other errors that are found */
#define DEBUG_NOTICE  3
#define DEBUG_DNS     4  /* used by all DNS related routines - a *lot* */
#define DEBUG_INFO    5  /* general useful info */
#define DEBUG_NUM     6  /* numerics */
#define DEBUG_SEND    7  /* everything that is sent out */
#define DEBUG_DEBUG   8  /* everything that is received */ 
#define DEBUG_MALLOC  9  /* malloc/free calls */
#define DEBUG_LIST   10  /* debug list use */
#define DEBUG_ENGINE 11  /* debug event engine; can dump gigabyte logs */

/*
 * proto types
 */

extern void vdebug(int level, const char *form, va_list vl);
extern void debug(int level, const char *form, ...);
extern void send_usage(struct Client *cptr, struct StatDesc *sd, int stat,
		       char *param);

#else /* !DEBUGMODE */

#define Debug(x)
#define LOGFILE "/dev/null"

#endif /* !DEBUGMODE */

extern const char* debug_serveropts(void);
extern void debug_init(int use_tty);
extern void count_memory(struct Client *cptr, struct StatDesc *sd, int stat,
			 char *param);

#endif /* INCLUDED_s_debug_h */
