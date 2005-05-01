/* - Internet Relay Chat, include/ircd_log.h
 *   Copyright (C) 1999 Thomas Helvey
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief IRC logging interface.
 * @version $Id$
 */
#ifndef INCLUDED_ircd_log_h
#define INCLUDED_ircd_log_h

#ifndef INCLUDED_stdarg_h
#include <stdarg.h>	    /* va_list */
#define INCLUDED_stdarg_h
#endif
#ifndef INCLUDED_stdlib_h
#include <stdlib.h> /* abort */
#define INCLUDED_stdlib_h
#endif

struct Client;

/* WARNING WARNING WARNING -- Order is important; these enums are
 * used as indexes into arrays.
 */
/** Level of a log message. */
enum LogLevel {
  L_CRIT,      /**< Critical failure. */
  L_ERROR,     /**< Serious error. */
  L_WARNING,   /**< Recoverable warning. */
  L_NOTICE,    /**< Important status messages. */
  L_TRACE,     /**< Client exit and kill logging. */
  L_INFO,      /**< Logging of other operator commands. */
  L_DEBUG,     /**< Debug message output. */
  L_LAST_LEVEL /**< Count of valid LogLevel values. */
};

/** Log systems. */
enum LogSys {
  LS_SYSTEM,     /**< Operational status changes. */
  LS_CONFIG,     /**< Configuration errors and warnings. */
  LS_OPERMODE,   /**< Uses of OPMODE, CLEARMODE< etc. */
  LS_GLINE,      /**< Adding, (de-)activating or removing GLINEs. */
  LS_JUPE,       /**< Adding, (de-)activating or removing JUPEs. */
  LS_WHO,        /**< Use of extended WHO privileges. */
  LS_NETWORK,    /**< New server connections. */
  LS_OPERKILL,   /**< Kills by IRC operators. */
  LS_SERVKILL,   /**< Kills by servers. */
  LS_USER,       /**< User exits. */
  LS_OPER,       /**< Users becoming operators. */
  LS_RESOLVER,   /**< DNS resolver errors. */
  LS_SOCKET,     /**< Unexpected socket operation errors. */
  LS_IAUTH,      /**< IAuth status. */
  LS_DEBUG,      /**< Debug messages. */
  LS_LAST_SYSTEM /**< Count of valid LogSys values. */
};

extern void log_debug_init(int usetty);
extern void log_init(const char *process_name);
extern void log_reopen(void);
extern void log_close(void);

extern void log_write(enum LogSys subsys, enum LogLevel severity,
		      unsigned int flags, const char *fmt, ...);
extern void log_vwrite(enum LogSys subsys, enum LogLevel severity,
		       unsigned int flags, const char *fmt, va_list vl);

extern void log_write_kill(const struct Client *victim,
			   const struct Client *killer,
			   const char	       *inpath,
			   const char	       *path,
			   const char	       *msg);

#define LOG_NOSYSLOG	0x01 /**< Do not send message to syslog. */
#define LOG_NOFILELOG	0x02 /**< Do not send message to a log file. */
#define LOG_NOSNOTICE	0x04 /**< Do not send message via server notice. */
/** Bitmask of suppression flags for log_write() and log_vwrite(). */
#define LOG_NOMASK	(LOG_NOSYSLOG | LOG_NOFILELOG | LOG_NOSNOTICE)

extern char *log_canon(const char *subsys);

extern int log_set_file(const char *subsys, const char *filename);
extern char *log_get_file(const char *subsys);

extern int log_set_facility(const char *subsys, const char *facility);
extern char *log_get_facility(const char *subsys);

extern int log_set_snomask(const char *subsys, const char *facility);
extern char *log_get_snomask(const char *subsys);

extern int log_set_level(const char *subsys, const char *level);
extern char *log_get_level(const char *subsys);

extern int log_set_default(const char *facility);
extern char *log_get_default(void);

extern void log_feature_unmark(void);
extern int log_feature_mark(int flag);
extern void log_feature_report(struct Client *to, int flag);

extern int log_inassert;

#endif /* INCLUDED_ircd_log_h */

/* The rest of this file implements our own custom version of assert.
 * This version will log the assertion failure using the LS_SYSTEM log
 * stream, thus putting the assertion failure message into a useful
 * place, rather than elsewhere, as is currently the case...
 */

/* We've been included twice; clean up before creating assert() again */
#ifdef _ircd_log_assert
# undef _ircd_log_assert
# undef assert
#endif

/* gcc has a nice way of hinting that an expression is expected to
 * produce a specific result, which can improve optimization.
 * Unfortunately, all the world's not gcc (at least, not yet), and not
 * all gcc's support it.  I don't know exactly when it appeared, but
 * it does appear to be in all versions from 3 and up.  So, we'll
 * create a dummy define if (we think) this version of gcc doesn't
 * have it...
 */
#ifndef _log_builtin_expect
# define _log_builtin_expect
# if __GNUC__ < 3
#  define __builtin_expect(expr, expect)	(expr)
# endif
#endif

/* let's try not to clash with the system assert()... */
#ifndef assert
# ifdef NDEBUG
#  define assert(expr)	((void)0)
# else
#  define assert(expr)							      \
  ((void)(__builtin_expect(!!(expr), 1) ? 0 :				      \
	  (__builtin_expect(log_inassert, 0) ? (abort(), 0) :		      \
	   ((log_inassert = 1), /* inhibit looping in assert() */	      \
	    log_write(LS_SYSTEM, L_CRIT, 0, "Assertion failure at %s:%d: "    \
		      "\"%s\"", __FILE__, __LINE__, #expr), abort(), 0))))
# endif
#endif
