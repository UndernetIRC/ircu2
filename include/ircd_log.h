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
 *
 *
 * $Id$
 */
#ifndef INCLUDED_ircd_log_h
#define INCLUDED_ircd_log_h

#ifndef INCLUDED_stdarg_h
#include <stdarg.h>	    /* va_list */
#define INCLUDED_stdarg_h
#endif

struct Client;

/* WARNING WARNING WARNING -- Order is important; these enums are
 * used as indexes into arrays.
 */

enum LogLevel {
  L_CRIT,
  L_ERROR,
  L_WARNING,
  L_NOTICE,
  L_TRACE,
  L_INFO,
  L_DEBUG,
  L_LAST_LEVEL
};

enum LogSys {
  LS_SYSTEM, LS_CONFIG, LS_OPERMODE, LS_GLINE, LS_JUPE, LS_WHO, LS_NETWORK,
  LS_OPERKILL, LS_SERVKILL, LS_OPER, LS_OPERLOG, LS_USERLOG, LS_RESOLVER,
  LS_SOCKET, LS_DEBUG, LS_OLDLOG,
  LS_LAST_SYSTEM
};

extern void open_log(const char* process_name);
extern void close_log(void);
extern void set_log_level(int level);
extern int  get_log_level(void);
extern void ircd_log(int priority, const char* fmt, ...);

extern void ircd_log_kill(const struct Client* victim,
                          const struct Client* killer,
                          const char*          inpath,
                          const char*          path);

extern void log_debug_init(char *file);
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
			   const char	       *path);

#define LOG_NOSYSLOG	0x01
#define LOG_NOFILELOG	0x02
#define LOG_NOSNOTICE	0x04

#define LOG_NOMASK	(LOG_NOSYSLOG | LOG_NOFILELOG | LOG_NOSNOTICE)

extern void log_set_file(char *subsys, char *filename);
extern char *log_get_file(char *subsys);

extern void log_set_facility(char *subsys, char *facility);
extern char *log_get_facility(char *subsys);

extern void log_set_snomask(char *subsys, char *facility);
extern char *log_get_snomask(char *subsys);

extern void log_set_level(char *subsys, char *level);
extern char *log_get_level(char *subsys);

extern void log_set_default(char *facility);
extern char *log_get_default(void);

#endif /* INCLUDED_ircd_log_h */
