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

struct Client;

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

/* WARNING WARNING WARNING -- Order is important; these are
 * used as indexes into an array of LogDesc structures.
 */
enum LogSys {
  LS_GLINE,
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

extern void log_init(const char *process_name);
extern void log_reopen(void);
extern void log_close(void);

extern void log_write(enum LogSys subsys, enum LogLevel severity,
		      const char *fmt, ...);

#endif /* INCLUDED_ircd_log_h */
