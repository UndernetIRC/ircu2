#ifndef INCLUDED_ircd_snprintf_h
#define INCLUDED_ircd_snprintf_h
/*
 * IRC - Internet Relay Chat, include/jupe.h
 * Copyright (C) 2000 Kevin L. Mitchell <klmitch@mit.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id$
 */
#ifndef INCLUDED_config_h
#include "config.h"
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_stdarg_h
#include <stdarg.h>
#define INCLUDED_stdarg_h
#endif

struct Client;

/* structure passed as argument for %v conversion */
struct VarData {
  size_t	vd_chars;	/* number of characters inserted */
  size_t	vd_overflow;	/* number of characters that couldn't be */
  const char   *vd_format;	/* format string */
  va_list	vd_args;	/* arguments for %v */
};

extern int ircd_snprintf(struct Client *dest, char *buf, size_t buf_len,
			 const char *format, ...);
extern int ircd_vsnprintf(struct Client *dest, char *buf, size_t buf_len,
			  const char *format, va_list args);

#endif /* INCLUDED_ircd_snprintf_h */
