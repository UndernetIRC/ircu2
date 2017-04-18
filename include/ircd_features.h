#ifndef INCLUDED_features_h
#define INCLUDED_features_h
/*
 * IRC - Internet Relay Chat, include/features.h
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
 */
/** @file
 * @brief Public interfaces and declarations for dealing with configurable features.
 */

struct Client;
struct StatDesc;

extern struct Client his;

#define F_I(NAME, FLAGS, DEFAULT, NOTIFY) extern int FEAT_ ## NAME;
#define F_U(NAME, FLAGS, DEFAULT, NOTIFY) extern unsigned int FEAT_ ## NAME;
#define F_B(NAME, FLAGS, DEFAULT, NOTIFY) extern int FEAT_ ## NAME;
#define F_S(NAME, FLAGS, DEFAULT, NOTIFY) extern const char *FEAT_ ## NAME;
#define F_A(NAME, REALNAME)

#include "ircd_features.inc"

#define feature_int(NAME) NAME
#define feature_bool(NAME) NAME
#define feature_str(NAME) NAME
#define feature_uint(NAME) NAME

extern void feature_init(void);

extern int feature_set(struct Client* from, const char* const* fields,
		       int count);
extern int feature_reset(struct Client* from, const char* const* fields,
			 int count);
extern int feature_get(struct Client* from, const char* const* fields,
		       int count);

extern void feature_unmark(void);
extern void feature_mark(void);

extern void feature_report(struct Client* to, const struct StatDesc* sd,
                           char* param);

#endif /* INCLUDED_features_h */
