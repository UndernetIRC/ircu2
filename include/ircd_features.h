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
 *
 * $Id$
 */

struct Client;

extern int feature_set(struct Client* from, const char* const* fields,
		       int count);
extern int feature_reset(struct Client* from, const char* const* fields,
			 int count);
extern int feature_get(struct Client* from, const char* const* fields,
		       int count);

#endif /* INCLUDED_features_h */
