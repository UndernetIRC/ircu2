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

enum Feature {
  FEAT_LOG,

  FEAT_OPER_NO_CHAN_LIMIT,
  FEAT_OPER_MODE_LCHAN,
  FEAT_OPER_WALK_THROUGH_LMODES,
  FEAT_NO_OPER_DEOP_LCHAN,
  FEAT_SHOW_INVISIBLE_USERS,
  FEAT_SHOW_ALL_INVISIBLE_USERS,
  FEAT_UNLIMIT_OPER_QUERY,
  FEAT_LOCAL_KILL_ONLY,
  FEAT_CONFIG_OPERCMDS,

  FEAT_OPER_KILL,
  FEAT_OPER_REHASH,
  FEAT_OPER_RESTART,
  FEAT_OPER_DIE,
  FEAT_OPER_GLINE,
  FEAT_OPER_LGLINE,
  FEAT_OPER_JUPE,
  FEAT_OPER_LJUPE,
  FEAT_OPER_OPMODE,
  FEAT_OPER_LOPMODE,
  FEAT_OPER_BADCHAN,
  FEAT_OPER_LBADCHAN,
  FEAT_OPERS_SEE_IN_SECRET_CHANNELS,

  FEAT_LOCOP_KILL,
  FEAT_LOCOP_REHASH,
  FEAT_LOCOP_RESTART,
  FEAT_LOCOP_DIE,
  FEAT_LOCOP_LGLINE,
  FEAT_LOCOP_LJUPE,
  FEAT_LOCOP_LOPMODE,
  FEAT_LOCOP_LBADCHAN,
  FEAT_LOCOP_SEE_IN_SECRET_CHANNELS,

  FEAT_LAST_F
};

extern int feature_set(struct Client* from, const char* const* fields,
		       int count);
extern int feature_reset(struct Client* from, const char* const* fields,
			 int count);
extern int feature_get(struct Client* from, const char* const* fields,
		       int count);

extern void feature_unmark(void);
extern void feature_mark(void);

extern void feature_report(struct Client* to);

extern int feature_int(enum Feature feat);
extern int feature_bool(enum Feature feat);
extern const char *feature_str(enum Feature feat);

#endif /* INCLUDED_features_h */
