/*
 * IRC - Internet Relay Chat, ircd/features.c
 * Copyright (C) 2000 Kevin L. Mitchell <klmitch@mit.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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
#include "features.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "support.h"
#include "sys.h"    /* FALSE bleah */

#include <assert.h>
#include <string.h>

static struct LogTypes {
  char *type;
  int (*set)(const char *, const char *);
  char *(*get)(const char *);
} logTypes[] = {
  { "FILE", log_set_file, log_get_file },
  { "FACILITY", log_set_facility, log_get_facility },
  { "SNOMASK", log_set_snomask, log_get_snomask },
  { "LEVEL", log_set_level, log_get_level },
  { 0, 0, 0 }
};

static struct LogTypes *
feature_log_desc(struct Client* from, const char *type)
{
  int i;

  assert(0 != type);

  for (i = 0; logTypes[i].type; i++) /* find appropriate descriptor */
    if (!ircd_strcmp(type, logTypes[i].type))
      return &logTypes[i];

  Debug((DEBUG_ERROR, "Unknown log feature type \"%s\"", type));
  if (from)
    send_reply(from, ERR_BADLOGTYPE, type);
  else
    log_write(LS_CONFIG, L_ERROR, 0, "Unknown log feature type \"%s\"", type);

  return 0; /* not found */
}

static void
feature_log_set(struct Client* from, const char* const* fields, int count)
{
  struct LogTypes *desc;
  char *subsys;

  if (count < 2) { /* set default facility */
    if (log_set_default(count < 1 ? 0 : fields[0])) {
      assert(count >= 1); /* should always accept default */

      if (from)
	send_reply(from, ERR_BADLOGVALUE, fields[0]);
      else
	log_write(LS_CONFIG, L_ERROR, 0,
		  "Bad value \"%s\" for default facility", fields[0]);
    }
  } else if (!(subsys = log_canon(fields[0]))) { /* no such subsystem */
    if (from)
      send_reply(from, ERR_BADLOGSYS, fields[0]);
    else
      log_write(LS_CONFIG, L_ERROR, 0,
		"No such logging subsystem \"%s\"", fields[0]);
  } else if ((desc = feature_log_desc(from, fields[1]))) { /* set value */
    if ((*desc->set)(fields[0], count < 3 ? 0 : fields[2])) {
      assert(count >= 3); /* should always accept default */

      if (from)
	send_reply(from, ERR_BADLOGVALUE, fields[2]);
      else
	log_write(LS_CONFIG, L_ERROR, 0,
		  "Bad value \"%s\" for log type %s (subsystem %s)",
		  fields[2], desc->type, subsys);
    }
  }
}

static void
feature_log_reset(struct Client* from, const char* const* fields, int count)
{
  struct LogTypes *desc;
  char *subsys;

  assert(0 != from);

  if (count < 1) /* reset default facility */
    log_set_default(0);
  else if (count < 2)
    need_more_params(from, "RESET");
  else if (!(subsys = log_canon(fields[0]))) /* no such subsystem */
    send_reply(from, ERR_BADLOGSYS, fields[0]);
  else if ((desc = feature_log_desc(from, fields[1]))) /* reset value */
    (*desc->set)(fields[0], 0);
}

static void
feature_log_get(struct Client* from, const char* const* fields, int count)
{
  struct LogTypes *desc;
  char *value, *subsys;

  assert(0 != from);

  if (count < 1) /* return default facility */
    send_reply(from, SND_EXPLICIT | RPL_FEATURE, ":Log facility: %s",
	       log_get_default());
  else if (count < 2)
    need_more_params(from, "GET");
  else if (!(subsys = log_canon(fields[0]))) { /* no such subsystem */
    send_reply(from, ERR_BADLOGSYS, fields[0]);
  } else if ((desc = feature_log_desc(from, fields[1]))) {
    if ((value = (*desc->get)(fields[0]))) /* send along value */
      send_reply(from, SND_EXPLICIT | RPL_FEATURE,
		 ":Log %s for subsystem %s: %s", desc->type, subsys,
		 (*desc->get)(subsys));
    else
      send_reply(from, SND_EXPLICIT | RPL_FEATURE,
		 ":No log %s is set for subsystem %s", desc->type, subsys);
  }
}

typedef void (*feature_call)(struct Client*, const char* const*, int);

static struct FeatureDesc {
  char *type;
  feature_call set;   /* set feature values */
  feature_call reset; /* reset feature values to defaults */
  feature_call get;   /* get feature values */
} features[] = {
  { "LOG", feature_log_set, feature_log_reset, feature_log_get },
  { 0, 0, 0, 0 }
};

static struct FeatureDesc *
feature_desc(struct Client* from, const char *feature)
{
  int i;

  assert(0 != feature);

  for (i = 0; features[i].type; i++) /* find appropriate descriptor */
    if (!ircd_strcmp(feature, features[i].type))
      return &features[i];

  Debug((DEBUG_ERROR, "Unknown feature \"%s\"", feature));
  if (from)
    send_reply(from, ERR_NOFEATURE, feature);
  else
    log_write(LS_CONFIG, L_ERROR, 0, "Unknown feature \"%s\"", feature);

  return 0; /* not found */
}

int
feature_set(struct Client* from, const char* const* fields, int count)
{
  struct FeatureDesc *feat;

  if (count < 1) {
    if (from)
      need_more_params(from, "SET");
    else
      log_write(LS_CONFIG, L_ERROR, 0, "Not enough fields in F line");
  } else if ((feat = feature_desc(from, fields[0])))
    (*feat->set)(from, fields + 1, count - 1);

  return 0;
}

int
feature_reset(struct Client* from, const char* const* fields, int count)
{
  struct FeatureDesc *feat;

  assert(0 != from);

  if (count < 1)
    need_more_params(from, "RESET");
  else if ((feat = feature_desc(from, fields[0])))
    (*feat->reset)(from, fields + 1, count - 1);

  return 0;
}

int
feature_get(struct Client* from, const char* const* fields, int count)
{
  struct FeatureDesc *feat;

  assert(0 != from);

  if (count < 1)
    need_more_params(from, "GET");
  else if ((feat = feature_desc(from, fields[0])))
    (*feat->get)(from, fields + 1, count - 1);

  return 0;
}
