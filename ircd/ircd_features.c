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
#include "ircd_features.h"
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
#include <stdlib.h>
#include <string.h>

/* List of log output types that can be set */
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

/* Look up a struct LogType given the type string */
static struct LogTypes *
feature_log_desc(struct Client* from, const char *type)
{
  int i;

  assert(0 != type);

  for (i = 0; logTypes[i].type; i++) /* find appropriate descriptor */
    if (!ircd_strcmp(type, logTypes[i].type))
      return &logTypes[i];

  Debug((DEBUG_ERROR, "Unknown log feature type \"%s\"", type));
  if (from) /* send an error; if from is NULL, called from conf parser */
    send_reply(from, ERR_BADLOGTYPE, type);
  else
    log_write(LS_CONFIG, L_ERROR, 0, "Unknown log feature type \"%s\"", type);

  return 0; /* not found */
}

/* Set the value of a log output type for a log subsystem */
static int
feature_log_set(struct Client* from, const char* const* fields, int count)
{
  struct LogTypes *desc;
  char *subsys;

  if (count < 2) { /* set default facility */
    if (log_set_default(count < 1 ? 0 : fields[0])) {
      assert(count >= 1); /* should always accept default */

      if (from) /* send an error */
	send_reply(from, ERR_BADLOGVALUE, fields[0]);
      else
	log_write(LS_CONFIG, L_ERROR, 0,
		  "Bad value \"%s\" for default facility", fields[0]);
    } else
      return count < 1 ? -1 : 1; /* tell feature to set or clear mark */
  } else if (!(subsys = log_canon(fields[0]))) { /* no such subsystem */
    if (from) /* send an error */
      send_reply(from, ERR_BADLOGSYS, fields[0]);
    else
      log_write(LS_CONFIG, L_ERROR, 0,
		"No such logging subsystem \"%s\"", fields[0]);
  } else if ((desc = feature_log_desc(from, fields[1]))) { /* set value */
    if ((*desc->set)(fields[0], count < 3 ? 0 : fields[2])) {
      assert(count >= 3); /* should always accept default */

      if (from) /* send an error */
	send_reply(from, ERR_BADLOGVALUE, fields[2]);
      else
	log_write(LS_CONFIG, L_ERROR, 0,
		  "Bad value \"%s\" for log type %s (subsystem %s)",
		  fields[2], desc->type, subsys);
    }
  }

  return 0;
}

/* reset a log type for a subsystem to its default value */
static int
feature_log_reset(struct Client* from, const char* const* fields, int count)
{
  struct LogTypes *desc;
  char *subsys;

  assert(0 != from); /* Never called by the .conf parser */

  if (count < 1) { /* reset default facility */
    log_set_default(0);
    return -1; /* unmark this entry */
  } else if (count < 2)
    need_more_params(from, "RESET");
  else if (!(subsys = log_canon(fields[0]))) /* no such subsystem */
    send_reply(from, ERR_BADLOGSYS, fields[0]);
  else if ((desc = feature_log_desc(from, fields[1]))) /* reset value */
    (*desc->set)(fields[0], 0); /* default should always be accepted */

  return 0;
}

/* report the value of a log setting */
static void
feature_log_get(struct Client* from, const char* const* fields, int count)
{
  struct LogTypes *desc;
  char *value, *subsys;

  assert(0 != from); /* never called by .conf parser */

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

/* sets a feature to the given value */
typedef int  (*feat_set_call)(struct Client*, const char* const*, int);
/* gets the value of a feature */
typedef void (*feat_get_call)(struct Client*, const char* const*, int);
/* unmarks all sub-feature values prior to reading .conf */
typedef void (*feat_unmark_call)(void);
/* resets to defaults all currently unmarked values */
typedef void (*feat_mark_call)(int);
/* reports features as a /stats f list */
typedef void (*feat_report_call)(struct Client*, int);

#define FEAT_NONE   0x0000	/* no value */
#define FEAT_INT    0x0001	/* set if entry contains an integer value */
#define FEAT_BOOL   0x0002	/* set if entry contains a boolean value */
#define FEAT_STR    0x0003	/* set if entry contains a string value */
#define FEAT_MASK   0x000f	/* possible value types */

#define FEAT_MARK   0x0010	/* set if entry has been changed */
#define FEAT_NULL   0x0020	/* NULL string is permitted */
#define FEAT_CASE   0x0040	/* string is case-sensitive */

#define FEAT_OPER   0x0100	/* set to display only to opers */
#define FEAT_MYOPER 0x0200	/* set to display only to local opers */

static struct FeatureDesc {
  enum Feature	   feat;    /* feature identifier */
  char*		   type;    /* string describing type */
  unsigned int     flags;   /* flags for feature */
  int		   v_int;   /* integer value */
  int		   def_int; /* default value */
  char*		   v_str;   /* string value */
  char*		   def_str; /* default value */
  feat_set_call	   set;	    /* set feature values */
  feat_set_call	   reset;   /* reset feature values to defaults */
  feat_get_call	   get;	    /* get feature values */
  feat_unmark_call unmark;  /* unmark all feature change values */
  feat_mark_call   mark;    /* reset to defaults all unchanged features */
  feat_report_call report;  /* report feature values */
} features[] = {
#define F(type, flags, v_int, v_str, set, reset, get, unmark, mark, report)   \
  { FEAT_ ## type, #type, (flags), 0, (v_int), 0, (v_str),		      \
    (set), (reset), (get), (unmark), (mark), (report) }
#define F_I(type, v_int)						      \
  { FEAT_ ## type, #type, FEAT_INT, 0, (v_int), 0, 0, 0, 0, 0, 0, 0, 0 }
#define F_B(type, v_int)						      \
  { FEAT_ ## type, #type, FEAT_BOOL, 0, (v_int), 0, 0, 0, 0, 0, 0, 0, 0 }
#define F_S(type, flags, v_int)						      \
  { FEAT_ ## type, #type, FEAT_STR | (flags), 0, 0, 0, (v_str),		      \
    0, 0, 0, 0, 0, 0 }

  F(LOG, FEAT_NONE | FEAT_MYOPER, 0, 0,
    feature_log_set, feature_log_reset, feature_log_get,
    log_feature_unmark, log_feature_mark, log_feature_report),

  F_B(OPER_NO_CHAN_LIMIT, 1),
  F_B(OPER_MODE_LCHAN, 1),
  F_B(OPER_WALK_THROUGH_LMODES, 0),
  F_B(NO_OPER_DEOP_LCHAN, 0),
  F_B(SHOW_INVISIBLE_USERS, 1),
  F_B(SHOW_ALL_INVISIBLE_USERS, 1),
  F_B(UNLIMIT_OPER_QUERY, 0),
  F_B(LOCAL_KILL_ONLY, 0),
  F_B(CONFIG_OPERCMDS, 1), /* XXX change default before release */

  F_B(OPER_KILL, 1),
  F_B(OPER_REHASH, 1),
  F_B(OPER_RESTART, 1),
  F_B(OPER_DIE, 1),
  F_B(OPER_GLINE, 1),
  F_B(OPER_LGLINE, 1),
  F_B(OPER_JUPE, 1),
  F_B(OPER_LJUPE, 1),
  F_B(OPER_OPMODE, 1),
  F_B(OPER_LOPMODE, 1),
  F_B(OPER_BADCHAN, 0),
  F_B(OPER_LBADCHAN, 0),
  F_B(OPERS_SEE_IN_SECRET_CHANNELS, 1),

  F_B(LOCOP_KILL, 0),
  F_B(LOCOP_REHASH, 1),
  F_B(LOCOP_RESTART, 0),
  F_B(LOCOP_DIE, 0),
  F_B(LOCOP_LGLINE, 1),
  F_B(LOCOP_LJUPE, 1),
  F_B(LOCOP_LOPMODE, 1),
  F_B(LOCOP_LBADCHAN, 0),
  F_B(LOCOP_SEE_IN_SECRET_CHANNELS, 0),

#undef F_S
#undef F_B
#undef F_I
#undef F
  { FEAT_LAST_F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

/* Given a feature's identifier, look up the feature descriptor */
static struct FeatureDesc *
feature_desc(struct Client* from, const char *feature)
{
  int i;

  assert(0 != feature);

  for (i = 0; features[i].type; i++) /* find appropriate descriptor */
    if (!ircd_strcmp(feature, features[i].type))
      return &features[i];

  Debug((DEBUG_ERROR, "Unknown feature \"%s\"", feature));
  if (from) /* report an error */
    send_reply(from, ERR_NOFEATURE, feature);
  else
    log_write(LS_CONFIG, L_ERROR, 0, "Unknown feature \"%s\"", feature);

  return 0; /* not found */
}

/* Given a feature vector string, set the value of a feature */
int
feature_set(struct Client* from, const char* const* fields, int count)
{
  int i;
  struct FeatureDesc *feat;

  if (from && !HasPriv(from, PRIV_SET))
    return send_reply(from, ERR_NOPRIVILEGES);

  if (count < 1) {
    if (from) /* report an error in the number of arguments */
      need_more_params(from, "SET");
    else
      log_write(LS_CONFIG, L_ERROR, 0, "Not enough fields in F line");
  } else if ((feat = feature_desc(from, fields[0]))) { /* find feature */
    if (feat->set && (i = (*feat->set)(from, fields + 1, count - 1))) {
      if (i > 0) /* call the set callback and do marking */
	feat->flags |= FEAT_MARK;
      else /* i < 0 */
	feat->flags &= ~FEAT_MARK;
    } else /* Ok, it's a value we can fiddle with */
      switch (feat->flags & FEAT_MASK) {
      case FEAT_INT: /* an integer value */
	if (count < 2) { /* reset value */
	  feat->v_int = feat->def_int;
	  feat->flags &= ~FEAT_MARK;
	} else { /* ok, figure out the value and whether to mark it */
	  feat->v_int = atoi(fields[1]);
	  if (feat->v_int == feat->def_int)
	    feat->flags &= ~FEAT_MARK;
	  else
	    feat->flags |= FEAT_MARK;
	}
	break;

      case FEAT_BOOL: /* it's a boolean value--true or false */
	if (count < 2) { /* reset value */
	  feat->v_int = feat->def_int;
	  feat->flags &= ~FEAT_MARK;
	} else { /* figure out the value and whether to mark it */
	  if (!ircd_strncmp(fields[1], "TRUE", strlen(fields[1])))
	    feat->v_int = 1;
	  else if (!ircd_strncmp(fields[1], "YES", strlen(fields[1])))
	    feat->v_int = 1;
	  else if (!ircd_strncmp(fields[1], "FALSE", strlen(fields[1])))
	    feat->v_int = 0;
	  else if (!ircd_strncmp(fields[1], "NO", strlen(fields[1])))
	    feat->v_int = 0;
	  else if (from) /* report an error... */
	    return send_reply(from, ERR_BADFEATVALUE, fields[1], feat->type);
	  else {
	    log_write(LS_CONFIG, L_ERROR, 0, "Bad value \"%s\" for feature %s",
		      fields[1], feat->type);
	    return 0;
	  }

	  if (feat->v_int == feat->def_int) /* figure out whether to mark it */
	    feat->flags &= ~FEAT_MARK;
	  else
	    feat->flags |= FEAT_MARK;
	}
	break;

      case FEAT_STR: /* it's a string value */
	if (count < 2 ||
	    !(feat->flags & FEAT_CASE ? strcmp(fields[1], feat->def_str) :
	      ircd_strcmp(fields[1], feat->def_str))) { /* reset to default */
	  if (feat->v_str && feat->v_str != feat->def_str)
	    MyFree(feat->v_str); /* free old value */
	  feat->v_str = feat->def_str; /* very special... */

	  feat->flags &= ~FEAT_MARK; /* unmark it */
	} else {
	  if (!*fields[1]) { /* empty string translates to NULL */
	    if (feat->flags & FEAT_NULL) { /* permitted? */
	      if (feat->v_str && feat->v_str != feat->def_str)
		MyFree(feat->v_str); /* free old value */
	      feat->v_str = 0; /* set it to NULL */
	    } else if (from) /* hmmm...not permitted; report error */
	      return send_reply(from, ERR_BADFEATVALUE, "NULL", feat->type);
	    else {
	      log_write(LS_CONFIG, L_ERROR, 0,
			"Bad value \"NULL\" for feature %s", feat->type);
	      return 0;
	    }
	  } else if ((feat->flags & FEAT_CASE ?
		      strcmp(fields[1], feat->v_str) :
		      ircd_strcmp(fields[1], feat->v_str))) { /* new value */
	    if (feat->v_str && feat->v_str != feat->def_str)
	      MyFree(feat->v_str); /* free old value */
	    DupString(feat->v_str, fields[1]); /* store new value */
	  }

	  feat->flags |= FEAT_MARK; /* mark it as having been touched */
	}
	break;
      }
  }

  return 0;
}

/* reset a feature to its default values */
int
feature_reset(struct Client* from, const char* const* fields, int count)
{
  int i;
  struct FeatureDesc *feat;

  assert(0 != from);

  if (!HasPriv(from, PRIV_SET))
    return send_reply(from, ERR_NOPRIVILEGES);

  if (count < 1) /* check arguments */
    need_more_params(from, "RESET");
  else if ((feat = feature_desc(from, fields[0]))) { /* get descriptor */
    if (feat->reset && (i = (*feat->reset)(from, fields + 1, count - 1))) {
      if (i > 0) /* call reset callback and parse mark return */
	feat->flags |= FEAT_MARK;
      else /* i < 0 */
	feat->flags &= ~FEAT_MARK;
    } else { /* oh, it's something we own... */
      switch (feat->flags & FEAT_MASK) {
      case FEAT_INT:  /* Integer... */
      case FEAT_BOOL: /* Boolean... */
	feat->v_int = feat->def_int; /* set the default */
	break;

      case FEAT_STR: /* string! */
	if (feat->v_str && feat->v_str != feat->def_str)
	  MyFree(feat->v_str); /* free old value */
	feat->v_str = feat->def_str; /* set it to default */
	break;
      }

      feat->flags &= ~FEAT_MARK; /* unmark it */
    }
  }

  return 0;
}

/* Gets the value of a specific feature and reports it to the user */
int
feature_get(struct Client* from, const char* const* fields, int count)
{
  struct FeatureDesc *feat;

  assert(0 != from);

  if (count < 1) /* check parameters */
    need_more_params(from, "GET");
  else if ((feat = feature_desc(from, fields[0]))) {
    if ((feat->flags & FEAT_MYOPER && !MyOper(from)) ||
	(feat->flags & FEAT_OPER && !IsAnOper(from))) /* check privs */
      return send_reply(from, ERR_NOPRIVILEGES);

    if (feat->get) /* if there's a callback, use it */
      (*feat->get)(from, fields + 1, count - 1);
    else /* something we own */
      switch (feat->flags & FEAT_MASK) {
      case FEAT_INT: /* integer, report integer value */
	send_reply(from, SND_EXPLICIT | RPL_FEATURE,
		   ":Integer value of %s: %d", feat->type, feat->v_int);
	break;

      case FEAT_BOOL: /* boolean, report boolean value */
	send_reply(from, SND_EXPLICIT | RPL_FEATURE,
		   ":Boolean value of %s: %s", feat->type,
		   feat->v_int ? "TRUE" : "FALSE");
	break;

      case FEAT_STR: /* string, report string value */
	if (feat->v_str) /* deal with null case */
	  send_reply(from, SND_EXPLICIT | RPL_FEATURE,
		     ":String value of %s: %s", feat->type, feat->v_str);
	else
	  send_reply(from, SND_EXPLICIT | RPL_FEATURE,
		     ":String value for %s not set", feat->type);
	break;
      }
  }

  return 0;
}

/* called before reading the .conf to clear all marks */
void
feature_unmark(void)
{
  int i;

  for (i = 0; features[i].type; i++) {
    features[i].flags &= ~FEAT_MARK; /* clear the marks... */
    if (features[i].unmark) /* call the unmark callback if necessary */
      (*features[i].unmark)();
  }
}

/* Called after reading the .conf to reset unmodified values to defaults */
void
feature_mark(void)
{
  int i;

  for (i = 0; features[i].type; i++) {
    if (!(features[i].flags & FEAT_MARK)) { /* not changed? */
      switch (features[i].flags & FEAT_MASK) {
      case FEAT_INT:  /* Integers or Booleans... */
      case FEAT_BOOL:
	features[i].v_int = features[i].def_int;
	break;

      case FEAT_STR: /* strings... */
	if (features[i].v_str && features[i].v_str != features[i].def_str)
	  MyFree(features[i].v_str); /* free old value */
	features[i].v_str = features[i].def_str;
	break;
      }
    }

    if (features[i].mark) /* call the mark callback if necessary */
      (*features[i].mark)(features[i].flags & FEAT_MARK ? 1 : 0);
  }
}

/* report all F-lines */
void
feature_report(struct Client* to)
{
  int i;

  for (i = 0; features[i].type; i++) {
    if ((features[i].flags & FEAT_MYOPER && !MyOper(to)) ||
	(features[i].flags & FEAT_OPER && !IsAnOper(to)))
      continue; /* skip this one */

    if (features[i].report) /* let the callback handle this */
      (*features[i].report)(to, features[i].flags & FEAT_MARK ? 1 : 0);
    else if (features[i].flags & FEAT_MARK) { /* it's been changed */
      switch (features[i].flags & FEAT_MASK) {
      case FEAT_INT: /* Report an F-line with integer values */
	send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "F %s %d",
		   features[i].type, features[i].v_int);
	break;

      case FEAT_BOOL: /* Report an F-line with boolean values */
	send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "F %s %s",
		   features[i].type, features[i].v_int ? "TRUE" : "FALSE");
	break;

      case FEAT_STR: /* Report an F-line with string values */
	if (features[i].v_str)
	  send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "F %s %s",
		     features[i].type, features[i].v_str);
	else /* Actually, F:<type> would reset it; you want F:<type>: */
	  send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "F %s",
		     features[i].type);
	break;
      }
    }
  }
}

/* return a feature's integer value */
int
feature_int(enum Feature feat)
{
  assert(features[feat].feat == feat);
  assert((features[feat].flags & FEAT_MASK) == FEAT_INT);

  return features[feat].v_int;
}

/* return a feature's boolean value */
int
feature_bool(enum Feature feat)
{
  assert(features[feat].feat == feat);
  assert((features[feat].flags & FEAT_MASK) == FEAT_BOOL);

  return features[feat].v_int;
}

/* return a feature's string value */
const char *
feature_str(enum Feature feat)
{
  assert(features[feat].feat == feat);
  assert((features[feat].flags & FEAT_MASK) == FEAT_STR);

  return features[feat].v_str;
}
