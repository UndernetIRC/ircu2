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
 */
/** @file
 * @brief Implementation of configurable feature support.
 */
#include "config.h"

#include "ircd_features.h"
#include "channel.h"	/* list_set_default */
#include "class.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "motd.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "random.h"	/* random_seed_set */
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "s_stats.h"
#include "send.h"
#include "struct.h"
#include "whowas.h"	/* whowas_realloc */

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

struct Client his;

#define F_I(NAME, FLAGS, DEFAULT, NOTIFY) int FEAT_ ## NAME = DEFAULT;
#define F_U(NAME, FLAGS, DEFAULT, NOTIFY) unsigned int FEAT_ ## NAME = DEFAULT;
#define F_B(NAME, FLAGS, DEFAULT, NOTIFY) int FEAT_ ## NAME = DEFAULT;
#define F_S(NAME, FLAGS, DEFAULT, NOTIFY) const char *FEAT_ ## NAME = DEFAULT;
#define F_A(NAME, REAL_NAME)
#include "ircd_features.inc"

/** List of log output types that can be set */
static struct LogTypes {
  char *type; /**< Settable name. */
  int (*set)(const char *, const char *); /**< Function to set the value. */
  char *(*get)(const char *); /**< Function to get the value. */
} logTypes[] = {
  { "FILE", log_set_file, log_get_file },
  { "FACILITY", log_set_facility, log_get_facility },
  { "SNOMASK", log_set_snomask, log_get_snomask },
  { "LEVEL", log_set_level, log_get_level },
  { 0, 0, 0 }
};

/** Look up a struct LogType given the type string.
 * @param[in] from &Client requesting type, or NULL.
 * @param[in] type Name of log type to find.
 * @return Pointer to the found LogType, or NULL if none was found.
 */
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

/** Set the value of a log output type for a log subsystem.
 * @param[in] from &Client trying to set the log type, or NULL.
 * @param[in] fields Array of parameters to set.
 * @param[in] count Number of parameters in \a fields.
 * @return -1 to clear the mark, 0 to leave the mask alone, 1 to set the mask.
 */
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

/** Reset a log type for a subsystem to its default value.
 * @param[in] from &Client trying to reset the subsystem.
 * @param[in] fields Array of parameters to reset.
 * @param[in] count Number of fields in \a fields.
 * @return -1 to unmark the entry, or zero to leave it alone.
 */
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

/** Handle an update to FEAT_HIS_SERVERNAME. */
static void
feature_notify_servername(void)
{
  ircd_strncpy(cli_name(&his), feature_str(FEAT_HIS_SERVERNAME), HOSTLEN);
}

/** Handle an update to FEAT_HIS_SERVERINFO. */
static void
feature_notify_serverinfo(void)
{
  ircd_strncpy(cli_info(&his), feature_str(FEAT_HIS_SERVERINFO), REALLEN);
}

/** Report the value of a log setting.
 * @param[in] from &Client asking for details.
 * @param[in] fields Array of parameters to get.
 * @param[in] count Number of fields in \a fields.
 */
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

static void
set_isupport_maxsiles(void)
{
    add_isupport_i("SILENCE", feature_int(FEAT_MAXSILES));
}

static void
set_isupport_maxchannels(void)
{
    add_isupport_i("MAXCHANNELS", feature_uint(FEAT_MAXCHANNELSPERUSER));
}

static void
set_isupport_maxbans(void)
{
    add_isupport_i("MAXBANS", feature_int(FEAT_MAXBANS));
}

static void
set_isupport_nicklen(void)
{
    add_isupport_i("NICKLEN", feature_uint(FEAT_NICKLEN));
}

static void
set_isupport_channellen(void)
{
    add_isupport_i("CHANNELLEN", feature_uint(FEAT_CHANNELLEN));
}

static void
set_isupport_chantypes(void)
{
    add_isupport_s("CHANTYPES", feature_bool(FEAT_LOCAL_CHANNELS) ? "#&" : "#");
}

static void
set_isupport_chanmodes(void)
{
    add_isupport_s("CHANMODES", feature_bool(FEAT_OPLEVELS) ? "b,AkU,l,imnpstrDdR" : "b,k,l,imnpstrDdR");
}

static void
set_isupport_network(void)
{
    add_isupport_s("NETWORK", feature_str(FEAT_NETWORK));
}

/** Update whether #me is a hub or not.
 */
static void
feature_notify_hub(void)
{
  if (feature_bool(FEAT_HUB))
    SetHub(&me);
  else
    ClearHub(&me);
}

/** Sets a feature to the given value.
 * @param[in] from Client trying to set parameters.
 * @param[in] fields Array of parameters to set.
 * @param[in] count Number of fields in \a count.
 * @return <0 to clear the feature mark, 0 to leave it, >0 to set the feature mark.
 */
typedef int  (*feat_set_call)(struct Client* from, const char* const* fields, int count);
/** Gets the value of a feature.
 * @param[in] from Client trying to get parameters.
 * @param[in] fields Array of parameters to set.
 * @param[in] count Number of fields in \a count.
 */
typedef void (*feat_get_call)(struct Client* from, const char* const* fields, int count);
/** Callback to notify of a feature's change. */
typedef void (*feat_notify_call)(void);
/** Unmarks all sub-feature values prior to reading .conf. */
typedef void (*feat_unmark_call)(void);
/** Resets to defaults all currently unmarked values.
 * @param[in] marked Non-zero if the feature is marked.
 */
typedef int  (*feat_mark_call)(int marked);
/* Reports features as a /stats f list.
 * @param[in] sptr Client asking for feature list.
 * @param[in] marked Non-zero if the feature is marked.
 */
typedef void (*feat_report_call)(struct Client* sptr, int marked);

#define FEAT_NONE   0x0000	/**< no value */
#define FEAT_INT    0x0001	/**< set if entry contains an integer value */
#define FEAT_BOOL   0x0002	/**< set if entry contains a boolean value */
#define FEAT_STR    0x0003	/**< set if entry contains a string value */
#define FEAT_ALIAS  0x0004	/**< set if entry is alias for another entry */
#define FEAT_UINT   0x0006	/**< set if entry contains an unsigned value */
#define FEAT_MASK   0x000f	/**< possible value types */

/** Extract just the feature type from a feature descriptor. */
#define feat_type(feat)		((feat)->flags & FEAT_MASK)

#define FEAT_MARK   0x0010	/**< set if entry has been changed */
#define FEAT_NULL   0x0020	/**< NULL string is permitted */
#define FEAT_CASE   0x0040	/**< string is case-sensitive */

#define FEAT_OPER   0x0100	/**< set to display only to opers */
#define FEAT_MYOPER 0x0200	/**< set to display only to local opers */
#define FEAT_NODISP 0x0400	/**< feature must never be displayed */

#define FEAT_READ   0x1000	/**< feature is read-only (for now, perhaps?) */

/** Declare a feature with custom behavior. */
#define F_N(type, flags, set, reset, get, notify, unmark, mark, report)	      \
  { NULL, #type, FEAT_NONE | (flags), 0, 0, 				      \
    (set), (reset), (get), (notify), (unmark), (mark), (report) },
/** Declare a feature that takes integer values. */
#define F_I(type, flags, v_int, notify)					      \
  { &FEAT_ ## type, #type, FEAT_INT | (flags), (v_int), 0,	      \
    0, 0, 0, (notify), 0, 0, 0 },
/** Declare a feature that takes unsigned integer values. */
#define F_U(type, flags, v_uint, notify)				      \
  { &FEAT_ ## type, #type, FEAT_UINT | (flags), (v_uint), 0,	      \
    0, 0, 0, (notify), 0, 0, 0 },
/** Declare a feature that takes boolean values. */
#define F_B(type, flags, v_int, notify)					      \
  { &FEAT_ ## type, #type, FEAT_BOOL | (flags), (v_int), 0,	      \
    0, 0, 0, (notify), 0, 0, 0 },
/** Declare a feature that takes string values. */
#define F_S(type, flags, v_str, notify)					      \
  { &FEAT_ ## type, #type, FEAT_STR | (flags), 0, (v_str),	      \
    0, 0, 0, (notify), 0, 0, 0 },
/** Declare a feature as an alias for another feature. */
#define F_A(type, alias)						      \
  { NULL, #type, FEAT_ALIAS, 0, #alias,				      \
    0, 0, 0, 0, 0, 0, 0 },

/** Table of feature descriptions. */
static struct FeatureDesc {
  void*            var;     /**< pointer to variable holding the value */
  char*		   type;    /**< unprefixed name of the feature */
  unsigned int     flags;   /**< flags for feature */
  int		   def_int; /**< default value */
  char*		   def_str; /**< default value */
  feat_set_call	   set;	    /**< set feature values */
  feat_set_call	   reset;   /**< reset feature values to defaults */
  feat_get_call	   get;	    /**< get feature values */
  feat_notify_call notify;  /**< notify of value change */
  feat_unmark_call unmark;  /**< unmark all feature change values */
  feat_mark_call   mark;    /**< reset to defaults all unchanged features */
  feat_report_call report;  /**< report feature values */
} features[] = {
  /* Misc. features */
  F_N(LOG, FEAT_MYOPER, feature_log_set, feature_log_reset, feature_log_get,
      0, log_feature_unmark, log_feature_mark, log_feature_report)
  F_N(RANDOM_SEED, FEAT_NODISP, random_seed_set, 0, 0, 0, 0, 0, 0)
#include "ircd_features.inc"
  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

#define N_FEATURES (sizeof(features) / sizeof(features[0]) - 1)

static int
feature_cmp(const void *v_a, const void *v_b)
{
  const struct FeatureDesc *a = v_a, *b = v_b;
  return strcmp(a->type, b->type);
}

static int
feature_find(const void *v_key, const void *v_feat)
{
  const char *key = v_key;
  const struct FeatureDesc *feat = v_feat;
  return strcmp(key, feat->type);
}

/** Given a feature's identifier, look up the feature descriptor.
 * @param[in] from Client looking up feature, or NULL.
 * @param[in] feature Feature name to find.
 * @return Pointer to a FeatureDesc, or NULL if none was found.
 */
static struct FeatureDesc *
feature_desc(struct Client* from, const char *feature)
{
  static int sorted;
  struct FeatureDesc *feat;
  int i;

  assert(0 != feature);

  if (!sorted) {
    qsort(features, N_FEATURES, sizeof(features[0]), feature_cmp);
    sorted = 1;
  }

  feat = bsearch(feature, features, N_FEATURES, sizeof(features[0]),
    feature_find);
  if (feat) {
      if (feat_type(feat) == FEAT_ALIAS) {
	Debug((DEBUG_NOTICE, "Deprecated feature \"%s\" referenced; replace "
	       "with %s", feature, feat->def_str));
	if (from) /* report a warning */
	  send_reply(from, SND_EXPLICIT | ERR_NOFEATURE,
		     "%s :Feature deprecated, use %s", feature,
		     feat->def_str);
	else
	  log_write(LS_CONFIG, L_WARNING, 0, "Feature \"%s\" deprecated, "
		    "use \"%s\"", feature, feat->def_str);

	return feature_desc(from, feat->def_str);
      }
      return feat;
    }

  Debug((DEBUG_ERROR, "Unknown feature \"%s\"", feature));
  if (from) /* report an error */
    send_reply(from, ERR_NOFEATURE, feature);
  else
    log_write(LS_CONFIG, L_ERROR, 0, "Unknown feature \"%s\"", feature);

  return 0; /* not found */
}

/** Given a feature vector string, set the value of a feature.
 * @param[in] from Client trying to set the feature, or NULL.
 * @param[in] fields Parameters to set, starting with feature name.
 * @param[in] count Number of fields in \a fields.
 * @return Zero (or, theoretically, CPTR_KILLED).
 */
int
feature_set(struct Client* from, const char* const* fields, int count)
{
  int i, change = 0, tmp, new_int;
  const char *t_str;
  char **p_str;
  struct FeatureDesc *feat;

  if (from && !HasPriv(from, PRIV_SET))
    return send_reply(from, ERR_NOPRIVILEGES);

  if (count < 1) {
    if (from) /* report an error in the number of arguments */
      need_more_params(from, "SET");
    else
      log_write(LS_CONFIG, L_ERROR, 0, "Not enough fields in F line");
  } else if ((feat = feature_desc(from, fields[0]))) { /* find feature */
    if (from && feat->flags & FEAT_READ)
      return send_reply(from, ERR_NOFEATURE, fields[0]);

    switch (feat_type(feat)) {
    case FEAT_NONE:
      if (feat->set && (i = (*feat->set)(from, fields + 1, count - 1))) {
	change++; /* feature handler wants a change recorded */

	if (i > 0) /* call the set callback and do marking */
	  feat->flags |= FEAT_MARK;
	else /* i < 0 */
	  feat->flags &= ~FEAT_MARK;
      }
      break;

    case FEAT_UINT: /* an unsigned integer value */
    case FEAT_INT: /* an integer value */
      tmp = *(int *)feat->var; /* detect changes... */

      if (count < 2) { /* reset value */
	new_int = feat->def_int;
	feat->flags &= ~FEAT_MARK;
      } else { /* ok, figure out the value and whether to mark it */
	new_int = strtoul(fields[1], 0, 0);
	if (new_int == feat->def_int)
	  feat->flags &= ~FEAT_MARK;
	else
	  feat->flags |= FEAT_MARK;
      }

      *(int *)feat->var = new_int;
      if (new_int != tmp) /* check for change */
	change++;
      break;

    case FEAT_BOOL: /* it's a boolean value--true or false */
      tmp = *(int *)feat->var; /* detect changes... */

      if (count < 2) { /* reset value */
	new_int = feat->def_int;
	feat->flags &= ~FEAT_MARK;
      } else { /* figure out the value and whether to mark it */
	if (!ircd_strncmp(fields[1], "TRUE", strlen(fields[1])) ||
	    !ircd_strncmp(fields[1], "YES", strlen(fields[1])) ||
	    (strlen(fields[1]) >= 2 &&
	     !ircd_strncmp(fields[1], "ON", strlen(fields[1]))))
	  new_int = 1;
	else if (!ircd_strncmp(fields[1], "FALSE", strlen(fields[1])) ||
		 !ircd_strncmp(fields[1], "NO", strlen(fields[1])) ||
		 (strlen(fields[1]) >= 2 &&
		  !ircd_strncmp(fields[1], "OFF", strlen(fields[1]))))
	  new_int = 0;
	else if (from) /* report an error... */
	  return send_reply(from, ERR_BADFEATVALUE, fields[1], feat->type);
	else {
	  log_write(LS_CONFIG, L_ERROR, 0, "Bad value \"%s\" for feature %s",
		    fields[1], feat->type);
	  return 0;
	}

	if (new_int == feat->def_int) /* figure out whether to mark it */
	  feat->flags &= ~FEAT_MARK;
	else
	  feat->flags |= FEAT_MARK;
      }

      *(int *)feat->var = new_int;
      if (new_int != tmp) /* check for change */
	change++;
      break;

    case FEAT_STR: /* it's a string value */
      if (count < 2)
	t_str = feat->def_str; /* changing to default */
      else
	t_str = *fields[1] ? fields[1] : 0;

      if (!t_str && !(feat->flags & FEAT_NULL)) { /* NULL value permitted? */
	if (from)
	  return send_reply(from, ERR_BADFEATVALUE, "NULL", feat->type);
	else {
	  log_write(LS_CONFIG, L_ERROR, 0, "Bad value \"NULL\" for feature %s",
		    feat->type);
	  return 0;
	}
      }

      p_str = (char **)feat->var;
      if (t_str == feat->def_str ||
	  (t_str && feat->def_str &&
	   !(feat->flags & FEAT_CASE ? strcmp(t_str, feat->def_str) :
	     ircd_strcmp(t_str, feat->def_str)))) { /* resetting to default */
	if (*p_str != feat->def_str) {
	  change++; /* change from previous value */

	  if (*p_str)
	    MyFree(*p_str); /* free old value */
	}

	*p_str = feat->def_str; /* very special... */

	feat->flags &= ~FEAT_MARK;
      } else if (!t_str) {
	if (*p_str) {
	  change++; /* change from previous value */

	  if (*p_str != feat->def_str)
	    MyFree(*p_str); /* free old value */
	}

	*p_str = 0; /* set it to NULL */

	feat->flags |= FEAT_MARK;
      } else if (!*p_str ||
		 (feat->flags & FEAT_CASE ? strcmp(t_str, *p_str) :
		  ircd_strcmp(t_str, *p_str))) { /* new value */
	change++; /* change from previous value */

	if (*p_str && *p_str != feat->def_str)
	  MyFree(*p_str); /* free old value */
	DupString(*p_str, t_str); /* store new value */

	feat->flags |= FEAT_MARK;
      } else /* they match, but don't match the default */
	feat->flags |= FEAT_MARK;
      break;
    }

    if (change && feat->notify) /* call change notify function */
      (*feat->notify)();

    if (from)
      return feature_get(from, fields, count);
  }

  return 0;
}

/** Reset a feature to its default values.
 * @param[in] from Client trying to reset the feature, or NULL.
 * @param[in] fields Parameters to set, starting with feature name.
 * @param[in] count Number of fields in \a fields.
 * @return Zero (or, theoretically, CPTR_KILLED).
 */
int
feature_reset(struct Client* from, const char* const* fields, int count)
{
  int i, change = 0;
  struct FeatureDesc *feat;

  assert(0 != from);

  if (!HasPriv(from, PRIV_SET))
    return send_reply(from, ERR_NOPRIVILEGES);

  if (count < 1) /* check arguments */
    need_more_params(from, "RESET");
  else if ((feat = feature_desc(from, fields[0]))) { /* get descriptor */
    if (from && feat->flags & FEAT_READ)
      return send_reply(from, ERR_NOFEATURE, fields[0]);

    switch (feat_type(feat)) {
    case FEAT_NONE: /* None... */
      if (feat->reset && (i = (*feat->reset)(from, fields + 1, count - 1))) {
	change++; /* feature handler wants a change recorded */

	if (i > 0) /* call reset callback and parse mark return */
	  feat->flags |= FEAT_MARK;
	else /* i < 0 */
	  feat->flags &= ~FEAT_MARK;
      }
      break;

    case FEAT_UINT: /* Unsigned... */
    case FEAT_INT:  /* Integer... */
    case FEAT_BOOL: /* Boolean... */
      if (*(int *)feat->var != feat->def_int)
	change++; /* change will be made */

      *(int *)feat->var = feat->def_int; /* set the default */
      feat->flags &= ~FEAT_MARK; /* unmark it */
      break;

    case FEAT_STR: /* string! */
      if (*(char **)feat->var != feat->def_str) {
	change++; /* change has been made */
	if (*(char **)feat->var)
	  MyFree(*(char **)feat->var); /* free old value */
      }

      *(char **)feat->var = feat->def_str; /* set it to default */
      feat->flags &= ~FEAT_MARK; /* unmark it */
      break;
    }

    if (change && feat->notify) /* call change notify function */
      (*feat->notify)();

    if (from)
      return feature_get(from, fields, count);
  }

  return 0;
}

/** Gets the value of a specific feature and reports it to the user.
 * @param[in] from Client trying to get the feature.
 * @param[in] fields Parameters to set, starting with feature name.
 * @param[in] count Number of fields in \a fields.
 * @return Zero (or, theoretically, CPTR_KILLED).
 */
int
feature_get(struct Client* from, const char* const* fields, int count)
{
  struct FeatureDesc *feat;

  assert(0 != from);

  if (count < 1) /* check parameters */
    need_more_params(from, "GET");
  else if ((feat = feature_desc(from, fields[0]))) {
    if ((feat->flags & FEAT_NODISP) ||
	(feat->flags & FEAT_MYOPER && !MyOper(from)) ||
	(feat->flags & FEAT_OPER && !IsAnOper(from))) /* check privs */
      return send_reply(from, ERR_NOPRIVILEGES);

    switch (feat_type(feat)) {
    case FEAT_NONE: /* none, call the callback... */
      if (feat->get) /* if there's a callback, use it */
	(*feat->get)(from, fields + 1, count - 1);
      break;

    case FEAT_INT: /* integer, report integer value */
      send_reply(from, SND_EXPLICIT | RPL_FEATURE,
		 ":Integer value of %s: %d", feat->type,
		 *(int *)feat->var);
      break;

    case FEAT_UINT: /* unsigned integer, report its value */
      send_reply(from, SND_EXPLICIT | RPL_FEATURE,
		 ":Unsigned value of %s: %u", feat->type,
		 *(int *)feat->var);
      break;

    case FEAT_BOOL: /* boolean, report boolean value */
      send_reply(from, SND_EXPLICIT | RPL_FEATURE,
		 ":Boolean value of %s: %s", feat->type,
		 *(int *)feat->var ? "TRUE" : "FALSE");
      break;

    case FEAT_STR: /* string, report string value */
      if (*(char **)feat->var) /* deal with null case */
	send_reply(from, SND_EXPLICIT | RPL_FEATURE,
		   ":String value of %s: %s", feat->type,
		   *(char **)feat->var);
      else
	send_reply(from, SND_EXPLICIT | RPL_FEATURE,
		   ":String value for %s not set", feat->type);
      break;
    }
  }

  return 0;
}

/** Called before reading the .conf to clear all dirty marks. */
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

/** Called after reading the .conf to reset unmodified values to defaults. */
void
feature_mark(void)
{
  int i, change;

  for (i = 0; features[i].type; i++) {
    change = 0;

    switch (feat_type(&features[i])) {
    case FEAT_NONE:
      if (features[i].mark &&
	  (*features[i].mark)(features[i].flags & FEAT_MARK ? 1 : 0))
	change++; /* feature handler wants a change recorded */
      break;

    case FEAT_INT:  /* Integers or Booleans... */
    case FEAT_UINT:
    case FEAT_BOOL:
      if (!(features[i].flags & FEAT_MARK)) { /* not changed? */
        int *p_int = features[i].var;
	if (*p_int != features[i].def_int)
	  change++; /* we're making a change */
	*p_int = features[i].def_int;
      }
      break;

    case FEAT_STR: /* strings... */
      if (!(features[i].flags & FEAT_MARK)) { /* not changed? */
        char **p_str = features[i].var;
	if (*p_str != features[i].def_str) {
	  change++; /* we're making a change */
	  if (*p_str)
	    MyFree(*p_str); /* free old value */
	}
	*p_str = features[i].def_str;
      }
      break;
    }

    if (change && features[i].notify)
      (*features[i].notify)(); /* call change notify function */
  }
}

/** Initialize the features subsystem. */
void
feature_init(void)
{
  int i;

  for (i = 0; features[i].type; i++) {
    struct FeatureDesc *feat = &features[i];

    switch (feat_type(feat)) {
    case FEAT_NONE: /* you're on your own */
    case FEAT_INT:  /* Integers or Booleans... */
    case FEAT_UINT:
    case FEAT_BOOL:
      break;

    case FEAT_STR:  /* Strings */
      assert(feat->def_str || (feat->flags & FEAT_NULL));
      break;
    }

    if (feat->notify)
      (*feat->notify)();
  }

  cli_magic(&his) = CLIENT_MAGIC;
  cli_status(&his) = STAT_SERVER;
}

/** Report all F-lines to a user.
 * @param[in] to Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
void
feature_report(struct Client* to, const struct StatDesc* sd, char* param)
{
  char changed;
  int report;
  int i;

  for (i = 0; features[i].type; i++) {
    if ((features[i].flags & FEAT_NODISP) ||
	(features[i].flags & FEAT_MYOPER && !MyOper(to)) ||
	(features[i].flags & FEAT_OPER && !IsAnOper(to)))
      continue; /* skip this one */

    changed = (features[i].flags & FEAT_MARK) ? 'F' : 'f';
    report = (features[i].flags & FEAT_MARK) || sd->sd_funcdata;

    switch (features[i].flags & FEAT_MASK) {
    case FEAT_NONE:
      if (features[i].report) /* let the callback handle this */
	(*features[i].report)(to, report);
      break;


    case FEAT_INT: /* Report an F-line with integer values */
      if (report) /* it's been changed */
	send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "%c %s %d",
		   changed, features[i].type, *(int *)features[i].var);
      break;

    case FEAT_UINT: /* Report an F-line with unsigned values */
      if (features[i].flags & FEAT_MARK) /* it's been changed */
	send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "F %s %u",
		   features[i].type, *(int *)features[i].var);
      break;

    case FEAT_BOOL: /* Report an F-line with boolean values */
      if (report) /* it's been changed */
	send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "%c %s %s",
		   changed, features[i].type,
		   *(int *)features[i].var ? "TRUE" : "FALSE");
      break;

    case FEAT_STR: /* Report an F-line with string values */
      if (report) { /* it's been changed */
	if (*(char **)features[i].var)
	  send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "%c %s %s",
		     changed, features[i].type,
		     *(char **)features[i].var);
	else /* Actually, F:<type> would reset it; you want F:<type>: */
	  send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "%c %s",
		     changed, features[i].type);
      }
      break;
    }
  }
}
