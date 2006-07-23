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
 * @version $Id$
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
#include "send.h"
#include "struct.h"
#include "whowas.h"	/* whowas_realloc */

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

struct Client his;

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
    add_isupport_i("MAXCHANNELS", feature_int(FEAT_MAXCHANNELSPERUSER));
}

static void
set_isupport_maxbans(void)
{
    add_isupport_i("MAXBANS", feature_int(FEAT_MAXBANS));
}

static void
set_isupport_nicklen(void)
{
    add_isupport_i("NICKLEN", feature_int(FEAT_NICKLEN));
}

static void
set_isupport_channellen(void)
{
    add_isupport_i("CHANNELLEN", feature_int(FEAT_CHANNELLEN));
}

static void
set_isupport_chantypes(void)
{
    add_isupport_s("CHANTYPES", feature_bool(FEAT_LOCAL_CHANNELS) ? "#&" : "#");
}

static void
set_isupport_chanmodes(void)
{
    add_isupport_s("CHANMODES", feature_bool(FEAT_OPLEVELS) ? "b,AkU,l,imnpstrDd" : "b,k,l,imnpstrDd");
}

static void
set_isupport_network(void)
{
    add_isupport_s("NETWORK", feature_str(FEAT_NETWORK));
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
#define FEAT_DEP    0x0005	/**< set if entry is deprecated feature */
#define FEAT_MASK   0x000f	/**< possible value types */

/** Extract just the feature type from a feature descriptor. */
#define feat_type(feat)		((feat)->flags & FEAT_MASK)

#define FEAT_MARK   0x0010	/**< set if entry has been changed */
#define FEAT_NULL   0x0020	/**< NULL string is permitted */
#define FEAT_CASE   0x0040	/**< string is case-sensitive */

#define FEAT_OPER   0x0100	/**< set to display only to opers */
#define FEAT_MYOPER 0x0200	/**< set to display only to local opers */
#define FEAT_NODISP 0x0400	/**< feature must never be displayed */
#define FEAT_NOINIT 0x0800      /**< notifier should not be called at init */

#define FEAT_READ   0x1000	/**< feature is read-only (for now, perhaps?) */

/** Declare a feature with custom behavior. */
#define F_N(type, flags, set, reset, get, notify, unmark, mark, report)	      \
  { FEAT_ ## type, #type, FEAT_NONE | (flags), 0, 0, 0, 0,		      \
    (set), (reset), (get), (notify), (unmark), (mark), (report) }
/** Declare a feature that takes integer values. */
#define F_I(type, flags, v_int, notify)					      \
  { FEAT_ ## type, #type, FEAT_INT | (flags), 0, (v_int), 0, 0,		      \
    0, 0, 0, (notify), 0, 0, 0 }
/** Declare a feature that takes boolean values. */
#define F_B(type, flags, v_int, notify)					      \
  { FEAT_ ## type, #type, FEAT_BOOL | (flags), 0, (v_int), 0, 0,	      \
    0, 0, 0, (notify), 0, 0, 0 }
/** Declare a feature that takes string values. */
#define F_S(type, flags, v_str, notify)					      \
  { FEAT_ ## type, #type, FEAT_STR | (flags), 0, 0, 0, (v_str),		      \
    0, 0, 0, (notify), 0, 0, 0 }
/** Declare a feature as an alias for another feature. */
#define F_A(type, alias)						      \
  { FEAT_ ## type, #type, FEAT_ALIAS, 0, FEAT_ ## alias, 0, 0,		      \
    0, 0, 0, 0, 0, 0, 0 }
/** Declare a feature as deprecated. */
#define F_D(type)							      \
  { FEAT_ ## type, #type, FEAT_DEP, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }

/** Table of feature descriptions. */
static struct FeatureDesc {
  enum Feature	   feat;    /**< feature identifier */
  char*		   type;    /**< string describing type */
  unsigned int     flags;   /**< flags for feature */
  int		   v_int;   /**< integer value */
  int		   def_int; /**< default value */
  char*		   v_str;   /**< string value */
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
      0, log_feature_unmark, log_feature_mark, log_feature_report),
  F_S(DOMAINNAME, 0, DOMAINNAME, 0),
  F_B(RELIABLE_CLOCK, 0, 0, 0),
  F_I(BUFFERPOOL, 0, 27000000, 0),
  F_B(HAS_FERGUSON_FLUSHER, 0, 0, 0),
  F_I(CLIENT_FLOOD, 0, 1024, 0),
  F_I(SERVER_PORT, FEAT_OPER, 4400, 0),
  F_B(NODEFAULTMOTD, 0, 1, 0),
  F_S(MOTD_BANNER, FEAT_NULL, 0, 0),
  F_S(PROVIDER, FEAT_NULL, 0, 0),
  F_B(KILL_IPMISMATCH, FEAT_OPER, 0, 0),
  F_B(IDLE_FROM_MSG, 0, 1, 0),
  F_B(HUB, 0, 0, 0),
  F_B(WALLOPS_OPER_ONLY, 0, 0, 0),
  F_B(NODNS, 0, 0, 0),
  F_B(NOIDENT, 0, 0, 0),
  F_N(RANDOM_SEED, FEAT_NODISP, random_seed_set, 0, 0, 0, 0, 0, 0),
  F_S(DEFAULT_LIST_PARAM, FEAT_NULL, 0, list_set_default),
  F_I(NICKNAMEHISTORYLENGTH, 0, 800, whowas_realloc),
  F_B(HOST_HIDING, 0, 1, 0),
  F_S(HIDDEN_HOST, FEAT_CASE, "users.undernet.org", 0),
  F_S(HIDDEN_IP, 0, "127.0.0.1", 0),
  F_B(CONNEXIT_NOTICES, 0, 0, 0),
  F_B(OPLEVELS, 0, 1, set_isupport_chanmodes),
  F_B(ZANNELS, 0, 1, 0),
  F_B(LOCAL_CHANNELS, 0, 1, set_isupport_chantypes),
  F_B(TOPIC_BURST, 0, 0, 0),
  F_B(USER_GLIST, 0, 1, 0),

  /* features that probably should not be touched */
  F_I(KILLCHASETIMELIMIT, 0, 30, 0),
  F_I(MAXCHANNELSPERUSER, 0, 10, set_isupport_maxchannels),
  F_I(NICKLEN, 0, 12, set_isupport_nicklen),
  F_I(AVBANLEN, 0, 40, 0),
  F_I(MAXBANS, 0, 45, set_isupport_maxbans),
  F_I(MAXSILES, 0, 15, set_isupport_maxsiles),
  F_I(HANGONGOODLINK, 0, 300, 0),
  F_I(HANGONRETRYDELAY, 0, 10, 0),
  F_I(CONNECTTIMEOUT, 0, 90, 0),
  F_I(MAXIMUM_LINKS, 0, 1, init_class), /* reinit class 0 as needed */
  F_I(PINGFREQUENCY, 0, 120, init_class),
  F_I(CONNECTFREQUENCY, 0, 600, init_class),
  F_I(DEFAULTMAXSENDQLENGTH, 0, 40000, init_class),
  F_I(GLINEMAXUSERCOUNT, 0, 20, 0),
  F_I(SOCKSENDBUF, 0, SERVER_TCP_WINDOW, 0),
  F_I(SOCKRECVBUF, 0, SERVER_TCP_WINDOW, 0),
  F_I(IPCHECK_CLONE_LIMIT, 0, 4, 0),
  F_I(IPCHECK_CLONE_PERIOD, 0, 40, 0),
  F_I(IPCHECK_CLONE_DELAY, 0, 600, 0),
  F_I(CHANNELLEN, 0, 200, set_isupport_channellen),

  /* Some misc. default paths */
  F_S(MPATH, FEAT_CASE | FEAT_MYOPER, "ircd.motd", motd_init),
  F_S(RPATH, FEAT_CASE | FEAT_MYOPER | FEAT_NOINIT, "remote.motd", motd_init),
  F_S(PPATH, FEAT_CASE | FEAT_MYOPER | FEAT_READ, "ircd.pid", 0),

  /* Networking features */
  F_I(TOS_SERVER, 0, 0x08, 0),
  F_I(TOS_CLIENT, 0, 0x08, 0),
  F_I(POLLS_PER_LOOP, 0, 200, 0),
  F_I(IRCD_RES_RETRIES, 0, 2, 0),
  F_I(IRCD_RES_TIMEOUT, 0, 4, 0),
  F_I(AUTH_TIMEOUT, 0, 9, 0),
  F_B(ANNOUNCE_INVITES, 0, 0, 0),

  /* features that affect all operators */
  F_B(CONFIG_OPERCMDS, 0, 0, 0),

  /* HEAD_IN_SAND Features */
  F_B(HIS_SNOTICES, 0, 1, 0),
  F_B(HIS_SNOTICES_OPER_ONLY, 0, 1, 0),
  F_B(HIS_DEBUG_OPER_ONLY, 0, 1, 0),
  F_B(HIS_WALLOPS, 0, 1, 0),
  F_B(HIS_MAP, 0, 1, 0),
  F_B(HIS_LINKS, 0, 1, 0),
  F_B(HIS_TRACE, 0, 1, 0),
  F_A(HIS_STATS_a, HIS_STATS_NAMESERVERS),
  F_B(HIS_STATS_NAMESERVERS, 0, 1, 0),
  F_A(HIS_STATS_c, HIS_STATS_CONNECT),
  F_B(HIS_STATS_CONNECT, 0, 1, 0),
  F_A(HIS_STATS_d, HIS_STATS_CRULES),
  F_B(HIS_STATS_CRULES, 0, 1, 0),
  F_A(HIS_STATS_e, HIS_STATS_ENGINE),
  F_B(HIS_STATS_ENGINE, 0, 1, 0),
  F_A(HIS_STATS_f, HIS_STATS_FEATURES),
  F_B(HIS_STATS_FEATURES, 0, 1, 0),
  F_A(HIS_STATS_g, HIS_STATS_GLINES),
  F_B(HIS_STATS_GLINES, 0, 1, 0),
  F_A(HIS_STATS_i, HIS_STATS_ACCESS),
  F_B(HIS_STATS_ACCESS, 0, 1, 0),
  F_A(HIS_STATS_j, HIS_STATS_HISTOGRAM),
  F_B(HIS_STATS_HISTOGRAM, 0, 1, 0),
  F_A(HIS_STATS_J, HIS_STATS_JUPES),
  F_B(HIS_STATS_JUPES, 0, 1, 0),
  F_A(HIS_STATS_k, HIS_STATS_KLINES),
  F_B(HIS_STATS_KLINES, 0, 1, 0),
  F_A(HIS_STATS_l, HIS_STATS_LINKS),
  F_B(HIS_STATS_LINKS, 0, 1, 0),
  F_A(HIS_STATS_L, HIS_STATS_MODULES),
  F_B(HIS_STATS_MODULES, 0, 1, 0),
  F_A(HIS_STATS_m, HIS_STATS_COMMANDS),
  F_B(HIS_STATS_COMMANDS, 0, 1, 0),
  F_A(HIS_STATS_o, HIS_STATS_OPERATORS),
  F_B(HIS_STATS_OPERATORS, 0, 1, 0),
  F_A(HIS_STATS_p, HIS_STATS_PORTS),
  F_B(HIS_STATS_PORTS, 0, 1, 0),
  F_A(HIS_STATS_q, HIS_STATS_QUARANTINES),
  F_B(HIS_STATS_QUARANTINES, 0, 1, 0),
  F_A(HIS_STATS_R, HIS_STATS_MAPPINGS),
  F_B(HIS_STATS_MAPPINGS, 0, 1, 0),
  F_A(HIS_STATS_r, HIS_STATS_USAGE),
  F_B(HIS_STATS_USAGE, 0, 1, 0),
  F_A(HIS_STATS_t, HIS_STATS_LOCALS),
  F_B(HIS_STATS_LOCALS, 0, 1, 0),
  F_A(HIS_STATS_T, HIS_STATS_MOTDS),
  F_B(HIS_STATS_MOTDS, 0, 1, 0),
  F_A(HIS_STATS_u, HIS_STATS_UPTIME),
  F_B(HIS_STATS_UPTIME, 0, 0, 0),
  F_A(HIS_STATS_U, HIS_STATS_UWORLD),
  F_B(HIS_STATS_UWORLD, 0, 1, 0),
  F_A(HIS_STATS_v, HIS_STATS_VSERVERS),
  F_B(HIS_STATS_VSERVERS, 0, 1, 0),
  F_A(HIS_STATS_w, HIS_STATS_USERLOAD),
  F_B(HIS_STATS_USERLOAD, 0, 0, 0),
  F_A(HIS_STATS_x, HIS_STATS_MEMUSAGE),
  F_B(HIS_STATS_MEMUSAGE, 0, 1, 0),
  F_A(HIS_STATS_y, HIS_STATS_CLASSES),
  F_B(HIS_STATS_CLASSES, 0, 1, 0),
  F_A(HIS_STATS_z, HIS_STATS_MEMORY),
  F_B(HIS_STATS_MEMORY, 0, 1, 0),
  F_B(HIS_STATS_IAUTH, 0, 1, 0),
  F_B(HIS_WHOIS_SERVERNAME, 0, 1, 0),
  F_B(HIS_WHOIS_IDLETIME, 0, 1, 0),
  F_B(HIS_WHOIS_LOCALCHAN, 0, 1, 0),
  F_B(HIS_WHO_SERVERNAME, 0, 1, 0),
  F_B(HIS_WHO_HOPCOUNT, 0, 1, 0),
  F_B(HIS_MODEWHO, 0, 1, 0),
  F_B(HIS_BANWHO, 0, 1, 0),
  F_B(HIS_KILLWHO, 0, 1, 0),
  F_B(HIS_REWRITE, 0, 1, 0),
  F_I(HIS_REMOTE, 0, 1, 0),
  F_B(HIS_NETSPLIT, 0, 1, 0),
  F_S(HIS_SERVERNAME, 0, "*.undernet.org", feature_notify_servername),
  F_S(HIS_SERVERINFO, 0, "The Undernet Underworld", feature_notify_serverinfo),
  F_S(HIS_URLSERVERS, 0, "http://www.undernet.org/servers.php", 0),

  /* Misc. random stuff */
  F_S(NETWORK, 0, "UnderNet", set_isupport_network),
  F_S(URL_CLIENTS, 0, "ftp://ftp.undernet.org/pub/irc/clients", 0),
  F_I(SPAM_OPER_COUNTDOWN, 0, 5, 0),
  F_I(SPAM_EXPIRE_TIME, 0, 120, 0),
  F_I(SPAM_JOINED_TIME, 0, 60, 0),
  F_I(SPAM_FJP_COUNT, 0, 5, 0),

#undef F_S
#undef F_B
#undef F_I
#undef F_N
  { FEAT_LAST_F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

/** Given a feature's identifier, look up the feature descriptor.
 * @param[in] from Client looking up feature, or NULL.
 * @param[in] feature Feature name to find.
 * @return Pointer to a FeatureDesc, or NULL if none was found.
 */
static struct FeatureDesc *
feature_desc(struct Client* from, const char *feature)
{
  int i;

  assert(0 != feature);

  for (i = 0; features[i].type; i++) /* find appropriate descriptor */
    if (!strcmp(feature, features[i].type)) {
      if (feat_type(&features[i]) == FEAT_ALIAS) {
	Debug((DEBUG_NOTICE, "Deprecated feature \"%s\" referenced; replace "
	       "with %s", feature, features[features[i].def_int].type));
	if (from) /* report a warning */
	  send_reply(from, SND_EXPLICIT | ERR_NOFEATURE,
		     "%s :Feature deprecated, use %s", feature,
		     features[features[i].def_int].type);
	else
	  log_write(LS_CONFIG, L_WARNING, 0, "Feature \"%s\" deprecated, "
		    "use \"%s\"", feature, features[features[i].def_int].type);

	return &features[features[i].def_int];
      } else if (feat_type(&features[i]) == FEAT_DEP) {
	Debug((DEBUG_NOTICE, "Deprecated feature \"%s\" referenced", feature));
	if (from) /* report a warning */
	  send_reply(from, SND_EXPLICIT | ERR_NOFEATURE,
		     "%s :Feature deprecated", feature);
	else
	  log_write(LS_CONFIG, L_WARNING, 0, "Feature \"%s\" deprecated",
		    feature);
      }
      return &features[i];
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
  int i, change = 0, tmp;
  const char *t_str;
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
	break;
      }

    case FEAT_INT: /* an integer value */
      tmp = feat->v_int; /* detect changes... */

      if (count < 2) { /* reset value */
	feat->v_int = feat->def_int;
	feat->flags &= ~FEAT_MARK;
      } else { /* ok, figure out the value and whether to mark it */
	feat->v_int = strtoul(fields[1], 0, 0);
	if (feat->v_int == feat->def_int)
	  feat->flags &= ~FEAT_MARK;
	else
	  feat->flags |= FEAT_MARK;
      }

      if (feat->v_int != tmp) /* check for change */
	change++;
      break;

    case FEAT_BOOL: /* it's a boolean value--true or false */
      tmp = feat->v_int; /* detect changes... */

      if (count < 2) { /* reset value */
	feat->v_int = feat->def_int;
	feat->flags &= ~FEAT_MARK;
      } else { /* figure out the value and whether to mark it */
	if (!ircd_strncmp(fields[1], "TRUE", strlen(fields[1])) ||
	    !ircd_strncmp(fields[1], "YES", strlen(fields[1])) ||
	    (strlen(fields[1]) >= 2 &&
	     !ircd_strncmp(fields[1], "ON", strlen(fields[1]))))
	  feat->v_int = 1;
	else if (!ircd_strncmp(fields[1], "FALSE", strlen(fields[1])) ||
		 !ircd_strncmp(fields[1], "NO", strlen(fields[1])) ||
		 (strlen(fields[1]) >= 2 &&
		  !ircd_strncmp(fields[1], "OFF", strlen(fields[1]))))
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

      if (feat->v_int != tmp) /* check for change */
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

      if (t_str == feat->def_str ||
	  (t_str && feat->def_str &&
	   !(feat->flags & FEAT_CASE ? strcmp(t_str, feat->def_str) :
	     ircd_strcmp(t_str, feat->def_str)))) { /* resetting to default */
	if (feat->v_str != feat->def_str) {
	  change++; /* change from previous value */

	  if (feat->v_str)
	    MyFree(feat->v_str); /* free old value */
	}

	feat->v_str = feat->def_str; /* very special... */

	feat->flags &= ~FEAT_MARK;
      } else if (!t_str) {
	if (feat->v_str) {
	  change++; /* change from previous value */

	  if (feat->v_str != feat->def_str)
	    MyFree(feat->v_str); /* free old value */
	}

	feat->v_str = 0; /* set it to NULL */

	feat->flags |= FEAT_MARK;
      } else if (!feat->v_str ||
		 (feat->flags & FEAT_CASE ? strcmp(t_str, feat->v_str) :
		  ircd_strcmp(t_str, feat->v_str))) { /* new value */
	change++; /* change from previous value */

	if (feat->v_str && feat->v_str != feat->def_str)
	  MyFree(feat->v_str); /* free old value */
	DupString(feat->v_str, t_str); /* store new value */

	feat->flags |= FEAT_MARK;
      } else /* they match, but don't match the default */
	feat->flags |= FEAT_MARK;
      break;
    }

    if (change && feat->notify) /* call change notify function */
      (*feat->notify)();
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

    case FEAT_INT:  /* Integer... */
    case FEAT_BOOL: /* Boolean... */
      if (feat->v_int != feat->def_int)
	change++; /* change will be made */

      feat->v_int = feat->def_int; /* set the default */
      feat->flags &= ~FEAT_MARK; /* unmark it */
      break;

    case FEAT_STR: /* string! */
      if (feat->v_str != feat->def_str) {
	change++; /* change has been made */
	if (feat->v_str)
	  MyFree(feat->v_str); /* free old value */
      }

      feat->v_str = feat->def_str; /* set it to default */
      feat->flags &= ~FEAT_MARK; /* unmark it */
      break;
    }

    if (change && feat->notify) /* call change notify function */
      (*feat->notify)();
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
    case FEAT_BOOL:
      if (!(features[i].flags & FEAT_MARK)) { /* not changed? */
	if (features[i].v_int != features[i].def_int)
	  change++; /* we're making a change */
	features[i].v_int = features[i].def_int;
      }
      break;

    case FEAT_STR: /* strings... */
      if (!(features[i].flags & FEAT_MARK)) { /* not changed? */
	if (features[i].v_str != features[i].def_str) {
	  change++; /* we're making a change */
	  if (features[i].v_str)
	    MyFree(features[i].v_str); /* free old value */
	}
	features[i].v_str = features[i].def_str;
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
      break;

    case FEAT_INT:  /* Integers or Booleans... */
    case FEAT_BOOL:
      feat->v_int = feat->def_int;
      break;

    case FEAT_STR:  /* Strings */
      feat->v_str = feat->def_str;
      assert(feat->def_str || (feat->flags & FEAT_NULL));
      break;
    }

    if (feat->notify && !(feat->flags & FEAT_NOINIT))
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
  int i;

  for (i = 0; features[i].type; i++) {
    if ((features[i].flags & FEAT_NODISP) ||
	(features[i].flags & FEAT_MYOPER && !MyOper(to)) ||
	(features[i].flags & FEAT_OPER && !IsAnOper(to)))
      continue; /* skip this one */

    switch (feat_type(&features[i])) {
    case FEAT_NONE:
      if (features[i].report) /* let the callback handle this */
	(*features[i].report)(to, features[i].flags & FEAT_MARK ? 1 : 0);
      break;


    case FEAT_INT: /* Report an F-line with integer values */
      if (features[i].flags & FEAT_MARK) /* it's been changed */
	send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "F %s %d",
		   features[i].type, features[i].v_int);
      break;

    case FEAT_BOOL: /* Report an F-line with boolean values */
      if (features[i].flags & FEAT_MARK) /* it's been changed */
	send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "F %s %s",
		   features[i].type, features[i].v_int ? "TRUE" : "FALSE");
      break;

    case FEAT_STR: /* Report an F-line with string values */
      if (features[i].flags & FEAT_MARK) { /* it's been changed */
	if (features[i].v_str)
	  send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "F %s %s",
		     features[i].type, features[i].v_str);
	else /* Actually, F:<type> would reset it; you want F:<type>: */
	  send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "F %s",
		     features[i].type);
      }
      break;
    }
  }
}

/** Return a feature's integer value.
 * @param[in] feat &Feature identifier.
 * @return Integer value of feature.
 */
int
feature_int(enum Feature feat)
{
  assert(features[feat].feat == feat);
  assert(feat_type(&features[feat]) == FEAT_INT);

  return features[feat].v_int;
}

/** Return a feature's boolean value.
 * @param[in] feat &Feature identifier.
 * @return Boolean value of feature.
 */
int
feature_bool(enum Feature feat)
{
  assert(feat <= FEAT_LAST_F);
  if (FEAT_LAST_F < feat)
    return 0;
  assert(features[feat].feat == feat);
  assert(feat_type(&features[feat]) == FEAT_BOOL);

  return features[feat].v_int;
}

/** Return a feature's string value.
 * @param[in] feat &Feature identifier.
 * @return String value of feature.
 */
const char *
feature_str(enum Feature feat)
{
  assert(features[feat].feat == feat);
  assert(feat_type(&features[feat]) == FEAT_STR);

  return features[feat].v_str;
}
