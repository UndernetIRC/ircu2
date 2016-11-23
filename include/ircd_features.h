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
 * @version $Id$
 */

struct Client;
struct StatDesc;

extern struct Client his;

/** Contains all feature settings for ircu.
 * For documentation of each, see doc/readme.features.
 */
enum Feature {
  /* Misc. features */
  FEAT_LOG,
  FEAT_DOMAINNAME,
  FEAT_RELIABLE_CLOCK,
  FEAT_BUFFERPOOL,
  FEAT_HAS_FERGUSON_FLUSHER,
  FEAT_CLIENT_FLOOD,
  FEAT_SERVER_PORT,
  FEAT_NODEFAULTMOTD,
  FEAT_MOTD_BANNER,
  FEAT_PROVIDER,
  FEAT_KILL_IPMISMATCH,
  FEAT_IDLE_FROM_MSG,
  FEAT_HUB,
  FEAT_WALLOPS_OPER_ONLY,
  FEAT_NODNS,
  FEAT_RANDOM_SEED,
  FEAT_DEFAULT_LIST_PARAM,
  FEAT_NICKNAMEHISTORYLENGTH,
  FEAT_HOST_HIDING,
  FEAT_HIDDEN_HOST,
  FEAT_HIDDEN_IP,
  FEAT_CONNEXIT_NOTICES,
  FEAT_OPLEVELS,
  FEAT_ZANNELS,
  FEAT_LOCAL_CHANNELS,
  FEAT_TOPIC_BURST,
  FEAT_DISABLE_GLINES,

  /* features that probably should not be touched */
  FEAT_KILLCHASETIMELIMIT,
  FEAT_MAXCHANNELSPERUSER,
  FEAT_NICKLEN,
  FEAT_AVBANLEN,
  FEAT_MAXBANS,
  FEAT_MAXSILES,
  FEAT_HANGONGOODLINK,
  FEAT_HANGONRETRYDELAY,
  FEAT_CONNECTTIMEOUT,
  FEAT_MAXIMUM_LINKS,
  FEAT_PINGFREQUENCY,
  FEAT_CONNECTFREQUENCY,
  FEAT_DEFAULTMAXSENDQLENGTH,
  FEAT_GLINEMAXUSERCOUNT,
  FEAT_SOCKSENDBUF,
  FEAT_SOCKRECVBUF,
  FEAT_IPCHECK_CLONE_LIMIT,
  FEAT_IPCHECK_CLONE_PERIOD,
  FEAT_IPCHECK_48_CLONE_LIMIT,
  FEAT_IPCHECK_48_CLONE_PERIOD,
  FEAT_IPCHECK_CLONE_DELAY,
  FEAT_CHANNELLEN,

  /* Some misc. default paths */
  FEAT_MPATH,
  FEAT_RPATH,
  FEAT_PPATH,

  /* Networking features */
  FEAT_TOS_SERVER,
  FEAT_TOS_CLIENT,
  FEAT_POLLS_PER_LOOP,
  FEAT_IRCD_RES_RETRIES,
  FEAT_IRCD_RES_TIMEOUT,
  FEAT_AUTH_TIMEOUT,
  FEAT_ANNOUNCE_INVITES,

  /* features that affect all operators */
  FEAT_CONFIG_OPERCMDS,

  /* HEAD_IN_SAND Features */
  FEAT_HIS_SNOTICES,
  FEAT_HIS_SNOTICES_OPER_ONLY,
  FEAT_HIS_DEBUG_OPER_ONLY,
  FEAT_HIS_WALLOPS,
  FEAT_HIS_MAP,
  FEAT_HIS_LINKS,
  FEAT_HIS_TRACE,
  FEAT_HIS_STATS_a,
  FEAT_HIS_STATS_c,
  FEAT_HIS_STATS_d,
  FEAT_HIS_STATS_e,
  FEAT_HIS_STATS_f,
  FEAT_HIS_STATS_g,
  FEAT_HIS_STATS_i,
  FEAT_HIS_STATS_j,
  FEAT_HIS_STATS_J,
  FEAT_HIS_STATS_k,
  FEAT_HIS_STATS_l,
  FEAT_HIS_STATS_L,
  FEAT_HIS_STATS_M,
  FEAT_HIS_STATS_m,
  FEAT_HIS_STATS_o,
  FEAT_HIS_STATS_p,
  FEAT_HIS_STATS_q,
  FEAT_HIS_STATS_R,
  FEAT_HIS_STATS_r,
  FEAT_HIS_STATS_t,
  FEAT_HIS_STATS_T,
  FEAT_HIS_STATS_u,
  FEAT_HIS_STATS_U,
  FEAT_HIS_STATS_v,
  FEAT_HIS_STATS_w,
  FEAT_HIS_STATS_W,
  FEAT_HIS_STATS_x,
  FEAT_HIS_STATS_y,
  FEAT_HIS_STATS_z,
  FEAT_HIS_STATS_IAUTH,
  FEAT_HIS_WEBIRC,
  FEAT_HIS_WHOIS_SERVERNAME,
  FEAT_HIS_WHOIS_IDLETIME,
  FEAT_HIS_WHOIS_LOCALCHAN,
  FEAT_HIS_WHO_SERVERNAME,
  FEAT_HIS_WHO_HOPCOUNT,
  FEAT_HIS_MODEWHO,
  FEAT_HIS_BANWHO,
  FEAT_HIS_KILLWHO,
  FEAT_HIS_REWRITE,
  FEAT_HIS_REMOTE,
  FEAT_HIS_NETSPLIT,
  FEAT_HIS_SERVERNAME,
  FEAT_HIS_SERVERINFO,
  FEAT_HIS_URLSERVERS,

  /* Misc. random stuff */
  FEAT_NETWORK,
  FEAT_URL_CLIENTS,
  FEAT_URLREG,

  FEAT_LAST_F
};

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

extern int feature_int(enum Feature feat);
extern int feature_bool(enum Feature feat);
extern const char *feature_str(enum Feature feat);

#endif /* INCLUDED_features_h */
