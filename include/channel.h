/*
 * IRC - Internet Relay Chat, ircd/channel.h
 * Copyright (C) 1990 Jarkko Oikarinen
 * Copyright (C) 1996 - 1997 Carlo Wood
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
#ifndef INCLUDED_channel_h
#define INCLUDED_channel_h
#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"        /* NICKLEN */
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

struct SLink;
struct Client;

/*
 * General defines
 */

#define MAXMODEPARAMS   6
#define MODEBUFLEN      200

#define KEYLEN          23
#define CHANNELLEN      200

#define MAXJOINARGS	15 /* number of slots for join buffer */
#define STARTJOINLEN	10 /* fuzzy numbers */
#define STARTCREATELEN	20

/*
 * Macro's
 */

#define ChannelExists(n)        (0 != FindChannel(n))

#define CHFL_CHANOP             0x0001  /* Channel operator */
#define CHFL_VOICE              0x0002  /* the power to speak */
#define CHFL_DEOPPED            0x0004  /* Is de-opped by a server */
#define CHFL_SERVOPOK           0x0008  /* Server op allowed */
#define CHFL_ZOMBIE             0x0010  /* Kicked from channel */
#define CHFL_BAN                0x0020  /* ban channel flag */
#define CHFL_BAN_IPMASK         0x0040  /* ban mask is an IP-number mask */
#define CHFL_BAN_OVERLAPPED     0x0080  /* ban overlapped, need bounce */
#define CHFL_BURST_JOINED       0x0100  /* Just joined by net.junction */
#define CHFL_BURST_BAN          0x0200  /* Ban part of last BURST */
#define CHFL_BURST_BAN_WIPEOUT  0x0400  /* Ban will be wiped at end of BURST */
#define CHFL_BANVALID           0x0800  /* CHFL_BANNED bit is valid */
#define CHFL_BANNED             0x1000  /* Channel member is banned */
#define CHFL_SILENCE_IPMASK     0x2000  /* silence mask is an IP-number mask */

#define CHFL_OVERLAP         (CHFL_CHANOP | CHFL_VOICE)
#define CHFL_BANVALIDMASK    (CHFL_BANVALID | CHFL_BANNED)
#define CHFL_VOICED_OR_OPPED (CHFL_CHANOP | CHFL_VOICE)

/* Channel Visibility macros */

#define MODE_CHANOP     CHFL_CHANOP
#define MODE_VOICE      CHFL_VOICE
#define MODE_PRIVATE    0x0004
#define MODE_SECRET     0x0008
#define MODE_MODERATED  0x0010
#define MODE_TOPICLIMIT 0x0020
#define MODE_INVITEONLY 0x0040
#define MODE_NOPRIVMSGS 0x0080
#define MODE_KEY        0x0100
#define MODE_BAN        0x0200
#define MODE_LIMIT      0x0400
#define MODE_REGONLY    0x0800  /* Only +r users may join */
#define MODE_LISTED     0x10000
#define MODE_SAVE	0x20000	/* save this mode-with-arg 'til later */
#define MODE_FREE	0x40000 /* string needs to be passed to MyFree() */
#define MODE_BURSTADDED	0x80000	/* channel was created by a BURST */
/*
 * mode flags which take another parameter (With PARAmeterS)
 */
#define MODE_WPARAS     (MODE_CHANOP|MODE_VOICE|MODE_BAN|MODE_KEY|MODE_LIMIT)

#define HoldChannel(x)          (!(x))
/* name invisible */
#define SecretChannel(x)        ((x) && ((x)->mode.mode & MODE_SECRET))
/* channel not shown but names are */
#define HiddenChannel(x)        ((x) && ((x)->mode.mode & MODE_PRIVATE))
/* channel visible */
#define ShowChannel(v,c)        (PubChannel(c) || find_channel_member((v),(c)))
#define PubChannel(x)           ((!x) || ((x)->mode.mode & \
                                    (MODE_PRIVATE | MODE_SECRET)) == 0)
#define is_listed(x)            ((x)->mode.mode & MODE_LISTED)

#define IsLocalChannel(name)    (*(name) == '&')
#define IsChannelName(name)     (*(name) == '#' || IsLocalChannel(name))

typedef enum ChannelGetType {
  CGT_NO_CREATE,
  CGT_CREATE
} ChannelGetType;

/* used in SetMode() in channel.c and m_umode() in s_msg.c */

#define MODE_NULL      0
#define MODE_ADD       0x40000000
#define MODE_DEL       0x20000000

/*
 * Maximum acceptable lag time in seconds: A channel younger than
 * this is not protected against hacking admins.
 * Mainly here to check if the TS clocks really sync (otherwise this
 * will start causing HACK notices.
 * This value must be the same on all servers.
 *
 * This value has been increased to 1 day in order to distinguish this
 * "normal" type of HACK wallops / desyncs, from possiblity still
 * existing bugs.
 */
#define TS_LAG_TIME 86400

/*
 * A Magic TS that is used for channels that are created by JOIN,
 * a channel with this TS accepts all TS without complaining that
 * it might receive later via MODE or CREATE.
 */
#define MAGIC_REMOTE_JOIN_TS 1270080000

/*
 * used in can_join to determine if an oper forced a join on a channel
 */
#define MAGIC_OPER_OVERRIDE 1000


extern const char* const PartFmt1;
extern const char* const PartFmt2;
extern const char* const PartFmt1serv;
extern const char* const PartFmt2serv;


/*
 * Structures
 */

struct Membership {
  struct Client*     user;
  struct Channel*    channel;
  struct Membership* next_member;
  struct Membership* prev_member;
  struct Membership* next_channel;
  struct Membership* prev_channel;
  unsigned int       status;
};

#define IsZombie(x)         ((x)->status & CHFL_ZOMBIE)
#define IsDeopped(x)        ((x)->status & CHFL_DEOPPED)
#define IsBanned(x)         ((x)->status & CHFL_BANNED)
#define IsBanValid(x)       ((x)->status & CHFL_BANVALID)
#define IsChanOp(x)         ((x)->status & CHFL_CHANOP)
#define HasVoice(x)         ((x)->status & CHFL_VOICE)
#define IsServOpOk(x)       ((x)->status & CHFL_SERVOPOK)
#define IsBurstJoined(x)    ((x)->status & CHFL_BURST_JOINED)
#define IsVoicedOrOpped(x)  ((x)->status & CHFL_VOICED_OR_OPPED)

#define SetBanned(x)        ((x)->status |= CHFL_BANNED)
#define SetBanValid(x)      ((x)->status |= CHFL_BANVALID)
#define SetDeopped(x)       ((x)->status |= CHFL_DEOPPED)
#define SetServOpOk(x)      ((x)->status |= CHFL_SERVOPOK)
#define SetBurstJoined(x)   ((x)->status |= CHFL_BURST_JOINED)
#define SetZombie(x)        ((x)->status |= CHFL_ZOMBIE)

#define ClearBanned(x)      ((x)->status &= ~CHFL_BANNED)
#define ClearBanValid(x)    ((x)->status &= ~CHFL_BANVALID)
#define ClearDeopped(x)     ((x)->status &= ~CHFL_DEOPPED)
#define ClearServOpOk(x)    ((x)->status &= ~CHFL_SERVOPOK)
#define ClearBurstJoined(x) ((x)->status &= ~CHFL_BURST_JOINED)


struct Mode {
  unsigned int mode;
  unsigned int limit;
  char key[KEYLEN + 1];
};

struct Channel {
  struct Channel*    next;
  struct Channel*    prev;
  struct Channel*    hnext;
  time_t             creationtime;
  time_t             topic_time;
  unsigned int       users;
  struct Membership* members;
  struct SLink*      invites;
  struct SLink*      banlist;
  struct Mode        mode;
  char               topic[TOPICLEN + 1];
  char               topic_nick[NICKLEN + 1];
  char               chname[1];
};

struct ListingArgs {
  time_t max_time;
  time_t min_time;
  unsigned int max_users;
  unsigned int min_users;
  unsigned int topic_limits;
  time_t max_topic_time;
  time_t min_topic_time;
  struct Channel *chptr;
};

struct ModeBuf {
  unsigned int		mb_add;		/* Modes to add */
  unsigned int		mb_rem;		/* Modes to remove */
  struct Client	       *mb_source;	/* Source of MODE changes */
  struct Client	       *mb_connect;	/* Connection of MODE changes */
  struct Channel       *mb_channel;	/* Channel they affect */
  unsigned int		mb_dest;	/* Destination of MODE changes */
  unsigned int		mb_count;	/* Number of modes w/args */
  struct {
    unsigned int	mbm_type;	/* Type of argument */
    union {
      unsigned int	mbma_uint;	/* A limit */
      char	       *mbma_string;	/* A string */
      struct Client    *mbma_client;	/* A client */
    }			mbm_arg;	/* The mode argument */
  }			mb_modeargs[MAXMODEPARAMS];
					/* A mode w/args */
};

#define MODEBUF_DEST_CHANNEL	0x00001	/* Mode is flushed to channel */
#define MODEBUF_DEST_SERVER	0x00002	/* Mode is flushed to server */

#define MODEBUF_DEST_OPMODE	0x00100	/* Send server mode as OPMODE */
#define MODEBUF_DEST_DEOP	0x00200	/* Deop the offender */
#define MODEBUF_DEST_BOUNCE	0x00400	/* Bounce the modes */
#define MODEBUF_DEST_LOG	0x00800	/* Log the mode changes to OPATH */

#define MODEBUF_DEST_HACK2	0x02000	/* Send a HACK(2) notice, reverse */
#define MODEBUF_DEST_HACK3	0x04000	/* Send a HACK(3) notice, TS == 0 */
#define MODEBUF_DEST_HACK4	0x08000	/* Send a HACK(4) notice, TS == 0 */

#define MODEBUF_DEST_NOKEY	0x10000	/* Don't send the real key */

#define MB_TYPE(mb, i)		((mb)->mb_modeargs[(i)].mbm_type)
#define MB_UINT(mb, i)		((mb)->mb_modeargs[(i)].mbm_arg.mbma_uint)
#define MB_STRING(mb, i)	((mb)->mb_modeargs[(i)].mbm_arg.mbma_string)
#define MB_CLIENT(mb, i)	((mb)->mb_modeargs[(i)].mbm_arg.mbma_client)

struct JoinBuf {
  struct Client	       *jb_source;	/* Source of joins (ie, joiner) */
  struct Client	       *jb_connect;	/* Connection of joiner */
  unsigned int		jb_type;	/* Type of join (JOIN or CREATE) */
  char		       *jb_comment;	/* part comment */
  time_t		jb_create;	/* Creation timestamp */
  unsigned int		jb_count;	/* Number of channels */
  unsigned int		jb_strlen;	/* length so far */
  struct Channel       *jb_channels[MAXJOINARGS];
					/* channels joined or whatever */
};

#define JOINBUF_TYPE_JOIN	0	/* send JOINs */
#define JOINBUF_TYPE_CREATE	1	/* send CREATEs */
#define JOINBUF_TYPE_PART	2	/* send PARTs */
#define JOINBUF_TYPE_PARTALL	3	/* send local PARTs, but not remote */

extern struct Channel* GlobalChannelList;
extern int             LocalChanOperMode;

/*
 * Proto types
 */
extern void clean_channelname(char* name);
extern void channel_modes(struct Client *cptr, char *mbuf, char *pbuf,
                          int buflen, struct Channel *chptr);
extern int set_mode(struct Client* cptr, struct Client* sptr,
                    struct Channel* chptr, int parc, char* parv[],
                    char* mbuf, char* pbuf, char* npbuf, int* badop);
extern void send_hack_notice(struct Client *cptr, struct Client *sptr,
                             int parc, char *parv[], int badop, int mtype);
extern struct Channel *get_channel(struct Client *cptr,
                                   char *chname, ChannelGetType flag);
extern struct Membership* find_member_link(struct Channel * chptr,
                                           const struct Client* cptr);
extern int sub1_from_channel(struct Channel* chptr);
extern int can_join(struct Client *sptr, struct Channel *chptr, char *key);
extern void add_user_to_channel(struct Channel* chptr, struct Client* who,
                                unsigned int flags);
extern void cancel_mode(struct Client *sptr, struct Channel *chptr, char m,
                        const char *param, int *count);
extern void add_token_to_sendbuf(char *token, size_t *sblenp, int *firstp,
                                 int *send_itp, char is_a_ban, int mode);
extern int add_banid(struct Client *cptr, struct Channel *chptr, char *banid,
                     int change, int firsttime);
extern struct SLink *next_removed_overlapped_ban(void);
extern void cancel_mode(struct Client *sptr, struct Channel *chptr, char m,
                        const char *param, int *count);
extern void make_zombie(struct Membership* member, struct Client* who,
                        struct Client* cptr, struct Client* sptr,
                        struct Channel* chptr);
extern struct Client* find_chasing(struct Client* sptr, const char* user, int* chasing);
void add_invite(struct Client *cptr, struct Channel *chptr);
int number_of_zombies(struct Channel *chptr);

extern const char* find_no_nickchange_channel(struct Client* cptr);
extern struct Membership* IsMember(struct Client *cptr, struct Channel *chptr);
extern struct Membership* find_channel_member(struct Client* cptr, struct Channel* chptr);
extern int member_can_send_to_channel(struct Membership* member);
extern int client_can_send_to_channel(struct Client *cptr, struct Channel *chptr);

extern void remove_user_from_channel(struct Client *sptr, struct Channel *chptr);
extern void remove_user_from_all_channels(struct Client* cptr);

extern int is_chan_op(struct Client *cptr, struct Channel *chptr);
extern int is_zombie(struct Client *cptr, struct Channel *chptr);
extern int has_voice(struct Client *cptr, struct Channel *chptr);
extern int IsInvited(struct Client* cptr, struct Channel* chptr);
extern void send_channel_modes(struct Client *cptr, struct Channel *chptr);
extern char *pretty_mask(char *mask);
extern void del_invite(struct Client *cptr, struct Channel *chptr);
extern void list_next_channels(struct Client *cptr, int nr);
extern void list_set_default(void); /* this belongs elsewhere! */

extern void modebuf_init(struct ModeBuf *mbuf, struct Client *source,
			 struct Client *connect, struct Channel *chan,
			 unsigned int dest);
extern void modebuf_mode(struct ModeBuf *mbuf, unsigned int mode);
extern void modebuf_mode_uint(struct ModeBuf *mbuf, unsigned int mode,
			      unsigned int uint);
extern void modebuf_mode_string(struct ModeBuf *mbuf, unsigned int mode,
				char *string, int free);
extern void modebuf_mode_client(struct ModeBuf *mbuf, unsigned int mode,
				struct Client *client);
extern int modebuf_flush(struct ModeBuf *mbuf);
extern void modebuf_extract(struct ModeBuf *mbuf, char *buf);

extern void mode_ban_invalidate(struct Channel *chan);
extern void mode_invite_clear(struct Channel *chan);

extern int mode_parse(struct ModeBuf *mbuf, struct Client *cptr,
		      struct Client *sptr, struct Channel *chptr,
		      int parc, char *parv[], unsigned int flags);

#define MODE_PARSE_SET		0x01	/* actually set channel modes */
#define MODE_PARSE_STRICT	0x02	/* +m +n +t style not supported */
#define MODE_PARSE_FORCE	0x04	/* force the mode to be applied */
#define MODE_PARSE_BOUNCE	0x08	/* we will be bouncing the modes */
#define MODE_PARSE_NOTOPER	0x10	/* send "not chanop" to user */
#define MODE_PARSE_NOTMEMBER	0x20	/* send "not member" to user */
#define MODE_PARSE_WIPEOUT	0x40	/* wipe out +k and +l during burst */
#define MODE_PARSE_BURST	0x80	/* be even more strict w/extra args */

extern void joinbuf_init(struct JoinBuf *jbuf, struct Client *source,
			 struct Client *connect, unsigned int type,
			 char *comment, time_t create);
extern void joinbuf_join(struct JoinBuf *jbuf, struct Channel *chan,
			 unsigned int flags);
extern int joinbuf_flush(struct JoinBuf *jbuf);

#endif /* INCLUDED_channel_h */
