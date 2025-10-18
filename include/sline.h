#ifndef INCLUDED_sline_h
#define INCLUDED_sline_h
/*
 * IRC - Internet Relay Chat, include/sline.h
 * Copyright (C) 2025 MrIron <mriron@undernet.org>
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

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

#include <stdint.h>
#include <regex.h>

struct Client;
struct StatDesc;
struct Channel;

/** Forward declaration for hold queue entry */
struct HoldQueueEntry;

/* Regex capture group limits */
#define SLINE_MAX_CAPTURES 16  /**< Maximum regex capture groups supported (including full match).
                                    If an S-line regex pattern contains more than 15 capture groups,
                                    only the first 15 will be captured and passed to spam filters. */

/* Message type flags */
#define SLINE_PRIVATE	0x0001  /**< Match private messages. */
#define SLINE_CHANNEL	0x0002  /**< Match channel messages. */
#define SLINE_PART	  0x0004  /**< Match partial messages. */
#define SLINE_QUIT	  0x0008  /**< Match quit messages. */

#define SLINE_ALL	    (SLINE_PRIVATE | SLINE_CHANNEL | SLINE_PART | SLINE_QUIT)

/** S:line flags */
#define SLINE_ACTIVE	0x0001  /**< S-line is active. */
#define SLINE_INVALID 0x0002  /**< S-line regex failed to compile. */

/* Flags to track update actions. */
#define SLINE_EXPIRE  0x0004  /**< S-line expire update. */
#define SLINE_MSGTYPE 0x0008  /**< S-line message type update. */
#define SLINE_STATE   0x0010  /**< S-line state update. */

/** Value to hold a set of message type bits. */
typedef unsigned short sl_msgtype_t;

/** Value to hold a set of S-line state bits. */
typedef unsigned short sl_flagtype_t;

/** Description of an S-line. */
struct Sline {
  struct Sline *sl_next;	    /**< Next S-line in linked list. */
  struct Sline **sl_prev_p;	  /**< Previous pointer to this S-line. */
  char	       *sl_pattern;	  /**< Regex pattern to match against messages. */
  time_t	      sl_lastmod;	  /**< When the S-line was last modified. */
  time_t        sl_expire;    /**< When the S-line will expire. */
  sl_msgtype_t 	sl_msgtype;	  /**< Message type to match against. */
  sl_flagtype_t sl_flags;     /**< S-line status flags. */
  uint64_t      sl_count;     /**< Number of times this S-line has matched. */
  regex_t       sl_regex;     /**< Precompiled regex for this pattern. */
};

extern int sline_add(struct Client *cptr, struct Client *sptr, char *pattern,
                     time_t lastmod, time_t expire, sl_msgtype_t msgtype, sl_flagtype_t flags);
extern void sline_modify(struct Client *sptr, struct Sline *sline, time_t lastmod,
                         time_t expire, sl_msgtype_t msgtype, sl_flagtype_t flags, unsigned int updates);

extern struct Sline *sline_find(char *pattern);
extern void sline_stats(struct Client *sptr, const struct StatDesc *sd,
                        char *param);
extern void sline_send_meminfo(struct Client* sptr);
extern void sline_burst(struct Client *cptr);
extern int sline_check_pattern_bool(const char *text, sl_msgtype_t msg_type);
extern int sline_check_privmsg(struct Client *sender, struct Client *recipient, const char *text, const char* cmd_type);
extern int sline_check_chanmsg(struct Client *sender, struct Channel *channel, const char *text, const char* cmd_type);
extern void sline_cleanup_client(struct Client *cptr);
extern void sline_cleanup_channel(struct Channel *chptr);
extern int sline_xreply_handler(struct Client *sptr, const char *token, const char *reply);
extern void sline_init(void);
extern const char *sline_flags_to_string(sl_msgtype_t msgtype);

#endif /* INCLUDED_sline_h */
