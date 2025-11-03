/*
 * IRC - Internet Relay Chat, ircd/sline.c
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

#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_netconf.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_stats.h"
#include "s_user.h"
#include "send.h"
#include "sline.h"
#include "struct.h"
#include "sys.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>

/** List of S-lines. */
struct Sline* GlobalSlineList = 0;

/** Hold queue entry structure */
struct HoldQueueEntry {
  struct HoldQueueEntry *next;      /**< Next entry in queue */
  struct HoldQueueEntry **prev_p;   /**< Previous pointer to this entry */
  unsigned int token;               /**< Unique token for this entry */
  sl_msgtype_t msgtype;             /**< Type of message (SLINE_PRIVATE, SLINE_CHANNEL) */
  const char *cmdtype;              /**< Type of command (MSG_PRIVATE, MSG_NOTICE, MSG_WALLCHOPS, MSG_WALLVOICES) */
  struct Client *sender;            /**< Sender of the message */
  union {
    struct Client *recipient;       /**< Recipient for private messages */
    struct Channel *channel;        /**< Channel for channel messages */
  } target;
  char *text;                       /**< Message text */
  char *captures;                   /**< S-line regex captures */
  time_t timestamp;                 /**< When message was held */
};

/** Global hold queue list */
static struct HoldQueueEntry *GlobalHoldQueue = 0;

/** Next available token number */
static uint64_t next_hold_token = 1;

/** Statistics counters for S-line operations */
static struct {
  unsigned int sline_hits;          /**< Number of times S-lines matched messages */
  unsigned int messages_held;       /**< Total number of messages held */
  unsigned int messages_released;   /**< Number of messages released (XREPLY YES) */
  unsigned int messages_blocked;    /**< Number of messages blocked (XREPLY NO + timeout) */
  unsigned int xreply_accepted;     /**< Number of XREPLY YES responses */
  unsigned int xreply_rejected;     /**< Number of XREPLY NO responses */
  unsigned int timeout_expired;     /**< Number of messages expired due to timeout */
} sline_stats_counters = { 0, 0, 0, 0, 0, 0, 0 };

/** Timer for checking expired hold queue entries */
static struct Timer hold_timeout_timer;

/** Forward declaration for timer callback */
static void sline_hold_timeout_callback(struct Event* ev);

/** Check if S-lines are active based on features and netconf settings.
 * @return 1 if S-lines are active, 0 if disabled.
 */
static int sline_is_enabled(void)
{
  /* Check if S-lines are disabled by feature */
  if (feature_bool(FEAT_DISABLE_SLINES))
    return 0;
  
  /* Check if S-line server is configured */
  const char *spamfilter_server = netconf_str(NETCONF_SLINE_SERVER);
  if (!spamfilter_server || *spamfilter_server == '\0')
    return 0;
  
  return 1;
}

/** Create an Sline structure.
 * @param[in] pattern Regex pattern to match against messages.
 * @param[in] lastmod Last modification timestamp.
 * @param[in] flags Bitwise combination of SLINE_* bits.
 * @return Newly allocated S-line.
 */
static struct Sline *
make_sline(char *pattern, time_t lastmod, time_t expire, sl_msgtype_t msgtype, sl_flagtype_t flags)
{
  assert(pattern);

  struct Sline *sline;

  sline = (struct Sline *)MyMalloc(sizeof(struct Sline));
  assert(0 != sline);

  DupString(sline->sl_pattern, pattern);
  sline->sl_lastmod = lastmod > 0 ? lastmod : TStime();
  sline->sl_expire = expire;
  sline->sl_msgtype = msgtype;
  sline->sl_count = 0;
  sline->sl_flags = flags;

  /* Precompile the regex at creation time; invalid patterns are accepted but marked invalid */
  {
    int ret = regcomp(&sline->sl_regex, sline->sl_pattern, REG_EXTENDED);
    if (ret == 0) {
      Debug((DEBUG_DEBUG, "make_sline: compiled regex for pattern '%s'", sline->sl_pattern));
    } else {
      sline->sl_flags |= SLINE_INVALID;
      Debug((DEBUG_DEBUG, "make_sline: failed to compile regex for pattern '%s'", sline->sl_pattern));
    }
  }

  sline->sl_next = GlobalSlineList; /* then link it into list */
  sline->sl_prev_p = &GlobalSlineList;
  if (GlobalSlineList)
    GlobalSlineList->sl_prev_p = &sline->sl_next;
  GlobalSlineList = sline;

  return sline;
}

/** Create a new S-line and add it to global lists.
 * @param[in] cptr Client that sent us the S-line.
 * @param[in] sptr Client that originated the S-line.
 * @param[in] pattern Regex pattern to match against messages.
 * @param[in] lastmod Last modification time of S-line.
 * @param[in] msgtype Bitwise combination of SLINE_* flags.
 * @return Zero.
 */
int
sline_add(struct Client *cptr, struct Client *sptr, char *pattern,
	  time_t lastmod, time_t expire, sl_msgtype_t msgtype, sl_flagtype_t flags)
{
  assert(pattern);
  assert(cptr);
  assert(sptr);

  struct Sline *asline;

  assert(0 != pattern);

  Debug((DEBUG_DEBUG, "sline_add(\"%s\", \"%s\", \"%s\", %Tu, %Tu, 0x%04x, 0x%04x)",
	 cli_name(cptr), cli_name(sptr), pattern, lastmod, expire, msgtype, flags));

  /* Check pattern length */
  if (strlen(pattern) >= SLINELEN)
    return send_reply(sptr, ERR_LONGMASK);

  /* make the sline */
  asline = make_sline(pattern, lastmod, expire, msgtype, flags);
  assert(asline);

  /* Inform ops... */
  sendto_opmask_butone(0, SNO_GLINE, "%s adding SLINE for pattern \"%s\" (%s) expiring at %Tu",
                      cli_name(sptr), pattern,
		                  asline->sl_flags & SLINE_INVALID ? "I" : sline_flags_to_string(msgtype), expire);

  /* and log it */
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C adding SLINE for pattern \"%s\" (%s)", sptr,
	    pattern,
	    asline->sl_flags & SLINE_INVALID ? "I" : sline_flags_to_string(msgtype));

  Debug((DEBUG_DEBUG, "S-line added successfully: pattern=%s, msgtype=0x%04x, lastmod=%Tu, expire=%Tu, flags=0x%04x",
         asline->sl_pattern, asline->sl_msgtype, asline->sl_lastmod, asline->sl_expire, asline->sl_flags));

  return 0;
}

void sline_modify(struct Client *sptr, struct Sline *sline, time_t lastmod, time_t expire, sl_msgtype_t msgtype, sl_flagtype_t flags, unsigned int updates)
{
  assert(sline);

  const char *buf;
  char text_extra[128] = "";
  char text_msgtype[40] = "";

  sline->sl_lastmod = lastmod;

  if (updates & SLINE_STATE) {
    if (flags & SLINE_ACTIVE) {
      sline->sl_flags |= SLINE_ACTIVE;
    } else {
      sline->sl_flags &= ~SLINE_ACTIVE;
    }
    buf = (sline->sl_flags & SLINE_ACTIVE) ? "activating" : "deactivating";
  } else {
    buf = "updating";
  }

  if (updates & SLINE_EXPIRE) {
    sline->sl_expire = expire;
    ircd_snprintf(0, text_extra, sizeof(text_extra), " changing expire time to %Tu", expire);
  } else if (sline->sl_flags & SLINE_ACTIVE && sline->sl_expire > 0) {
    ircd_snprintf(0, text_extra, sizeof(text_extra), " expiring at %Tu", sline->sl_expire);
  }

  if (updates & SLINE_MSGTYPE) {
    char old_type[16], new_type[16];
    strncpy(old_type, sline_flags_to_string(sline->sl_msgtype), sizeof(old_type));
    old_type[sizeof(old_type) - 1] = '\0';
    strncpy(new_type, sline_flags_to_string(msgtype), sizeof(new_type));
    new_type[sizeof(new_type) - 1] = '\0';
    ircd_snprintf(0, text_msgtype, sizeof(text_msgtype), "%s -> %s", old_type, new_type);
    sline->sl_msgtype = msgtype;
  } else {
    ircd_snprintf(0, text_msgtype, sizeof(text_msgtype), "%s", sline_flags_to_string(sline->sl_msgtype));
  }

  sendto_opmask_butone(0, SNO_GLINE, "%C %s SLINE for pattern \"%s\" (%s)%s",
                        sptr, buf, sline->sl_pattern,
                        text_msgtype, text_extra);

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
            "%#C %s SLINE for pattern \"%s\" (%s)%s",
                        sptr, buf, sline->sl_pattern,
                        text_msgtype, text_extra);

  Debug((DEBUG_DEBUG, "S-line modified successfully: pattern=%s, msgtype=0x%04x, lastmod=%Tu, expire=%Tu, flags=0x%04x",
        sline->sl_pattern, sline->sl_msgtype, sline->sl_lastmod, sline->sl_expire, sline->sl_flags));
}

/** Find an S-line for a particular pattern, guided by certain flags.
 * @param[in] pattern Pattern to search for.
 * @return First matching S-line, or NULL if none are found.
 */
struct Sline *
sline_find(char *pattern)
{
  struct Sline *sline;

  for (sline = GlobalSlineList; sline; sline = sline->sl_next) {
    if (ircd_strcmp(sline->sl_pattern, pattern) == 0)
      return sline;
  }

  return 0;
}

/** Delink and free an S-line.
 * @param[in] sline S-line to free.
 */
static void
sline_free(struct Sline *sline)
{
  assert(0 != sline);

  *sline->sl_prev_p = sline->sl_next; /* squeeze this sline out */
  if (sline->sl_next)
    sline->sl_next->sl_prev_p = sline->sl_prev_p;

  /* Free compiled regex if present */
  if (sline->sl_flags & SLINE_INVALID) {
    regfree(&sline->sl_regex);
    sline->sl_flags &= ~SLINE_INVALID;
  }

  MyFree(sline->sl_pattern); /* free up the memory */
  MyFree(sline);
}

/** Convert S-line message type flags to a readable string.
 * @param[in] msgtype Message type flags to convert.
 * @return Static string buffer containing the flag representation.
 */
const char *
sline_flags_to_string(sl_msgtype_t msgtype)
{
  static char flag_str[16]; /* Buffer for flag string */
  int flag_pos = 0;
  
  /* Clear the buffer */
  memset(flag_str, 0, sizeof(flag_str));
  
  /* Check for SLINE_ALL first */
  if (msgtype == SLINE_ALL) {
    return "A";
  }
  
  /* Build individual flag string */
  if (msgtype & SLINE_PRIVATE) {
    flag_str[flag_pos++] = 'P';
  }
  if (msgtype & SLINE_CHANNEL) {
    flag_str[flag_pos++] = 'C';
  }
  if (msgtype & SLINE_PART) {
    flag_str[flag_pos++] = 'L';
  }
  if (msgtype & SLINE_QUIT) {
    flag_str[flag_pos++] = 'Q';
  }
  
  /* If no flags were set, return "U" for unknown */
  if (flag_pos == 0) {
    return "U";
  }
  
  /* Null terminate and return */
  flag_str[flag_pos] = '\0';
  return flag_str;
}

/** Statistics callback to list S-lines.
 * @param[in] sptr Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Pattern to filter reported S-lines.
 */
void
sline_stats(struct Client *sptr, const struct StatDesc *sd,
            char *param)
{
  struct Sline *sline;
  char type_str[32];
  int count = 0;

  for (sline = GlobalSlineList; sline; sline = sline->sl_next) {
    if (!(sline->sl_flags & SLINE_ACTIVE)) {
      /* Deactivated S-line, skip it */
      continue;
    }

    /* Build type string */
    if (sline->sl_flags & SLINE_INVALID)
      ircd_strncpy(type_str, "I", sizeof(type_str));
    else
      ircd_strncpy(type_str, sline_flags_to_string(sline->sl_msgtype), sizeof(type_str));

    send_reply(sptr, RPL_STATSSLINE, 
	       sline->sl_lastmod, sline->sl_expire, sline->sl_count, type_str,
         sline->sl_pattern);
    count++;
  }
  
  send_reply(sptr, SND_EXPLICIT | RPL_STATSSLINE, 
    "S:line enabled: %s", sline_is_enabled() ? "yes" : "no");
  if (sline_is_enabled()) {
    send_reply(sptr, SND_EXPLICIT | RPL_STATSSLINE,
      "spamfilter server configured: %s", netconf_str(NETCONF_SLINE_SERVER));
    send_reply(sptr, SND_EXPLICIT | RPL_STATSSLINE,
      "hold timeout: %u", netconf_int(NETCONF_SLINE_HOLD_TIMEOUT));
    send_reply(sptr, SND_EXPLICIT | RPL_STATSSLINE,
      "hold timeout block: %s", netconf_bool(NETCONF_SLINE_HOLD_TIMEOUT_BLOCK) ? "yes" : "no");
  }

  /* Send summary statistics */
  send_reply(sptr, SND_EXPLICIT | RPL_STATSSLINE, 
             "S :--- S-line Summary ---");
  send_reply(sptr, SND_EXPLICIT | RPL_STATSSLINE,
             "S :S-line Hits: %u", sline_stats_counters.sline_hits);
  send_reply(sptr, SND_EXPLICIT | RPL_STATSSLINE,
             "S :Messages Held: %u", sline_stats_counters.messages_held);
  send_reply(sptr, SND_EXPLICIT | RPL_STATSSLINE,
             "S :Messages Released: %u", sline_stats_counters.messages_released);
  send_reply(sptr, SND_EXPLICIT | RPL_STATSSLINE,
             "S :Messages Blocked: %u", sline_stats_counters.messages_blocked);
  send_reply(sptr, SND_EXPLICIT | RPL_STATSSLINE,
             "S :XREPLY Accepted: %u", sline_stats_counters.xreply_accepted);
  send_reply(sptr, SND_EXPLICIT | RPL_STATSSLINE,
             "S :XREPLY Rejected: %u", sline_stats_counters.xreply_rejected);
  send_reply(sptr, SND_EXPLICIT | RPL_STATSSLINE,
             "S :Timeout Expired: %u", sline_stats_counters.timeout_expired);
  
  Debug((DEBUG_DEBUG, "sline_stats: found %d S-lines total", count));
}

/** Calculate memory used by S-lines.
 * @param[out] sl_size Number of bytes used by S-lines.
 * @return Number of S-lines in use.
 */
static int
sline_memory_count(size_t *sl_size)
{
  struct Sline *sline;
  unsigned int sl = 0;

  for (sline = GlobalSlineList; sline; sline = sline->sl_next) {
    sl++;
    *sl_size += sizeof(struct Sline);
    *sl_size += sline->sl_pattern ? (strlen(sline->sl_pattern) + 1) : 0;
  }

  return sl;
}

/** Report hold queue memory usage to a client.
 * @param[in] sptr Client requesting memory information.
 */
void
sline_send_meminfo(struct Client* sptr)
{
  struct HoldQueueEntry *entry;
  unsigned int hold_count = 0;
  size_t hold_size = 0;
  
  /* Count hold queue entries and calculate memory usage */
  for (entry = GlobalHoldQueue; entry; entry = entry->next) {
    hold_count++;
    hold_size += sizeof(struct HoldQueueEntry);
    if (entry->text)
      hold_size += strlen(entry->text) + 1;
    if (entry->captures)
      hold_size += strlen(entry->captures) + 1;
  }
  
  send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
             ":S-line hold queue: %u entries using %zu bytes",
             hold_count, hold_size);
}

/** Burst all known S-lines to another server.
 * @param[in] cptr Destination of burst.
 */
void
sline_burst(struct Client *cptr)
{
  assert(cptr);

  struct Sline *sline, *next;

  for (sline = GlobalSlineList; sline; sline = next) {
    next = sline->sl_next;
    if (sline->sl_expire > 0 && sline->sl_expire < TStime()) {
      sline_free(sline);
      continue;
    }
    sendcmdto_one(&me, CMD_SLINE, cptr, "%c %Tu %Tu %s :%s",
      sline->sl_flags & SLINE_ACTIVE ? '+' : '-',
      sline->sl_lastmod,
      sline->sl_expire,
      sline_flags_to_string(sline->sl_msgtype),
      sline->sl_pattern);
  }
}

/** Check if a string matches any S-line pattern and return captures.
 * @param[in] text String to check against S-line patterns.
 * @param[in] msg_type Message type flags (SLINE_PRIVATE, SLINE_CHANNEL, SLINE_ALL).
 * @return Allocated string with captures if match found, NULL otherwise.
 *         Caller is responsible for freeing the returned string.
 */
static char *
sline_check_pattern(const char *text, sl_msgtype_t msg_type)
{
  struct Sline *sline;
  regmatch_t matches[SLINE_MAX_CAPTURES]; /* Support up to 15 capture groups + full match */
  int ret;
  char *result = NULL;

  if (!text)
    return NULL;

  Debug((DEBUG_DEBUG, "sline_check_pattern: checking text='%s' against msg_type=0x%04x", text, msg_type));

  struct Sline *next;
  for (sline = GlobalSlineList; sline; sline = next) {
    next = sline->sl_next;
    if (sline->sl_expire > 0 && sline->sl_expire < TStime()) {
      sline_free(sline);
      continue;
    }

    /* Check if this S-line is active and valid and applies to the message type */
    if (!(sline->sl_msgtype & msg_type)
        || !(sline->sl_flags & SLINE_ACTIVE)
        || (sline->sl_flags & SLINE_INVALID))
      continue;

    Debug((DEBUG_DEBUG, "sline_check_pattern: testing pattern '%s'", sline->sl_pattern));

    /* Execute the regex match */
    ret = regexec(&sline->sl_regex, text, SLINE_MAX_CAPTURES, matches, 0);
    if (ret == 0) {
      /* Match found! Extract captures */
      Debug((DEBUG_DEBUG, "sline_check_pattern: pattern '%s' matched text '%s'", sline->sl_pattern, text));
      sline->sl_count++; /* Increment match count for this S-line */
      sline_stats_counters.sline_hits++; /* Increment global hit counter */
      
      /* Calculate total length needed for all captures */
      int total_len = 0;
      int num_captures = 0;
      for (int i = 1; i < SLINE_MAX_CAPTURES && matches[i].rm_so != -1; i++) {
        total_len += (matches[i].rm_eo - matches[i].rm_so) + 1; /* +1 for separator/null */
        num_captures++;
      }
      
      if (num_captures > 0) {
        /* Allocate result string */
        result = (char *)MyMalloc(total_len + 1);
        result[0] = '\0';
        
        /* Copy captures separated by spaces */
        for (int i = 1; i < SLINE_MAX_CAPTURES && matches[i].rm_so != -1; i++) {
          if (i > 1) strcat(result, " ");
          strncat(result, text + matches[i].rm_so, matches[i].rm_eo - matches[i].rm_so);
        }
        
        Debug((DEBUG_DEBUG, "sline_check_pattern: extracted captures: '%s'", result));
      } else {
        /* No captures, just return the full match */
        int match_len = matches[0].rm_eo - matches[0].rm_so;
        result = (char *)MyMalloc(match_len + 1);
        strncpy(result, text + matches[0].rm_so, match_len);
        result[match_len] = '\0';
        
        Debug((DEBUG_DEBUG, "sline_check_pattern: no captures, returning full match: '%s'", result));
      }
      return result;
    }
  }

  Debug((DEBUG_DEBUG, "sline_check_pattern: no patterns matched"));
  return NULL;
}

/** Check if text matches any S-line patterns for a given message type.
 * This is a boolean version that doesn't allocate memory.
 * @param[in] text Text to check against S-line patterns.
 * @param[in] msg_type Message type to check (SLINE_PRIVATE, SLINE_CHANNEL, etc.).
 * @return 1 if text matches any S-line pattern, 0 otherwise.
 */
int
sline_check_pattern_bool(const char *text, sl_msgtype_t msg_type)
{
  struct Sline *sline, *next;
  regmatch_t matches[SLINE_MAX_CAPTURES];
  
  if (!text)
    return 0;

  Debug((DEBUG_DEBUG, "sline_check_pattern_bool: checking text='%s' against msg_type=0x%04x", text, msg_type));

  /* Check each S-line pattern */
  for (sline = GlobalSlineList; sline; sline = next) {
    next = sline->sl_next;
    if (sline->sl_expire > 0 && sline->sl_expire < TStime()) {
      sline_free(sline);
      continue;
    }

    /* Check if this S-line is active and valid and applies to the message type */
    if (!(sline->sl_msgtype & msg_type)
        || (sline->sl_expire > 0 && sline->sl_expire < TStime())
        || !(sline->sl_flags & SLINE_ACTIVE)
        || (sline->sl_flags & SLINE_INVALID))
      continue;

    Debug((DEBUG_DEBUG, "sline_check_pattern_bool: testing pattern '%s'", sline->sl_pattern));

    /* Execute the precompiled regex match */
    if (regexec(&sline->sl_regex, text, SLINE_MAX_CAPTURES, matches, 0) == 0) {
      Debug((DEBUG_DEBUG, "sline_check_pattern_bool: pattern '%s' matched text '%s'", sline->sl_pattern, text));
      sline->sl_count++; /* Increment match count for this S-line */
      sline_stats_counters.sline_hits++; /* Increment global hit counter */
      return 1; /* Match found */
    }
  }

  Debug((DEBUG_DEBUG, "sline_check_pattern_bool: no patterns matched"));
  return 0;
}

/** Send S-line match notification to the configured spam filter server.
 * @param[in] entry Hold queue entry containing message and match information.
 */
static int
sline_notify_spamfilter(struct HoldQueueEntry *entry)
{
  assert(entry);
  assert(entry->sender);
  assert(entry->target.recipient || entry->target.channel);
  assert(entry->msgtype == SLINE_PRIVATE || entry->msgtype == SLINE_CHANNEL);

  struct Client *acptr;
  const char *target_name;
  
  if (!entry || !entry->sender)
    return 0;

  /* Get target name based on message type */
  if (entry->msgtype == SLINE_PRIVATE && entry->target.recipient)
    target_name = NumNick(entry->target.recipient);
  else if (entry->msgtype == SLINE_CHANNEL && entry->target.channel)
    target_name = entry->target.channel->chname;
  else
    return 0;

  Debug((DEBUG_DEBUG, "sline_notify_spamfilter: notifying about token %u from %s to %s", 
         entry->token, cli_name(entry->sender), target_name));

  struct Client *serv = FindServer(netconf_str(NETCONF_SLINE_SERVER));
  if (!serv) {
    Debug((DEBUG_DEBUG, "sline_notify_spamfilter: the spamfilter server is not available"));
    return 0;
  }

  Debug((DEBUG_DEBUG, "sline_notify_spamfilter: sending notification to spamfilter %s", cli_name(serv)));

  /* Send the S-line match notification to the nearest spam filter server
  * Format: SL spam:<token> :<sender> <target> :<captures>
  */
  if (entry->msgtype == SLINE_PRIVATE) {
    sendcmdto_one(&me, CMD_XQUERY, serv,
                  "%C spam:%d :%C %C :%s",
                  serv,
                  entry->token,
                  entry->sender,
                  entry->target.recipient,
                  entry->captures ? entry->captures : "");
  } else {
    sendcmdto_one(&me, CMD_XQUERY, serv,
                  "%C spam:%d :%C %H :%s",
                  serv,
                  entry->token,
                  entry->sender,
                  entry->target.channel,
                  entry->captures ? entry->captures : "");
  }

  return 1;
}

/** Add a private message to the hold queue.
 * @param[in] sender Client who sent the message.
 * @param[in] recipient Client who should receive the message.
 * @param[in] text Message text.
 * @param[in] captures S-line regex captures (can be NULL).
 * @param[in] cmd_type Message type (MSG_PRIVATE, MSG_NOTICE).
 * @return Pointer to the created hold queue entry, or NULL on failure.
 */
static struct HoldQueueEntry *
sline_hold_privmsg(struct Client *sender, struct Client *recipient, 
                   const char *text, const char *captures, const char* cmd_type)
{
  assert(sender);
  assert(recipient);

  struct HoldQueueEntry *entry;
  
  if (!sender || !recipient || !text)
    return NULL;

  Debug((DEBUG_DEBUG, "sline_hold_privmsg: holding %s from %s to %s: '%s'", 
         cmd_type, cli_name(sender), cli_name(recipient), text));

  /* Allocate new hold queue entry */
  entry = (struct HoldQueueEntry *)MyMalloc(sizeof(struct HoldQueueEntry));
  if (!entry)
    return NULL;

  /* Initialize entry */
  entry->token = next_hold_token++;
  entry->msgtype = SLINE_PRIVATE;
  entry->cmdtype = cmd_type;
  entry->sender = sender;
  entry->target.recipient = recipient;
  entry->timestamp = TStime();
  
  /* Mark both sender and recipient as having messages on hold */
  SetSpamHold(sender);
  SetSpamHold(recipient);
  
  /* Duplicate strings */
  DupString(entry->text, text);
  if (captures)
    DupString(entry->captures, captures);
  else
    entry->captures = NULL;

  /* Add to global hold queue */
  entry->next = GlobalHoldQueue;
  entry->prev_p = &GlobalHoldQueue;
  if (GlobalHoldQueue)
    GlobalHoldQueue->prev_p = &entry->next;
  GlobalHoldQueue = entry;

  /* Update statistics */
  sline_stats_counters.messages_held++;

  Debug((DEBUG_DEBUG, "sline_hold_privmsg: assigned token %u", entry->token));
  return entry;
}

/** Add a channel message to the hold queue.
 * @param[in] sender Client who sent the message.
 * @param[in] channel Channel where message was sent.
 * @param[in] text Message text.
 * @param[in] captures S-line regex captures (can be NULL).
 * @param[in] cmd_type Type of command (MSG_PRIVATE, MSG_NOTICE, MSG_WALLCHOPS, MSG_WALLVOICES).
 * @return Pointer to the created hold queue entry, or NULL on failure.
 */
static struct HoldQueueEntry *
sline_hold_chanmsg(struct Client *sender, struct Channel *channel,
                   const char *text, const char *captures, const char* cmd_type)
{
  assert(sender);
  assert(channel);

  struct HoldQueueEntry *entry;
  
  if (!sender || !channel || !text)
    return NULL;

  Debug((DEBUG_DEBUG, "sline_hold_chanmsg: holding %s from %s to %s: '%s'", 
         cmd_type, cli_name(sender), channel->chname, text));

  /* Allocate new hold queue entry */
  entry = (struct HoldQueueEntry *)MyMalloc(sizeof(struct HoldQueueEntry));
  if (!entry)
    return NULL;

  /* Initialize entry */
  entry->token = next_hold_token++;
  entry->msgtype = SLINE_CHANNEL;
  entry->cmdtype = cmd_type;
  entry->sender = sender;
  entry->target.channel = channel;
  entry->timestamp = TStime();
  
  /* Mark sender as having messages on hold */
  SetSpamHold(sender);
  
  /* Duplicate strings */
  DupString(entry->text, text);
  if (captures)
    DupString(entry->captures, captures);
  else
    entry->captures = NULL;

  /* Add to global hold queue */
  entry->next = GlobalHoldQueue;
  entry->prev_p = &GlobalHoldQueue;
  if (GlobalHoldQueue)
    GlobalHoldQueue->prev_p = &entry->next;
  GlobalHoldQueue = entry;

  /* Update statistics */
  sline_stats_counters.messages_held++;

  Debug((DEBUG_DEBUG, "sline_hold_chanmsg: assigned token %u", entry->token));
  return entry;
}

/** Check if a client has any messages on hold and clear FLAG_SPAMHOLD if not.
 * This is called when removing a hold queue entry to efficiently manage the flag.
 * @param[in] cptr Client to check and potentially clear flag for.
 */
static void
sline_check_clear_spamhold(struct Client *cptr)
{
  assert(cptr);

  struct HoldQueueEntry *entry;
  
  if (!cptr || !IsSpamHold(cptr))
    return;
  
  /* Check if this client is referenced in any remaining hold queue entries */
  for (entry = GlobalHoldQueue; entry; entry = entry->next) {
    if (entry->sender == cptr)
      return; /* Still has messages on hold as sender */
    
    if (entry->msgtype == SLINE_PRIVATE && 
        entry->target.recipient == cptr)
      return; /* Still has messages on hold as recipient */
  }
  
  /* No more hold queue entries reference this client */
  ClearSpamHold(cptr);
  Debug((DEBUG_DEBUG, "sline_check_clear_spamhold: cleared FLAG_SPAMHOLD for %s", cli_name(cptr)));
}

/** Remove and free a hold queue entry.
 * @param[in] entry Hold queue entry to remove.
 */
static void
sline_hold_free(struct HoldQueueEntry *entry)
{
  assert(entry);

  struct Client *sender, *recipient;
  
  if (!entry)
    return;

  Debug((DEBUG_DEBUG, "sline_hold_free: removing token %u", entry->token));

  /* Store references for FLAG_SPAMHOLD cleanup */
  sender = entry->sender;
  recipient = NULL;
  if (entry->msgtype == SLINE_PRIVATE)
    recipient = entry->target.recipient;

  /* Remove from linked list */
  *entry->prev_p = entry->next;
  if (entry->next)
    entry->next->prev_p = entry->prev_p;

  /* Free allocated strings */
  MyFree(entry->text);
  if (entry->captures)
    MyFree(entry->captures);
  
  /* Free the entry itself */
  MyFree(entry);
  
  /* Check if FLAG_SPAMHOLD should be cleared for affected clients */
  if (sender)
    sline_check_clear_spamhold(sender);
  if (recipient)
    sline_check_clear_spamhold(recipient);
}

/** Helper function to check S-line and handle private messages.
 * @param[in] sender Client who sent the message.
 * @param[in] recipient Client who should receive the message.
 * @param[in] text Message text to check against S-lines.
 * @param[in] cmd_type Message type (MSG_PRIVATE, MSG_NOTICE).
 * @return 1 if message was held (S-line matched), 0 if message should be delivered normally.
 */
int
sline_check_privmsg(struct Client *sender, struct Client *recipient, const char *text, const char* cmd_type)
{
  assert(sender);
  assert(recipient);
  assert(text);

  char *captures;
  struct HoldQueueEntry *entry;

  if (!sender || !recipient || !text || IsAnOper(sender) || !sline_is_enabled())
    return 0;

  Debug((DEBUG_DEBUG, "sline_check_privmsg: checking %s from %s to %s: '%s'", 
         cmd_type, cli_name(sender), cli_name(recipient), text));

  /* Check if message matches any S-line patterns for private messages */
  captures = sline_check_pattern(text, SLINE_PRIVATE);
  if (!captures) {
    Debug((DEBUG_DEBUG, "sline_check_privmsg: no S-line match, allowing message"));
    return 0; /* No match, allow message to be delivered */
  }

  Debug((DEBUG_DEBUG, "sline_check_privmsg: S-line matched, captures: '%s'", captures));

  /* S-line matched, add to hold queue */
  entry = sline_hold_privmsg(sender, recipient, text, captures, cmd_type);
  if (!entry) {
    Debug((DEBUG_DEBUG, "sline_check_privmsg: failed to add to hold queue"));
    MyFree(captures);
    return 0; /* Failed to hold, allow delivery */
  }

  /* Notify spam filter servers */
  sline_notify_spamfilter(entry);

  /* Clean up */
  MyFree(captures);

  Debug((DEBUG_DEBUG, "sline_check_privmsg: message held with token %u", entry->token));
  return 1; /* Message was held */
}

/** Helper function to check S-line and handle channel messages.
 * @param[in] sender Client who sent the message.
 * @param[in] channel Channel where message was sent.
 * @param[in] text Message text to check against S-lines.
 * @param[in] cmd_type Message type (MSG_PRIVATE, MSG_NOTICE, MSG_WALLCHOPS, MSG_WALLVOICES).
 * @return 1 if message was held (S-line matched), 0 if message should be delivered normally.
 */
int
sline_check_chanmsg(struct Client *sender, struct Channel *channel, const char *text, const char* cmd_type)
{
  assert(sender);
  assert(channel);
  assert(text);

  char *captures;
  struct HoldQueueEntry *entry;
  
  if (!sender || !channel || !text || IsAnOper(sender) || !sline_is_enabled())
    return 0;

  Debug((DEBUG_DEBUG, "sline_check_chanmsg: checking %s from %s to %s: '%s'", 
         cmd_type, cli_name(sender), channel->chname, text));

  /* Check if message matches any S-line patterns for channel messages */
  captures = sline_check_pattern(text, SLINE_CHANNEL);
  if (!captures) {
    Debug((DEBUG_DEBUG, "sline_check_chanmsg: no S-line match, allowing message"));
    return 0; /* No match, allow message to be delivered */
  }

  Debug((DEBUG_DEBUG, "sline_check_chanmsg: S-line matched, captures: '%s'", captures));

  /* S-line matched, add to hold queue */
  entry = sline_hold_chanmsg(sender, channel, text, captures, cmd_type);
  if (!entry) {
    Debug((DEBUG_DEBUG, "sline_check_chanmsg: failed to add to hold queue"));
    MyFree(captures);
    return 0; /* Failed to hold, allow delivery */
  }

  /* Notify spam filter servers */
  sline_notify_spamfilter(entry);

  /* Clean up */
  MyFree(captures);

  Debug((DEBUG_DEBUG, "sline_check_chanmsg: message held with token %u", entry->token));
  return 1; /* Message was held */
}

/** Find a hold queue entry by token.
 * @param[in] token Token to search for.
 * @return Pointer to hold queue entry if found, NULL otherwise.
 */
static struct HoldQueueEntry *
sline_find_hold_entry(unsigned int token)
{
  struct HoldQueueEntry *entry;
  
  for (entry = GlobalHoldQueue; entry; entry = entry->next) {
    if (entry->token == token)
      return entry;
  }
  
  return NULL;
}

/** Release a private message from the hold queue and deliver it.
 * @param[in] entry Hold queue entry to release.
 * @return 1 if message was delivered, 0 if there was an error.
 */
static int
sline_release_privmsg(struct HoldQueueEntry *entry)
{
  assert(entry != NULL);
  assert(entry->sender != NULL);
  assert(entry->target.recipient != NULL);
  assert(entry->text != NULL);
  assert(entry->msgtype == SLINE_PRIVATE);
  
  if (!entry || entry->msgtype != SLINE_PRIVATE || !entry->sender || !entry->target.recipient || !entry->text)
    return 0;

  Debug((DEBUG_DEBUG, "sline_release_privmsg: releasing token %u from %s to %s", 
         entry->token, cli_name(entry->sender), cli_name(entry->target.recipient)));

  /* Check if the sender and recipient are still valid */
  if (!IsUser(entry->sender) || !IsUser(entry->target.recipient)) {
    Debug((DEBUG_DEBUG, "sline_release_privmsg: sender or recipient no longer valid"));
    return 0;
  }

  /* Check silence list */
  if (is_silenced(entry->sender, entry->target.recipient)) {
    Debug((DEBUG_DEBUG, "sline_release_privmsg: sender is silenced by recipient"));
    return 0;
  }

  /* Send away message if user is away */
  if (cli_user(entry->target.recipient) && cli_user(entry->target.recipient)->away)
    send_reply(entry->sender, RPL_AWAY, cli_name(entry->target.recipient), cli_user(entry->target.recipient)->away);

  /* Deliver the message */
  if (MyUser(entry->target.recipient))
    add_target(entry->target.recipient, entry->sender);

  sendcmdto_one(entry->sender, entry->cmdtype == MSG_NOTICE ? CMD_NOTICE : CMD_PRIVATE, entry->target.recipient, "%C :%s", entry->target.recipient, entry->text);
  if (CapHas(cli_active(entry->sender), CAP_ECHOMESSAGE))
    sendcmdto_one(entry->sender, entry->cmdtype == MSG_NOTICE ? CMD_NOTICE : CMD_PRIVATE, cli_from(entry->sender), "%C :%s", entry->target.recipient, entry->text);

  Debug((DEBUG_DEBUG, "sline_release_privmsg: message delivered successfully"));
  return 1;
}

/** Release a channel message from the hold queue and deliver it.
 * @param[in] entry Hold queue entry to release.
 * @return 1 if message was delivered, 0 if there was an error.
 */
static int
sline_release_chanmsg(struct HoldQueueEntry *entry)
{
  assert(entry != NULL);
  assert(entry->sender != NULL);
  assert(entry->target.channel != NULL);
  assert(entry->text != NULL);
  assert(entry->msgtype == SLINE_CHANNEL);

  if (!entry || entry->msgtype != SLINE_CHANNEL || !entry->sender || !entry->target.channel || !entry->text)
    return 0;

  Debug((DEBUG_DEBUG, "sline_release_chanmsg: releasing token %u from %s to %s", 
         entry->token, cli_name(entry->sender), entry->target.channel->chname));

  /* Check if the sender and channel are still valid */
  if (!IsUser(entry->sender) || !entry->target.channel->chname) {
    Debug((DEBUG_DEBUG, "sline_release_chanmsg: sender or channel no longer valid"));
    return 0;
  }

  /* Check if sender can still send to channel */
  if (!client_can_send_to_channel(entry->sender, entry->target.channel, 0)) {
    Debug((DEBUG_DEBUG, "sline_release_chanmsg: sender can no longer send to channel"));
    return 0;
  }

  /* Reveal delayed join if needed */
  RevealDelayedJoinIfNeeded(entry->sender, entry->target.channel);

  /* Deliver the message */
  if (entry->cmdtype == MSG_NOTICE || entry->cmdtype == MSG_PRIVATE) {
    sendcmdto_channel_butone(entry->sender, entry->cmdtype == MSG_NOTICE ? CMD_NOTICE : CMD_PRIVATE,
                             entry->target.channel, cli_from(entry->sender),
                             SKIP_DEAF | SKIP_BURST, "%H :%s", entry->target.channel, entry->text);
    if (CapHas(cli_active(entry->sender), CAP_ECHOMESSAGE))
      sendcmdto_one(entry->sender, entry->cmdtype == MSG_NOTICE ? CMD_NOTICE : CMD_PRIVATE,
                    cli_from(entry->sender), "%H :%s", entry->target.channel, entry->text);
  } else if (entry->cmdtype == MSG_WALLVOICES) {
    sendcmdto_channel_butone(entry->sender, CMD_WALLVOICES, entry->target.channel, cli_from(entry->sender),
                             SKIP_DEAF | SKIP_BURST | SKIP_NONVOICES, 
                             "%H :+ %s", entry->target.channel, entry->text);
    if (CapHas(cli_active(entry->sender), CAP_ECHOMESSAGE))
      sendcmdto_one(entry->sender, CMD_NOTICE, cli_from(entry->sender), // Sending CMD_NOTICE since CMD_WALLVOICES is translated into CMD_NOTICE in sendcmdto_channel_butone()
                    "@%H :+ %s", entry->target.channel, entry->text);
  } else if (entry->cmdtype == MSG_WALLCHOPS) {
    sendcmdto_channel_butone(entry->sender, CMD_WALLCHOPS, entry->target.channel, cli_from(entry->sender),
                             SKIP_DEAF | SKIP_BURST | SKIP_NONOPS,
                             "%H :@ %s", entry->target.channel, entry->text);
    if (CapHas(cli_active(entry->sender), CAP_ECHOMESSAGE))
    sendcmdto_one(entry->sender, CMD_NOTICE, cli_from(entry->sender), // Sending CMD_NOTICE since CMD_WALLCHOPS is translated into CMD_NOTICE in sendcmdto_channel_butone()
                  "@%H :@ %s", entry->target.channel, entry->text);
  }

  Debug((DEBUG_DEBUG, "sline_release_chanmsg: message delivered successfully"));
  return 1;
}

/** Release a message from the hold queue by token.
 * @param[in] token Token of the message to release.
 * @return 1 if message was found and delivered, 0 otherwise.
 */
static int
sline_release_hold(unsigned int token)
{
  struct HoldQueueEntry *entry;
  int result = 0;

  Debug((DEBUG_DEBUG, "sline_release_hold: attempting to release token %u", token));

  entry = sline_find_hold_entry(token);
  if (!entry) {
    Debug((DEBUG_DEBUG, "sline_release_hold: token %u not found in hold queue", token));
    return 0;
  }

  /* Release based on message type */
  if (entry->msgtype == SLINE_PRIVATE) {
    result = sline_release_privmsg(entry);
  } else if (entry->msgtype == SLINE_CHANNEL) {
    result = sline_release_chanmsg(entry);
  } else {
    Debug((DEBUG_DEBUG, "sline_release_hold: unknown message type %d for token %u", entry->msgtype, token));
  }

  /* Remove from hold queue regardless of delivery result */
  sline_hold_free(entry);

  return result;
}

/** Block a held message and send appropriate error to sender.
 * @param[in] entry Hold queue entry to block.
 */
static void
sline_block_message(struct HoldQueueEntry *entry)
{
  assert(entry);

  if (!entry || !entry->sender || !IsUser(entry->sender))
    return;

  Debug((DEBUG_DEBUG, "sline_block_message: blocking token %u", entry->token));

  /* Send error to sender based on message type */
  if (entry->msgtype == SLINE_PRIVATE) {
    /* Private message - send ERR_NOSUCHNICK */
    if (entry->target.recipient) {
      send_reply(entry->sender, ERR_NOSUCHNICK, cli_name(entry->target.recipient));
      Debug((DEBUG_DEBUG, "sline_block_message: sent ERR_NOSUCHNICK to %s for %s", 
             cli_name(entry->sender), cli_name(entry->target.recipient)));
    }
  } else if (entry->msgtype == SLINE_CHANNEL) {
    /* Channel message - send ERR_CANNOTSENDTOCHAN */
    if (entry->target.channel) {
      send_reply(entry->sender, ERR_CANNOTSENDTOCHAN, entry->target.channel->chname);
      Debug((DEBUG_DEBUG, "sline_block_message: sent ERR_CANNOTSENDTOCHAN to %s for %s", 
             cli_name(entry->sender), entry->target.channel->chname));
    }
  }
}

/** Handle XREPLY response from spam filter servers.
 * @param[in] sptr Client that sent the XREPLY.
 * @param[in] token Token string of the held message.
 * @param[in] reply Reply string - "YES" to release, "NO" to drop.
 * @return 1 if message was found and processed, 0 otherwise.
 */
int
sline_xreply_handler(struct Client *sptr, const char *token, const char *reply)
{
  struct HoldQueueEntry *entry;
  unsigned int token_num;
  int should_release;
  
  if (!sptr || !token || !reply) {
    Debug((DEBUG_DEBUG, "sline_xreply_handler: invalid parameters"));
    return 0;
  }
  
  /* Convert token string to number */
  token_num = atoi(token);
  if (token_num == 0 && strcmp(token, "0") != 0) {
    Debug((DEBUG_DEBUG, "sline_xreply_handler: invalid token '%s' from %s", token, cli_name(sptr)));
    return 0;
  }
  
  /* Determine action based on reply */
  if (ircd_strcmp(reply, "YES") == 0) {
    should_release = 1;
    sline_stats_counters.xreply_accepted++; /* Increment accepted counter */
  } else if (ircd_strcmp(reply, "NO") == 0) {
    should_release = 0;
    sline_stats_counters.xreply_rejected++; /* Increment rejected counter */
  } else {
    Debug((DEBUG_DEBUG, "sline_xreply_handler: invalid reply '%s' from %s for token %u", reply, cli_name(sptr), token_num));
    return 0;
  }
  
  Debug((DEBUG_DEBUG, "sline_xreply_handler: processing %s for token %u from %s", reply, token_num, cli_name(sptr)));
  
  /* Find the hold queue entry */
  entry = sline_find_hold_entry(token_num);
  if (!entry) {
    Debug((DEBUG_DEBUG, "sline_xreply_handler: token %u not found in hold queue", token_num));
    return 0;
  }
  
  if (should_release) {
    /* Release the message */
    Debug((DEBUG_DEBUG, "sline_xreply_handler: releasing token %u", token_num));
    sline_stats_counters.messages_released++; /* Increment released counter */
    if (sline_release_hold(token_num)) {
      Debug((DEBUG_DEBUG, "sline_xreply_handler: successfully released token %u", token_num));
    } else {
      Debug((DEBUG_DEBUG, "sline_xreply_handler: failed to release token %u", token_num));
    }
  } else {
    /* Drop the message and send appropriate error */
    Debug((DEBUG_DEBUG, "sline_xreply_handler: dropping token %u and sending error", token_num));
    sline_stats_counters.messages_blocked++; /* Increment blocked counter */
    
    /* Block the message using helper function */
    sline_block_message(entry);
    
    /* Drop the message */
    sline_hold_free(entry);
  }
  
  return 1;
}

/** Clean up hold queue entries for a disconnecting client.
 * This should be called when a client disconnects to remove any
 * hold queue entries that reference that client.
 * @param[in] cptr Client that is disconnecting.
 */
void
sline_cleanup_client(struct Client *cptr)
{
  assert(cptr);

  struct HoldQueueEntry *entry, *next_entry;
  int cleaned = 0;
  
  Debug((DEBUG_DEBUG, "sline_cleanup_client: cleaning up hold queue for %s", cli_name(cptr)));
  
  for (entry = GlobalHoldQueue; entry; entry = next_entry) {
    next_entry = entry->next;
    
    /* Check if this entry references the disconnecting client */
    if (entry->sender == cptr || 
        (entry->msgtype == SLINE_PRIVATE && entry->target.recipient == cptr)) {
      
      Debug((DEBUG_DEBUG, "sline_cleanup_client: removing hold entry token %u", entry->token));
      sline_hold_free(entry);
      cleaned++;
    }
  }
  
  if (cleaned > 0) {
    Debug((DEBUG_DEBUG, "sline_cleanup_client: cleaned %d hold queue entries for %s", cleaned, cli_name(cptr)));
  }
}

/** Clean up hold queue entries for a channel being destroyed.
 * This should be called when a channel is destroyed to remove any
 * hold queue entries that reference that channel.
 * @param[in] chptr Channel that is being destroyed.
 */
void
sline_cleanup_channel(struct Channel *chptr)
{
  assert(chptr);
  
  struct HoldQueueEntry *entry, *next_entry;
  int cleaned = 0;
  
  Debug((DEBUG_DEBUG, "sline_cleanup_channel: cleaning up hold queue for %s", chptr->chname));
  
  for (entry = GlobalHoldQueue; entry; entry = next_entry) {
    next_entry = entry->next;
    
    /* Check if this entry references the channel being destroyed */
    if (entry->msgtype == SLINE_CHANNEL && entry->target.channel == chptr) {
      Debug((DEBUG_DEBUG, "sline_cleanup_channel: removing hold entry token %u", entry->token));
      sline_hold_free(entry);
      cleaned++;
    }
  }
  
  if (cleaned > 0) {
    Debug((DEBUG_DEBUG, "sline_cleanup_channel: cleaned %d hold queue entries for %s", cleaned, chptr->chname));
  }
}

/** Timer callback to check and remove expired hold queue entries.
 * @param[in] ev Event structure for the timer event.
 */
static void
sline_hold_timeout_callback(struct Event* ev)
{
  struct HoldQueueEntry *entry, *next_entry;
  time_t current_time = TStime();
  
  /* Iterate over hold queue and find expired entries */
  for (entry = GlobalHoldQueue; entry; entry = next_entry) {
    next_entry = entry->next;

    /* Check if entry is expired */
    if (entry->timestamp + netconf_int(NETCONF_SLINE_HOLD_TIMEOUT) <= current_time) {
      Debug((DEBUG_DEBUG, "sline_hold_timeout_callback: processing expired hold entry token %u", entry->token));
      
      /* Increment timeout counter */
      sline_stats_counters.timeout_expired++;
      
      /* Check if we should block or release expired messages */
      if (netconf_bool(NETCONF_SLINE_HOLD_TIMEOUT_BLOCK)) {
        /* Block the message (default behavior) - send timeout error to sender */
        Debug((DEBUG_DEBUG, "sline_hold_timeout_callback: blocking expired token %u", entry->token));
        sline_stats_counters.messages_blocked++; /* Increment blocked counter */
        
        /* Block the message using helper function */
        sline_block_message(entry);
        
        /* Remove the entry */
        sline_hold_free(entry);
      } else {
        /* Release the message (allow it to be delivered) */
        Debug((DEBUG_DEBUG, "sline_hold_timeout_callback: releasing expired token %u", entry->token));
        sline_stats_counters.messages_released++; /* Increment released counter */
        
        if (sline_release_hold(entry->token)) {
          Debug((DEBUG_DEBUG, "sline_hold_timeout_callback: successfully released expired token %u", entry->token));
        } else {
          Debug((DEBUG_DEBUG, "sline_hold_timeout_callback: failed to release expired token %u, removing entry", entry->token));
          sline_hold_free(entry);
        }
      }
    }
  }
}

/** Initialize the S-line subsystem.
 * This should be called during server initialization to start the
 * hold queue timeout timer.
 */
void
sline_init(void)
{
  timer_add(timer_init(&hold_timeout_timer), sline_hold_timeout_callback, 0, TT_PERIODIC, 10);
}
