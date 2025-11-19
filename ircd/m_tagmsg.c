/*
 * IRC - Internet Relay Chat, ircd/m_tagmsg.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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

/** @file
 * @brief Handlers for TAGMSG command (IRCv3 message-tags).
 * @version $Id$
 */

#include "config.h"

#include "capab.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

/* Forward declaration */
int ms_tagmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[]);

/* Limits (conservative) */
#define TAGMSG_LINE_TAGS_MAX   1024   /**< total length of tag segment */
#define TAGMSG_KEY_MAX         64     /**< max length of a tag key */
#define TAGMSG_VALUE_MAX       256    /**< max length of a tag value */
#define TAGMSG_COUNT_MAX       64     /**< max number of tags */

/** Check if character is valid in a tag key.
 * @param[in] c Character to check.
 * @return Non-zero if valid, zero otherwise.
 */
static int valid_tag_key_char(int c)
{
  return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '-' || c == '/' || c == '+' || c == '.');
}

/** Validate and normalize tag string.
 * Tags are modified in-place to decode escape sequences.
 * @param[in,out] tags Tag string to validate (modified in-place).
 * @return 0 on success, -1 on validation error.
 */
static int validate_and_normalize_tags(char *tags)
{
  if (!tags || *tags != '@')
    return 0; /* no tag prefix */

  char *p = tags + 1; /* skip leading '@' */
  int tag_count = 0;
  
  while (*p) {
    if (tag_count++ >= TAGMSG_COUNT_MAX)
      return -1;
      
    char *key_start = p;
    while (*p && *p != '=' && *p != ';') {
      if (!valid_tag_key_char((unsigned char)*p))
        return -1;
      if ((p - key_start) >= TAGMSG_KEY_MAX)
        return -1;
      p++;
    }
    
    if (*p == '=') {
      p++; /* value start */
      char *val_start = p;
      char *write = p; /* decode escape sequences */
      
      while (*p && *p != ';') {
        if (*p == '\\') { /* escape */
          p++;
          if (*p == ':' || *p == 's' || *p == 'r' || *p == 'n' || *p == '\\') {
            /* Decode IRCv3 tag escapes */
            switch (*p) {
              case ':':  *write++ = ';';  break;
              case 's':  *write++ = ' ';  break;
              case 'r':  *write++ = '\r'; break;
              case 'n':  *write++ = '\n'; break;
              case '\\': *write++ = '\\'; break;
            }
            p++;
          } else if (*p) {
            /* unknown escape, keep char if present */
            *write++ = *p++;
          }
        } else {
          *write++ = *p++;
        }
        
        if ((write - val_start) >= TAGMSG_VALUE_MAX)
          return -1;
      }
      
      *write = '\0';
      p = (*p == ';') ? p + 1 : p; /* skip separator */
    } else if (*p == ';') {
      /* key-only tag */
      p++;
    } else {
      /* end of string after a key-only tag */
      break;
    }
  }
  
  return 0;
}

/** Handle TAGMSG from local clients.
 * @param[in] cptr Client that sent the command.
 * @param[in] sptr Original source of the command.
 * @param[in] parc Number of parameters.
 * @param[in] parv Parameter array. parv[1] = target
 */
int m_tagmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *tags;
  struct Channel *chptr;
  struct Client *acptr;

  /* After parser shift: parv[1]=tags, parv[2]=target */
  if (parc < 3 || EmptyString(parv[1]) || EmptyString(parv[2]))
    return need_more_params(sptr, "TAGMSG");

  /* Check if capability is negotiated */
  if (!feature_bool(FEAT_CAP_MESSAGETAGS) || !CapActive(sptr, CAP_MESSAGETAGS))
    return 0;

  /* Get tags from parv[1] (inserted by parser) */
  tags = parv[1];
  
  /* Validate tag length */
  if (strlen(tags) > TAGMSG_LINE_TAGS_MAX)
    return 0; /* silently drop oversized tag block */

  /* Validate and normalize tags */
  if (validate_and_normalize_tags(tags) != 0)
    return 0; /* invalid tag syntax */

  /* Apply per-client TAGMSG rate limiting for local users */
  if (MyUser(sptr)) {
    time_t now = CurrentTime;
    int win = feature_int(FEAT_TAGMSG_WINDOW_SECONDS);
    int max = feature_int(FEAT_TAGMSG_MAX_PER_WINDOW);
    
    if (win < 1) win = 1; /* safety */
    if (max < 1) max = 1;
    
    if (cli_tagmsg_window(sptr) + win > now) {
      /* same window */
      if (cli_tagmsg_count(sptr) + 1 > (unsigned int)max) {
        /* Silently drop excess TAGMSG */
        return 0;
      }
      cli_tagmsg_count(sptr)++;
    } else {
      /* start a new window */
      cli_tagmsg_window(sptr) = now;
      cli_tagmsg_count(sptr) = 1;
    }
  }

  /* Find target (now in parv[2] after parser shift) */
  if (IsChannelName(parv[2])) {
    if (!(chptr = FindChannel(parv[2])))
      return 0; /* No such channel */

    /* Check permissions */
    if (!client_can_send_to_channel(sptr, chptr, 0))
      return 0;

    /* Send to channel members with message-tags capability */
    sendcmdto_channel_tagmsg(sptr, chptr, cptr, tags);
  } else {
    if (!(acptr = FindUser(parv[2])))
      return 0; /* No such nick */

    /* Check if silenced */
    if (is_silenced(sptr, acptr))
      return 0;

    /* Send to user if they have message-tags capability */
    sendcmdto_user_tagmsg(sptr, acptr, cptr, tags);
  }

  return 0;
}

/** Handle TAGMSG from unregistered connections.
 * @param[in] cptr Client that sent the command.
 * @param[in] sptr Original source of the command.
 * @param[in] parc Number of parameters.
 * @param[in] parv Parameter array.
 */
int mu_tagmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  /* If this is a server in handshake state, route through server handler */
  if (IsHandshake(cptr) || IsServer(cptr))
    return ms_tagmsg(cptr, sptr, parc, parv);

  /* Unregistered clients cannot send TAGMSG */
  return send_reply(sptr, ERR_NOTREGISTERED);
}

/** Handle TAGMSG from servers.
 * @param[in] cptr Client that sent the command.
 * @param[in] sptr Original source of the command.
 * @param[in] parc Number of parameters.
 * @param[in] parv Parameter array. parv[1] = target
 */
int ms_tagmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  struct Client *acptr;
  char *tags;

  /* After parser shift: parv[1]=tags, parv[2]=target */
  if (parc < 3)
    return need_more_params(sptr, "TAGMSG");

  if (!feature_bool(FEAT_CAP_MESSAGETAGS))
    return 0;

  /* Trust upstream server validation */
  tags = parv[1];

  /* Find target and forward */
  if (IsChannelName(parv[2])) {
    if ((chptr = FindChannel(parv[2])))
      sendcmdto_channel_tagmsg(sptr, chptr, cptr, tags);
  } else {
    if ((acptr = FindUser(parv[2])))
      sendcmdto_user_tagmsg(sptr, acptr, cptr, tags);
  }

  return 0;
}
