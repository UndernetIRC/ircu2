/*
 * IRC - Internet Relay Chat, ircd/ircd_relay.c
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
 */
/** @file
 * @brief Helper functions to relay various types of messages.
 * @version $Id$
 *
 * There are four basic types of messages, each with four subtypes.
 *
 * The basic types are: channel, directed, masked, and private.
 * Channel messages are (perhaps obviously) sent directly to a
 * channel.  Directed messages are sent to "NICK[%host]@server", but
 * only allowed if the server is a services server (to avoid
 * information leaks for normal clients).  Masked messages are sent to
 * either *@*host.mask or *.server.mask.  Private messages are sent to
 * NICK.
 *
 * The subtypes for each type are: client message, client notice,
 * server message, and server notice.  Client subtypes are sent by a
 * local user, and server subtypes are given to us by a server.
 * Notice subtypes correspond to the NOTICE command, and message
 * subtypes correspond to the PRIVMSG command.
 *
 * As a special note, directed messages do not have server subtypes,
 * since there is no difference in handling them based on origin.
 */
#include "config.h"

#include "ircd_relay.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * This file contains message relaying functions for client and server
 * private messages and notices
 * TODO: This file contains a lot of cut and paste code, and needs
 * to be cleaned up a bit. The idea is to factor out the common checks
 * but not introduce any IsOper/IsUser/MyUser/IsServer etc. stuff.
 */

/** Relay a local user's message to a channel.
 * Generates an error if the client cannot send to the channel.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Name of target channel.
 * @param[in] text %Message to relay.
 */
void relay_channel_message(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  const char *ch;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (chptr = FindChannel(name))) {
    send_reply(sptr, ERR_NOSUCHCHANNEL, name);
    return;
  }
  /*
   * This first: Almost never a server/service
   */
  if (!client_can_send_to_channel(sptr, chptr, 0)) {
    send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
    return;
  }
  if ((chptr->mode.mode & MODE_NOPRIVMSGS) &&
      check_target_limit(sptr, chptr, chptr->chname, 0))
    return;

  if (chptr->mode.mode & MODE_NOCOLOR) {
    for (ch = text; *ch != '\0'; ++ch) {
      if (*ch == 3 || *ch == 27) {
        send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
        return;
      }
    }
  }

  if ((chptr->mode.mode & MODE_NOCTCP) && ircd_strncmp(text, "\001ACTION ", 8)) {
    for (ch = text; *ch != '\0'; ++ch) {
      if (*ch == 1) {
        send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
        return;
      }
    }
  }

  RevealDelayedJoinIfNeeded(sptr, chptr);
  sendcmdto_channel_butone(sptr, CMD_PRIVATE, chptr, cli_from(sptr),
			   SKIP_DEAF | SKIP_BURST, "%H :%s", chptr, text);
}

/** Relay a local user's notice to a channel.
 * Silently exits if the client cannot send to the channel.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Name of target channel.
 * @param[in] text %Message to relay.
 */
void relay_channel_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  const char *ch;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (chptr = FindChannel(name)))
    return;
  /*
   * This first: Almost never a server/service
   */
  if (!client_can_send_to_channel(sptr, chptr, 0))
    return;

  if ((chptr->mode.mode & MODE_NOPRIVMSGS) &&
      check_target_limit(sptr, chptr, chptr->chname, 0))
    return;

  if (chptr->mode.mode & MODE_NOCOLOR) {
    for (ch = text; *ch != '\0'; ++ch) {
      if (*ch == 3 || *ch == 27) {
        send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
        return;
      }
    }
  }

  if ((chptr->mode.mode & MODE_NOCTCP) && ircd_strncmp(text, "\001ACTION ", 8)) {
    for (ch = text; *ch != '\0'; ++ch) {
      if (*ch == 1) {
        send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
        return;
      }
    }
  }

  RevealDelayedJoinIfNeeded(sptr, chptr);
  sendcmdto_channel_butone(sptr, CMD_NOTICE, chptr, cli_from(sptr),
			   SKIP_DEAF | SKIP_BURST, "%H :%s", chptr, text);
}

/** Relay a message to a channel.
 * Generates an error if the client cannot send to the channel,
 * or if the channel is a local channel
 * @param[in] sptr Client that originated the message.
 * @param[in] name Name of target channel.
 * @param[in] text %Message to relay.
 */
void server_relay_channel_message(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (IsLocalChannel(name) || 0 == (chptr = FindChannel(name))) {
    send_reply(sptr, ERR_NOSUCHCHANNEL, name);
    return;
  }
  /*
   * This first: Almost never a server/service
   * Servers may have channel services, need to check for it here
   */
  if (client_can_send_to_channel(sptr, chptr, 1) || IsChannelService(sptr)) {
    sendcmdto_channel_butone(sptr, CMD_PRIVATE, chptr, cli_from(sptr),
			     SKIP_DEAF | SKIP_BURST, "%H :%s", chptr, text);
  }
  else
    send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
}

/** Relay a notice to a channel.
 * Generates an error if the client cannot send to the channel,
 * or if the channel is a local channel
 * @param[in] sptr Client that originated the message.
 * @param[in] name Name of target channel.
 * @param[in] text %Message to relay.
 */
void server_relay_channel_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (IsLocalChannel(name) || 0 == (chptr = FindChannel(name)))
    return;
  /*
   * This first: Almost never a server/service
   * Servers may have channel services, need to check for it here
   */
  if (client_can_send_to_channel(sptr, chptr, 1) || IsChannelService(sptr)) {
    sendcmdto_channel_butone(sptr, CMD_NOTICE, chptr, cli_from(sptr),
			     SKIP_DEAF | SKIP_BURST, "%H :%s", chptr, text);
  }
}

/** Relay a directed message.
 * Generates an error if the named server does not exist, if it is not
 * a services server, or if \a name names a local user and a hostmask
 * is specified but does not match.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Target nickname, with optional "%hostname" suffix.
 * @param[in] server Name of target server.
 * @param[in] text %Message to relay.
 */
void relay_directed_message(struct Client* sptr, char* name, char* server, const char* text)
{
  struct Client* acptr;
  char*          host;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  assert(0 != server);

  if ((acptr = FindServer(server + 1)) == NULL || !IsService(acptr))
  {
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }
  /*
   * NICK[%host]@server addressed? See if <server> is me first
   */
  if (!IsMe(acptr))
  {
    sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%s :%s", name, text);
    return;
  }
  /*
   * Look for an user whose NICK is equal to <name> and then
   * check if it's hostname matches <host> and if it's a local
   * user.
   */
  *server = '\0';
  if ((host = strchr(name, '%')))
    *host++ = '\0';

  /* As reported by Vampire-, it's possible to brute force finding users
   * by sending a message to each server and see which one succeeded.
   * This means we have to remove error reporting.  Sigh.  Better than
   * removing the ability to send directed messages to client servers 
   * Thanks for the suggestion Vampire=.  -- Isomer 2001-08-28
   * Argh, /ping nick@server, disallow messages to non +k clients :/  I hate
   * this. -- Isomer 2001-09-16
   */
  if (!(acptr = FindUser(name)) || !MyUser(acptr) ||
      (!EmptyString(host) && 0 != match(host, cli_user(acptr)->host)) ||
      !IsChannelService(acptr))
  {
    /*
     * By this stage we might as well not bother because they will
     * know that this server is currently linked because of the
     * increased lag.
     */
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }

  *server = '@';
  if (host)
    *--host = '%';

  if (!(is_silenced(sptr, acptr)))
    sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%s :%s", name, text);
}

/** Relay a directed notice.
 * Generates an error if the named server does not exist, if it is not
 * a services server, or if \a name names a local user and a hostmask
 * is specified but does not match.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Target nickname, with optional "%hostname" suffix.
 * @param[in] server Name of target server.
 * @param[in] text %Message to relay.
 */
void relay_directed_notice(struct Client* sptr, char* name, char* server, const char* text)
{
  struct Client* acptr;
  char*          host;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  assert(0 != server);

  if (0 == (acptr = FindServer(server + 1)))
    return;
  /*
   * NICK[%host]@server addressed? See if <server> is me first
   */
  if (!IsMe(acptr)) {
    sendcmdto_one(sptr, CMD_NOTICE, acptr, "%s :%s", name, text);
    return;
  }
  /*
   * Look for an user whose NICK is equal to <name> and then
   * check if it's hostname matches <host> and if it's a local
   * user.
   */
  *server = '\0';
  if ((host = strchr(name, '%')))
    *host++ = '\0';

  if (!(acptr = FindUser(name)) || !MyUser(acptr) ||
      (!EmptyString(host) && 0 != match(host, cli_user(acptr)->host)))
    return;

  *server = '@';
  if (host)
    *--host = '%';

  if (!(is_silenced(sptr, acptr)))
    sendcmdto_one(sptr, CMD_NOTICE, acptr, "%s :%s", name, text);
}

/** Relay a private message from a local user.
 * Returns an error if the user does not exist or sending to him would
 * exceed the source's free targets.  Sends an AWAY status message if
 * the target is marked as away.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Nickname of target user.
 * @param[in] text %Message to relay.
 */
void relay_private_message(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (acptr = FindUser(name))) {
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }
  if ((!IsChannelService(acptr) &&
       check_target_limit(sptr, acptr, cli_name(acptr), 0)) ||
      is_silenced(sptr, acptr))
    return;

  /*
   * send away message if user away
   */
  if (cli_user(acptr) && cli_user(acptr)->away)
    send_reply(sptr, RPL_AWAY, cli_name(acptr), cli_user(acptr)->away);
  /*
   * deliver the message
   */
  if (MyUser(acptr))
    add_target(acptr, sptr);

  sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%C :%s", acptr, text);
}

/** Relay a private notice from a local user.
 * Returns an error if the user does not exist or sending to him would
 * exceed the source's free targets.  Sends an AWAY status message if
 * the target is marked as away.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Nickname of target user.
 * @param[in] text %Message to relay.
 */
void relay_private_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (acptr = FindUser(name)))
    return;
  if ((!IsChannelService(acptr) && 
       check_target_limit(sptr, acptr, cli_name(acptr), 0)) ||
      is_silenced(sptr, acptr))
    return;
  /*
   * deliver the message
   */
  if (MyUser(acptr))
    add_target(acptr, sptr);

  sendcmdto_one(sptr, CMD_NOTICE, acptr, "%C :%s", acptr, text);
}

/** Relay a private message that arrived from a server.
 * Returns an error if the user does not exist.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Nickname of target user.
 * @param[in] text %Message to relay.
 */
void server_relay_private_message(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  /*
   * nickname addressed?
   */
  if (0 == (acptr = findNUser(name)) || !IsUser(acptr)) {
    send_reply(sptr, SND_EXPLICIT | ERR_NOSUCHNICK, "* :Target left %s. "
	       "Failed to deliver: [%.20s]", feature_str(FEAT_NETWORK),
               text);
    return;
  }
  if (is_silenced(sptr, acptr))
    return;

  if (MyUser(acptr))
    add_target(acptr, sptr);

  sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%C :%s", acptr, text);
}


/** Relay a private notice that arrived from a server.
 * Returns an error if the user does not exist.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Nickname of target user.
 * @param[in] text %Message to relay.
 */
void server_relay_private_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  /*
   * nickname addressed?
   */
  if (0 == (acptr = findNUser(name)) || !IsUser(acptr))
    return;

  if (is_silenced(sptr, acptr))
    return;

  if (MyUser(acptr))
    add_target(acptr, sptr);

  sendcmdto_one(sptr, CMD_NOTICE, acptr, "%C :%s", acptr, text);
}

/** Relay a masked message from a local user.
 * Sends an error response if there is no top-level domain label in \a
 * mask, or if that TLD contains a wildcard.
 * @param[in] sptr Client that originated the message.
 * @param[in] mask Target mask for the message.
 * @param[in] text %Message to relay.
 */
void relay_masked_message(struct Client* sptr, const char* mask, const char* text)
{
  const char* s;
  int   host_mask = 0;

  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);
  /*
   * look for the last '.' in mask and scan forward
   */
  if (0 == (s = strrchr(mask, '.'))) {
    send_reply(sptr, ERR_NOTOPLEVEL, mask);
    return;
  }
  while (*++s) {
    if (*s == '.' || *s == '*' || *s == '?')
       break;
  }
  if (*s == '*' || *s == '?') {
    send_reply(sptr, ERR_WILDTOPLEVEL, mask);
    return;
  }
  s = mask;
  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }

  sendcmdto_match_butone(sptr, CMD_PRIVATE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

/** Relay a masked notice from a local user.
 * Sends an error response if there is no top-level domain label in \a
 * mask, or if that TLD contains a wildcard.
 * @param[in] sptr Client that originated the message.
 * @param[in] mask Target mask for the message.
 * @param[in] text %Message to relay.
 */
void relay_masked_notice(struct Client* sptr, const char* mask, const char* text)
{
  const char* s;
  int   host_mask = 0;

  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);
  /*
   * look for the last '.' in mask and scan forward
   */
  if (0 == (s = strrchr(mask, '.'))) {
    send_reply(sptr, ERR_NOTOPLEVEL, mask);
    return;
  }
  while (*++s) {
    if (*s == '.' || *s == '*' || *s == '?')
       break;
  }
  if (*s == '*' || *s == '?') {
    send_reply(sptr, ERR_WILDTOPLEVEL, mask);
    return;
  }
  s = mask;
  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }

  sendcmdto_match_butone(sptr, CMD_NOTICE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

/** Relay a masked message that arrived from a server.
 * @param[in] sptr Client that originated the message.
 * @param[in] mask Target mask for the message.
 * @param[in] text %Message to relay.
 */
void server_relay_masked_message(struct Client* sptr, const char* mask, const char* text)
{
  const char* s = mask;
  int         host_mask = 0;
  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);

  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }
  sendcmdto_match_butone(sptr, CMD_PRIVATE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

/** Relay a masked notice that arrived from a server.
 * @param[in] sptr Client that originated the message.
 * @param[in] mask Target mask for the message.
 * @param[in] text %Message to relay.
 */
void server_relay_masked_notice(struct Client* sptr, const char* mask, const char* text)
{
  const char* s = mask;
  int         host_mask = 0;
  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);

  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }
  sendcmdto_match_butone(sptr, CMD_NOTICE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

