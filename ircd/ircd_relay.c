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
 *
 * $Id$
 */
#include "ircd_relay.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
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

#include <assert.h>
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
void relay_channel_message(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (chptr = FindChannel(name))) {
    send_error_to_client(sptr, ERR_NOSUCHCHANNEL, name);
    return;
  }
  /*
   * This first: Almost never a server/service
   */
  if (!client_can_send_to_channel(sptr, chptr)) {
    send_error_to_client(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
    return;
  }
  if ((chptr->mode.mode & MODE_NOPRIVMSGS) &&
      check_target_limit(sptr, chptr, chptr->chname, 0))
    return;

  sendmsgto_channel_butone(sptr->from, sptr, chptr, sptr->name,
                           TOK_PRIVATE, chptr->chname, text);
}

void relay_channel_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (chptr = FindChannel(name)))
    return;
  /*
   * This first: Almost never a server/service
   */
  if (!client_can_send_to_channel(sptr, chptr))
    return;

  if ((chptr->mode.mode & MODE_NOPRIVMSGS) &&
      check_target_limit(sptr, chptr, chptr->chname, 0))
    return;  

  sendmsgto_channel_butone(sptr->from, sptr, chptr, sptr->name,
                           TOK_NOTICE, chptr->chname, text);
}

void server_relay_channel_message(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (chptr = FindChannel(name))) {
    /*
     * XXX - do we need to send this back from a remote server?
     */
    send_error_to_client(sptr, ERR_NOSUCHCHANNEL, name);
    return;
  }
  /*
   * This first: Almost never a server/service
   * Servers may have channel services, need to check for it here
   */
  if (client_can_send_to_channel(sptr, chptr) || IsChannelService(sptr)) {
    sendmsgto_channel_butone(sptr->from, sptr, chptr, sptr->name,
                             TOK_PRIVATE, chptr->chname, text);
  }
  else
    send_error_to_client(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
}

void server_relay_channel_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (chptr = FindChannel(name)))
    return;
  /*
   * This first: Almost never a server/service
   * Servers may have channel services, need to check for it here
   */
  if (client_can_send_to_channel(sptr, chptr) || IsChannelService(sptr)) {
    sendmsgto_channel_butone(sptr->from, sptr, chptr, sptr->name,
                             TOK_NOTICE, chptr->chname, text);
  }
}


void relay_directed_message(struct Client* sptr, char* name, char* server, const char* text)
{
  struct Client* acptr;
  char*          host;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  assert(0 != server);

  if (0 == (acptr = FindServer(server + 1))) {
    send_error_to_client(sptr, ERR_NOSUCHNICK, name);
    return;
  }
  /*
   * NICK[%host]@server addressed? See if <server> is me first
   */
  if (!IsMe(acptr)) { /* thus remote client; use server<->server protocol */
    if (IsUser(sptr))
      sendto_one(acptr, "%s%s " TOK_PRIVATE " %s :%s", NumNick(sptr), name,
		 text);
    else
      sendto_one(acptr, "%s " TOK_PRIVATE " %s :%s", NumServ(sptr), name,
		 text);
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
   * This means we have to remove error reporting.  Sigh.   Better than
   * removing the ability to send directed messages to client servers
   * Thanks for the suggestion Vampire-.  -- Isomer 2001-08-28
   * Argh, /ping nick@server, disallow msgs to non +k clients :/  I hate this.
   *  -- Isomer 2001-09-16
   */
  if (!(acptr = FindUser(name)) || !MyUser(acptr) ||
      (!EmptyString(host) && 0 != match(host, acptr->user->host)) ||
      !IsChannelService(acptr)) {
#if 0
    send_error_to_client(sptr, ERR_NOSUCHNICK, name);
#endif
    return;
  }

  *server = '@';
  if (host)
    *--host = '%';

  if (!(is_silenced(sptr, acptr))) /* local client; use client<->server */
    sendto_prefix_one(acptr, sptr, ":%s %s %s :%s",
                      sptr->name, MSG_PRIVATE, name, text);
}

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
  if (!IsMe(acptr)) { /* thus remote client; use server<->server protocol */
    if (IsUser(sptr))
      sendto_one(acptr, "%s%s " TOK_NOTICE " %s :%s", NumNick(sptr), name,
		 text);
    else
      sendto_one(acptr, "%s " TOK_NOTICE " %s :%s", NumServ(sptr), name, text);
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
      (!EmptyString(host) && 0 != match(host, acptr->user->host)))
    return;

  *server = '@';
  if (host)
    *--host = '%';

  if (!(is_silenced(sptr, acptr))) /* local client; use client<->server */
    sendto_prefix_one(acptr, sptr, ":%s %s %s :%s",
                      sptr->name, MSG_NOTICE, name, text);
}

void relay_private_message(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (acptr = FindUser(name))) {
    send_error_to_client(sptr, ERR_NOSUCHNICK, name);
    return;
  }
  if (check_target_limit(sptr, acptr, acptr->name, 0) ||
      is_silenced(sptr, acptr))
    return;

  /*
   * send away message if user away
   */
  if (acptr->user && acptr->user->away)
    sendto_one(sptr, rpl_str(RPL_AWAY),
               me.name, sptr->name, acptr->name, acptr->user->away);
  /*
   * deliver the message
   */
  if (MyUser(acptr)) {
    add_target(acptr, sptr);
    sendto_prefix_one(acptr, sptr, ":%s %s %s :%s",
                      sptr->name, MSG_PRIVATE, acptr->name, text);
  }
  else
    sendto_one(acptr, "%s%s %s %s%s :%s", NumNick(sptr),
               TOK_PRIVATE, NumNick(acptr), text);
}

void relay_private_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (acptr = FindUser(name)))
    return;
  if (check_target_limit(sptr, acptr, acptr->name, 0) ||
      is_silenced(sptr, acptr))
    return;
  /*
   * deliver the message
   */
  if (MyUser(acptr)) {
    add_target(acptr, sptr);
    sendto_prefix_one(acptr, sptr, ":%s %s %s :%s",
                      sptr->name, MSG_NOTICE, acptr->name, text);
  }
  else
    sendto_one(acptr, "%s%s %s %s%s :%s", NumNick(sptr),
               TOK_NOTICE, NumNick(acptr), text);
}

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
    sendto_one(sptr,
               ":%s %d %s * :Target left %s. Failed to deliver: [%.20s]",
               me.name, ERR_NOSUCHNICK, sptr->name, NETWORK, text);
    return;
  }
  if (is_silenced(sptr, acptr))
    return;

  if (MyUser(acptr)) {
    add_target(acptr, sptr);
    sendto_prefix_one(acptr, sptr, ":%s %s %s :%s",
                      sptr->name, MSG_PRIVATE, acptr->name, text);
  }
  else {
    if (IsServer(sptr))
      sendto_one(acptr, "%s %s %s%s :%s", NumServ(sptr),
                 TOK_PRIVATE, NumNick(acptr), text);
    else
      sendto_one(acptr, "%s%s %s %s%s :%s", NumNick(sptr),
                 TOK_PRIVATE, NumNick(acptr), text);
  }        
}


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

  if (MyUser(acptr)) {
    add_target(acptr, sptr);
    sendto_prefix_one(acptr, sptr, ":%s %s %s :%s",
                      sptr->name, MSG_NOTICE, acptr->name, text);
  }
  else {
    if (IsServer(sptr))
      sendto_one(acptr, "%s %s %s%s :%s", NumServ(sptr), 
                 TOK_NOTICE, NumNick(acptr), text);
    else            
      sendto_one(acptr, "%s%s %s %s%s :%s", NumNick(sptr), 
                 TOK_NOTICE, NumNick(acptr), text);
  }              
}

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
    send_error_to_client(sptr, ERR_NOTOPLEVEL, mask);
    return;
  }
  while (*++s) {
    if (*s == '.' || *s == '*' || *s == '?')
       break;
  }
  if (*s == '*' || *s == '?') {
    send_error_to_client(sptr, ERR_WILDTOPLEVEL, mask);
    return;
  }
  s = mask;
  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }
  sendto_match_butone(IsServer(sptr->from) ? sptr->from : 0,
                      sptr, s, host_mask ? MATCH_HOST : MATCH_SERVER,
		      MSG_PRIVATE, TOK_PRIVATE, mask, text);
}

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
    send_error_to_client(sptr, ERR_NOTOPLEVEL, mask);
    return;
  }
  while (*++s) {
    if (*s == '.' || *s == '*' || *s == '?')
       break;
  }
  if (*s == '*' || *s == '?') {
    send_error_to_client(sptr, ERR_WILDTOPLEVEL, mask);
    return;
  }
  s = mask;
  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }
  sendto_match_butone(IsServer(sptr->from) ? sptr->from : 0,
                      sptr, s, host_mask ? MATCH_HOST : MATCH_SERVER,
		      MSG_NOTICE, TOK_NOTICE, mask, text);
}

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
  sendto_match_butone(sptr->from, sptr, s, host_mask ? MATCH_HOST:MATCH_SERVER,
		      MSG_PRIVATE, TOK_PRIVATE, mask, text);
}

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
  sendto_match_butone(sptr->from, sptr, s, host_mask ? MATCH_HOST:MATCH_SERVER,
		      MSG_NOTICE, TOK_NOTICE, mask, text);
}

