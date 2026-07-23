/*
 * IRC - Internet Relay Chat, ircd/m_tagmsg.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
/** @file
 * @brief IRCv3 TAGMSG command handler
 */
#include "config.h"

#include "capab.h"
#include "client.h"
#include "handlers.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_relay.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"

#include <string.h>

static int
tagmsg_check_cap(struct Client *sptr)
{
  if (!CapHas(cli_active(sptr), CAP_MESSAGE_TAGS))
    return send_reply(sptr, ERR_UNKNOWNCOMMAND, MSG_TAGMSG);
  return 0;
}

int
m_tagmsg(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char *name;
  char *server;
  int i;
  int count;
  char *vector[MAXTARGETS];

  assert(0 != cptr);
  assert(cptr == sptr);

  if (tagmsg_check_cap(sptr))
    return 0;

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NORECIPIENT, MSG_TAGMSG);

  count = unique_name_vector(parv[1], ',', vector, MAXTARGETS);

  for (i = 0; i < count; ++i) {
    name = vector[i];
    if (IsChannelPrefix(*name))
      relay_channel_tagmsg(sptr, name);
    else if ((server = strchr(name, '@')))
      relay_directed_tagmsg(sptr, name, server);
    else
      relay_private_tagmsg(sptr, name);
  }
  return 0;
}

int
ms_tagmsg(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char *name;
  char *server;

  if (parc < 2)
    return 0;

  name = parv[1];
  if (IsChannelPrefix(*name))
    server_relay_channel_tagmsg(sptr, name);
  else if ('$' == *name && IsOper(sptr))
    server_relay_masked_tagmsg(sptr, name);
  else if ((server = strchr(name, '@')))
    relay_directed_tagmsg(sptr, name, server);
  else
    server_relay_private_tagmsg(sptr, name);
  return 0;
}

int
mo_tagmsg(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char *name;
  char *server;
  int i;
  int count;
  char *vector[MAXTARGETS];

  assert(0 != cptr);
  assert(cptr == sptr);

  if (tagmsg_check_cap(sptr))
    return 0;

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NORECIPIENT, MSG_TAGMSG);

  count = unique_name_vector(parv[1], ',', vector, MAXTARGETS);

  for (i = 0; i < count; ++i) {
    name = vector[i];
    if (IsChannelPrefix(*name))
      relay_channel_tagmsg(sptr, name);
    else if (*name == '$')
      relay_masked_tagmsg(sptr, name);
    else if ((server = strchr(name, '@')))
      relay_directed_tagmsg(sptr, name, server);
    else
      relay_private_tagmsg(sptr, name);
  }
  return 0;
}
