/*
 * IRC - Internet Relay Chat, ircd/s_numeric.c
 * Copyright (C) 1990 Jarkko Oikarinen
 *
 * Numerous fixes by Markku Savela
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
#include "s_numeric.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_policy.h"
#include "numnicks.h"
#include "send.h"
#include "struct.h"


static char buffer[1024];

/*
 * do_numeric()
 * Rewritten by Nemesi, Jan 1999, to support numeric nicks in parv[1]
 *
 * Called when we get a numeric message from a remote _server_ and we are
 * supposed to forward it somewhere. Note that we always ignore numerics sent
 * to 'me' and simply drop the message if we can't handle with this properly:
 * the savy approach is NEVER generate an error in response to an... error :)
 */

int do_numeric(int numeric, int nnn, struct Client *cptr, struct Client *sptr,
    int parc, char *parv[])
{
  struct Client *acptr = 0;
  struct Channel *achptr = 0;
  char *p, *b;
  int i;

  /* Avoid trash, we need it to come from a server and have a target  */
  if ((parc < 2) || !IsServer(sptr))
    return 0;

  /* Who should receive this message ? Will we do something with it ?
     Note that we use findUser functions, so the target can't be neither
     a server, nor a channel (?) nor a list of targets (?) .. u2.10
     should never generate numeric replies to non-users anyway
     Ahem... it can be a channel actually, csc bots use it :\ --Nem */

  if (IsChannelName(parv[1]))
    achptr = FindChannel(parv[1]);
  else
    acptr = (nnn) ? (findNUser(parv[1])) : (FindUser(parv[1]));

  if (((!acptr) || (acptr->from == cptr)) && !achptr)
    return 0;

  /* Remap low number numerics, not that I understand WHY.. --Nemesi  */
  if (numeric < 100)
    numeric += 100;

  /* Rebuild the buffer with all the parv[] without wasting cycles :) */
  b = buffer;
  if (parc > 2)
  {
    for (i = 2; i < (parc - 1); i++)
      for (*b++ = ' ', p = parv[i]; *p; p++)
        *b++ = *p;
    for (*b++ = ' ', *b++ = ':', p = parv[parc - 1]; *p; p++)
      *b++ = *p;
  }
  *b = '\000';

  /* Since .06 this will implicitly use numeric nicks when needed     */
#ifdef HEAD_IN_SAND_REWRITE
  /* Since 2.10.10.pl14 we rewrite numerics from remote servers to appear to
   * come from the local server
   */
  if (IsOper(acptr)) {
#endif
	if (acptr)
    	  sendto_prefix_one(acptr, sptr, ":%s %d %s%s",
       	    sptr->name, numeric, acptr->name, buffer);
  	else
    	   sendto_channel_butone(cptr, sptr, achptr, ":%s %d %s%s",
            sptr->name, numeric, achptr->chname, buffer);
#ifdef HEAD_IN_SAND_REWRITE
  }
  else {
	if (acptr) 
    	  sendto_prefix_one(acptr, sptr, ":%s %d %s%s",
       	    me.name, numeric, acptr->name, buffer);
  	else
    	   sendto_channel_butone(cptr, sptr, achptr, ":%s %d %s%s",
            me.name, numeric, achptr->chname, buffer);
  }
#endif

  return 0;
}
