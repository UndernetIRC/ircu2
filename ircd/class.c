/*
 * IRC - Internet Relay Chat, ircd/class.c
 * Copyright (C) 1990 Darren Reed
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

#include "sys.h"
#include "h.h"
#include "struct.h"
#include "class.h"
#include "s_conf.h"
#include "s_serv.h"
#include "send.h"
#include "s_err.h"
#include "numeric.h"
#include "ircd.h"

RCSTAG_CC("$Id$");

#define BAD_CONF_CLASS		((unsigned int)-1)
#define BAD_PING		((unsigned int)-2)
#define BAD_CLIENT_CLASS	((unsigned int)-3)

aConfClass *classes;

unsigned int get_conf_class(aConfItem *aconf)
{
  if ((aconf) && (aconf->confClass))
    return (ConfClass(aconf));

  Debug((DEBUG_DEBUG, "No Class For %s", (aconf) ? aconf->name : "*No Conf*"));

  return (BAD_CONF_CLASS);

}

static unsigned int get_conf_ping(aConfItem *aconf)
{
  if ((aconf) && (aconf->confClass))
    return (ConfPingFreq(aconf));

  Debug((DEBUG_DEBUG, "No Ping For %s", (aconf) ? aconf->name : "*No Conf*"));

  return (BAD_PING);
}

unsigned int get_client_class(aClient *acptr)
{
  Reg1 Link *tmp;
  Reg2 aConfClass *cl;
  unsigned int retc = BAD_CLIENT_CLASS;

  if (acptr && !IsMe(acptr) && !IsPing(acptr) && (acptr->confs))
    for (tmp = acptr->confs; tmp; tmp = tmp->next)
    {
      if (!tmp->value.aconf || !(cl = tmp->value.aconf->confClass))
	continue;
      if (ConClass(cl) > retc || retc == BAD_CLIENT_CLASS)
	retc = ConClass(cl);
    }

  Debug((DEBUG_DEBUG, "Returning Class %d For %s", retc, acptr->name));

  return (retc);
}

int unsigned get_client_ping(aClient *acptr)
{
  unsigned int ping = 0, ping2;
  aConfItem *aconf;
  Link *link;

  link = acptr->confs;

  if (link)
    while (link)
    {
      aconf = link->value.aconf;
      if (aconf->status &
	  (CONF_CLIENT | CONF_CONNECT_SERVER | CONF_NOCONNECT_SERVER))
      {
	ping2 = get_conf_ping(aconf);
	if ((ping2 != BAD_PING) && ((ping > ping2) || !ping))
	  ping = ping2;
      }
      link = link->next;
    }
  else
  {
    ping = PINGFREQUENCY;
    Debug((DEBUG_DEBUG, "No Attached Confs"));
  }
  if (ping <= 0)
    ping = PINGFREQUENCY;
  Debug((DEBUG_DEBUG, "Client %s Ping %d", acptr->name, ping));
  return (ping);
}

unsigned int get_con_freq(aConfClass * clptr)
{
  if (clptr)
    return (ConFreq(clptr));
  else
    return (CONNECTFREQUENCY);
}

/*
 * When adding a class, check to see if it is already present first.
 * if so, then update the information for that class, rather than create
 * a new entry for it and later delete the old entry.
 * if no present entry is found, then create a new one and add it in
 * immeadiately after the first one (class 0).
 */
void add_class(unsigned int conClass, unsigned int ping, unsigned int confreq,
    unsigned int maxli, size_t sendq)
{
  aConfClass *t, *p;

  t = find_class(conClass);
  if ((t == classes) && (conClass != 0))
  {
    p = (aConfClass *) make_class();
    NextClass(p) = NextClass(t);
    NextClass(t) = p;
  }
  else
    p = t;
  Debug((DEBUG_DEBUG, "Add Class %u: p %p t %p - cf: %u pf: %u ml: %u sq: %d",
      conClass, p, t, confreq, ping, maxli, sendq));
  ConClass(p) = conClass;
  ConFreq(p) = confreq;
  PingFreq(p) = ping;
  MaxLinks(p) = maxli;
  MaxSendq(p) = (sendq > 0) ? sendq : DEFAULTMAXSENDQLENGTH;
  if (p != t)
    Links(p) = 0;
}

aConfClass *find_class(unsigned int cclass)
{
  aConfClass *cltmp;

  for (cltmp = FirstClass(); cltmp; cltmp = NextClass(cltmp))
    if (ConClass(cltmp) == cclass)
      return cltmp;
  return classes;
}

void check_class(void)
{
  aConfClass *cltmp, *cltmp2;

  Debug((DEBUG_DEBUG, "Class check:"));

  for (cltmp2 = cltmp = FirstClass(); cltmp; cltmp = NextClass(cltmp2))
  {
    Debug((DEBUG_DEBUG,
	"Class %d : CF: %d PF: %d ML: %d LI: %d SQ: %d",
	ConClass(cltmp), ConFreq(cltmp), PingFreq(cltmp),
	MaxLinks(cltmp), Links(cltmp), MaxSendq(cltmp)));
    if (IsMarkedDelete(cltmp))
    {
      NextClass(cltmp2) = NextClass(cltmp);
      if (Links(cltmp) == 0)
	free_class(cltmp);
    }
    else
      cltmp2 = cltmp;
  }
}

void initclass(void)
{
  classes = (aConfClass *) make_class();

  ConClass(FirstClass()) = 0;
  ConFreq(FirstClass()) = CONNECTFREQUENCY;
  PingFreq(FirstClass()) = PINGFREQUENCY;
  MaxLinks(FirstClass()) = MAXIMUM_LINKS;
  MaxSendq(FirstClass()) = DEFAULTMAXSENDQLENGTH;
  Links(FirstClass()) = 0;
  NextClass(FirstClass()) = NULL;
}

void report_classes(aClient *sptr)
{
  aConfClass *cltmp;

  for (cltmp = FirstClass(); cltmp; cltmp = NextClass(cltmp))
    sendto_one(sptr, rpl_str(RPL_STATSYLINE), me.name, sptr->name,
	'Y', ConClass(cltmp), PingFreq(cltmp), ConFreq(cltmp),
	MaxLinks(cltmp), MaxSendq(cltmp));
}

size_t get_sendq(aClient *cptr)
{
  size_t sendq = DEFAULTMAXSENDQLENGTH;
  Link *tmp;
  aConfClass *cl;

  if (cptr && !IsMe(cptr) && (cptr->confs))
    for (tmp = cptr->confs; tmp; tmp = tmp->next)
    {
      if (!tmp->value.aconf || !(cl = tmp->value.aconf->confClass))
	continue;
      if (ConClass(cl) != BAD_CLIENT_CLASS)
	sendq = MaxSendq(cl);
    }
  return sendq;
}
