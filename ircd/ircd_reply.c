/*
 * IRC - Internet Relay Chat, ircd/m_proto.c
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
#include "config.h"

#include "ircd_reply.h"
#include "client.h"
#include "ircd.h"
#include "ircd_snprintf.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_debug.h"
#include "send.h"

#include <assert.h>
#include <string.h>

/* Report a protocol violation warning to anyone listening.  This can be
 * easily used to cleanup the last couple of parts of the code up.
 */
 
int protocol_violation(struct Client* cptr, const char* pattern, ...)
{
  struct VarData vd;

  assert(pattern);
  assert(cptr);

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);

  sendwallto_group_butone(&me, WALL_DESYNCH, NULL,
			"Protocol Violation from %s: %v", cli_name(cptr), &vd);

  va_end(vd.vd_args);
  return 0;
}

int need_more_params(struct Client* cptr, const char* cmd)
{
  send_reply(cptr, ERR_NEEDMOREPARAMS, cmd);
  return 0;
}

int send_reply(struct Client *to, int reply, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  const struct Numeric *num;

  assert(0 != to);
  assert(0 != reply);

  num = get_error_numeric(reply & ~SND_EXPLICIT); /* get reply... */

  va_start(vd.vd_args, reply);

  if (reply & SND_EXPLICIT) /* get right pattern */
    vd.vd_format = (const char *) va_arg(vd.vd_args, char *);
  else
    vd.vd_format = num->format;

  assert(0 != vd.vd_format);

  /* build buffer */
  mb = msgq_make(cli_from(to), "%:#C %s %C %v", &me, num->str, to, &vd);

  va_end(vd.vd_args);

  /* send it to the user */
  send_buffer(to, mb, 0);

  msgq_clean(mb);

  return 0; /* convenience return */
}



