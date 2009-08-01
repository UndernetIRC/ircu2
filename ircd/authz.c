/*
 * IRC - Internet Relay Chat, ircd/authz.c
 * Copyright (C) 2009 Kevin L. Mitchell
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
/** @file
 * @brief Implementation of client authorization.
 * @version $Id$
 */
#include "config.h"

#include "authz.h"
#include "client.h"
#include "ircd_log.h"
#include "ircd_reply.h"

#include <stdarg.h>

unsigned int
authz(struct Client* client, unsigned int flags, authzset_t *set, ...)
{
  va_list vl;
  authz_t *authz;
  int i, ret = 0, def = AUTHZ_DENY;

  /* Sanity-check our arguments */
  if (!client || !AUTHZSET_CHECK(set))
    return AUTHZ_DENY;

  /* Update the default return value */
  if (flags & AUTHZ_PASSTHRU)
    def = AUTHZ_PASS;
  else if (set->azs_mode & AUTHZ_ACCEPT)
    def = AUTHZ_GRANT;

  /* Walk the authorization chain */
  for (i = 0; set->azs_set[i]; i++) {
    authz = set->azs_set[i];

    assert(AUTHZ_CHECK(authz));

    /* Do we even have a check routine? */
    if (authz->az_check) {
      va_start(vl, authz);
      ret = (*authz->az_check)(client, flags, authz, vl); /* call it */
      va_end(vl);
    } else /* use the extra integer data */
      ret = az_e_int(authz);

    assert((ret & AUTHZ_MASK) == AUTHZ_DENY ||
	   (ret & AUTHZ_MASK) == AUTHZ_PASS ||
	   (ret & AUTHZ_MASK) == AUTHZ_GRANT)

    /* OK, what do we do now? */
    switch (ret & AUTHZ_MASK) {
    case AUTHZ_GRANT: /* authorization granted */
      if ((set->azs_mode & AUTHZ_MODEMASK) == AUTHZ_OR)
	return ret;

      /* OK, we're in AND mode, just change the default */
      def = AUTHZ_GRANT;
      break;

    case AUTHZ_DENY: /* authorization denied */
      if ((set->azs_mode & AUTHZ_MODEMASK) == AUTHZ_AND) {
	if (!(flags & AUTHZ_NOMSG) && !(ret & AUTHZ_MSGSENT)) {
	  /* Send the authorization denied message */
	  send_reply(client, ERR_NOPRIVILEGES);

	  ret |= AUTHZ_MSGSENT; /* mark that we sent the message */
	}

	return ret;
      }

      /* OK, we're in OR mode, just change the default */
      def = AUTHZ_DENY;
      break;
    }
  }

  assert(def == AUTHZ_DENY || def == AUTHZ_PASS || def == AUTHZ_GRANT);

  /* OK, we're going to return def; if it's AUTHZ_DENY, let's send a message */
  if (def == AUTHZ_GRANT && !(flags & AUTHZ_NOMSG)) {
    /* Send the authorization denied message */
    send_reply(client, ERR_NOPRIVILEGES);

    def |= AUTHZ_MSGSENT; /* mark that we sent the message */
  }

  return def; /* Return the default return value */
}
