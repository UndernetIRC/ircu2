/*
 * IRC - Internet Relay Chat, common/packet.c
 * Copyright (C) 1990  Jarkko Oikarinen and
 *                     University of Oulu, Computing Center
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
 * @brief Input packet handling functions.
 * @version $Id$
 */
#include "config.h"

#include "packet.h"
#include "client.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "parse.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Add a certain number of bytes to a client's received statistics.
 * @param[in,out] cptr Client to update.
 * @param[in] length Number of newly received bytes to add.
 */
static void update_bytes_received(struct Client* cptr, unsigned int length)
{
  cli_receiveB(&me)  += length;     /* Update bytes received */
  cli_receiveB(cptr) += length;
}

/** Add one message to a client's received statistics.
 * @param[in,out] cptr Client to update.
 */
static void update_messages_received(struct Client* cptr)
{
  ++(cli_receiveM(&me));
  ++(cli_receiveM(cptr));
}

/** Handle received data from a directly connected server.
 * @param[in] cptr Peer server that sent us data.
 * @param[in] buffer Input buffer.
 * @param[in] length Number of bytes in input buffer.
 * @return 1 on success or CPTR_KILLED if the client is squit.
 */
int server_dopacket(struct Client* cptr, const char* buffer, int length)
{
  const char* src;
  char*       endp;
  char*       client_buffer;

  assert(0 != cptr);

  update_bytes_received(cptr, length);

  client_buffer = cli_buffer(cptr);
  endp = client_buffer + cli_count(cptr);
  src = buffer;

  while (length-- > 0) {
    *endp = *src++;
    /*
     * Yuck.  Stuck.  To make sure we stay backward compatible,
     * we must assume that either CR or LF terminates the message
     * and not CR-LF.  By allowing CR or LF (alone) into the body
     * of messages, backward compatibility is lost and major
     * problems will arise. - Avalon
     */
    if (IsEol(*endp)) {
      if (endp == client_buffer)
        continue;               /* Skip extra LF/CR's */
      *endp = '\0';

      update_messages_received(cptr);

      if (parse_server(cptr, cli_buffer(cptr), endp) == CPTR_KILLED)
        return CPTR_KILLED;
      /*
       *  Socket is dead so exit
       */
      if (IsDead(cptr))
        return exit_client(cptr, cptr, &me, cli_info(cptr));
      endp = client_buffer;
    }
    else if (endp < client_buffer + BUFSIZE)
      ++endp;                   /* There is always room for the null */
  }
  cli_count(cptr) = endp - cli_buffer(cptr);
  return 1;
}

/** Handle received data from a new (unregistered) connection.
 * @param[in] cptr Unregistered connection that sent us data.
 * @param[in] buffer Input buffer.
 * @param[in] length Number of bytes in input buffer.
 * @return 1 on success or CPTR_KILLED if the client is squit.
 */
int connect_dopacket(struct Client *cptr, const char *buffer, int length)
{
  const char* src;
  char*       endp;
  char*       client_buffer;

  assert(0 != cptr);

  update_bytes_received(cptr, length);

  client_buffer = cli_buffer(cptr);
  endp = client_buffer + cli_count(cptr);
  src = buffer;

  while (length-- > 0)
  {
    *endp = *src++;
    /*
     * Yuck.  Stuck.  To make sure we stay backward compatible,
     * we must assume that either CR or LF terminates the message
     * and not CR-LF.  By allowing CR or LF (alone) into the body
     * of messages, backward compatibility is lost and major
     * problems will arise. - Avalon
     */
    if (IsEol(*endp))
    {
      /* Skip extra LF/CR's */
      if (endp == client_buffer)
        continue;
      *endp = '\0';

      update_messages_received(cptr);

      if (parse_client(cptr, cli_buffer(cptr), endp) == CPTR_KILLED)
        return CPTR_KILLED;
      /* Socket is dead so exit */
      if (IsDead(cptr))
        return exit_client(cptr, cptr, &me, cli_info(cptr));
      else if (IsServer(cptr))
      {
        cli_count(cptr) = 0;
        return server_dopacket(cptr, src, length);
      }
      endp = client_buffer;
    }
    else if (endp < client_buffer + BUFSIZE)
      /* There is always room for the null */
      ++endp;
  }
  cli_count(cptr) = endp - cli_buffer(cptr);
  return 1;
}

/** Handle received data from a local client.
 * @param[in] cptr Local client that sent us data.
 * @param[in] length Total number of bytes in client's input buffer.
 * @return 1 on success or CPTR_KILLED if the client is squit.
 */
int client_dopacket(struct Client *cptr, unsigned int length)
{
  assert(0 != cptr);

  update_bytes_received(cptr, length);
  update_messages_received(cptr);

  if (CPTR_KILLED == parse_client(cptr, cli_buffer(cptr), cli_buffer(cptr) + length))
    return CPTR_KILLED;
  else if (IsDead(cptr))
    return exit_client(cptr, cptr, &me, cli_info(cptr));

  return 1;
}


