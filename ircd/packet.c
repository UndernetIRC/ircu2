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
 *
 * $Id$
 */
#include "config.h"

#include "packet.h"
#include "client.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "parse.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "send.h"

#include <assert.h>

static void update_bytes_received(struct Client* cptr, unsigned int length)
{
  cli_receiveB(&me)  += length;     /* Update bytes received */
  cli_receiveB(cptr) += length;

  if (cli_receiveB(cptr) > 1023) {
    cli_receiveK(cptr) += (cli_receiveB(cptr) >> 10);
    cli_receiveB(cptr) &= 0x03ff;   /* 2^10 = 1024, 3ff = 1023 */
  }
  if (cli_receiveB(&me) > 1023) {
    cli_receiveK(&me) += (cli_receiveB(&me) >> 10);
    cli_receiveB(&me) &= 0x03ff;
  }
}

static void update_messages_received(struct Client* cptr)
{
  ++(cli_receiveM(&me));
  ++(cli_receiveM(cptr));
}

/*
 * dopacket
 *
 *    cptr - pointer to client structure for which the buffer data
 *           applies.
 *    buffer - pointer to the buffer containing the newly read data
 *    length - number of valid bytes of data in the buffer
 *
 *  Note:
 *    It is implicitly assumed that dopacket is called only
 *    with cptr of "local" variation, which contains all the
 *    necessary fields (buffer etc..)
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

/*
 * client_dopacket - handle client messages
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


