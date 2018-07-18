/*
 * IRC - Internet Relay Chat, ircd/channel.c
 * Copyright (C) 1996 Carlo Wood (I wish this was C++ - this sucks :/)
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
 * @brief Implementation of numeric nickname operations.
 * @version $Id$
 */
#include "config.h"

#include "numnicks.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "match.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "struct.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/** @page numnicks Numeric Nicks
 * %Numeric nicks (numnicks) are new as of version ircu2.10.00beta1.
 *
 * The idea is as follows:
 * In most messages (for protocol 10+) the original nick will be
 * replaced by a 5 character string: YYXXX
 * Where 'YY' represents the server, and 'XXX' the nick on that server.
 *
 * 'YYXXX' should not interfere with the input parser, and therefore is
 * not allowed to contain spaces or a ':'.
 * Also, 'YY' can't start with a '+' because of m_server().
 *
 * We keep the characters printable for debugging reasons too.
 *
 * The 'XXX' value can be larger then the maximum number of clients
 * per server, we use a mask (Server::nn_mask) to get the real
 * client numeric. The overhead is used to have some redundancy so
 * just-disconnected-client aren't confused with just-connected ones.
 */


/* These must be the same on ALL servers ! Do not change ! */

/** Number of bits encoded in one numnick character. */
#define NUMNICKLOG 6
/** Bitmask to select value of next numnick character. */
#define NUMNICKMASK 63          /* (NUMNICKBASE-1) */
/** Number of servers representable in a numnick. */
#define NN_MAX_SERVER 4096      /* (NUMNICKBASE * NUMNICKBASE) */
/** Number of clients representable in a numnick. */
#define NN_MAX_CLIENT 262144    /* NUMNICKBASE ^ 3 */

/*
 * The internal counter for the 'XX' of local clients
 */
/** Maximum used server numnick, plus one. */
static unsigned int lastNNServer = 0;
/** Array of servers indexed by numnick. */
static struct Client* server_list[NN_MAX_SERVER];

/* *INDENT-OFF* */

/**
 * Converts a numeric to the corresponding character.
 * The following characters are currently known to be forbidden:
 *
 * '\\0' : Because we use '\\0' as end of line.
 *
 * ' '  : Because parse_*() uses this as parameter separator.
 *
 * ':'  : Because parse_server() uses this to detect if a prefix is a
 *        numeric or a name.
 *
 * '+'  : Because m_nick() uses this to determine if parv[6] is a
 *        umode or not.
 *
 * '&', '#', '$', '@' and '%' :
 *        Because m_message() matches these characters to detect special cases.
 */
static const char convert2y[] = {
  'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
  'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
  'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
  'w','x','y','z','0','1','2','3','4','5','6','7','8','9','[',']'
};

/** Converts a character to its (base64) numnick value. */
static const unsigned int convert2n[] = {
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  52,53,54,55,56,57,58,59,60,61, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
  15,16,17,18,19,20,21,22,23,24,25,62, 0,63, 0, 0,
   0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
  41,42,43,44,45,46,47,48,49,50,51, 0, 0, 0, 0, 0,

   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* *INDENT-ON* */

/** Convert a string to its value as a numnick.
 * @param[in] s Numnick string to decode.
 * @return %Numeric nickname value.
 */
unsigned int base64toint(const char* s)
{
  unsigned int i = convert2n[(unsigned char) *s++];
  while (*s) {
    i <<= NUMNICKLOG;
    i += convert2n[(unsigned char) *s++];
  }
  return i;
}

/** Encode a number as a numnick.
 * @param[out] buf Output buffer.
 * @param[in] v Value to encode.
 * @param[in] count Number of numnick digits to write to \a buf.
 */
const char* inttobase64(char* buf, unsigned int v, unsigned int count)
{
  buf[count] = '\0';
  while (count > 0) {
    buf[--count] = convert2y[(v & NUMNICKMASK)];
    v >>= NUMNICKLOG;
  }
  return buf;
}

/** Look up a server by numnick string.
 * See @ref numnicks for more details.
 * @param[in] numeric %Numeric nickname of server (may contain trailing junk).
 * @return %Server with that numnick (or NULL).
 */
static struct Client* FindXNServer(const char* numeric)
{
  char buf[3];
  buf[0] = *numeric++;
  buf[1] = *numeric;
  buf[2] = '\0';
  Debug((DEBUG_DEBUG, "FindXNServer: %s(%d)", buf, base64toint(buf)));
  return server_list[base64toint(buf)];
}

/** Look up a server by numnick string.
 * See @ref numnicks for more details.
 * @param[in] numeric %Numeric nickname of server.
 * @return %Server with that numnick (or NULL).
 */
struct Client* FindNServer(const char* numeric)
{
  unsigned int len = strlen(numeric);

  if (len < 3) {
    Debug((DEBUG_DEBUG, "FindNServer: %s(%d)", numeric, base64toint(numeric)));
    return server_list[base64toint(numeric)];
  }
  else if (len == 3) {
    Debug((DEBUG_DEBUG, "FindNServer: %c(%d)", *numeric, 
           convert2n[(unsigned char) *numeric]));
    return server_list[convert2n[(unsigned char) *numeric]];
  }
  return FindXNServer(numeric);
}

/** Look up a user by numnick string.
 * See @ref numnicks for more details.
 * @param[in] yxx %Numeric nickname of user.
 * @return %User with that numnick (or NULL).
 */
struct Client* findNUser(const char* yxx)
{
  struct Client* server = 0;
  if (5 == strlen(yxx)) {
    if (0 != (server = FindXNServer(yxx))) {
      Debug((DEBUG_DEBUG, "findNUser: %s(%d)", yxx, 
             base64toint(yxx + 2) & cli_serv(server)->nn_mask));
      return cli_serv(server)->client_list[base64toint(yxx + 2) & cli_serv(server)->nn_mask];
    }
  }
  else if (0 != (server = FindNServer(yxx))) {
    Debug((DEBUG_DEBUG, "findNUser: %s(%d)",
           yxx, base64toint(yxx + 1) & cli_serv(server)->nn_mask));
    return cli_serv(server)->client_list[base64toint(yxx + 1) & cli_serv(server)->nn_mask];
  }
  return 0;
}

/** Remove a client from a server's user array.
 * @param[in] server %Server that owns the user to remove.
 * @param[in] yxx Numnick of client to remove.
 */
void RemoveYXXClient(struct Client* server, const char* yxx)
{
  assert(0 != server);
  assert(0 != yxx);
  if (*yxx) {
    Debug((DEBUG_DEBUG, "RemoveYXXClient: %s(%d)", yxx,
           base64toint(yxx) & cli_serv(server)->nn_mask));
    cli_serv(server)->client_list[base64toint(yxx) & cli_serv(server)->nn_mask] = 0;
  }
}

/** Set a server's numeric nick.
 * @param[in] cptr %Client that announced the server (ignored).
 * @param[in,out] server %Server that is being assigned a numnick.
 * @param[in] yxx %Numeric nickname for server.
 */
void SetServerYXX(struct Client* cptr, struct Client* server, const char* yxx)
{
  unsigned int index;
  if (5 == strlen(yxx)) {
    ircd_strncpy(cli_yxx(server), yxx, 2);
    ircd_strncpy(cli_serv(server)->nn_capacity, yxx + 2, 3);
  }
  else {
    (cli_yxx(server))[0]               = yxx[0];
    cli_serv(server)->nn_capacity[0] = yxx[1];
    cli_serv(server)->nn_capacity[1] = yxx[2];
  }
  cli_serv(server)->nn_mask = base64toint(cli_serv(server)->nn_capacity);

  index = base64toint(cli_yxx(server));
  if (index >= lastNNServer)
    lastNNServer = index + 1;
  server_list[index] = server;

  /* Note, exit_one_client uses the fact that `client_list' != NULL to
   * determine that SetServerYXX has been called - and then calls
   * ClearServerYXX. However, freeing the allocation happens in free_client() */
  cli_serv(server)->client_list =
      (struct Client**) MyCalloc(cli_serv(server)->nn_mask + 1, sizeof(struct Client*));
}

/** Set a server's capacity.
 * @param[in] c %Server whose capacity is being set.
 * @param[in] capacity Maximum number of clients the server supports.
 */
void SetYXXCapacity(struct Client* c, unsigned int capacity)
{
  unsigned int max_clients = 16;
  /*
   * Calculate mask to be used for the maximum number of clients
   */
  while (max_clients < capacity)
    max_clients <<= 1;
  /*
   * Sanity checks
   */
  if (max_clients > NN_MAX_CLIENT) {
    fprintf(stderr, "MAXCLIENTS (or MAXCONNECTIONS) is (at least) %u "
            "too large ! Please decrease this value.\n",
             max_clients - NN_MAX_CLIENT);
    exit(-1);
  }
  --max_clients;
  inttobase64(cli_serv(c)->nn_capacity, max_clients, 3);
  cli_serv(c)->nn_mask = max_clients;       /* Our Numeric Nick mask */
  cli_serv(c)->client_list = (struct Client**) MyCalloc(max_clients + 1,
                                                     sizeof(struct Client*));
  server_list[base64toint(cli_yxx(c))] = c;
}

/** Set a server's numeric nick.
 * See @ref numnicks for more details.
 * @param[in] c %Server that is being assigned a numnick.
 * @param[in] numeric Numnick value for server.
 */
void SetYXXServerName(struct Client* c, unsigned int numeric)
{
  assert(0 != c);
  assert(numeric < NN_MAX_SERVER);

  inttobase64(cli_yxx(c), numeric, 2);
  if (numeric >= lastNNServer)
    lastNNServer = numeric + 1;
  server_list[numeric] = c;
}

/** Unassign a server's numnick.
 * @param[in] server %Server that should be removed from the numnick table.
 */
void ClearServerYXX(const struct Client *server)
{
  unsigned int index = base64toint(cli_yxx(server));
  if (server_list[index] == server)     /* Sanity check */
    server_list[index] = 0;
}

/** Register numeric of new (remote) client.
 * See @ref numnicks for more details.
 * Add it to the appropriate client_list.
 * @param[in] acptr %User being registered.
 * @param[in] yxx User's numnick.
 */
void SetRemoteNumNick(struct Client* acptr, const char *yxx)
{
  struct Client** acptrp;
  struct Client*  server = cli_user(acptr)->server;

  if (5 == strlen(yxx)) {
    strcpy(cli_yxx(acptr), yxx + 2);
  }
  else {
    (cli_yxx(acptr))[0] = *++yxx;
    (cli_yxx(acptr))[1] = *++yxx;
    (cli_yxx(acptr))[2] = 0;
  }
  Debug((DEBUG_DEBUG, "SetRemoteNumNick: %s(%d)", cli_yxx(acptr),
         base64toint(cli_yxx(acptr)) & cli_serv(server)->nn_mask));

  acptrp = &(cli_serv(server))->client_list[base64toint(cli_yxx(acptr)) & cli_serv(server)->nn_mask];
  if (*acptrp) {
    /*
     * this exits the old client in the array, not the client
     * that is being set
     */
    exit_client(cli_from(acptr), *acptrp, server, "Numeric nick collision (Ghost)");
  }
  *acptrp = acptr;
}


/** Register numeric of new (local) client.
 * See @ref numnicks for more details.
 * Assign a numnick and add it to our client_list.
 * @param[in] cptr %User being registered.
 */
int SetLocalNumNick(struct Client *cptr)
{
  static unsigned int last_nn     = 0;
  struct Client**     client_list = cli_serv(&me)->client_list;
  unsigned int        mask        = cli_serv(&me)->nn_mask;
  unsigned int        count       = 0;

  assert(cli_user(cptr)->server == &me);

  while (client_list[last_nn & mask]) {
    if (++count == NN_MAX_CLIENT) {
      assert(count < NN_MAX_CLIENT);
      return 0;
    }
    if (++last_nn == NN_MAX_CLIENT)
      last_nn = 0;
  }
  client_list[last_nn & mask] = cptr;  /* Reserve the numeric ! */

  inttobase64(cli_yxx(cptr), last_nn, 3);
  if (++last_nn == NN_MAX_CLIENT)
    last_nn = 0;
  return 1;
}

/** Mark servers whose name matches the given (compiled) mask by
 * setting their FLAG_MAP flag.
 * @param[in] cmask Compiled mask for server names.
 * @param[in] minlen Minimum match length for \a cmask.
 * @return Number of servers marked.
 */
int markMatchexServer(const char *cmask, int minlen)
{
  int cnt = 0;
  int i;
  struct Client *acptr;

  for (i = 0; i < lastNNServer; i++) {
    if ((acptr = server_list[i]))
    {
      if (matchexec(cli_name(acptr), cmask, minlen))
        ClrFlag(acptr, FLAG_MAP);
      else
      {
        SetFlag(acptr, FLAG_MAP);
        cnt++;
      }
    }
  }
  return cnt;
}

/** Find first server whose name matches the given mask.
 * @param[in,out] mask %Server name mask (collapse()d in-place).
 * @return Matching server with lowest numnick value (or NULL).
 */
struct Client* find_match_server(char *mask)
{
  struct Client *acptr;
  int i;

  if (!(BadPtr(mask))) {
    collapse(mask);
    for (i = 0; i < lastNNServer; i++) {
      if ((acptr = server_list[i]) && (!match(mask, cli_name(acptr))))
        return acptr;
    }
  }
  return 0;
}

/** Encode an IP address in the base64 used by numnicks.
 * For IPv4 addresses (including IPv4-mapped and IPv4-compatible IPv6
 * addresses), the 32-bit host address is encoded directly as six
 * characters.
 *
 * For IPv6 addresses, each 16-bit address segment is encoded as three
 * characters, but the longest run of zero segments is encoded using an
 * underscore.
 * @param[out] buf Output buffer to write to.
 * @param[in] addr IP address to encode.
 * @param[in] count Number of bytes writable to \a buf.
 * @param[in] v6_ok If non-zero, peer understands base-64 encoded IPv6 addresses.
 */
const char* iptobase64(char* buf, const struct irc_in_addr* addr, unsigned int count, int v6_ok)
{
  if (irc_in_addr_is_ipv4(addr)) {
    assert(count >= 6);
    inttobase64(buf, (ntohs(addr->in6_16[6]) << 16) | ntohs(addr->in6_16[7]), 6);
  } else if (!v6_ok) {
    assert(count >= 6);
    if (addr->in6_16[0] == htons(0x2002))
        inttobase64(buf, (ntohs(addr->in6_16[1]) << 16) | ntohs(addr->in6_16[2]), 6);
    else
        strcpy(buf, "AAAAAA");
  } else {
    unsigned int max_start, max_zeros, curr_zeros, zero, ii;
    char *output = buf;

    assert(count >= 25);
    /* Can start by printing out the leading non-zero parts. */
    for (ii = 0; (ii < 8) && (addr->in6_16[ii]); ++ii) {
      inttobase64(output, ntohs(addr->in6_16[ii]), 3);
      output += 3;
    }
    /* Find the longest run of zeros. */
    for (max_start = zero = ii, max_zeros = curr_zeros = 0; ii < 8; ++ii) {
      if (!addr->in6_16[ii])
        curr_zeros++;
      else if (curr_zeros > max_zeros) {
        max_start = ii - curr_zeros;
        max_zeros = curr_zeros;
        curr_zeros = 0;
      }
    }
    if (curr_zeros > max_zeros) {
      max_start = ii - curr_zeros;
      max_zeros = curr_zeros;
      curr_zeros = 0;
    }
    /* Print the rest of the address */
    for (ii = zero; ii < 8; ) {
      if ((ii == max_start) && max_zeros) {
        *output++ = '_';
        ii += max_zeros;
      } else {
        inttobase64(output, ntohs(addr->in6_16[ii]), 3);
        output += 3;
        ii++;
      }
    }
    *output = '\0';
  }
  return buf;
}

/** Decode an IP address from base64.
 * @param[in] input Input buffer to decode.
 * @param[out] addr IP address structure to populate.
 */
void base64toip(const char* input, struct irc_in_addr* addr)
{
  memset(addr, 0, sizeof(*addr));
  if (strlen(input) == 6) {
    unsigned int in = base64toint(input);
    /* An all-zero address should stay that way. */
    if (in) {
      addr->in6_16[5] = htons(65535);
      addr->in6_16[6] = htons(in >> 16);
      addr->in6_16[7] = htons(in & 65535);
    }
  } else {
    unsigned int pos = 0;
    do {
      if (*input == '_') {
        unsigned int left;
        for (left = (25 - strlen(input)) / 3 - pos; left; left--)
          addr->in6_16[pos++] = 0;
        input++;
      } else {
        unsigned short accum = convert2n[(unsigned char)*input++];
        accum = (accum << NUMNICKLOG) | convert2n[(unsigned char)*input++];
        accum = (accum << NUMNICKLOG) | convert2n[(unsigned char)*input++];
        addr->in6_16[pos++] = ntohs(accum);
      }
    } while (pos < 8);
  }
}
