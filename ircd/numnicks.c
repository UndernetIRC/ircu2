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
 *
 * $Id$
 */

#include "numnicks.h"
#include "sys.h"
#include "h.h"
#include "s_serv.h"
#include "struct.h"
#include "common.h"
#include "ircd.h"
#include "s_misc.h"
#include "match.h"
#include "s_bsd.h"
#include "s_debug.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

RCSTAG_CC("$Id$");

/*
 * Numeric nicks are new as of version ircu2.10.00beta1.
 *
 * The idea is as follows:
 * In most messages (for protocol 10+) the original nick will be
 * replaced by a 3 character string: YXX
 * Where 'Y' represents the server, and 'XX' the nick on that server.
 *
 * 'YXX' should not interfer with the input parser, and therefore is
 * not allowed to contain spaces or a ':'.
 * Also, 'Y' can't start with a '+' because of m_server().
 *
 * We keep the characters printable for debugging reasons too.
 *
 * The 'XX' value can be larger then the maximum number of clients
 * per server, we use a mask (struct Server::nn_mask) to get the real
 * client numeric. The overhead is used to have some redundancy so
 * just-disconnected-client aren't confused with just-connected ones.
 */

/*
 * when n2k comes, define this for more capacity
 */
#undef  EXTENDED_NUMERICS

/* These must be the same on ALL servers ! Do not change ! */

#define NUMNICKLOG 6
#define NUMNICKMAXCHAR 'z'      /* See convert2n[] */
#define NUMNICKBASE 64          /* (2 << NUMNICKLOG) */
#define NUMNICKMASK 63          /* (NUMNICKBASE-1) */
#define NN_MAX_SERVER 4096      /* (NUMNICKBASE * NUMNICKBASE) */
#if defined(EXTENDED_NUMERICS)
#define NN_MAX_CLIENT 262144    /* NUMNICKBASE ^ 3 */
#else
#define NN_MAX_CLIENT 4096      /* (NUMNICKBASE * NUMNICKBASE) */
#endif

/*
 * The internal counter for the 'XX' of local clients
 */
static unsigned int lastNNServer = 0;
static struct Client* server_list[NN_MAX_SERVER];

/* *INDENT-OFF* */

/*
 * convert2y[] converts a numeric to the corresponding character.
 * The following characters are currently known to be forbidden:
 *
 * '\0' : Because we use '\0' as end of line.
 *
 * ' '  : Because parse_*() uses this as parameter seperator.
 * ':'  : Because parse_server() uses this to detect if a prefix is a
 *        numeric or a name.
 * '+'  : Because m_nick() uses this to determine if parv[6] is a
 *        umode or not.
 * '&', '#', '+', '$', '@' and '%' :
 *        Because m_message() matches these characters to detect special cases.
 */
static const char convert2y[] = {
  'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
  'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
  'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
  'w','x','y','z','0','1','2','3','4','5','6','7','8','9','[',']'
};

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


unsigned int base64toint(const char* s)
{
  unsigned int i = convert2n[(unsigned char) *s++];
  while (*s) {
    i <<= NUMNICKLOG;
    i += convert2n[(unsigned char) *s++];
  }
  return i;
}

const char* inttobase64(char* buf, unsigned int v, unsigned int count)
{
  buf[count] = '\0';  
  while (count > 0) {
    buf[--count] = convert2y[(v & NUMNICKMASK)];
    v >>= NUMNICKLOG;
  }
  return buf;
}

static struct Client* FindXNServer(const char* numeric)
{
  char buf[3];
  buf[0] = *numeric++;
  buf[1] = *numeric;
  buf[2] = '\0';
  Debug((DEBUG_DEBUG, "FindXNServer: %s(%d)", buf, base64toint(buf)));
  return server_list[base64toint(buf)];
}

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

struct Client* findNUser(const char* yxx)
{
  struct Client* server = 0;
  if (5 == strlen(yxx)) {
    if (0 != (server = FindXNServer(yxx))) {
      Debug((DEBUG_DEBUG, "findNUser: %s(%d)", yxx, 
             base64toint(yxx + 2) & server->serv->nn_mask));
      return server->serv->client_list[base64toint(yxx + 2) & server->serv->nn_mask];
    }
  }
  else if (0 != (server = FindNServer(yxx))) {
    Debug((DEBUG_DEBUG, "findNUser: %s(%d)",
           yxx, base64toint(yxx + 1) & server->serv->nn_mask));
    return server->serv->client_list[base64toint(yxx + 1) & server->serv->nn_mask];
  }
  return 0;
}

void RemoveYXXClient(struct Client* server, const char* yxx)
{
  assert(0 != server);
  assert(0 != yxx);
  if (*yxx) {
    Debug((DEBUG_DEBUG, "RemoveYXXClient: %s(%d)", yxx,
           base64toint(yxx) & server->serv->nn_mask));
    server->serv->client_list[base64toint(yxx) & server->serv->nn_mask] = 0;
  }
}

void SetServerYXX(struct Client* cptr, struct Client* server, const char* yxx)
{
  unsigned int index;
  if (Protocol(cptr) > 9) {
    if (5 == strlen(yxx)) {
      strncpy(server->yxx, yxx, 2);
      strncpy(server->serv->nn_capacity, yxx + 2, 3);
    }
    else {
      server->yxx[0]               = yxx[0];
      server->serv->nn_capacity[0] = yxx[1];
      server->serv->nn_capacity[1] = yxx[2];
    }
    server->serv->nn_mask = base64toint(server->serv->nn_capacity);
  }
  else {
    /*
     * special case uworld and channels
     */
    static const struct ServerNameNumeric {
      const char *name;
      unsigned int numeric;
    } server_table[] = {
      { "Uworld.undernet.org",    22 },
      { "Uworld2.undernet.org",   23 },
      { "channels.undernet.org",  30 },
      { "channels2.undernet.org", 31 },
      { 0, 0 }
    };
    int i;
    for (i = 0; i < 4; ++i) {
      if (!strCasediff(server_table[i].name, server->name)) {
	/*
	 * XXX - just use the old format for services for now
	 */
	*server->yxx = convert2y[server_table[i].numeric];
	inttobase64(server->serv->nn_capacity, 63, 2);
	server->serv->nn_mask = 63;
	break;
      }
    }
  }
  index = base64toint(server->yxx);
  if (index >= lastNNServer)
    lastNNServer = index + 1;
  server_list[index] = server;

  /* Note, exit_one_client uses the fact that `client_list' != NULL to
   * determine that SetServerYXX has been called - and then calls
   * ClearServerYXX. However, freeing the allocation happens in free_client() */
  server->serv->client_list =
      (struct Client**) RunCalloc(server->serv->nn_mask + 1, sizeof(struct Client*));
}

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
    fprintf(stderr, "MAXCLIENTS (or MAXCONNECTIONS) is (at least) %d "
            "too large ! Please decrease this value.\n",
             max_clients - NN_MAX_CLIENT);
    exit(-1);
  }
  --max_clients;
  inttobase64(c->serv->nn_capacity, max_clients, 2); 
  c->serv->nn_mask = max_clients;       /* Our Numeric Nick mask */
  c->serv->client_list = (struct Client**) RunCalloc(max_clients + 1, 
                                                     sizeof(struct Client*));
  server_list[base64toint(c->yxx)] = c;
}

void SetYXXServerName(struct Client* c, unsigned int numeric)
{
  assert(0 != c);
  assert(numeric < NN_MAX_SERVER);

#if defined(EXTENDED_NUMERICS)
  inttobase64(c->yxx, numeric, 2);
#else
  assert(numeric < NUMNICKBASE);
  c->yxx[0] = convert2y[numeric];
#endif
  if (numeric >= lastNNServer)
    lastNNServer = numeric + 1;
  server_list[numeric] = c;
}

void ClearServerYXX(const struct Client *server)
{
  unsigned int index = base64toint(server->yxx);
  if (server_list[index] == server)     /* Sanity check */
    server_list[index] = 0;
}

/*
 * SetRemoteNumNick()
 *
 * Register numeric of new, remote, client.
 * Add it to the appropriate client_list.
 */
void SetRemoteNumNick(struct Client* acptr, const char *yxx)
{
  struct Client** acptrp;
  struct Client*  server = acptr->user->server;
 
  if (5 == strlen(yxx)) {
    strcpy(acptr->yxx, yxx + 2);
  }
  else {
    acptr->yxx[0] = *++yxx;
    acptr->yxx[1] = *++yxx;
    acptr->yxx[2] = 0;
  }
  Debug((DEBUG_DEBUG, "SetRemoteNumNick: %s(%d)", acptr->yxx, 
         base64toint(acptr->yxx) & server->serv->nn_mask));

  acptrp = &server->serv->client_list[base64toint(acptr->yxx) & server->serv->nn_mask];
  if (*acptrp) {
    /*
     * this exits the old client in the array, not the client
     * that is being set
     */
    exit_client(acptr->from, *acptrp, server, "Numeric nick collision (Ghost)");
  }
  *acptrp = acptr;
}


/*
 * SetLocalNumNick()
 *
 * Register numeric of new, local, client. Add it to our client_list.
 * Muxtex needed if threaded
 */
int SetLocalNumNick(struct Client *cptr)
{
  static unsigned int last_nn     = 0;
  struct Client**     client_list = me.serv->client_list;
  unsigned int        mask        = me.serv->nn_mask;
  unsigned int        count       = 0;

  assert(cptr->user->server == &me);

  while (client_list[last_nn & mask]) {
    if (++count == NN_MAX_CLIENT) {
      assert(count < NN_MAX_CLIENT);
      return 0;
    }
    if (++last_nn == NN_MAX_CLIENT)
      last_nn = 0;
  }
  client_list[last_nn & mask] = cptr;  /* Reserve the numeric ! */

#if defined(EXTENDED_NUMERICS)
  inttobase64(cptr->yxx, last_nn, 3);
#else
  inttobase64(cptr->yxx, last_nn, 2);
#endif
  if (++last_nn == NN_MAX_CLIENT)
    last_nn = 0;
  return 1;
}

/* 
 * markMatchexServer()
 * Mark all servers whose name matches the given (compiled) mask
 * and return their count, abusing FLAGS_MAP for this :)
 */
int markMatchexServer(const char *cmask, int minlen)
{
  int cnt = 0;
  int i;
  struct Client *acptr;

  for (i = 0; i < lastNNServer; i++) {
    if ((acptr = server_list[i])) {
      if (matchexec(acptr->name, cmask, minlen))
        acptr->flags &= ~FLAGS_MAP;
      else {
        acptr->flags |= FLAGS_MAP;
        cnt++;
      }
    }
  }
  return cnt;
}

struct Client* find_match_server(char *mask)
{
  struct Client *acptr;
  int i;

  if (!(BadPtr(mask))) {
    collapse(mask);
    for (i = 0; i < lastNNServer; i++) {
      if ((acptr = server_list[i]) && (!match(mask, acptr->name)))
        return acptr;
    }
  }
  return 0;
}


/*
 * CreateNNforProtocol9server
 *
 * We do not receive numeric nicks from servers behind a protocol 9 link
 * so we generate it ourselfs.
 */
const char *CreateNNforProtocol9server(const struct Client *server)
{
  static char YXX[4];
  struct Server *serv = server->serv;
  unsigned int count = 0;

  assert(IsServer(server));
  assert(9 == Protocol(server));

  YXX[0] = *server->yxx;
  YXX[3] = 0;

  while (serv->client_list[serv->nn_last])
  {
    if (++count == NUMNICKBASE)
    {
      assert(count < NUMNICKBASE);
      return NULL;
    }
    if (++serv->nn_last == NUMNICKBASE)
      serv->nn_last = 0;
  }
  inttobase64(YXX + 1, serv->nn_last, 2);
  if (++serv->nn_last == NUMNICKBASE)
      serv->nn_last = 0;
  return YXX;
}

