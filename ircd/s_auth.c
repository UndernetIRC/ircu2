/************************************************************************
 *   IRC - Internet Relay Chat, src/s_auth.c
 *   Copyright (C) 1992 Darren Reed
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *   $Id$
 *
 * Changes:
 *   July 6, 1999 - Rewrote most of the code here. When a client connects
 *     to the server and passes initial socket validation checks, it
 *     is owned by this module (auth) which returns it to the rest of the
 *     server when dns and auth queries are finished. Until the client is
 *     released, the server does not know it exists and does not process
 *     any messages from it.
 *     --Bleep  Thomas Helvey <tomh@inxpress.net>
 */
#include "s_auth.h"
#include "client.h"
#include "IPcheck.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_osdep.h"
#include "ircd_string.h"
#include "list.h"
#include "numeric.h"
#include "querycmds.h"
#include "res.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "sprintf_irc.h"
#include "struct.h"
#include "sys.h"               /* TRUE bleah */

#include <arpa/inet.h>         /* inet_netof */
#include <netdb.h>             /* struct hostent */
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>

/*
 * a bit different approach
 * this replaces the original sendheader macros
 */
static struct {
  const char*  message;
  unsigned int length;
} HeaderMessages [] = {
  /* 123456789012345678901234567890123456789012345678901234567890 */
  { "NOTICE AUTH :*** Looking up your hostname\r\n",       43 },
  { "NOTICE AUTH :*** Found your hostname\r\n",            38 },
  { "NOTICE AUTH :*** Found your hostname, cached\r\n",    46 },
  { "NOTICE AUTH :*** Couldn't look up your hostname\r\n", 49 },
  { "NOTICE AUTH :*** Checking Ident\r\n",                 33 },
  { "NOTICE AUTH :*** Got ident response\r\n",             37 },
  { "NOTICE AUTH :*** No ident response\r\n",              36 },
  { "NOTICE AUTH :*** Your forward and reverse DNS do not match, " \
    "ignoring hostname.\r\n",                              80 }
};

typedef enum {
  REPORT_DO_DNS,
  REPORT_FIN_DNS,
  REPORT_FIN_DNSC,
  REPORT_FAIL_DNS,
  REPORT_DO_ID,
  REPORT_FIN_ID,
  REPORT_FAIL_ID,
  REPORT_IP_MISMATCH
} ReportType;

#define sendheader(c, r) \
   send(cli_fd(c), HeaderMessages[(r)].message, HeaderMessages[(r)].length, 0)

struct AuthRequest* AuthPollList = 0; /* GLOBAL - auth queries pending io */
static struct AuthRequest* AuthIncompleteList = 0;

enum { AUTH_TIMEOUT = 60 };

/*
 * make_auth_request - allocate a new auth request
 */
static struct AuthRequest* make_auth_request(struct Client* client)
{
  struct AuthRequest* auth = 
               (struct AuthRequest*) MyMalloc(sizeof(struct AuthRequest));
  assert(0 != auth);
  memset(auth, 0, sizeof(struct AuthRequest));
  auth->fd      = -1;
  auth->client  = client;
  auth->timeout = CurrentTime + AUTH_TIMEOUT;
  return auth;
}

/*
 * free_auth_request - cleanup auth request allocations
 */
void free_auth_request(struct AuthRequest* auth)
{
  if (-1 < auth->fd)
    close(auth->fd);
  MyFree(auth);
}

/*
 * unlink_auth_request - remove auth request from a list
 */
static void unlink_auth_request(struct AuthRequest* request,
                                struct AuthRequest** list)
{
  if (request->next)
    request->next->prev = request->prev;
  if (request->prev)
    request->prev->next = request->next;
  else
    *list = request->next;
}

/*
 * link_auth_request - add auth request to a list
 */
static void link_auth_request(struct AuthRequest* request,
                              struct AuthRequest** list)
{
  request->prev = 0;
  request->next = *list;
  if (*list)
    (*list)->prev = request;
  *list = request;
}

/*
 * release_auth_client - release auth client from auth system
 * this adds the client into the local client lists so it can be read by
 * the main io processing loop
 */
static void release_auth_client(struct Client* client)
{
  assert(0 != client);
  cli_lasttime(client) = cli_since(client) = CurrentTime;
  if (cli_fd(client) > HighestFd)
    HighestFd = cli_fd(client);
  LocalClientArray[cli_fd(client)] = client;

  add_client_to_list(client);
  Debug((DEBUG_INFO, "Auth: release_auth_client %s@%s[%s]",
         cli_username(client), cli_sockhost(client), cli_sock_ip(client)));
}
 
static void auth_kill_client(struct AuthRequest* auth)
{
  assert(0 != auth);

  unlink_auth_request(auth, (IsDoingAuth(auth)) ? &AuthPollList : &AuthIncompleteList);

  if (IsDNSPending(auth))
    delete_resolver_queries(auth);
  IPcheck_disconnect(auth->client);
  Count_unknowndisconnects(UserStats);
  free_client(auth->client);
  free_auth_request(auth);
}

/*
 * auth_dns_callback - called when resolver query finishes
 * if the query resulted in a successful search, hp will contain
 * a non-null pointer, otherwise hp will be null.
 * set the client on it's way to a connection completion, regardless
 * of success of failure
 */
static void auth_dns_callback(void* vptr, struct DNSReply* reply)
{
  struct AuthRequest* auth = (struct AuthRequest*) vptr;

  assert(0 != auth);
  /*
   * need to do this here so auth_kill_client doesn't
   * try have the resolver delete the query it's about
   * to delete anyways. --Bleep
   */
  ClearDNSPending(auth);

  if (reply) {
    const struct hostent* hp = reply->hp;
    int i;
    assert(0 != hp);
    /*
     * Verify that the host to ip mapping is correct both ways and that
     * the ip#(s) for the socket is listed for the host.
     */
    for (i = 0; hp->h_addr_list[i]; ++i) {
      if (0 == memcmp(hp->h_addr_list[i], &(cli_ip(auth->client)),
                      sizeof(struct in_addr)))
         break;
    }
    if (!hp->h_addr_list[i]) {
      if (IsUserPort(auth->client))
        sendheader(auth->client, REPORT_IP_MISMATCH);
      sendto_opmask_butone(0, SNO_IPMISMATCH, "IP# Mismatch: %s != %s[%s]",
			   cli_sock_ip(auth->client), hp->h_name, 
			   ircd_ntoa(hp->h_addr_list[0]));
      if (feature_bool(FEAT_KILL_IPMISMATCH)) {
	auth_kill_client(auth);
	return;
      }
    }
    else {
      ++reply->ref_count;
      cli_dns_reply(auth->client) = reply;
      ircd_strncpy(cli_sockhost(auth->client), hp->h_name, HOSTLEN);
      if (IsUserPort(auth->client))
        sendheader(auth->client, REPORT_FIN_DNS);
    }
  }
  else {
    /*
     * this should have already been done by s_bsd.c in add_connection
     *
     * strcpy(auth->client->sockhost, auth->client->sock_ip);
     */
    if (IsUserPort(auth->client))
      sendheader(auth->client, REPORT_FAIL_DNS);
  }
  if (!IsDoingAuth(auth)) {
    release_auth_client(auth->client);
    unlink_auth_request(auth, &AuthIncompleteList);
    free_auth_request(auth);
  }
}

/*
 * authsenderr - handle auth send errors
 */
static void auth_error(struct AuthRequest* auth, int kill)
{
  ++ServerStats->is_abad;

  assert(0 != auth);
  close(auth->fd);
  auth->fd = -1;

  if (IsUserPort(auth->client))
    sendheader(auth->client, REPORT_FAIL_ID);

  if (kill) {
    /*
     * we can't read the client info from the client socket,
     * close the client connection and free the client
     * Need to do this before we ClearAuth(auth) so we know
     * which list to remove the query from. --Bleep
     */
    auth_kill_client(auth);
    return;
  }

  ClearAuth(auth);
  unlink_auth_request(auth, &AuthPollList);

  if (IsDNSPending(auth))
    link_auth_request(auth, &AuthIncompleteList);
  else {
    release_auth_client(auth->client);
    free_auth_request(auth);
  }
}

/*
 * start_auth_query - Flag the client to show that an attempt to 
 * contact the ident server on the client's host.  The connect and
 * subsequently the socket are all put into 'non-blocking' mode.  
 * Should the connect or any later phase of the identifing process fail,
 * it is aborted and the user is given a username of "unknown".
 */
static int start_auth_query(struct AuthRequest* auth)
{
  struct sockaddr_in remote_addr;
  struct sockaddr_in local_addr;
  int                fd;

  assert(0 != auth);
  assert(0 != auth->client);

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
#if 0
    report_error(SOCKET_ERROR_MSG, get_client_name(auth->client, HIDE_IP), errno);
#endif
    ++ServerStats->is_abad;
    return 0;
  }
  if ((MAXCONNECTIONS - 10) < fd) {
#if 0
    report_error(CONNLIMIT_ERROR_MSG, 
                 get_client_name(auth->client, HIDE_IP), errno);
#endif
    close(fd);
    return 0;
  }
  if (!os_set_nonblocking(fd)) {
#if 0
    report_error(NONB_ERROR_MSG, get_client_name(auth->client, HIDE_IP), errno);
#endif
    close(fd);
    return 0;
  }
  if (IsUserPort(auth->client))
    sendheader(auth->client, REPORT_DO_ID);
  /* 
   * get the local address of the client and bind to that to
   * make the auth request.  This used to be done only for
   * ifdef VIRTTUAL_HOST, but needs to be done for all clients
   * since the ident request must originate from that same address--
   * and machines with multiple IP addresses are common now
   */
  memset(&local_addr, 0, sizeof(struct sockaddr_in));
  os_get_sockname(cli_fd(auth->client), &local_addr);
  local_addr.sin_port = htons(0);

  if (bind(fd, (struct sockaddr*) &local_addr, sizeof(struct sockaddr_in))) {
#if 0
    report_error(BIND_ERROR_MSG,
                 get_client_name(auth->client, HIDE_IP), errno);
#endif
    close(fd);
    return 0;
  }

  remote_addr.sin_addr.s_addr = (cli_ip(auth->client)).s_addr;
  remote_addr.sin_port = htons(113);
  remote_addr.sin_family = AF_INET;

  if (!os_connect_nonb(fd, &remote_addr)) {
    ServerStats->is_abad++;
    /*
     * No error report from this...
     */
    close(fd);
    if (IsUserPort(auth->client))
      sendheader(auth->client, REPORT_FAIL_ID);
    return 0;
  }

  auth->fd = fd;

  SetAuthConnect(auth);
  return 1;
}


enum IdentReplyFields {
  IDENT_PORT_NUMBERS,
  IDENT_REPLY_TYPE,
  IDENT_OS_TYPE,
  IDENT_INFO,
  USERID_TOKEN_COUNT
};

static char* check_ident_reply(char* reply)
{
  char* token;
  char* end;
  char* vector[USERID_TOKEN_COUNT];
  int count = token_vector(reply, ':', vector, USERID_TOKEN_COUNT);

  if (USERID_TOKEN_COUNT != count)
    return 0;
  /*
   * second token is the reply type
   */
  token = vector[IDENT_REPLY_TYPE];
  if (EmptyString(token))
    return 0;

  while (IsSpace(*token))
    ++token;

  if (0 != strncmp(token, "USERID", 6))
    return 0;

  /*
   * third token is the os type
   */
  token = vector[IDENT_OS_TYPE];
  if (EmptyString(token))
    return 0;
  while (IsSpace(*token))
   ++token;

  /*
   * Unless "OTHER" is specified as the operating system
   * type, the server is expected to return the "normal"
   * user identification of the owner of this connection.
   * "Normal" in this context may be taken to mean a string
   * of characters which uniquely identifies the connection
   * owner such as a user identifier assigned by the system
   * administrator and used by such user as a mail
   * identifier, or as the "user" part of a user/password
   * pair used to gain access to system resources.  When an
   * operating system is specified (e.g., anything but
   * "OTHER"), the user identifier is expected to be in a
   * more or less immediately useful form - e.g., something
   * that could be used as an argument to "finger" or as a
   * mail address.
   */
  if (0 == strncmp(token, "OTHER", 5))
    return 0;
  /*
   * fourth token is the username
   */
  token = vector[IDENT_INFO];
  if (EmptyString(token))
    return 0;
  while (IsSpace(*token))
    ++token;
  /*
   * look for the end of the username, terminators are '\0, @, <SPACE>, :'
   */
  for (end = token; *end; ++end) {
    if (IsSpace(*end) || '@' == *end || ':' == *end)
      break;
  }
  *end = '\0'; 
  return token;
}

#if 0
/*
 * GetValidIdent - parse ident query reply from identd server
 * 
 * Inputs        - pointer to ident buf
 * Output        - NULL if no valid ident found, otherwise pointer to name
 * Side effects        -
 */
static char* GetValidIdent(char *buf)
{
  int   remp = 0;
  int   locp = 0;
  char* colon1Ptr;
  char* colon2Ptr;
  char* colon3Ptr;
  char* commaPtr;
  char* remotePortString;

  /* All this to get rid of a sscanf() fun. */
  remotePortString = buf;
  
  colon1Ptr = strchr(remotePortString,':');
  if(!colon1Ptr)
    return 0;

  *colon1Ptr = '\0';
  colon1Ptr++;
  colon2Ptr = strchr(colon1Ptr,':');
  if(!colon2Ptr)
    return 0;

  *colon2Ptr = '\0';
  colon2Ptr++;
  commaPtr = strchr(remotePortString, ',');

  if(!commaPtr)
    return 0;

  *commaPtr = '\0';
  commaPtr++;

  remp = atoi(remotePortString);
  if(!remp)
    return 0;
              
  locp = atoi(commaPtr);
  if(!locp)
    return 0;

  /* look for USERID bordered by first pair of colons */
  if(!strstr(colon1Ptr, "USERID"))
    return 0;

  colon3Ptr = strchr(colon2Ptr,':');
  if(!colon3Ptr)
    return 0;
  
  *colon3Ptr = '\0';
  colon3Ptr++;
  return(colon3Ptr);
}
#endif

/*
 * start_auth - starts auth (identd) and dns queries for a client
 */
enum { LOOPBACK = 127 };

void start_auth(struct Client* client)
{
  struct AuthRequest* auth = 0;

  assert(0 != client);

  auth = make_auth_request(client);
  assert(0 != auth);

  if (!feature_bool(FEAT_NODNS)) {
    if (LOOPBACK == inet_netof(cli_ip(client)))
      strcpy(cli_sockhost(client), cli_name(&me));
    else {
      struct DNSQuery query;

      query.vptr     = auth;
      query.callback = auth_dns_callback;

      if (IsUserPort(auth->client))
	sendheader(client, REPORT_DO_DNS);

      cli_dns_reply(client) = gethost_byaddr((const char*) &(cli_ip(client)),
					     &query);

      if (cli_dns_reply(client)) {
	++(cli_dns_reply(client))->ref_count;
	ircd_strncpy(cli_sockhost(client), cli_dns_reply(client)->hp->h_name,
		     HOSTLEN);
	if (IsUserPort(auth->client))
	  sendheader(client, REPORT_FIN_DNSC);
      } else
	SetDNSPending(auth);
    }
  }

  if (start_auth_query(auth))
    link_auth_request(auth, &AuthPollList);
  else if (IsDNSPending(auth))
    link_auth_request(auth, &AuthIncompleteList);
  else {
    free_auth_request(auth);
    release_auth_client(client);
  }
}

/*
 * timeout_auth_queries - timeout resolver and identd requests
 * allow clients through if requests failed
 */
void timeout_auth_queries(time_t now)
{
  struct AuthRequest* auth;
  struct AuthRequest* auth_next = 0;

  for (auth = AuthPollList; auth; auth = auth_next) {
    auth_next = auth->next;
    if (auth->timeout < CurrentTime) {
      if (-1 < auth->fd) {
        close(auth->fd);
        auth->fd = -1;
      }

      if (IsUserPort(auth->client))
        sendheader(auth->client, REPORT_FAIL_ID);
      if (IsDNSPending(auth)) {
        delete_resolver_queries(auth);
        if (IsUserPort(auth->client))
          sendheader(auth->client, REPORT_FAIL_DNS);
      }
      log_write(LS_RESOLVER, L_INFO, 0, "DNS/AUTH timeout %s",
		get_client_name(auth->client, HIDE_IP));

      release_auth_client(auth->client);
      unlink_auth_request(auth, &AuthPollList);
      free_auth_request(auth);
    }
  }
  for (auth = AuthIncompleteList; auth; auth = auth_next) {
    auth_next = auth->next;
    if (auth->timeout < CurrentTime) {
      delete_resolver_queries(auth);
      if (IsUserPort(auth->client))
        sendheader(auth->client, REPORT_FAIL_DNS);
      log_write(LS_RESOLVER, L_INFO, 0, "DNS timeout %s",
		get_client_name(auth->client, HIDE_IP));

      release_auth_client(auth->client);
      unlink_auth_request(auth, &AuthIncompleteList);
      free_auth_request(auth);
    }
  }
}

/*
 * send_auth_query - send the ident server a query giving "theirport , ourport"
 * The write is only attempted *once* so it is deemed to be a fail if the
 * entire write doesn't write all the data given.  This shouldnt be a
 * problem since the socket should have a write buffer far greater than
 * this message to store it in should problems arise. -avalon
 */
void send_auth_query(struct AuthRequest* auth)
{
  struct sockaddr_in us;
  struct sockaddr_in them;
  char               authbuf[32];
  unsigned int       count;

  assert(0 != auth);
  assert(0 != auth->client);

  if (!os_get_sockname(cli_fd(auth->client), &us) ||
      !os_get_peername(cli_fd(auth->client), &them)) {
    auth_error(auth, 1);
    return;
  }
  sprintf_irc(authbuf, "%u , %u\r\n",
             (unsigned int) ntohs(them.sin_port),
             (unsigned int) ntohs(us.sin_port));

  if (IO_SUCCESS == os_send_nonb(auth->fd, authbuf, strlen(authbuf), &count)) {
    ClearAuthConnect(auth);
    SetAuthPending(auth);
  }
  else
    auth_error(auth, 0);
}


/*
 * read_auth_reply - read the reply (if any) from the ident server 
 * we connected to.
 * We only give it one shot, if the reply isn't good the first time
 * fail the authentication entirely. --Bleep
 */
void read_auth_reply(struct AuthRequest* auth)
{
  char*        username = 0;
  unsigned int len;
  /*
   * rfc1453 sez we MUST accept 512 bytes
   */
  char   buf[BUFSIZE + 1];

  assert(0 != auth);
  assert(0 != auth->client);

  if (IO_SUCCESS == os_recv_nonb(auth->fd, buf, BUFSIZE, &len)) {
    buf[len] = '\0';
    username = check_ident_reply(buf);
  }

  close(auth->fd);
  auth->fd = -1;
  ClearAuth(auth);
  
  if (!EmptyString(username)) {
    ircd_strncpy(cli_username(auth->client), username, USERLEN);
    /*
     * Not needed, struct is zeroed by memset
     * auth->client->username[USERLEN] = '\0';
     */
    SetGotId(auth->client);
    ++ServerStats->is_asuc;
    if (IsUserPort(auth->client))
      sendheader(auth->client, REPORT_FIN_ID);
  }
  else {
    ++ServerStats->is_abad;
#if 0
    strcpy(cli_username(auth->client), "unknown");
#endif
  }
  unlink_auth_request(auth, &AuthPollList);

  if (IsDNSPending(auth))
    link_auth_request(auth, &AuthIncompleteList);
  else {
    release_auth_client(auth->client);
    free_auth_request(auth);
  }
}


