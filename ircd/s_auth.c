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
 * Changes:
 *   July 6, 1999 - Rewrote most of the code here. When a client connects
 *     to the server and passes initial socket validation checks, it
 *     is owned by this module (auth) which returns it to the rest of the
 *     server when dns and auth queries are finished. Until the client is
 *     released, the server does not know it exists and does not process
 *     any messages from it.
 *     --Bleep  Thomas Helvey <tomh@inxpress.net>
 */
/** @file
 * @brief Implementation of DNS and ident lookups.
 * @version $Id$
 */
#include "config.h"

#include "s_auth.h"
#include "client.h"
#include "IPcheck.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_osdep.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "numeric.h"
#include "querycmds.h"
#include "res.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
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

/** Array of message text (with length) pairs for AUTH status
 * messages.  Indexed using #ReportType. */
static struct {
  const char*  message;
  unsigned int length;
} HeaderMessages [] = {
#define MSG(STR) { STR, sizeof(STR) - 1 }
  MSG("NOTICE AUTH :*** Looking up your hostname\r\n"),
  MSG("NOTICE AUTH :*** Found your hostname\r\n"),
  MSG("NOTICE AUTH :*** Found your hostname, cached\r\n"),
  MSG("NOTICE AUTH :*** Couldn't look up your hostname\r\n"),
  MSG("NOTICE AUTH :*** Checking Ident\r\n"),
  MSG("NOTICE AUTH :*** Got ident response\r\n"),
  MSG("NOTICE AUTH :*** No ident response\r\n"),
  MSG("NOTICE AUTH :*** Your forward and reverse DNS do not match, "
    "ignoring hostname.\r\n"),
  MSG("NOTICE AUTH :*** Invalid hostname\r\n")
#undef MSG
};

/** Enum used to index messages in the HeaderMessages[] array. */
typedef enum {
  REPORT_DO_DNS,
  REPORT_FIN_DNS,
  REPORT_FIN_DNSC,
  REPORT_FAIL_DNS,
  REPORT_DO_ID,
  REPORT_FIN_ID,
  REPORT_FAIL_ID,
  REPORT_IP_MISMATCH,
  REPORT_INVAL_DNS
} ReportType;

/** Sends response \a r (from #ReportType) to client \a c. */
#define sendheader(c, r) \
   send(cli_fd(c), HeaderMessages[(r)].message, HeaderMessages[(r)].length, 0)

static void release_auth_client(struct Client* client);
void free_auth_request(struct AuthRequest* auth);

/** Verify that a hostname is valid, i.e., only contains characters
 * valid for a hostname and that a hostname is not too long.
 * @param host Hostname to check.
 * @param maxlen Maximum length of hostname, not including NUL terminator.
 * @return Non-zero if the hostname is valid.
 */
static int
auth_verify_hostname(char *host, int maxlen)
{
  int i;

  /* Walk through the host name */
  for (i = 0; host[i]; i++)
    /* If it's not a hostname character or if it's too long, return false */
    if (!IsHostChar(host[i]) || i >= maxlen)
      return 0;

  return 1; /* it's a valid hostname */
}

/** Timeout a given auth request.
 * @param ev A timer event whose associated data is the expired struct
 * AuthRequest.
 */
static void auth_timeout_callback(struct Event* ev)
{
  struct AuthRequest* auth;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));

  auth = (struct AuthRequest*) t_data(ev_timer(ev));

  if (ev_type(ev) == ET_DESTROY) { /* being destroyed */
    auth->flags &= ~AM_TIMEOUT;

    if (!(auth->flags & AM_FREE_MASK)) {
      Debug((DEBUG_LIST, "Freeing auth from timeout callback; %p [%p]", auth,
	     ev_timer(ev)));
      MyFree(auth); /* done with it, finally */
    }
  } else {
    assert(ev_type(ev) == ET_EXPIRE);

    destroy_auth_request(auth, 1);
  }
}

/** Handle socket I/O activity.
 * @param ev A socket event whos associated data is the active struct
 * AuthRequest.
 */
static void auth_sock_callback(struct Event* ev)
{
  struct AuthRequest* auth;

  assert(0 != ev_socket(ev));
  assert(0 != s_data(ev_socket(ev)));

  auth = (struct AuthRequest*) s_data(ev_socket(ev));

  switch (ev_type(ev)) {
  case ET_DESTROY: /* being destroyed */
    auth->flags &= ~AM_SOCKET;

    if (!(auth->flags & AM_FREE_MASK)) {
      Debug((DEBUG_LIST, "Freeing auth from sock callback; %p [%p]", auth,
	     ev_socket(ev)));
      MyFree(auth); /* done with it finally */
    }
    break;

  case ET_CONNECT: /* socket connection completed */
    Debug((DEBUG_LIST, "Connection completed for auth %p [%p]; sending query",
	   auth, ev_socket(ev)));
    socket_state(&auth->socket, SS_CONNECTED);
    send_auth_query(auth);
    break;

  case ET_READ: /* socket is readable */
  case ET_EOF: /* end of file on socket */
  case ET_ERROR: /* error on socket */
    Debug((DEBUG_LIST, "Auth socket %p [%p] readable", auth, ev_socket(ev)));
    read_auth_reply(auth);
    break;

  default:
    assert(0 && "Unrecognized event in auth_socket_callback().");
    break;
  }
}

/** Stop an auth request completely.
 * @param auth The struct AuthRequest to cancel.
 * @param send_reports If non-zero, report the failure to the user and
 * resolver log.
 */
void destroy_auth_request(struct AuthRequest* auth, int send_reports)
{
  if (IsDoingAuth(auth)) {
    if (-1 < auth->fd) {
      close(auth->fd);
      auth->fd = -1;
      socket_del(&auth->socket);
    }

    if (send_reports && IsUserPort(auth->client))
      sendheader(auth->client, REPORT_FAIL_ID);
  }

  if (IsDNSPending(auth)) {
    delete_resolver_queries(auth);
    if (send_reports && IsUserPort(auth->client))
      sendheader(auth->client, REPORT_FAIL_DNS);
  }

  if (send_reports) {
    log_write(LS_RESOLVER, L_INFO, 0, "DNS/AUTH timeout %s",
	      get_client_name(auth->client, HIDE_IP));
    release_auth_client(auth->client);
  }

  free_auth_request(auth);
}

/** Allocate a new auth request.
 * @param client The client being looked up.
 * @return The newly allocated auth request.
 */
static struct AuthRequest* make_auth_request(struct Client* client)
{
  struct AuthRequest* auth = 
               (struct AuthRequest*) MyMalloc(sizeof(struct AuthRequest));
  assert(0 != auth);
  memset(auth, 0, sizeof(struct AuthRequest));
  auth->flags   = AM_TIMEOUT;
  auth->fd      = -1;
  auth->client  = client;
  cli_auth(client) = auth;
  timer_add(timer_init(&auth->timeout), auth_timeout_callback, (void*) auth,
	    TT_RELATIVE, feature_int(FEAT_AUTH_TIMEOUT));
  return auth;
}

/** Clean up auth request allocations (event loop objects, etc).
 * @param auth The request to clean up.
 */
void free_auth_request(struct AuthRequest* auth)
{
  if (-1 < auth->fd) {
    close(auth->fd);
    Debug((DEBUG_LIST, "Deleting auth socket for %p", auth->client));
    socket_del(&auth->socket);
  }
  Debug((DEBUG_LIST, "Deleting auth timeout timer for %p", auth->client));
  timer_del(&auth->timeout);
}

/** Release auth client from auth system.  This adds the client into
 * the local client lists so it can be read by the main io processing
 * loop.
 * @param client The client to release.
 */
static void release_auth_client(struct Client* client)
{
  assert(0 != client);
  cli_auth(client) = 0;
  cli_lasttime(client) = cli_since(client) = CurrentTime;
  if (cli_fd(client) > HighestFd)
    HighestFd = cli_fd(client);
  LocalClientArray[cli_fd(client)] = client;

  add_client_to_list(client);
  socket_events(&(cli_socket(client)), SOCK_ACTION_SET | SOCK_EVENT_READABLE);
  Debug((DEBUG_INFO, "Auth: release_auth_client %s@%s[%s]",
         cli_username(client), cli_sockhost(client), cli_sock_ip(client)));
}

/** Terminate a client's connection due to auth failure.
 * @param auth The client to terminate.
 */
static void auth_kill_client(struct AuthRequest* auth)
{
  assert(0 != auth);

  if (IsDNSPending(auth))
    delete_resolver_queries(auth);
  IPcheck_disconnect(auth->client);
  Count_unknowndisconnects(UserStats);
  cli_auth(auth->client) = 0;
  free_client(auth->client);
  free_auth_request(auth);
}

/** Handle a complete DNS lookup.  Send the client on it's way to a
 * connection completion, regardless of success or failure -- unless
 * there was a mismatch and KILL_IPMISMATCH is set.
 * @param vptr The pending struct AuthRequest.
 * @param hp Pointer to the DNS reply (or NULL, if lookup failed).
 */
static void auth_dns_callback(void* vptr, struct DNSReply* hp)
{
  struct AuthRequest* auth = (struct AuthRequest*) vptr;
  assert(auth);
  /*
   * need to do this here so auth_kill_client doesn't
   * try have the resolver delete the query it's about
   * to delete anyways. --Bleep
   */
  ClearDNSPending(auth);

  if (hp) {
    /*
     * Verify that the host to ip mapping is correct both ways and that
     * the ip#(s) for the socket is listed for the host.
     */
    if (irc_in_addr_cmp(&hp->addr, &cli_ip(auth->client))) {
      if (IsUserPort(auth->client))
        sendheader(auth->client, REPORT_IP_MISMATCH);
      sendto_opmask_butone(0, SNO_IPMISMATCH, "IP# Mismatch: %s != %s[%s]",
			   cli_sock_ip(auth->client), hp->h_name,
			   ircd_ntoa(&hp->addr));
      if (feature_bool(FEAT_KILL_IPMISMATCH)) {
	auth_kill_client(auth);
	return;
      }
    }
    else if (!auth_verify_hostname(hp->h_name, HOSTLEN))
    {
      if (IsUserPort(auth->client))
        sendheader(auth->client, REPORT_INVAL_DNS);
    }
    else
    {
      cli_dns_reply(auth->client) = hp;
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
    free_auth_request(auth);
  }
}

/** Handle auth send errors.
 * @param auth The request that saw the failure.
 * @param kill If non-zero, a critical error; close the client's connection.
 */
static void auth_error(struct AuthRequest* auth, int kill)
{
  ++ServerStats->is_abad;

  assert(0 != auth);
  close(auth->fd);
  auth->fd = -1;
  socket_del(&auth->socket);

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

  if (!IsDNSPending(auth)) {
    release_auth_client(auth->client);
    free_auth_request(auth);
  }
}

/** Flag the client to show an attempt to contact the ident server on
 * the client's host.  Should the connect or any later phase of the
 * identifing process fail, it is aborted and the user is given a
 * username of "unknown".
 * @param auth The request for which to start the ident lookup.
 * @return Non-zero on success; zero if unable to start the lookup.
 */
static int start_auth_query(struct AuthRequest* auth)
{
  struct irc_sockaddr remote_addr;
  struct irc_sockaddr local_addr;
  int                fd;
  IOResult           result;

  assert(0 != auth);
  assert(0 != auth->client);

  /*
   * get the local address of the client and bind to that to
   * make the auth request.  This used to be done only for
   * ifdef VIRTTUAL_HOST, but needs to be done for all clients
   * since the ident request must originate from that same address--
   * and machines with multiple IP addresses are common now
   */
  memset(&local_addr, 0, sizeof(local_addr));
  os_get_sockname(cli_fd(auth->client), &local_addr);
  local_addr.port = 0;
  fd = os_socket(&local_addr, SOCK_STREAM, "auth query");
  if (fd < 0)
    return 0;
  if (IsUserPort(auth->client))
    sendheader(auth->client, REPORT_DO_ID);
  memcpy(&remote_addr.addr, &cli_ip(auth->client), sizeof(remote_addr.addr));
  remote_addr.port = 113;

  if ((result = os_connect_nonb(fd, &remote_addr)) == IO_FAILURE ||
      !socket_add(&auth->socket, auth_sock_callback, (void*) auth,
		  result == IO_SUCCESS ? SS_CONNECTED : SS_CONNECTING,
		  SOCK_EVENT_READABLE, fd)) {
    ServerStats->is_abad++;
    /*
     * No error report from this...
     */
    close(fd);
    if (IsUserPort(auth->client))
      sendheader(auth->client, REPORT_FAIL_ID);
    return 0;
  }

  auth->flags |= AM_SOCKET;
  auth->fd = fd;

  SetAuthConnect(auth);
  if (result == IO_SUCCESS)
    send_auth_query(auth); /* this does a SetAuthPending(auth) for us */

  return 1;
}

/** Enum used to index ident reply fields in a human-readable way. */
enum IdentReplyFields {
  IDENT_PORT_NUMBERS,
  IDENT_REPLY_TYPE,
  IDENT_OS_TYPE,
  IDENT_INFO,
  USERID_TOKEN_COUNT
};

/** Parse an ident reply line and extract the userid from it.
 * @param reply The ident reply line.
 * @return The userid, or NULL on parse failure.
 */
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

/** Starts auth (identd) and dns queries for a client.
 * @param client The client for which to start queries.
 */
void start_auth(struct Client* client)
{
  struct AuthRequest* auth = 0;

  assert(0 != client);

  auth = make_auth_request(client);
  assert(0 != auth);

  Debug((DEBUG_INFO, "Beginning auth request on client %p", client));

  if (!feature_bool(FEAT_NODNS)) {
    if (irc_in_addr_is_loopback(&cli_ip(client)))
      strcpy(cli_sockhost(client), cli_name(&me));
    else {
      struct DNSQuery query;

      query.vptr     = auth;
      query.callback = auth_dns_callback;

      if (IsUserPort(auth->client))
	sendheader(client, REPORT_DO_DNS);

      gethost_byaddr(&cli_ip(client), &query);
      SetDNSPending(auth);
    }
  }

  if (start_auth_query(auth)) {
    Debug((DEBUG_LIST, "identd query for %p initiated successfully",
	   auth->client));
  } else if (IsDNSPending(auth)) {
    Debug((DEBUG_LIST, "identd query for %p not initiated successfully; "
	   "waiting on DNS", auth->client));
  } else {
    Debug((DEBUG_LIST, "identd query for %p not initiated successfully; "
	   "no DNS pending; releasing immediately", auth->client));
    free_auth_request(auth);
    release_auth_client(client);
  }
}

/** Send the ident server a query giving "theirport , ourport". The
 * write is only attempted *once* so it is deemed to be a fail if the
 * entire write doesn't write all the data given.  This shouldnt be a
 * problem since the socket should have a write buffer far greater
 * than this message to store it in should problems arise. -avalon
 * @param auth The request to send.
 */
void send_auth_query(struct AuthRequest* auth)
{
  struct irc_sockaddr us;
  struct irc_sockaddr them;
  char               authbuf[32];
  unsigned int       count;

  assert(0 != auth);
  assert(0 != auth->client);

  if (!os_get_sockname(cli_fd(auth->client), &us) ||
      !os_get_peername(cli_fd(auth->client), &them)) {
    auth_error(auth, 1);
    return;
  }
  ircd_snprintf(0, authbuf, sizeof(authbuf), "%u , %u\r\n",
		(unsigned int) them.port,
		(unsigned int) us.port);

  if (IO_SUCCESS == os_send_nonb(auth->fd, authbuf, strlen(authbuf), &count)) {
    ClearAuthConnect(auth);
    SetAuthPending(auth);
  }
  else
    auth_error(auth, 0);
}


/** Read the reply (if any) from the ident server we connected to.  We
 * only give it one shot, if the reply isn't good the first time fail
 * the authentication entirely. --Bleep
 * @param auth The request to read.
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
  assert(auth == cli_auth(auth->client));

  if (IO_SUCCESS == os_recv_nonb(auth->fd, buf, BUFSIZE, &len)) {
    buf[len] = '\0';
    Debug((DEBUG_LIST, "Auth %p [%p] reply: %s", auth, &auth->socket, buf));
    username = check_ident_reply(buf);
    Debug((DEBUG_LIST, "Username: %s", username));
  }

  close(auth->fd);
  auth->fd = -1;
  Debug((DEBUG_LIST, "Deleting auth [%p] socket %p", auth, &auth->socket));
  socket_del(&auth->socket);
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
  }

  if (!IsDNSPending(auth)) {
    release_auth_client(auth->client);
    free_auth_request(auth);
  }
}
