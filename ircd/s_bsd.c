/*
 * IRC - Internet Relay Chat, ircd/s_bsd.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
 * @brief Functions that now (or in the past) relied on BSD APIs.
 * @version $Id$
 */
#include "config.h"

#include "s_bsd.h"
#include "client.h"
#include "IPcheck.h"
#include "channel.h"
#include "class.h"
#include "hash.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_features.h"
#include "ircd_osdep.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd.h"
#include "list.h"
#include "listener.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "numnicks.h"
#include "packet.h"
#include "parse.h"
#include "querycmds.h"
#include "res.h"
#include "s_auth.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"
#include "sys.h"
#include "uping.h"
#include "version.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <unistd.h>

/** Array of my own clients, indexed by file descriptor. */
struct Client*            LocalClientArray[MAXCONNECTIONS];
/** Maximum file descriptor in current use. */
int                       HighestFd = -1;
/** Default local address for outbound IPv4 connections. */
struct irc_sockaddr       VirtualHost_v4;
/** Default local address for outbound IPv6 connections. */
struct irc_sockaddr       VirtualHost_v6;
/** Temporary buffer for reading data from a peer. */
static char               readbuf[SERVER_TCP_WINDOW];

/*
 * report_error text constants
 */
const char* const ACCEPT_ERROR_MSG    = "error accepting connection for %s: %s";
const char* const BIND_ERROR_MSG      = "bind error for %s: %s";
const char* const CONNECT_ERROR_MSG   = "connect to host %s failed: %s";
const char* const CONNLIMIT_ERROR_MSG = "connect limit exceeded for %s: %s";
const char* const LISTEN_ERROR_MSG    = "listen error for %s: %s";
const char* const NONB_ERROR_MSG      = "error setting non-blocking for %s: %s";
const char* const PEERNAME_ERROR_MSG  = "getpeername failed for %s: %s";
const char* const POLL_ERROR_MSG      = "poll error for %s: %s";
const char* const REGISTER_ERROR_MSG  = "registering %s: %s";
const char* const REUSEADDR_ERROR_MSG = "error setting SO_REUSEADDR for %s: %s";
const char* const SELECT_ERROR_MSG    = "select error for %s: %s";
const char* const SETBUFS_ERROR_MSG   = "error setting buffer size for %s: %s";
const char* const SOCKET_ERROR_MSG    = "error creating socket for %s: %s";
const char* const TOS_ERROR_MSG	      = "error setting TOS for %s: %s";


static void client_sock_callback(struct Event* ev);
static void client_timer_callback(struct Event* ev);


/*
 * Cannot use perror() within daemon. stderr is closed in
 * ircd and cannot be used. And, worse yet, it might have
 * been reassigned to a normal connection...
 */

/** Replacement for perror(). Record error to log.  Send a copy to all
 * *LOCAL* opers, but only if no errors were sent to them in the last
 * 20 seconds.
 * @param text A *format* string for outputting error. It must contain
 * only two '%s', the first will be replaced by the sockhost from the
 * cptr, and the latter will be taken from sys_errlist[errno].
 * @param who The client associated with the error.
 * @param err The errno value to display.
 */
void report_error(const char* text, const char* who, int err)
{
  static time_t last_notice = 0;
  int           errtmp = errno;   /* debug may change 'errno' */
  const char*   errmsg = (err) ? strerror(err) : "";

  if (!errmsg)
    errmsg = "Unknown error"; 

  if (EmptyString(who))
    who = "unknown";

  sendto_opmask_butone_ratelimited(0, SNO_OLDSNO, &last_notice, text, who, errmsg);
  log_write(LS_SOCKET, L_ERROR, 0, text, who, errmsg);
  errno = errtmp;
}


/** Called when resolver query finishes.  If the DNS lookup was
 * successful, start the connection; otherwise notify opers of the
 * failure.
 * @param vptr The struct ConfItem representing the Connect block.
 * @param hp A pointer to the DNS lookup results (NULL on failure).
 */
static void connect_dns_callback(void* vptr, const struct irc_in_addr *addr, const char *h_name)
{
  struct ConfItem* aconf = (struct ConfItem*) vptr;
  assert(aconf);
  aconf->dns_pending = 0;
  if (addr) {
    memcpy(&aconf->address, addr, sizeof(aconf->address));
    connect_server(aconf, 0);
  }
  else
    sendto_opmask_butone(0, SNO_OLDSNO, "Connect to %s failed: host lookup",
                         aconf->name);
}

/** Closes all file descriptors.
 * @param close_stderr If non-zero, also close stderr.
 */
void close_connections(int close_stderr)
{
  int i;
  if (close_stderr)
  {
    close(0);
    close(1);
    close(2);
  }
  for (i = 3; i < MAXCONNECTIONS; ++i)
    close(i);
}

/** Initialize process fd limit to MAXCONNECTIONS.
 */
int init_connection_limits(void)
{
  int limit = os_set_fdlimit(MAXCONNECTIONS);
  if (0 == limit)
    return 1;
  if (limit < 0) {
    fprintf(stderr, "error setting max fds to %d: %s\n", limit, strerror(errno));
  }
  else if (limit > 0) {
    fprintf(stderr, "ircd fd table too big\nHard Limit: %d IRC max: %d\n",
            limit, MAXCONNECTIONS);
    fprintf(stderr, "set MAXCONNECTIONS to a smaller value");
  }
  return 0;
}

/** Set up address and port and make a connection.
 * @param aconf Provides the connection information.
 * @param cptr Client structure for the peer.
 * @return Non-zero on success; zero on failure.
 */
static int connect_inet(struct ConfItem* aconf, struct Client* cptr)
{
  const struct irc_sockaddr *local;
  IOResult result;
  int family = 0;

  assert(0 != aconf);
  assert(0 != cptr);
  /*
   * Might as well get sockhost from here, the connection is attempted
   * with it so if it fails its useless.
   */
  if (irc_in_addr_valid(&aconf->origin.addr))
    local = &aconf->origin;
  else if (irc_in_addr_is_ipv4(&aconf->address.addr)) {
    local = &VirtualHost_v4;
    family = AF_INET;
  } else
    local = &VirtualHost_v6;
  cli_fd(cptr) = os_socket(local, SOCK_STREAM, cli_name(cptr), family);
  if (cli_fd(cptr) < 0)
    return 0;
#ifdef AF_INET6
  if ((family == 0) && !irc_in_addr_is_ipv4(&local->addr))
    family = AF_INET6;
  else
#endif
    family = AF_INET;

  /*
   * save connection info in client
   */
  memcpy(&cli_ip(cptr), &aconf->address.addr, sizeof(cli_ip(cptr)));
  ircd_ntoa_r(cli_sock_ip(cptr), &cli_ip(cptr));
  /*
   * we want a big buffer for server connections
   */
  if (!os_set_sockbufs(cli_fd(cptr), feature_int(FEAT_SOCKSENDBUF), feature_int(FEAT_SOCKRECVBUF))) {
    cli_error(cptr) = errno;
    report_error(SETBUFS_ERROR_MSG, cli_name(cptr), errno);
    close(cli_fd(cptr));
    cli_fd(cptr) = -1;
    return 0;
  }
  /*
   * Set the TOS bits - this is nonfatal if it doesn't stick.
   */
  if (!os_set_tos(cli_fd(cptr), feature_int(FEAT_TOS_SERVER), family)) {
    report_error(TOS_ERROR_MSG, cli_name(cptr), errno);
  }
  if ((result = os_connect_nonb(cli_fd(cptr), &aconf->address)) == IO_FAILURE) {
    cli_error(cptr) = errno;
    report_error(CONNECT_ERROR_MSG, cli_name(cptr), errno);
    close(cli_fd(cptr));
    cli_fd(cptr) = -1;
    return 0;
  }
  if (!socket_add(&(cli_socket(cptr)), client_sock_callback,
		  (void*) cli_connect(cptr),
		  (result == IO_SUCCESS) ? SS_CONNECTED : SS_CONNECTING,
		  SOCK_EVENT_READABLE, cli_fd(cptr))) {
    cli_error(cptr) = ENFILE;
    report_error(REGISTER_ERROR_MSG, cli_name(cptr), ENFILE);
    close(cli_fd(cptr));
    cli_fd(cptr) = -1;
    return 0;
  }
  cli_freeflag(cptr) |= FREEFLAG_SOCKET;
  return 1;
}

/** Attempt to send a sequence of bytes to the connection.
 * As a side effect, updates \a cptr's FLAG_BLOCKED setting
 * and sendB/sendK fields.
 * @param cptr Client that should receive data.
 * @param buf Message buffer to send to client.
 * @return Negative on connection-fatal error; otherwise
 *  number of bytes sent.
 */
unsigned int deliver_it(struct Client *cptr, struct MsgQ *buf)
{
  unsigned int bytes_written = 0;
  unsigned int bytes_count = 0;
  assert(0 != cptr);

  switch (os_sendv_nonb(cli_fd(cptr), buf, &bytes_count, &bytes_written)) {
  case IO_SUCCESS:
    ClrFlag(cptr, FLAG_BLOCKED);

    cli_sendB(cptr) += bytes_written;
    cli_sendB(&me)  += bytes_written;
    /* A partial write implies that future writes will block. */
    if (bytes_written < bytes_count)
      SetFlag(cptr, FLAG_BLOCKED);
    break;
  case IO_BLOCKED:
    SetFlag(cptr, FLAG_BLOCKED);
    break;
  case IO_FAILURE:
    cli_error(cptr) = errno;
    SetFlag(cptr, FLAG_DEADSOCKET);
    break;
  }
  return bytes_written;
}

/** Complete non-blocking connect()-sequence. Check access and
 * terminate connection, if trouble detected.
 * @param cptr Client to which we have connected, with all ConfItem structs attached.
 * @return Zero on failure (caller should exit_client()), non-zero on success.
 */
static int completed_connection(struct Client* cptr)
{
  struct ConfItem *aconf;
  time_t newts;
  struct Client *acptr;
  int i;

  assert(0 != cptr);

  /*
   * get the socket status from the fd first to check if
   * connection actually succeeded
   */
  if (cli_fd(cptr) >= 0)
      cli_error(cptr) = os_get_sockerr(cli_fd(cptr));
  if (cli_error(cptr) != 0) {
    const char* msg = strerror(cli_error(cptr));
    if (!msg)
      msg = "Unknown error";
    sendto_opmask_butone(0, SNO_OLDSNO, "Connection failed to %s: %s",
                         cli_name(cptr), msg);
    return 0;
  }
  if (!(aconf = find_conf_byname(cli_confs(cptr), cli_name(cptr), CONF_SERVER))) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Lost Server Line for %s", cli_name(cptr));
    return 0;
  }
  if (s_state(&(cli_socket(cptr))) == SS_CONNECTING)
    socket_state(&(cli_socket(cptr)), SS_CONNECTED);

  if (!EmptyString(aconf->passwd))
    sendrawto_one(cptr, MSG_PASS " :%s", aconf->passwd);

  /*
   * Create a unique timestamp
   */
  newts = TStime();
  for (i = HighestFd; i > -1; --i) {
    if ((acptr = LocalClientArray[i]) && 
        (IsServer(acptr) || IsHandshake(acptr))) {
      if (cli_serv(acptr)->timestamp >= newts)
        newts = cli_serv(acptr)->timestamp + 1;
    }
  }
  assert(0 != cli_serv(cptr));

  cli_serv(cptr)->timestamp = newts;
  SetHandshake(cptr);
  /*
   * Make us timeout after twice the timeout for DNS look ups
   */
  cli_lasttime(cptr) = CurrentTime;
  ClearPingSent(cptr);

  sendrawto_one(cptr, MSG_SERVER " %s 1 %Tu %Tu J%s %s%s +%s6 :%s",
                cli_name(&me), cli_serv(&me)->timestamp, newts,
		MAJOR_PROTOCOL, NumServCap(&me),
		feature_bool(FEAT_HUB) ? "h" : "", cli_info(&me));

  return (IsDead(cptr)) ? 0 : 1;
}

/** Close the physical connection.  Side effects: MyConnect(cptr)
 * becomes false and cptr->from becomes NULL.
 * @param cptr Client to disconnect.
 */
void close_connection(struct Client *cptr)
{
  struct ConfItem* aconf;

  if (IsServer(cptr)) {
    ServerStats->is_sv++;
    ServerStats->is_sbs += cli_sendB(cptr);
    ServerStats->is_sbr += cli_receiveB(cptr);
    ServerStats->is_sti += CurrentTime - cli_firsttime(cptr);
    /*
     * If the connection has been up for a long amount of time, schedule
     * a 'quick' reconnect, else reset the next-connect cycle.
     */
    if ((aconf = find_conf_exact(cli_name(cptr), cptr, CONF_SERVER))) {
      /*
       * Reschedule a faster reconnect, if this was a automatically
       * connected configuration entry. (Note that if we have had
       * a rehash in between, the status has been changed to
       * CONF_ILLEGAL). But only do this if it was a "good" link.
       */
      aconf->hold = CurrentTime;
      aconf->hold += ((aconf->hold - cli_since(cptr) >
		       feature_int(FEAT_HANGONGOODLINK)) ?
		      feature_int(FEAT_HANGONRETRYDELAY) : ConfConFreq(aconf));
/*        if (nextconnect > aconf->hold) */
/*          nextconnect = aconf->hold; */
    }
  }
  else if (IsUser(cptr)) {
    ServerStats->is_cl++;
    ServerStats->is_cbs += cli_sendB(cptr);
    ServerStats->is_cbr += cli_receiveB(cptr);
    ServerStats->is_cti += CurrentTime - cli_firsttime(cptr);
  }
  else
    ServerStats->is_ni++;

  if (-1 < cli_fd(cptr)) {
    flush_connections(cptr);
    LocalClientArray[cli_fd(cptr)] = 0;
    close(cli_fd(cptr));
    socket_del(&(cli_socket(cptr))); /* queue a socket delete */
    cli_fd(cptr) = -1;
  }
  SetFlag(cptr, FLAG_DEADSOCKET);

  MsgQClear(&(cli_sendQ(cptr)));
  client_drop_sendq(cli_connect(cptr));
  DBufClear(&(cli_recvQ(cptr)));
  memset(cli_passwd(cptr), 0, sizeof(cli_passwd(cptr)));
  set_snomask(cptr, 0, SNO_SET);

  det_confs_butmask(cptr, 0);

  if (cli_listener(cptr)) {
    release_listener(cli_listener(cptr));
    cli_listener(cptr) = 0;
  }

  for ( ; HighestFd > 0; --HighestFd) {
    if (LocalClientArray[HighestFd])
      break;
  }
}

/** Close all unregistered connections.
 * @param source Oper who requested the close.
 * @return Number of closed connections.
 */
int net_close_unregistered_connections(struct Client* source)
{
  int            i;
  struct Client* cptr;
  int            count = 0;
  assert(0 != source);

  for (i = HighestFd; i > 0; --i) {
    if ((cptr = LocalClientArray[i]) && !IsRegistered(cptr)) {
      send_reply(source, RPL_CLOSING, get_client_name(source, HIDE_IP));
      exit_client(source, cptr, &me, "Oper Closing");
      ++count;
    }
  }
  return count;
}

/** Creates a client which has just connected to us on the given fd.
 * The sockhost field is initialized with the ip# of the host.
 * The client is not added to the linked list of clients, it is
 * passed off to the auth handler for dns and ident queries.
 * @param listener Listening socket that received the connection.
 * @param fd File descriptor of new connection.
 */
void add_connection(struct Listener* listener, int fd) {
  struct irc_sockaddr addr;
  struct Client      *new_client;
  time_t             next_target = 0;

  const char* const throttle_message =
         "ERROR :Your host is trying to (re)connect too fast -- throttled\r\n";
       /* 12345678901234567890123456789012345679012345678901234567890123456 */
  const char* const register_message =
         "ERROR :Unable to complete your registration\r\n";

  assert(0 != listener);

  /*
   * Removed preliminary access check. Full check is performed in m_server and
   * m_user instead. Also connection time out help to get rid of unwanted
   * connections.
   */
  if (!os_get_peername(fd, &addr) || !os_set_nonblocking(fd)) {
    ++ServerStats->is_bad_socket;
    close(fd);
    return;
  }
  /*
   * Disable IP (*not* TCP) options.  In particular, this makes it impossible
   * to use source routing to connect to the server.  If we didn't do this
   * (and if intermediate networks didn't drop source-routed packets), an
   * attacker could successfully IP spoof us...and even return the anti-spoof
   * ping, because the options would cause the packet to be routed back to
   * the spoofer's machine.  When we disable the IP options, we delete the
   * source route, and the normal routing takes over.
   */
  os_disable_options(fd);

  if (listener_server(listener))
  {
    new_client = make_client(0, STAT_UNKNOWN_SERVER);
  }
  else if (listener_webirc(listener))
  {
      new_client = make_client(0, STAT_WEBIRC);
  }
  else
  {
    /*
     * Add this local client to the IPcheck registry.
     *
     * If they're throttled, murder them, but tell them why first.
     */
    if (!IPcheck_local_connect(&addr.addr, &next_target))
    {
      ++ServerStats->is_throttled;
      write(fd, throttle_message, strlen(throttle_message));
      close(fd);
      return;
    }
    new_client = make_client(0, STAT_UNKNOWN_USER);
    SetIPChecked(new_client);
  }

  /*
   * Copy ascii address to 'sockhost' just in case. Then we have something
   * valid to put into error messages...
   */
  ircd_ntoa_r(cli_sock_ip(new_client), &addr.addr);
  strcpy(cli_sockhost(new_client), cli_sock_ip(new_client));
  memcpy(&cli_ip(new_client), &addr.addr, sizeof(cli_ip(new_client)));

  if (next_target)
    cli_nexttarget(new_client) = next_target;

  cli_fd(new_client) = fd;
  if (!socket_add(&(cli_socket(new_client)), client_sock_callback,
		  (void*) cli_connect(new_client), SS_CONNECTED, 0, fd)) {
    ++ServerStats->is_bad_socket;
    write(fd, register_message, strlen(register_message));
    close(fd);
    cli_fd(new_client) = -1;
    return;
  }
  cli_freeflag(new_client) |= FREEFLAG_SOCKET;
  cli_listener(new_client) = listener;
  ++listener->ref_count;

  Count_newunknown(UserStats);
  /* if we've made it this far we can put the client on the auth query pile */
  start_auth(new_client);
}

/** Determines whether to tell the events engine we're interested in
 * writable events.
 * @param cptr Client for which to decide this.
 */
void update_write(struct Client* cptr)
{
  /* If there are messages that need to be sent along, or if the client
   * is in the middle of a /list, then we need to tell the engine that
   * we're interested in writable events--otherwise, we need to drop
   * that interest.
   */
  socket_events(&(cli_socket(cptr)),
		((MsgQLength(&cli_sendQ(cptr)) || cli_listing(cptr)) ?
		 SOCK_ACTION_ADD : SOCK_ACTION_DEL) | SOCK_EVENT_WRITABLE);
}

/** Read a 'packet' of data from a connection and process it.  Read in
 * 8k chunks to give a better performance rating (for server
 * connections).  Do some tricky stuff for client connections to make
 * sure they don't do any flooding >:-) -avalon
 * @param cptr Client from which to read data.
 * @param socket_ready If non-zero, more data can be read from the client's socket.
 * @return Positive number on success, zero on connection-fatal failure, negative
 *   if user is killed.
 */
static int read_packet(struct Client *cptr, int socket_ready)
{
  unsigned int dolen = 0;
  unsigned int length = 0;

  if (socket_ready &&
      !(IsUser(cptr) &&
	DBufLength(&(cli_recvQ(cptr))) > feature_int(FEAT_CLIENT_FLOOD))) {
    switch (os_recv_nonb(cli_fd(cptr), readbuf, sizeof(readbuf), &length)) {
    case IO_SUCCESS:
      if (length)
      {
        cli_lasttime(cptr) = CurrentTime;
        ClearPingSent(cptr);
        ClrFlag(cptr, FLAG_NONL);
        if (cli_lasttime(cptr) > cli_since(cptr))
          cli_since(cptr) = cli_lasttime(cptr);
      }
      break;
    case IO_BLOCKED:
      break;
    case IO_FAILURE:
      cli_error(cptr) = errno;
      /* SetFlag(cptr, FLAG_DEADSOCKET); */
      return 0;
    }
  }

  /*
   * For server connections, we process as many as we can without
   * worrying about the time of day or anything :)
   */
  if (length > 0 && IsServer(cptr))
    return server_dopacket(cptr, readbuf, length);
  else if (length > 0 && (IsHandshake(cptr) || IsConnecting(cptr)))
    return connect_dopacket(cptr, readbuf, length);
  else
  {
    /*
     * Before we even think of parsing what we just read, stick
     * it on the end of the receive queue and do it when its
     * turn comes around.
     */
    if (length > 0 && dbuf_put(&(cli_recvQ(cptr)), readbuf, length) == 0)
      return exit_client(cptr, cptr, &me, "dbuf_put fail");

    if (DBufLength(&(cli_recvQ(cptr))) > feature_int(FEAT_CLIENT_FLOOD))
      return exit_client(cptr, cptr, &me, "Excess Flood");

    while (DBufLength(&(cli_recvQ(cptr))) && !NoNewLine(cptr) && 
           (IsTrusted(cptr) || cli_since(cptr) - CurrentTime < 10))
    {
      dolen = dbuf_getmsg(&(cli_recvQ(cptr)), cli_buffer(cptr), BUFSIZE);
      /*
       * Devious looking...whats it do ? well..if a client
       * sends a *long* message without any CR or LF, then
       * dbuf_getmsg fails and we pull it out using this
       * loop which just gets the next 512 bytes and then
       * deletes the rest of the buffer contents.
       * -avalon
       */
      if (dolen == 0)
      {
        if (DBufLength(&(cli_recvQ(cptr))) < 510)
          SetFlag(cptr, FLAG_NONL);
        else
        {
          /* More than 512 bytes in the line - drop the input and yell
           * at the client.
           */
          DBufClear(&(cli_recvQ(cptr)));
          send_reply(cptr, ERR_INPUTTOOLONG);
        }
      }
      else if (client_dopacket(cptr, dolen) == CPTR_KILLED)
        return CPTR_KILLED;
      /*
       * If it has become registered as a Server
       * then skip the per-message parsing below.
       */
      if (IsHandshake(cptr) || IsServer(cptr))
      {
        while (1)
        {
          dolen = dbuf_get(&(cli_recvQ(cptr)), readbuf, sizeof(readbuf));
          if (dolen == 0)
            return 1;
          if ((IsServer(cptr)
               ? server_dopacket(cptr, readbuf, dolen)
               : connect_dopacket(cptr, readbuf, dolen)) == CPTR_KILLED)
            return CPTR_KILLED;
        }
      }
    }

    /* If there's still data to process, wait 2 seconds first */
    if (DBufLength(&(cli_recvQ(cptr))) && !NoNewLine(cptr) &&
	!t_onqueue(&(cli_proc(cptr))))
    {
      Debug((DEBUG_LIST, "Adding client process timer for %C", cptr));
      cli_freeflag(cptr) |= FREEFLAG_TIMER;
      timer_add(&(cli_proc(cptr)), client_timer_callback, cli_connect(cptr),
		TT_RELATIVE, 2);
    }
  }
  return 1;
}

/** Start a connection to another server.
 * @param aconf Connect block data for target server.
 * @param by Client who requested the connection (if any).
 * @return Non-zero on success; zero on failure.
 */
int connect_server(struct ConfItem* aconf, struct Client* by)
{
  struct Client*   cptr = 0;
  assert(0 != aconf);

  if (aconf->dns_pending) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Server %s connect DNS pending",
                         aconf->name);
    return 0;
  }
  Debug((DEBUG_NOTICE, "Connect to %s[@%s]", aconf->name,
         ircd_ntoa(&aconf->address.addr)));

  if ((cptr = FindClient(aconf->name))) {
    if (IsServer(cptr) || IsMe(cptr)) {
      sendto_opmask_butone(0, SNO_OLDSNO, "Server %s already present from %s", 
                           aconf->name, cli_name(cli_from(cptr)));
      if (by && IsUser(by) && !MyUser(by)) {
        sendcmdto_one(&me, CMD_NOTICE, by, "%C :Server %s already present "
                      "from %s", by, aconf->name, cli_name(cli_from(cptr)));
      }
      return 0;
    }
    else if (IsHandshake(cptr) || IsConnecting(cptr)) {
      if (by && IsUser(by)) {
        sendcmdto_one(&me, CMD_NOTICE, by, "%C :Connection to %s already in "
                      "progress", by, cli_name(cptr));
      }
      return 0;
    }
  }
  /*
   * If we don't know the IP# for this host and it is a hostname and
   * not a ip# string, then try and find the appropriate host record.
   */
  if (!irc_in_addr_valid(&aconf->address.addr)
      && !ircd_aton(&aconf->address.addr, aconf->host)) {
    char buf[HOSTLEN + 1];

    host_from_uh(buf, aconf->host, HOSTLEN);
    gethost_byname(buf, connect_dns_callback, aconf);
    aconf->dns_pending = 1;
    return 0;
  }
  cptr = make_client(NULL, STAT_UNKNOWN_SERVER);

  /*
   * Copy these in so we have something for error detection.
   */
  ircd_strncpy(cli_name(cptr), aconf->name, HOSTLEN);
  ircd_strncpy(cli_sockhost(cptr), aconf->host, HOSTLEN);

  /*
   * Attach config entries to client here rather than in
   * completed_connection. This to avoid null pointer references
   */
  attach_confs_byhost(cptr, aconf->host, CONF_SERVER);

  if (!find_conf_byhost(cli_confs(cptr), aconf->host, CONF_SERVER)) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Host %s is not enabled for "
                         "connecting: no Connect block", aconf->name);
    if (by && IsUser(by) && !MyUser(by)) {
      sendcmdto_one(&me, CMD_NOTICE, by, "%C :Connect to host %s failed: no "
                    "Connect block", by, aconf->name);
    }
    det_confs_butmask(cptr, 0);
    free_client(cptr);
    return 0;
  }
  /*
   * attempt to connect to the server in the conf line
   */
  if (!connect_inet(aconf, cptr)) {
    if (by && IsUser(by) && !MyUser(by)) {
      sendcmdto_one(&me, CMD_NOTICE, by, "%C :Couldn't connect to %s", by,
                    cli_name(cptr));
    }
    det_confs_butmask(cptr, 0);
    free_client(cptr);
    return 0;
  }
  /*
   * NOTE: if we're here we have a valid C:Line and the client should
   * have started the connection and stored the remote address/port and
   * ip address name in itself
   *
   * The socket has been connected or connect is in progress.
   */
  make_server(cptr);
  if (by && IsUser(by)) {
    ircd_snprintf(0, cli_serv(cptr)->by, sizeof(cli_serv(cptr)->by), "%s%s",
		  NumNick(by));
    assert(0 == cli_serv(cptr)->user);
    cli_serv(cptr)->user = cli_user(by);
    cli_user(by)->refcnt++;
  }
  else {
    *(cli_serv(cptr))->by = '\0';
    /* strcpy(cptr->serv->by, "Auto"); */
  }
  cli_serv(cptr)->up = &me;
  SetConnecting(cptr);

  if (cli_fd(cptr) > HighestFd)
    HighestFd = cli_fd(cptr);

  LocalClientArray[cli_fd(cptr)] = cptr;

  Count_newunknown(UserStats);
  /* Actually we lie, the connect hasn't succeeded yet, but we have a valid
   * cptr, so we register it now.
   * Maybe these two calls should be merged.
   */
  add_client_to_list(cptr);
  hAddClient(cptr);
/*    nextping = CurrentTime; */

  return (s_state(&cli_socket(cptr)) == SS_CONNECTED) ?
    completed_connection(cptr) : 1;
}

/** Find the real hostname for the host running the server (or one which
 * matches the server's name) and its primary IP#.  Hostname is stored
 * in the client structure passed as a pointer.
 */
void init_server_identity(void)
{
  const struct LocalConf* conf = conf_get_local();
  assert(0 != conf);

  ircd_strncpy(cli_name(&me), conf->name, HOSTLEN);
  SetYXXServerName(&me, conf->numeric);
}

/** Process events on a client socket.
 * @param ev Socket event structure that has a struct Connection as
 *   its associated data.
 */
static void client_sock_callback(struct Event* ev)
{
  struct Client* cptr;
  struct Connection* con;
  char *fmt = "%s";
  char *fallback = 0;

  assert(0 != ev_socket(ev));
  assert(0 != s_data(ev_socket(ev)));

  con = (struct Connection*) s_data(ev_socket(ev));

  assert(0 != con_client(con) || ev_type(ev) == ET_DESTROY);

  cptr = con_client(con);

  assert(0 == cptr || con == cli_connect(cptr));

  switch (ev_type(ev)) {
  case ET_DESTROY:
    con_freeflag(con) &= ~FREEFLAG_SOCKET;

    if (!con_freeflag(con) && !cptr)
      free_connection(con);
    break;

  case ET_CONNECT: /* socket connection completed */
    if (!completed_connection(cptr) || IsDead(cptr))
      fallback = cli_info(cptr);
    break;

  case ET_ERROR: /* an error occurred */
    fallback = cli_info(cptr);
    cli_error(cptr) = ev_data(ev);
    /* If the OS told us we have a bad file descriptor, we should
     * record that for future reference.
     */
    if (cli_error(cptr) == EBADF)
      cli_fd(cptr) = -1;
    if (s_state(&(con_socket(con))) == SS_CONNECTING) {
      completed_connection(cptr);
      /* for some reason, the os_get_sockerr() in completed_connect()
       * can return 0 even when ev_data(ev) indicates a real error, so
       * re-assign the client error here.
       */
      cli_error(cptr) = ev_data(ev);
      break;
    }
    /*FALLTHROUGH*/
  case ET_EOF: /* end of file on socket */
    Debug((DEBUG_ERROR, "READ ERROR: fd = %d %d", cli_fd(cptr),
	   cli_error(cptr)));
    SetFlag(cptr, FLAG_DEADSOCKET);
    if ((IsServer(cptr) || IsHandshake(cptr)) && cli_error(cptr) == 0) {
      exit_client_msg(cptr, cptr, &me, "Server %s closed the connection (%s)",
		      cli_name(cptr), cli_serv(cptr)->last_error_msg);
      return;
    } else {
      fmt = "Read error: %s";
      fallback = "EOF from client";
    }
    break;

  case ET_WRITE: /* socket is writable */
    ClrFlag(cptr, FLAG_BLOCKED);
    if (cli_listing(cptr) && MsgQLength(&(cli_sendQ(cptr))) < 2048)
      list_next_channels(cptr);
    Debug((DEBUG_SEND, "Sending queued data to %C", cptr));
    send_queued(cptr);
    break;

  case ET_READ: /* socket is readable */
    if (!IsDead(cptr)) {
      Debug((DEBUG_DEBUG, "Reading data from %C", cptr));
      if (read_packet(cptr, 1) == 0) /* error while reading packet */
	fallback = "EOF from client";
    }
    break;

  default:
    assert(0 && "Unrecognized socket event in client_sock_callback()");
    break;
  }

  assert(0 == cptr || 0 == cli_connect(cptr) || con == cli_connect(cptr));

  if (fallback) {
    const char* msg = (cli_error(cptr)) ? strerror(cli_error(cptr)) : fallback;
    if (!msg)
      msg = "Unknown error";
    exit_client_msg(cptr, cptr, &me, fmt, msg);
  }
}

/** Process a timer on client socket.
 * @param ev Timer event that has a struct Connection as its
 * associated data.
 */
static void client_timer_callback(struct Event* ev)
{
  struct Client* cptr;
  struct Connection* con;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));
  assert(ET_DESTROY == ev_type(ev) || ET_EXPIRE == ev_type(ev));

  con = (struct Connection*) t_data(ev_timer(ev));

  assert(0 != con_client(con) || ev_type(ev) == ET_DESTROY);

  cptr = con_client(con);

  assert(0 == cptr || con == cli_connect(cptr));

  if (ev_type(ev)== ET_DESTROY) {
    con_freeflag(con) &= ~FREEFLAG_TIMER; /* timer has expired... */

    if (!con_freeflag(con) && !cptr)
      free_connection(con); /* client is being destroyed */
  } else {
    Debug((DEBUG_LIST, "Client process timer for %C expired; processing",
	   cptr));
    read_packet(cptr, 0); /* read_packet will re-add timer if needed */
  }

  assert(0 == cptr || 0 == cli_connect(cptr) || con == cli_connect(cptr));
}
