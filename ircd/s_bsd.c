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
 *
 * $Id$
 */
#include "s_bsd.h"
#include "client.h"
#include "IPcheck.h"
#include "channel.h"
#include "class.h"
#include "hash.h"
#include "ircd_log.h"
#include "ircd_osdep.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd.h"
#include "list.h"
#include "listener.h"
#include "msg.h"
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
#include "sprintf_irc.h"
#include "struct.h"
#include "support.h"
#include "sys.h"
#include "uping.h"
#include "version.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifdef USE_POLL
#include <sys/poll.h>
#endif /* USE_POLL */

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

struct Client*            LocalClientArray[MAXCONNECTIONS];
int                       HighestFd = -1;
struct sockaddr_in        VirtualHost;
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
const char* const REUSEADDR_ERROR_MSG = "error setting SO_REUSEADDR for %s: %s";
const char* const SELECT_ERROR_MSG    = "select error for %s: %s";
const char* const SETBUFS_ERROR_MSG   = "error setting buffer size for %s: %s";
const char* const SOCKET_ERROR_MSG    = "error creating socket for %s: %s";


#ifdef GODMODE
#ifndef NODNS
#define NODNS
#endif
#ifndef NOFLOODCONTROL
#define NOFLOODCONTROL
#endif
#endif

#if !defined(USE_POLL)
#if FD_SETSIZE < (MAXCONNECTIONS + 4)
/*
 * Sanity check
 *
 * All operating systems work when MAXCONNECTIONS <= 252.
 * Most operating systems work when MAXCONNECTIONS <= 1020 and FD_SETSIZE is
 *   updated correctly in the system headers (on BSD systems our sys.h has
 *   defined FD_SETSIZE to MAXCONNECTIONS+4 before including the system's headers 
 *   but sys/types.h might have abruptly redefined it so the check is still 
 *   done), you might already need to recompile your kernel.
 * For larger FD_SETSIZE your milage may vary (kernel patches may be needed).
 * The check is _NOT_ done if we will not use FD_SETS at all (USE_POLL)
 */
#error "FD_SETSIZE is too small or MAXCONNECTIONS too large."
#endif
#endif


/*
 * Cannot use perror() within daemon. stderr is closed in
 * ircd and cannot be used. And, worse yet, it might have
 * been reassigned to a normal connection...
 */

/*
 * report_error
 *
 * This a replacement for perror(). Record error to log and
 * also send a copy to all *LOCAL* opers online.
 *
 * text    is a *format* string for outputting error. It must
 *         contain only two '%s', the first will be replaced
 *         by the sockhost from the cptr, and the latter will
 *         be taken from sys_errlist[errno].
 *
 * cptr    if not NULL, is the *LOCAL* client associated with
 *         the error.
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

  if (last_notice + 20 < CurrentTime) {
    /*
     * pace error messages so opers don't get flooded by transients
     */
    sendto_opmask_butone(0, SNO_OLDSNO, text, who, errmsg);
    last_notice = CurrentTime;
  }
  ircd_log(L_ERROR, text, who, errmsg);
  errno = errtmp;
}


/*
 * connect_dns_callback - called when resolver query finishes
 * if the query resulted in a successful search, reply will contain
 * a non-null pointer, otherwise reply will be null.
 * if successful start the connection, otherwise notify opers
 */
static void connect_dns_callback(void* vptr, struct DNSReply* reply)
{
  struct ConfItem* aconf = (struct ConfItem*) vptr;
  aconf->dns_pending = 0;
  if (reply) {
    memcpy(&aconf->ipnum, reply->hp->h_addr, sizeof(struct in_addr));
    connect_server(aconf, 0, reply);
  }
  else
    sendto_opmask_butone(0, SNO_OLDSNO, "Connect to %s failed: host lookup",
			 aconf->name);
}

/*
 * close_connections - closes all connections
 * close stderr if specified
 */
void close_connections(int close_stderr)
{
  int i;
  close(0);
  close(1);
  if (close_stderr)
    close(2);
  for (i = 3; i < MAXCONNECTIONS; ++i)
    close(i);
}

/*
 * init_connection_limits - initialize process fd limit to
 * MAXCONNECTIONS
 */
int init_connection_limits(void)
{
  int limit = os_set_fdlimit(MAXCONNECTIONS);
  if (0 == limit)
    return 1;
  if (limit < 0) {
    fprintf(stderr, "error setting max fd's to %d\n", limit);
  }
  else if (limit > 0) {
    fprintf(stderr, "ircd fd table too big\nHard Limit: %d IRC max: %d\n",
            limit, MAXCONNECTIONS);
    fprintf(stderr, "set MAXCONNECTIONS to a smaller value");
  }
  return 0;
}

/*
 * connect_inet - set up address and port and make a connection
 */
static int connect_inet(struct ConfItem* aconf, struct Client* cptr)
{
  static struct sockaddr_in sin;
  assert(0 != aconf);
  assert(0 != cptr);
  /*
   * Might as well get sockhost from here, the connection is attempted
   * with it so if it fails its useless.
   */
  cptr->fd = socket(AF_INET, SOCK_STREAM, 0);
  if (-1 == cptr->fd) {
    cptr->error = errno;
    report_error(SOCKET_ERROR_MSG, cptr->name, errno);
    return 0;
  }
  if (cptr->fd >= MAXCLIENTS) {
    report_error(CONNLIMIT_ERROR_MSG, cptr->name, 0);
    close(cptr->fd);
    cptr->fd = -1;
    return 0;
  }
  /*
   * Bind to a local IP# (with unknown port - let unix decide) so
   * we have some chance of knowing the IP# that gets used for a host
   * with more than one IP#.
   *
   * No we don't bind it, not all OS's can handle connecting with
   * an already bound socket, different ip# might occur anyway
   * leading to a freezing select() on this side for some time.
   * I had this on my Linux 1.1.88 --Run
   */
#ifdef VIRTUAL_HOST
  /*
   * No, we do bind it if we have virtual host support. If we don't
   * explicitly bind it, it will default to IN_ADDR_ANY and we lose
   * due to the other server not allowing our base IP --smg
   */
  if (bind(cptr->fd, (struct sockaddr*) &VirtualHost, sizeof(VirtualHost))) {
    report_error(BIND_ERROR_MSG, cptr->name, errno);
    return 0;
  }
#endif

  memset(&sin, 0, sizeof(sin));
  sin.sin_family      = AF_INET;
  sin.sin_addr.s_addr = aconf->ipnum.s_addr;
  sin.sin_port        = htons(aconf->port);
  /*
   * save connection info in client
   */
  cptr->ip.s_addr = aconf->ipnum.s_addr;
  cptr->port      = aconf->port;
  ircd_ntoa_r(cptr->sock_ip, (const char*) &cptr->ip);
  /*
   * we want a big buffer for server connections
   */
  if (!os_set_sockbufs(cptr->fd, SERVER_TCP_WINDOW)) {
    cptr->error = errno;
    report_error(SETBUFS_ERROR_MSG, cptr->name, errno);
    return 0;
  }
  /*
   * ALWAYS set sockets non-blocking
   */
  if (!os_set_nonblocking(cptr->fd)) {
    cptr->error = errno;
    report_error(NONB_ERROR_MSG, cptr->name, errno);
    return 0;
  }
  if (!os_connect_nonb(cptr->fd, &sin)) {
    cptr->error = errno;
    report_error(CONNECT_ERROR_MSG, cptr->name, errno);
    return 0;
  }
  return 1;
}

/*
 * deliver_it
 *   Attempt to send a sequence of bytes to the connection.
 *   Returns
 *
 *   < 0     Some fatal error occurred, (but not EWOULDBLOCK).
 *           This return is a request to close the socket and
 *           clean up the link.
 *
 *   >= 0    No real error occurred, returns the number of
 *           bytes actually transferred. EWOULDBLOCK and other
 *           possibly similar conditions should be mapped to
 *           zero return. Upper level routine will have to
 *           decide what to do with those unwritten bytes...
 *
 *   *NOTE*  alarm calls have been preserved, so this should
 *           work equally well whether blocking or non-blocking
 *           mode is used...
 *
 *   We don't use blocking anymore, that is impossible with the
 *      net.loads today anyway. Commented out the alarms to save cpu.
 *      --Run
 */
unsigned int deliver_it(struct Client *cptr, const char *str, unsigned int len)
{
  unsigned int bytes_written = 0;
  assert(0 != cptr);

  switch (os_send_nonb(cptr->fd, str, len, &bytes_written)) {
  case IO_SUCCESS:
    cptr->flags &= ~FLAGS_BLOCKED;

    cptr->sendB += bytes_written;
    me.sendB    += bytes_written;
    if (cptr->sendB > 1023) {
      cptr->sendK += (cptr->sendB >> 10);
      cptr->sendB &= 0x03ff;    /* 2^10 = 1024, 3ff = 1023 */
    }
    if (me.sendB > 1023) {
      me.sendK += (me.sendB >> 10);
      me.sendB &= 0x03ff;
    }
    /*
     * XXX - hrmm.. set blocked here? the socket didn't
     * say it was blocked
     */
    if (bytes_written < len)
      cptr->flags |= FLAGS_BLOCKED;
    break;
  case IO_BLOCKED:
    cptr->flags |= FLAGS_BLOCKED;
    break;
  case IO_FAILURE:
    cptr->error = errno;
    cptr->flags |= FLAGS_DEADSOCKET;
    break;
  }
  return bytes_written;
}


void release_dns_reply(struct Client* cptr)
{
  assert(0 != cptr);
  assert(MyConnect(cptr));

  if (cptr->dns_reply) {
    assert(0 < cptr->dns_reply->ref_count);
    --cptr->dns_reply->ref_count;
    cptr->dns_reply = 0;
  }
}

/*
 * completed_connection
 *
 * Complete non-blocking connect()-sequence. Check access and
 * terminate connection, if trouble detected.
 *
 * Return  TRUE, if successfully completed
 *        FALSE, if failed and ClientExit
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
  if ((cptr->error = os_get_sockerr(cptr->fd))) {
    const char* msg = strerror(cptr->error);
    if (!msg)
      msg = "Unknown error";
    sendto_opmask_butone(0, SNO_OLDSNO, "Connection failed to %s: %s",
			 cptr->name, msg);
    return 0;
  }
  if (!(aconf = find_conf_byname(cptr->confs, cptr->name, CONF_SERVER))) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Lost Server Line for %s", cptr->name);
    return 0;
  }

  if (!EmptyString(aconf->passwd))
    sendrawto_one(cptr, MSG_PASS " :%s", aconf->passwd);

#if 0 
  /* dead code, already done in connect_server */
  make_server(cptr);
#endif
  /*
   * Create a unique timestamp
   */
  newts = TStime();
  for (i = HighestFd; i > -1; --i) {
    if ((acptr = LocalClientArray[i]) && 
        (IsServer(acptr) || IsHandshake(acptr))) {
      if (acptr->serv->timestamp >= newts)
        newts = acptr->serv->timestamp + 1;
    }
  }
  assert(0 != cptr->serv);

  cptr->serv->timestamp = newts;
  SetHandshake(cptr);
  /*
   * Make us timeout after twice the timeout for DNS look ups
   */
  cptr->lasttime = CurrentTime;
  cptr->flags |= FLAGS_PINGSENT;

  sendrawto_one(cptr, MSG_SERVER " %s 1 %Tu %Tu J%s %s%s :%s",
		me.name, me.serv->timestamp, newts, MAJOR_PROTOCOL, 
		NumServCap(&me), me.info);

  return (IsDead(cptr)) ? 0 : 1;
}

/*
 * close_connection
 *
 * Close the physical connection. This function must make
 * MyConnect(cptr) == FALSE, and set cptr->from == NULL.
 */
void close_connection(struct Client *cptr)
{
  struct ConfItem* aconf;

  if (IsServer(cptr)) {
    ServerStats->is_sv++;
    ServerStats->is_sbs += cptr->sendB;
    ServerStats->is_sbr += cptr->receiveB;
    ServerStats->is_sks += cptr->sendK;
    ServerStats->is_skr += cptr->receiveK;
    ServerStats->is_sti += CurrentTime - cptr->firsttime;
    if (ServerStats->is_sbs > 1023) {
      ServerStats->is_sks += (ServerStats->is_sbs >> 10);
      ServerStats->is_sbs &= 0x3ff;
    }
    if (ServerStats->is_sbr > 1023) {
      ServerStats->is_skr += (ServerStats->is_sbr >> 10);
      ServerStats->is_sbr &= 0x3ff;
    }
    /*
     * If the connection has been up for a long amount of time, schedule
     * a 'quick' reconnect, else reset the next-connect cycle.
     */
    if ((aconf = find_conf_exact(cptr->name, 0, cptr->sockhost, CONF_SERVER))) {
      /*
       * Reschedule a faster reconnect, if this was a automaticly
       * connected configuration entry. (Note that if we have had
       * a rehash in between, the status has been changed to
       * CONF_ILLEGAL). But only do this if it was a "good" link.
       */
      aconf->hold = CurrentTime;
      aconf->hold += (aconf->hold - cptr->since > HANGONGOODLINK) ?
                     HANGONRETRYDELAY : ConfConFreq(aconf);
      if (nextconnect > aconf->hold)
        nextconnect = aconf->hold;
    }
  }
  else if (IsUser(cptr)) {
    ServerStats->is_cl++;
    ServerStats->is_cbs += cptr->sendB;
    ServerStats->is_cbr += cptr->receiveB;
    ServerStats->is_cks += cptr->sendK;
    ServerStats->is_ckr += cptr->receiveK;
    ServerStats->is_cti += CurrentTime - cptr->firsttime;
    if (ServerStats->is_cbs > 1023) {
      ServerStats->is_cks += (ServerStats->is_cbs >> 10);
      ServerStats->is_cbs &= 0x3ff;
    }
    if (ServerStats->is_cbr > 1023) {
      ServerStats->is_ckr += (ServerStats->is_cbr >> 10);
      ServerStats->is_cbr &= 0x3ff;
    }
  }
  else
    ServerStats->is_ni++;

  if (-1 < cptr->fd) {
    flush_connections(cptr);
    ip_registry_local_disconnect(cptr);
    LocalClientArray[cptr->fd] = 0;
    close(cptr->fd);
    cptr->fd = -1;
  }
  cptr->flags |= FLAGS_DEADSOCKET;

  DBufClear(&cptr->sendQ);
  DBufClear(&cptr->recvQ);
  memset(cptr->passwd, 0, sizeof(cptr->passwd));
  set_snomask(cptr, 0, SNO_SET);

  det_confs_butmask(cptr, 0);

  if (cptr->listener) {
    release_listener(cptr->listener);
    cptr->listener = 0;
  }

  for ( ; HighestFd > 0; --HighestFd) {
    if (LocalClientArray[HighestFd])
      break;
  }
}

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

/*----------------------------------------------------------------------------
 * add_connection
 *
 * Creates a client which has just connected to us on the given fd.
 * The sockhost field is initialized with the ip# of the host.
 * The client is not added to the linked list of clients, it is
 * passed off to the auth handler for dns and ident queries.
 *--------------------------------------------------------------------------*/
void add_connection(struct Listener* listener, int fd) {
  struct sockaddr_in addr;
  struct Client      *new_client;
  time_t             next_target = 0;

  const char* const throttle_message =
         "ERROR :Your host is trying to (re)connect too fast -- throttled\r\n";
       /* 12345678901234567890123456789012345679012345678901234567890123456 */
  
  assert(0 != listener);

 
  /*
   * Removed preliminary access check. Full check is performed in m_server and
   * m_user instead. Also connection time out help to get rid of unwanted
   * connections.  
   */
  if (!os_get_peername(fd, &addr) || !os_set_nonblocking(fd)) {
    ++ServerStats->is_ref;
    close(fd);
    return;
  }

  /*
   * Add this local client to the IPcheck registry.
   *
   * If they're throttled, murder them, but tell them why first.
   */
  if ( !ip_registry_check_local(addr.sin_addr.s_addr,&next_target) ) {
  	++ServerStats->is_ref;
  	write(fd,throttle_message,strlen(throttle_message));
  	close(fd);
  	return;
  }

  new_client = make_client(0, ((listener->server) ? 
			       STAT_UNKNOWN_SERVER : STAT_UNKNOWN_USER));

  /*
   * Copy ascii address to 'sockhost' just in case. Then we have something
   * valid to put into error messages...  
   */
  ircd_ntoa_r(new_client->sock_ip, (const char*) &addr.sin_addr);   
  strcpy(new_client->sockhost, new_client->sock_ip);
  new_client->ip.s_addr = addr.sin_addr.s_addr;
  new_client->port      = ntohs(addr.sin_port);

  if (next_target)
    new_client->nexttarget = next_target;

  new_client->fd = fd;
  new_client->listener = listener;
  ++listener->ref_count;

  Count_newunknown(UserStats);
  ip_registry_connect_succeeded(new_client);
  /* if we've made it this far we can put the client on the auth query pile */
  start_auth(new_client);
}


/*
 * read_packet
 *
 * Read a 'packet' of data from a connection and process it.  Read in 8k
 * chunks to give a better performance rating (for server connections).
 * Do some tricky stuff for client connections to make sure they don't do
 * any flooding >:-) -avalon
 */
static int read_packet(struct Client *cptr, int socket_ready)
{
  unsigned int dolen = 0;
  unsigned int length = 0;

  if (socket_ready && !(IsUser(cptr) && DBufLength(&cptr->recvQ) > CLIENT_FLOOD)) {
    switch (os_recv_nonb(cptr->fd, readbuf, sizeof(readbuf), &length)) {
    case IO_SUCCESS:
      if (length) {
        cptr->lasttime = CurrentTime;
        if (cptr->lasttime > cptr->since)
          cptr->since = cptr->lasttime;
        cptr->flags &= ~(FLAGS_PINGSENT | FLAGS_NONL);
      }
      break;
    case IO_BLOCKED:
      break;
    case IO_FAILURE:
      cptr->error = errno;
      /* cptr->flags |= FLAGS_DEADSOCKET; */
      return 0;
    }
  }

  /*
   * For server connections, we process as many as we can without
   * worrying about the time of day or anything :)
   */
  if (length > 0 && IsServer(cptr)) {
    return server_dopacket(cptr, readbuf, length);
  }
  else {
    /*
     * Before we even think of parsing what we just read, stick
     * it on the end of the receive queue and do it when its
     * turn comes around.
     */
    if (length > 0 && 0 == dbuf_put(&cptr->recvQ, readbuf, length)) {
      return exit_client(cptr, cptr, &me, "dbuf_put fail");
    }
#ifndef NOFLOODCONTROL
    /*
     * XXX - cptr will always be a user or unregistered
     */
    if (IsUser(cptr) && DBufLength(&cptr->recvQ) > CLIENT_FLOOD)
      return exit_client(cptr, cptr, &me, "Excess Flood");

    while (DBufLength(&cptr->recvQ) && !NoNewLine(cptr) && 
           (IsTrusted(cptr) || cptr->since - CurrentTime < 10))
#else
    while (DBufLength(&cptr->recvQ) && !NoNewLine(cptr))
#endif
    {
      /*
       * If it has become registered as a Server
       * then skip the per-message parsing below.
       */
      if (IsServer(cptr)) {
        dolen = dbuf_get(&cptr->recvQ, readbuf, sizeof(readbuf));
        return (dolen) ? server_dopacket(cptr, readbuf, dolen) : 1;
      }
      dolen = dbuf_getmsg(&cptr->recvQ, cptr->buffer, BUFSIZE);
      /*
       * Devious looking...whats it do ? well..if a client
       * sends a *long* message without any CR or LF, then
       * dbuf_getmsg fails and we pull it out using this
       * loop which just gets the next 512 bytes and then
       * deletes the rest of the buffer contents.
       * -avalon
       */
      if (0 == dolen) {
        if (DBufLength(&cptr->recvQ) < 510)
          cptr->flags |= FLAGS_NONL;
        else
          DBufClear(&cptr->recvQ);
      }
      else if (CPTR_KILLED == client_dopacket(cptr, dolen))
        return CPTR_KILLED;
    }
  }
  return 1;
}

static int on_write_unblocked(struct Client* cptr)
{
  /*
   *  ...room for writing, empty some queue then...
   */
  cptr->flags &= ~FLAGS_BLOCKED;
  if (IsConnecting(cptr)) {
    if (!completed_connection(cptr))
      return 0;
  }
  else if (cptr->listing && DBufLength(&cptr->sendQ) < 2048)
    list_next_channels(cptr, 64);
  send_queued(cptr);
  return 1;
}

/*
 * Select / Poll Read Algorithm for ircd
 *
 * We need to check the file descriptors for all the different types
 * of things that use them, so check for reads on everything but connects
 * and writes on connects and descriptors that are blocked
 *
 * for each (client in local) {
 *   if (not connecting)
 *     check for read;
 *   if (connecting or blocked)
 *     check for write;
 * }
 * wait for activity;
 *
 * for each (client in local) {
 *   if (there are descriptors to check) {
 *     if (write activity)
 *       send data;
 *     if (read activity)
 *       read data;
 *   }
 *   process data read;
 * }
 * Note we must always process data read whether or not there has been
 * read activity or file descriptors set, since data is buffered by the client.
 */


#ifdef USE_POLL

/*
 * poll macros
 */
#if defined(POLLMSG) && defined(POLLIN) && defined(POLLRDNORM)
#  define POLLREADFLAGS (POLLMSG|POLLIN|POLLRDNORM)
#else
#  if defined(POLLIN) && defined(POLLRDNORM)
#    define POLLREADFLAGS (POLLIN|POLLRDNORM)
#  else
#    if defined(POLLIN)
#      define POLLREADFLAGS POLLIN
#    else
#      if defined(POLLRDNORM)
#        define POLLREADFLAGS POLLRDNORM
#      endif
#    endif
#  endif
#endif

#if defined(POLLOUT) && defined(POLLWRNORM)
#define POLLWRITEFLAGS (POLLOUT|POLLWRNORM)
#else
#  if defined(POLLOUT)
#    define POLLWRITEFLAGS POLLOUT
#  else
#    if defined(POLLWRNORM)
#      define POLLWRITEFLAGS POLLWRNORM
#    endif
#  endif
#endif

#ifdef POLLHUP
#define POLLERRORS (POLLHUP|POLLERR)
#else
#define POLLERRORS POLLERR
#endif

/*
 * NOTE: pfd and pfd_count are local variable names in read_message
 */
#define PFD_SETR(xfd) \
  do { CHECK_ADD_PFD(xfd) pfd->events |= POLLREADFLAGS; } while(0)
#define PFD_SETW(xfd) \
  do { CHECK_ADD_PFD(xfd) pfd->events |= POLLWRITEFLAGS; } while(0)

#define CHECK_ADD_PFD(xfd) \
  if (pfd->fd != xfd) { \
    pfd = &poll_fds[pfd_count++]; \
    poll_fds[pfd_count].fd = -1; \
    pfd->fd = xfd; \
    pfd->events = 0; \
  }

/*
 * Check all connections for new connections and input data that is to be
 * processed. Also check for connections with data queued and whether we can
 * write it out.
 *
 * Don't ever use ZERO for `delay', unless you mean to poll and then
 * you have to have sleep/wait somewhere else in the code.--msa
 */
int read_message(time_t delay)
{
  struct pollfd poll_fds[MAXCONNECTIONS + 1];
  struct Client*      cptr;
  struct Listener*    listener   = 0;
  struct AuthRequest* auth       = 0;
  struct AuthRequest* auth_next  = 0;
  struct UPing*       uping      = 0;
  struct UPing*       uping_next = 0;
  time_t delay2 = delay;
  int nfds;
  int length;
  int i;
  int res = 0;
  int pfd_count;
  struct pollfd* pfd;
  struct pollfd* res_pfd;
  struct pollfd* uping_pfd;
  int read_ready;
  int write_ready;

  unsigned int timeout;

  for ( ; ; ) {
    pfd_count = 0;
    pfd = poll_fds;
    res_pfd = 0;
    uping_pfd = 0;
    pfd->fd = -1;

    if (-1 < ResolverFileDescriptor) {
      PFD_SETR(ResolverFileDescriptor);
      res_pfd = pfd;
    }
    if (-1 < UPingFileDescriptor) {
      PFD_SETR(UPingFileDescriptor);
      uping_pfd = pfd;
    }
    /*
     * add uping descriptors
     */
    for (uping = uping_begin(); uping; uping = uping_next) {
      uping_next = uping->next;
      if (uping->active) {
        delay2 = 1;
       if (uping->lastsent && CurrentTime > uping->timeout) {
          uping_end(uping);
          continue;
        }
        uping->index = pfd_count;
        PFD_SETR(uping->fd);
      }
    }
    /*
     * add auth file descriptors
     */
    for (auth = AuthPollList; auth; auth = auth->next) {
      assert(-1 < auth->fd);
      auth->index = pfd_count;
      if (IsAuthConnect(auth))
        PFD_SETW(auth->fd);
      else
        PFD_SETR(auth->fd);
    }
    /*
     * add listener file descriptors
     */    
    for (listener = ListenerPollList; listener; listener = listener->next) {
      assert(-1 < listener->fd);
      /*
       * pfd_count is incremented by PFD_SETR so we need to save the 
       * index first 
       */
      listener->index = pfd_count;
      PFD_SETR(listener->fd);
    }

    for (i = HighestFd; -1 < i; --i) {
      if ((cptr = LocalClientArray[i])) {

        if (DBufLength(&cptr->recvQ))
          delay2 = 1;
        if (DBufLength(&cptr->recvQ) < 4088 || IsServer(cptr)) {
          PFD_SETR(i);
        }
        if (DBufLength(&cptr->sendQ) || IsConnecting(cptr) ||
            (cptr->listing && DBufLength(&cptr->sendQ) < 2048)) {
          PFD_SETW(i);
        }
      }
    }

    Debug((DEBUG_INFO, "poll: %d %d", delay, delay2));

    timeout = (IRCD_MIN(delay2, delay)) * 1000;

    nfds = poll(poll_fds, pfd_count, timeout);

    CurrentTime = time(0);
    if (-1 < nfds)
      break;

    if (EINTR == errno)
      return -1;
    report_error(POLL_ERROR_MSG, me.name, errno);
    ++res;
    if (res > 5)
      server_restart("too many poll errors");
    sleep(1);
    CurrentTime = time(0);
  }

  if (uping_pfd && (uping_pfd->revents & (POLLREADFLAGS | POLLERRORS))) {
    uping_echo();
    --nfds;
  }
  /*
   * check uping replies
   */
  for (uping = uping_begin(); uping; uping = uping_next) {
    uping_next = uping->next;
    if (uping->active) {
      assert(-1 < uping->index);
      if (poll_fds[uping->index].revents) {
        uping_read(uping);
        if (0 == --nfds)
          break;
      }
      else if (CurrentTime > uping->lastsent) {
        uping->lastsent = CurrentTime;
        uping_send(uping);
      }
    }
  }

  if (res_pfd && (res_pfd->revents & (POLLREADFLAGS | POLLERRORS))) {
    resolver_read();
    --nfds;
  }
  /*
   * check auth queries
   */
  for (auth = AuthPollList; auth; auth = auth_next) {
    auth_next = auth->next;
    i = auth->index;
    /*
     * check for any event, we only ask for one at a time
     */
    if (poll_fds[i].revents) {
      if (IsAuthConnect(auth))
        send_auth_query(auth);
      else
        read_auth_reply(auth);
      if (0 == --nfds)
        break;
    }
  }
  /*
   * check listeners
   */
  for (listener = ListenerPollList; listener; listener = listener->next) {
    i = listener->index;
    if (poll_fds[i].revents) {
      accept_connection(listener);
      if (0 == --nfds)
        break;
    }
  }
  /*
   * i contains the next non-auth/non-listener index, since we put the
   * resolver, auth and listener, file descriptors in poll_fds first,
   * the very next one should be the start of the clients
   */
  pfd = &poll_fds[++i];

  for ( ; (i < pfd_count); ++i, ++pfd) {
    if (!(cptr = LocalClientArray[pfd->fd]))
      continue;
    read_ready = write_ready = 0;

    if (0 < nfds && pfd->revents) {
      --nfds;
    
      read_ready  = pfd->revents & POLLREADFLAGS;
      write_ready = pfd->revents & POLLWRITEFLAGS;

      if (pfd->revents & POLLERRORS) {
        if (pfd->events & POLLREADFLAGS)
          ++read_ready;
        if (pfd->events & POLLWRITEFLAGS)
          ++write_ready;
      }
    }
    if (write_ready) {
      if (!on_write_unblocked(cptr) || IsDead(cptr)) {
        const char* msg = (cptr->error) ? strerror(cptr->error) : cptr->info;
        if (!msg)
          msg = "Unknown error";
        exit_client(cptr, cptr, &me, msg);
        continue;
      }
    }
    length = 1;                 /* for fall through case */
    if ((!NoNewLine(cptr) || read_ready) && !IsDead(cptr)) {
      if (CPTR_KILLED == (length = read_packet(cptr, read_ready)))
        continue;
    }
#if 0
    /* Bullshit, why would we want to flush sockets while using non-blocking?
     * This uses > 4% cpu! --Run */
    if (length > 0)
      flush_connections(poll_cptr[i]);
#endif
    if (IsDead(cptr)) {
      const char* msg = (cptr->error) ? strerror(cptr->error) : cptr->info;
      if (!msg)
        msg = "Unknown error";
      exit_client(cptr, cptr, &me, (char*) msg);
      continue;
    }
    if (length > 0)
      continue;
    cptr->flags |= FLAGS_DEADSOCKET;
    /*
     * ...hmm, with non-blocking sockets we might get
     * here from quite valid reasons, although.. why
     * would select report "data available" when there
     * wasn't... So, this must be an error anyway...  --msa
     * actually, EOF occurs when read() returns 0 and
     * in due course, select() returns that fd as ready
     * for reading even though it ends up being an EOF. -avalon
     */
    Debug((DEBUG_ERROR, "READ ERROR: fd = %d %d %d", pfd->fd, errno, length));

    if ((IsServer(cptr) || IsHandshake(cptr)) && cptr->error == 0 && length == 0)
      exit_client_msg(cptr, cptr, &me, "Server %s closed the connection (%s)",
                      cptr->name, cptr->serv->last_error_msg);
    else {
      const char* msg = (cptr->error) ? strerror(cptr->error) : "EOF from client";
      if (!msg)
        msg = "Unknown error";
      exit_client_msg(cptr, cptr, &me, "Read error: %s",
                      msg);
    }
  }
  return 0;
}
#else /* USE_SELECT */

/*
 * Check all connections for new connections and input data that is to be
 * processed. Also check for connections with data queued and whether we can
 * write it out.
 *
 * Don't ever use ZERO for `delay', unless you mean to poll and then
 * you have to have sleep/wait somewhere else in the code.--msa
 */
int read_message(time_t delay)
{
  struct Client*   cptr;
  struct Listener* listener;
  struct AuthRequest* auth = 0;
  struct AuthRequest* auth_next = 0;
  struct UPing*       uping;
  struct UPing*       uping_next;
  int              nfds;
  struct timeval   wait;
  time_t           delay2 = delay;
  unsigned int     usec = 0;
  int              res = 0;
  int              length;
  int              i;
  int              read_ready;
  fd_set           read_set;
  fd_set           write_set;

  for ( ; ; )
  {
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);

    if (-1 < ResolverFileDescriptor)
      FD_SET(ResolverFileDescriptor, &read_set);
    if (-1 < UPingFileDescriptor)
      FD_SET(UPingFileDescriptor, &read_set);
    /*
     * set up uping file descriptors
     */
    for (uping = uping_begin(); uping; uping = uping_next) {
      uping_next = uping->next;
      if (uping->active) {
        delay2 = 1;
        if (uping->lastsent && CurrentTime > uping->timeout) {
          uping_end(uping);
          continue;
        }
        assert(-1 < uping->fd);
        FD_SET(uping->fd, &read_set);
      }
    }
    /*
     * set auth file descriptors
     */
    for (auth = AuthPollList; auth; auth = auth->next) {
      assert(-1 < auth->fd);
      if (IsAuthConnect(auth))
        FD_SET(auth->fd, &write_set);
      else /* if (IsAuthPending(auth)) */
        FD_SET(auth->fd, &read_set);
    }
    /*
     * set listener file descriptors
     */
    for (listener = ListenerPollList; listener; listener = listener->next) {
      assert(-1 < listener->fd);
      FD_SET(listener->fd, &read_set);
    }

    for (i = HighestFd; i > -1; --i) {
      if ((cptr = LocalClientArray[i])) {
        if (DBufLength(&cptr->recvQ))
          delay2 = 1;
        if (DBufLength(&cptr->recvQ) < 4088 || IsServer(cptr))
          FD_SET(i, &read_set);
        if (DBufLength(&cptr->sendQ) || IsConnecting(cptr) ||
            (cptr->listing && DBufLength(&cptr->sendQ) < 2048))
          FD_SET(i, &write_set);
      }
    }

    wait.tv_sec = IRCD_MIN(delay2, delay);
    wait.tv_usec = usec;

    Debug((DEBUG_INFO, "select: %d %d", delay, delay2));

    nfds = select(FD_SETSIZE, &read_set, &write_set, 0, &wait);

    CurrentTime = time(0);

    if (-1 < nfds)
      break;

    if (errno == EINTR)
      return -1;
    report_error(SELECT_ERROR_MSG, me.name, errno);
    if (++res > 5)
      server_restart("too many select errors");
    sleep(1);
    CurrentTime = time(0);
  }

  if (-1 < UPingFileDescriptor && FD_ISSET(UPingFileDescriptor, &read_set)) {
    uping_echo();
    --nfds;
  }
  for (uping = uping_begin(); uping; uping = uping_next) {
    uping_next = uping->next;
    if (uping->active) {
      assert(-1 < uping->fd);
      if (FD_ISSET(uping->fd, &read_set)) {
        uping_read(uping);
        if (0 == --nfds)
          break;
      }
      else if (CurrentTime > uping->lastsent) {
        uping->lastsent = CurrentTime;
        uping_send(uping);
      }
    }
  }
  if (-1 < ResolverFileDescriptor && FD_ISSET(ResolverFileDescriptor, &read_set)) {
    resolver_read();
    --nfds;
  }
  /*
   * Check fd sets for the auth fd's (if set and valid!) first
   * because these can not be processed using the normal loops below.
   * -avalon
   */
  for (auth = AuthPollList; auth; auth = auth_next) {
    auth_next = auth->next;
    assert(-1 < auth->fd);
    if (IsAuthConnect(auth) && FD_ISSET(auth->fd, &write_set)) {
      send_auth_query(auth);
      if (0 == --nfds)
        break;
    }
    else if (FD_ISSET(auth->fd, &read_set)) {
      read_auth_reply(auth);
      if (0 == --nfds)
        break;
    }
  }
  /*
   * next accept connections from active listeners
   */
  for (listener = ListenerPollList; listener; listener = listener->next) {
    assert(-1 < listener->fd);
    if (0 < nfds && FD_ISSET(listener->fd, &read_set))
      accept_connection(listener);
  } 

  for (i = HighestFd; -1 < i; --i) {
    if (!(cptr = LocalClientArray[i]))
      continue;
    read_ready = 0;
    if (0 < nfds) {
      if (FD_ISSET(i, &write_set)) {
        --nfds;
        if (!on_write_unblocked(cptr) || IsDead(cptr)) {
          const char* msg = (cptr->error) ? strerror(cptr->error) : cptr->info;
          if (!msg)
            msg = "Unknown error";
          if (FD_ISSET(i, &read_set))
            --nfds;
          exit_client(cptr, cptr, &me, msg);
          continue;
        }
      }
      if ((read_ready = FD_ISSET(i, &read_set)))
        --nfds;
    }
    length = 1;                 /* for fall through case */
    if ((!NoNewLine(cptr) || read_ready) && !IsDead(cptr)) {
      if (CPTR_KILLED == (length = read_packet(cptr, read_ready)))
        continue;
    }
    if (IsDead(cptr)) {
      const char* msg = (cptr->error) ? strerror(cptr->error) : cptr->info;
      if (!msg)
        msg = "Unknown error";
      exit_client(cptr, cptr, &me, msg);
      continue;
    }
    if (length > 0)
      continue;

    /*
     * ...hmm, with non-blocking sockets we might get
     * here from quite valid reasons, although.. why
     * would select report "data available" when there
     * wasn't... So, this must be an error anyway...  --msa
     * actually, EOF occurs when read() returns 0 and
     * in due course, select() returns that fd as ready
     * for reading even though it ends up being an EOF. -avalon
     */
    Debug((DEBUG_ERROR, "READ ERROR: fd = %d %d %d", i, cptr->error, length));

    if ((IsServer(cptr) || IsHandshake(cptr)) && cptr->error == 0 && length == 0)
      exit_client_msg(cptr, cptr, &me, "Server %s closed the connection (%s)",
                      cptr->name, cptr->serv->last_error_msg);
    else {
      const char* msg = (cptr->error) ? strerror(cptr->error) : "EOF from client";
      if (!msg)
        msg = "Unknown error";
      exit_client_msg(cptr, cptr, &me, "Read error: %s",
                      msg);
    }
  }
  return 0;
}

#endif /* USE_SELECT */

/*
 * connect_server - start or complete a connection to another server
 * returns true (1) if successful, false (0) otherwise
 *
 * aconf must point to a valid C:line
 * m_connect            calls this with a valid by client and a null reply
 * try_connections      calls this with a null by client, and a null reply
 * connect_dns_callback call this with a null by client, and a valid reply
 *
 * XXX - if this comes from an m_connect message and a dns query needs to
 * be done, we loose the information about who started the connection and
 * it's considered an auto connect.
 */
int connect_server(struct ConfItem* aconf, struct Client* by,
                   struct DNSReply* reply)
{
  struct Client*   cptr = 0;
  assert(0 != aconf);

  if (aconf->dns_pending) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Server %s connect DNS pending",
			 aconf->name);
    return 0;
  }
  Debug((DEBUG_NOTICE, "Connect to %s[@%s]", aconf->name,
         ircd_ntoa((const char*) &aconf->ipnum)));

  if ((cptr = FindClient(aconf->name))) {
    if (IsServer(cptr) || IsMe(cptr)) {
      sendto_opmask_butone(0, SNO_OLDSNO, "Server %s already present from %s", 
			   aconf->name, cptr->from->name);
      if (by && IsUser(by) && !MyUser(by)) {
	sendcmdto_one(&me, CMD_NOTICE, by, "%C :Server %s already present "
		      "from %s", by, aconf->name, cptr->from->name);
      }
      return 0;
    }
    else if (IsHandshake(cptr) || IsConnecting(cptr)) {
      if (by && IsUser(by)) {
	sendcmdto_one(&me, CMD_NOTICE, by, "%C :Connection to %s already in "
		      "progress", by, cptr->name);
      }
      return 0;
    }
  }
  /*
   * If we dont know the IP# for this host and itis a hostname and
   * not a ip# string, then try and find the appropriate host record.
   */
  if (INADDR_NONE == aconf->ipnum.s_addr) {
    char buf[HOSTLEN + 1];
    assert(0 == reply);
    if (INADDR_NONE == (aconf->ipnum.s_addr = inet_addr(aconf->host))) {
      struct DNSQuery  query;

      query.vptr     = aconf;
      query.callback = connect_dns_callback;
      host_from_uh(buf, aconf->host, HOSTLEN);
      buf[HOSTLEN] = '\0';

      reply = gethost_byname(buf, &query);

      if (!reply) {
        aconf->dns_pending = 1;
        return 0;
      }
      memcpy(&aconf->ipnum, reply->hp->h_addr, sizeof(struct in_addr));
    }
  }
  cptr = make_client(NULL, STAT_UNKNOWN_SERVER);
  if (reply)
    ++reply->ref_count;
  cptr->dns_reply = reply;

  /*
   * Copy these in so we have something for error detection.
   */
  ircd_strncpy(cptr->name, aconf->name, HOSTLEN);
  ircd_strncpy(cptr->sockhost, aconf->host, HOSTLEN);

  /*
   * Attach config entries to client here rather than in
   * completed_connection. This to avoid null pointer references
   */
  attach_confs_byhost(cptr, aconf->host, CONF_SERVER);

  if (!find_conf_byhost(cptr->confs, aconf->host, CONF_SERVER)) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Host %s is not enabled for "
			 "connecting: no C-line", aconf->name);
    if (by && IsUser(by) && !MyUser(by)) {
      sendcmdto_one(&me, CMD_NOTICE, by, "%C :Connect to host %s failed: no "
		    "C-line", by, aconf->name);
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
		    cptr->name);
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
    sprintf_irc(cptr->serv->by, "%s%s", NumNick(by));
    assert(0 == cptr->serv->user);
    cptr->serv->user = by->user;
    by->user->refcnt++;
  }
  else {
    *cptr->serv->by = '\0';
    /* strcpy(cptr->serv->by, "Auto"); */
  }
  cptr->serv->up = &me;
  SetConnecting(cptr);

  if (cptr->fd > HighestFd)
    HighestFd = cptr->fd;

  
  LocalClientArray[cptr->fd] = cptr;

  Count_newunknown(UserStats);
  ip_registry_add_local(aconf->ipnum.s_addr);
  /* Actually we lie, the connect hasn't succeeded yet, but we have a valid
   * cptr, so we register it now.
   * Maybe these two calls should be merged.
   */
  ip_registry_connect_succeeded(cptr);
  add_client_to_list(cptr);
  hAddClient(cptr);
  nextping = CurrentTime;

  return 1;
}

/*
 * Setup local socket structure to use for binding to.
 */
void init_virtual_host(const struct ConfItem* conf)
{
  assert(0 != conf);

  memset(&VirtualHost, 0, sizeof(VirtualHost));
  VirtualHost.sin_family = AF_INET;
  VirtualHost.sin_addr.s_addr = INADDR_ANY;

  if (EmptyString(conf->passwd) || 0 == strcmp(conf->passwd, "*"))
    return;
  VirtualHost.sin_addr.s_addr = inet_addr(conf->passwd);

  if (INADDR_NONE == VirtualHost.sin_addr.s_addr)
    VirtualHost.sin_addr.s_addr = INADDR_ANY;
}  

/*
 * Find the real hostname for the host running the server (or one which
 * matches the server's name) and its primary IP#.  Hostname is stored
 * in the client structure passed as a pointer.
 */
int init_server_identity()
{
  struct ConfItem* conf = find_me();

  if (!conf || EmptyString(conf->host))
    return 0;

  ircd_strncpy(me.name, conf->host, HOSTLEN);

  init_virtual_host(conf);
  return 1;
}


