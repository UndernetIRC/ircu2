/*
 * IRC - Internet Relay Chat, ircd/ircd_auth.c
 * Copyright 2004 Michael Poole <mdpoole@troilus.org>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * $Id$
 */

#include "config.h"
#include "client.h"
#include "ircd_alloc.h"
#include "ircd_auth.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_osdep.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd.h"
#include "msg.h"
#include "msgq.h"
#include "res.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct IAuthRequest {
  struct IAuthRequest *iar_prev;        /* previous request struct */
  struct IAuthRequest *iar_next;        /* next request struct */
  struct Client *iar_client;            /* client being authenticated */
  char iar_timed;                       /* if non-zero, using parent i_request_timer */
};

enum IAuthFlag
{
  IAUTH_BLOCKED,                        /* socket buffer full */
  IAUTH_CONNECTED,                      /* server greeting/handshake done */
  IAUTH_ABORT,                          /* abort connection asap */
  IAUTH_ICLASS,                         /* tell iauth about all local users */
  IAUTH_CLOSING,                        /* candidate to be disposed */
  IAUTH_LAST_FLAG
};
DECLARE_FLAGSET(IAuthFlags, IAUTH_LAST_FLAG);

struct IAuth {
  struct IAuthRequest i_list_head;      /* doubly linked list of requests */
  struct MsgQ i_sendQ;                  /* messages queued to send */
  struct Socket i_socket;               /* connection to server */
  struct Timer i_reconn_timer;          /* when to reconnect the connection */
  struct Timer i_request_timer;         /* when the current request times out */
  struct IAuthFlags i_flags;            /* connection state/status/flags */
  struct DNSQuery i_query;              /* DNS lookup for iauth server */
  unsigned int i_recvM;                 /* messages received */
  unsigned int i_sendM;                 /* messages sent */
  unsigned int i_recvK;                 /* kilobytes received */
  unsigned int i_sendK;                 /* kilobytes sent */
  unsigned short i_recvB;               /* bytes received modulo 1024 */
  unsigned short i_sendB;               /* bytes sent modulo 1024 */
  time_t i_reconnect;                   /* seconds to wait before reconnecting */
  time_t i_timeout;                     /* seconds to wait for a request */
  unsigned int i_count;                 /* characters used in i_buffer */
  char i_buffer[BUFSIZE+1];             /* partial unprocessed line from server */
  char i_passwd[PASSWDLEN+1];           /* password for connection */
  char i_host[HOSTLEN+1];               /* iauth server hostname */
  in_addr_t i_addr;                     /* iauth server ip address */
  unsigned short i_port;                /* iauth server port */
  struct IAuth *i_next;                 /* next connection in list */
};

#define i_flags(iauth) ((iauth)->i_flags)
#define IAuthGet(iauth, flag) FlagHas(&i_flags(iauth), flag)
#define IAuthSet(iauth, flag) FlagSet(&i_flags(iauth), flag)
#define IAuthClr(iauth, flag) FlagClr(&i_flags(iauth), flag)
#define i_GetBlocked(iauth) IAuthGet(iauth, IAUTH_BLOCKED)
#define i_SetBlocked(iauth) IAuthSet(iauth, IAUTH_BLOCKED)
#define i_ClrBlocked(iauth) IAuthClr(iauth, IAUTH_BLOCKED)
#define i_GetConnected(iauth) IAuthGet(iauth, IAUTH_CONNECTED)
#define i_SetConnected(iauth) IAuthSet(iauth, IAUTH_CONNECTED)
#define i_ClrConnected(iauth) IAuthClr(iauth, IAUTH_CONNECTED)
#define i_GetAbort(iauth) IAuthGet(iauth, IAUTH_ABORT)
#define i_SetAbort(iauth) IAuthSet(iauth, IAUTH_ABORT)
#define i_ClrAbort(iauth) IAuthClr(iauth, IAUTH_ABORT)
#define i_GetIClass(iauth) IAuthGet(iauth, IAUTH_ICLASS)
#define i_SetIClass(iauth) IAuthSet(iauth, IAUTH_ICLASS)
#define i_ClrIClass(iauth) IAuthClr(iauth, IAUTH_ICLASS)
#define i_GetClosing(iauth) IAuthGet(iauth, IAUTH_CLOSING)
#define i_SetClosing(iauth) IAuthSet(iauth, IAUTH_CLOSING)
#define i_ClrClosing(iauth) IAuthClr(iauth, IAUTH_CLOSING)

#define i_list_head(iauth) ((iauth)->i_list_head)
#define i_socket(iauth) ((iauth)->i_socket)
#define i_reconn_timer(iauth) ((iauth)->i_reconn_timer)
#define i_request_timer(iauth) ((iauth)->i_request_timer)
#define i_query(iauth) ((iauth)->i_query)
#define i_recvB(iauth) ((iauth)->i_recvB)
#define i_recvK(iauth) ((iauth)->i_recvK)
#define i_recvM(iauth) ((iauth)->i_recvM)
#define i_sendB(iauth) ((iauth)->i_sendB)
#define i_sendK(iauth) ((iauth)->i_sendK)
#define i_sendM(iauth) ((iauth)->i_sendM)
#define i_sendQ(iauth) ((iauth)->i_sendQ)
#define i_reconnect(iauth) ((iauth)->i_reconnect)
#define i_timeout(iauth) ((iauth)->i_timeout)
#define i_count(iauth) ((iauth)->i_count)
#define i_buffer(iauth) ((iauth)->i_buffer)
#define i_passwd(iauth) ((iauth)->i_passwd)
#define i_host(iauth) ((iauth)->i_host)
#define i_addr(iauth) ((iauth)->i_addr)
#define i_port(iauth) ((iauth)->i_port)
#define i_next(iauth) ((iauth)->i_next)

struct IAuthCmd {
  const char *iac_name;
  void (*iac_func)(struct IAuth *iauth, int, char *[]);
};

struct IAuth *iauth_active;

static const struct IAuthCmd iauth_cmdtab[];

static void iauth_write(struct IAuth *iauth);
static void iauth_reconnect(struct IAuth *iauth);
static void iauth_disconnect(struct IAuth *iauth);
static void iauth_sock_callback(struct Event *ev);
static void iauth_send_request(struct IAuth *iauth, struct IAuthRequest *iar);
static void iauth_dispose_request(struct IAuth *iauth, struct IAuthRequest *iar);

struct IAuth *iauth_connect(char *host, unsigned short port, char *passwd, time_t reconnect, time_t timeout)
{
  struct IAuth *iauth;

  for (iauth = iauth_active; iauth; iauth = i_next(iauth)) {
    if (!ircd_strncmp(i_host(iauth), host, HOSTLEN)
        && (i_port(iauth) == port)) {
      i_ClrClosing(iauth);
      i_reconnect(iauth) = reconnect;
      if (t_active(&i_reconn_timer(iauth)) && (t_expire(&i_reconn_timer(iauth)) > CurrentTime + i_reconnect(iauth)))
        timer_chg(&i_reconn_timer(iauth), TT_RELATIVE, i_reconnect(iauth));
      break;
    }
  }
  if (NULL == iauth) {
    if (iauth_active && !i_GetClosing(iauth_active)) {
      log_write(LS_CONFIG, L_WARNING, 0, "Creating extra active IAuth connection to %s:%d.", host, port);
    }
    iauth = MyCalloc(1, sizeof(*iauth));
    i_list_head(iauth).iar_prev = &i_list_head(iauth);
    i_list_head(iauth).iar_next = &i_list_head(iauth);
    msgq_init(&i_sendQ(iauth));
    ircd_strncpy(i_host(iauth), host, HOSTLEN);
    i_port(iauth) = port;
    i_addr(iauth) = INADDR_NONE;
    i_next(iauth) = iauth_active;
    iauth_active = iauth;
    i_reconnect(iauth) = reconnect;
    iauth_reconnect(iauth);
  }
  if (passwd)
    ircd_strncpy(i_passwd(iauth), passwd, PASSWDLEN);
  else
    i_passwd(iauth)[0] = '\0';
  i_timeout(iauth) = timeout;
  return iauth;
}

void iauth_mark_closing(void)
{
  struct IAuth *iauth;
  for (iauth = iauth_active; iauth; iauth = i_next(iauth))
    i_SetClosing(iauth);
}

void iauth_close(struct IAuth *iauth)
{
  /* Figure out what to do with the closing connection's requests. */
  if (i_list_head(iauth).iar_next != &i_list_head(iauth)) {
    struct IAuthRequest *iar;
    if (iauth_active || i_next(iauth)) {
      /* If iauth_active != NULL, send requests to it; otherwise if
       * i_next(iauth) != NULL, we can hope it or some later
       * connection will be active.
       */
      struct IAuth *target = iauth_active ? iauth_active : i_next(iauth);

      /* Append iauth->i_list_head to end of target->i_list_head. */
      iar = i_list_head(iauth).iar_next;
      iar->iar_prev = i_list_head(target).iar_prev;
      i_list_head(target).iar_prev->iar_next = iar;
      iar = i_list_head(iauth).iar_prev;
      iar->iar_next = &i_list_head(target);
      i_list_head(target).iar_prev = iar;

      /* If the target is not closing, send the requests. */
      for (iar = i_list_head(iauth).iar_next;
           iar != &i_list_head(target);
           iar = iar->iar_next) {
        if (!i_GetClosing(target))
          iauth_send_request(target, iar);
      }
    } else {
      /* No active connections - approve the requests and drop them. */
      while ((iar = i_list_head(iauth).iar_next) != &i_list_head(iauth)) {
        struct Client *client = iar->iar_client;
        iauth_dispose_request(iauth, iar);
        register_user(client, client, cli_name(client), cli_username(client));
      }
    }
  }
  /* Make sure the connection closes with an empty request list. */
  i_list_head(iauth).iar_prev = &i_list_head(iauth);
  i_list_head(iauth).iar_next = &i_list_head(iauth);
  /* Cancel the timer, if it is active. */
  if (t_active(&i_reconn_timer(iauth)))
    timer_del(&i_reconn_timer(iauth));
  if (t_active(&i_request_timer(iauth)))
    timer_del(&i_request_timer(iauth));
  /* Disconnect from the server. */
  if (s_fd(&i_socket(iauth)) != -1)
    iauth_disconnect(iauth);
  /* Free memory. */
  MyFree(iauth);
}

void iauth_close_unused(void)
{
  struct IAuth *prev, *iauth, *next;
  
  for (prev = NULL, iauth = iauth_active; iauth; iauth = next) {
    next = i_next(iauth);
    if (i_GetClosing(iauth)) {
      /* Update iauth_active linked list. */
      if (prev)
        i_next(prev) = next;
      else
        iauth_active = next;
      /* Close and destroy the connection. */
      iauth_close(iauth);
    } else {
      prev = iauth;
    }
  }
}

static void iauth_send(struct IAuth *iauth, const char *format, ...)
{
  va_list vl;
  struct MsgBuf *mb;

  va_start(vl, format);
  mb = msgq_vmake(0, format, vl);
  va_end(vl);
  msgq_add(&i_sendQ(iauth), mb, 0);
  msgq_clean(mb);
}

static void iauth_protocol_violation(struct IAuth *iauth, const char *format, ...)
{
  struct VarData vd;
  assert(iauth != 0);
  assert(format != 0);
  vd.vd_format = format;
  va_start(vd.vd_args, format);
  sendwallto_group_butone(&me, WALL_DESYNCH, NULL, "IAuth protocol violation: %v", &vd);
  va_end(vd.vd_args);
}

static void iauth_on_connect(struct IAuth *iauth)
{
  struct IAuthRequest *iar;
  if (EmptyString(i_passwd(iauth)))
    iauth_send(iauth, "Server %s", cli_name(&me));
  else
    iauth_send(iauth, "Server %s %s", cli_name(&me), i_passwd(iauth));
  if (i_GetIClass(iauth)) {
    /* TODO: report local users to iauth */
    iauth_send(iauth, "EndUsers");
  }
  i_SetConnected(iauth);
  for (iar = i_list_head(iauth).iar_next;
       iar != &i_list_head(iauth);
       iar = iar->iar_next)
    iauth_send_request(iauth, iar);
  iauth_write(iauth);
}

static void iauth_disconnect(struct IAuth *iauth)
{
  close(s_fd(&i_socket(iauth)));
  socket_del(&i_socket(iauth));
  s_fd(&i_socket(iauth)) = -1;
}

static void iauth_dns_callback(void *vptr, struct DNSReply *he)
{
  struct IAuth *iauth = vptr;
  if (!he) {
    sendto_opmask_butone(0, SNO_OLDSNO, "IAuth connection to %s failed: host lookup failed", i_host(iauth));
  } else if (he->h_addrtype != AF_INET) {
    sendto_opmask_butone(0, SNO_OLDSNO, "IAuth connection to %s failed: bad host type %d", i_host(iauth), he->h_addrtype);
  } else {
    struct sockaddr_in *sin = (struct sockaddr_in*)&he->addr;
    i_addr(iauth) = sin->sin_addr.s_addr;
    if (INADDR_NONE == i_addr(iauth)) {
      sendto_opmask_butone(0, SNO_OLDSNO, "IAuth connection to %s failed: host came back as INADDR_NONE", i_host(iauth));
      return;
    }
    iauth_reconnect(iauth);
  }
}

static void iauth_reconnect_ev(struct Event *ev)
{
  if (ev_type(ev) == ET_EXPIRE)
    iauth_reconnect(t_data(ev_timer(ev)));
}

static void iauth_schedule_reconnect(struct IAuth *iauth)
{
  struct Timer *timer;
  assert(!t_active(&i_reconn_timer(iauth)));
  timer = timer_init(&i_reconn_timer(iauth));
  timer_add(timer, iauth_reconnect_ev, iauth, TT_RELATIVE, i_reconnect(iauth));
}

static void iauth_reconnect(struct IAuth *iauth)
{
  extern struct sockaddr_in VirtualHost;
  struct sockaddr_in sin;
  IOResult result;
  int fd;

  if (INADDR_NONE == i_addr(iauth)) {
    i_addr(iauth) = inet_addr(i_host(iauth));
    if (INADDR_NONE == i_addr(iauth)) {
      i_query(iauth).vptr = iauth;
      i_query(iauth).callback = iauth_dns_callback;
      gethost_byname(i_host(iauth), &i_query(iauth));
      return;
    }
  }
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (0 > fd) {
    sendto_opmask_butone(0, SNO_OLDSNO, "IAuth reconnect unable to allocate socket: %s", strerror(errno));
    return;
  }
  if (feature_bool(FEAT_VIRTUAL_HOST)
      && bind(fd, (struct sockaddr*)&VirtualHost, sizeof(VirtualHost)) != 0) {
    close(fd);
    sendto_opmask_butone(0, SNO_OLDSNO, "IAuth reconnect unable to bind vhost: %s", strerror(errno));
    return;
  }
  if (!os_set_sockbufs(fd, SERVER_TCP_WINDOW, SERVER_TCP_WINDOW)) {
    close(fd);
    sendto_opmask_butone(0, SNO_OLDSNO, "IAuth reconnect unable to set socket buffers: %s", strerror(errno));
    return;
  }
  if (!os_set_nonblocking(fd)) {
    close(fd);
    sendto_opmask_butone(0, SNO_OLDSNO, "IAuth reconnect unable to make socket non-blocking: %s", strerror(errno));
    return;
  }
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = i_addr(iauth);
  sin.sin_port = htons(i_port(iauth));
  result = os_connect_nonb(fd, &sin);
  if (result == IO_FAILURE) {
    close(fd);
    sendto_opmask_butone(0, SNO_OLDSNO, "IAuth reconnect unable to initiate connection: %s", strerror(errno));
    return;
  }
  if (!socket_add(&i_socket(iauth), iauth_sock_callback, iauth,
                  (result == IO_SUCCESS) ? SS_CONNECTED : SS_CONNECTING,
                  SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE, fd)) {
    close(fd);
    sendto_opmask_butone(0, SNO_OLDSNO, "IAuth reconnect unable to add socket: %s", strerror(errno));
    return;
  }
}

static void iauth_read(struct IAuth *iauth)
{
  char *src, *endp, *old_buffer, *argv[MAXPARA + 1];
  unsigned int length, argc, ii;
  char readbuf[SERVER_TCP_WINDOW];

  length = 0;
  if (IO_FAILURE == os_recv_nonb(s_fd(&i_socket(iauth)), readbuf, sizeof(readbuf), &length))
    return;
  i_recvB(iauth) += length;
  if (i_recvB(iauth) > 1023) {
    i_recvK(iauth) += i_recvB(iauth) >> 10;
    i_recvB(iauth) &= 1023;
  }
  old_buffer = i_buffer(iauth);
  endp = old_buffer + i_count(iauth);
  for (src = readbuf; length > 0; --length) {
    *endp = *src++;
    if (IsEol(*endp)) {
      /* Skip blank lines. */
      if (endp == old_buffer)
        continue;
      /* NUL-terminate line and split parameters. */
      *endp = '\0';
      for (argc = 0, endp = old_buffer; *endp && (argc < MAXPARA); ) {
        while (*endp == ' ')
          *endp++ = '\0';
        if (*endp == '\0')
          break;
        if (*endp == ':')
        {
          argv[argc++] = endp + 1;
          break;
        }
        argv[argc++] = endp;
        for (; *endp && *endp != ' '; ++endp) ;
      }
      argv[argc] = NULL;
      /* Count line and reset endp to start of buffer. */
      i_recvM(iauth)++;
      endp = old_buffer;
      /* Look up command and try to dispatch. */
      if (argc > 0) {
        for (ii = 0; iauth_cmdtab[ii].iac_name; ++ii) {
          if (!ircd_strcmp(iauth_cmdtab[ii].iac_name, argv[0])) {
            iauth_cmdtab[ii].iac_func(iauth, argc, argv);
            if (i_GetAbort(iauth))
              iauth_disconnect(iauth);
            break;
          }
        }
      }
    }
    else if (endp < old_buffer + BUFSIZE)
      endp++;
  }
  i_count(iauth) = endp - old_buffer;
}

static void iauth_write(struct IAuth *iauth)
{
  unsigned int bytes_tried, bytes_sent;
  IOResult iores;

  if (i_GetBlocked(iauth))
    return;
  while (MsgQLength(&i_sendQ(iauth)) > 0) {
    iores = os_sendv_nonb(s_fd(&i_socket(iauth)), &i_sendQ(iauth), &bytes_tried, &bytes_sent);
    switch (iores) {
    case IO_SUCCESS:
      msgq_delete(&i_sendQ(iauth), bytes_sent);
      i_sendB(iauth) += bytes_sent;
      if (i_sendB(iauth) > 1023) {
        i_sendK(iauth) += i_sendB(iauth) >> 10;
        i_sendB(iauth) &= 1023;
      }
      if (bytes_tried == bytes_sent)
        break;
      /* If bytes_sent < bytes_tried, fall through to IO_BLOCKED. */
    case IO_BLOCKED:
      i_SetBlocked(iauth);
      socket_events(&i_socket(iauth), SOCK_ACTION_ADD | SOCK_EVENT_WRITABLE);
      return;
    case IO_FAILURE:
      iauth_disconnect(iauth);
      return;
    }
  }
  /* We were able to flush all events, so remove notification. */
  socket_events(&i_socket(iauth), SOCK_ACTION_DEL | SOCK_EVENT_WRITABLE);
}

static void iauth_sock_callback(struct Event *ev)
{
  struct IAuth *iauth;

  assert(0 != ev_socket(ev));
  iauth = (struct IAuth*) s_data(ev_socket(ev));
  assert(0 != iauth);

  switch (ev_type(ev)) {
  case ET_CONNECT:
    socket_state(ev_socket(ev), SS_CONNECTED);
    iauth_on_connect(iauth);
    break;
  case ET_DESTROY:
    if (!i_GetClosing(iauth))
      iauth_schedule_reconnect(iauth);
    break;
  case ET_READ:
    iauth_read(iauth);
    break;
  case ET_WRITE:
    i_ClrBlocked(iauth);
    iauth_write(iauth);
    break;
  case ET_EOF:
    iauth_disconnect(iauth);
    break;
  case ET_ERROR:
    sendto_opmask_butone(0, SNO_OLDSNO, "IAuth socket error: %s", strerror(ev_data(ev)));
    log_write(LS_SOCKET, L_ERROR, 0, "IAuth socket error: %s", strerror(ev_data(ev)));
    iauth_disconnect(iauth);
    break;
  default:
    assert(0 && "Unrecognized event type");
    break;
  }
}

/* Functions related to IAuthRequest structs */

static void iauth_request_ev(struct Event *ev)
{
  /* TODO: this could probably be more intelligent */
  if (ev_type(ev) == ET_EXPIRE) {
    sendto_opmask_butone(0, SNO_OLDSNO, "IAuth request timed out; reconnecting");
    iauth_reconnect(t_data(ev_timer(ev)));
  }
}

static void iauth_send_request(struct IAuth *iauth, struct IAuthRequest *iar)
{
  struct Client *client;

  /* If iauth is not connected, we must defer the request. */
  if (!i_GetConnected(iauth))
    return;

  /* If no timed request, set up expiration timer. */
  if (!t_active(&i_request_timer(iauth))) {
    struct Timer *timer = timer_init(&i_request_timer(iauth));
    timer_add(timer, iauth_request_ev, iauth, TT_RELATIVE, i_timeout(iauth));
    iar->iar_timed = 1;
  } else
    iar->iar_timed = 0;

  /* Send the FullAuth request. */
  client = iar->iar_client;
  assert(iar->iar_client != NULL);
  iauth_send(iauth, "FullAuth %x %s %s %s %s %s :%s",
             client, cli_name(client), cli_username(client),
             cli_user(client)->host, cli_sock_ip(client),
             cli_passwd(client), cli_info(client));

  /* Write to the socket if we can. */
  iauth_write(iauth);
}

int iauth_start_client(struct IAuth *iauth, struct Client *cptr)
{
  struct IAuthRequest *iar;

  /* Allocate and initialize IAuthRequest struct. */
  if (!(iar = MyCalloc(1, sizeof(*iar))))
    return exit_client(cptr, cptr, &me, "IAuth memory allocation failed");
  iar->iar_next = &i_list_head(iauth);
  iar->iar_prev = i_list_head(iauth).iar_prev;
  iar->iar_client = cptr;
  iar->iar_prev->iar_next = iar;
  iar->iar_next->iar_prev = iar;

  /* Send request. */
  iauth_send_request(iauth, iar);

  return 0;
}

void iauth_exit_client(struct Client *cptr)
{
  if (cli_iauth(cptr)) {
    iauth_dispose_request(iauth_active, cli_iauth(cptr));
    cli_iauth(cptr) = NULL;
  } else if (IsIAuthed(cptr) && i_GetIClass(iauth_active)) {
    /* TODO: report quit to iauth */
  }
}

static struct IAuthRequest *iauth_find_request(struct IAuth *iauth, char *id)
{
  struct IAuthRequest *curr;
  struct Client *target;
  target = (struct Client*)strtoul(id, NULL, 16);
  for (curr = i_list_head(iauth).iar_next;
       curr != &i_list_head(iauth);
       curr = curr->iar_next) {
    assert(curr->iar_client != NULL);
    if (target == curr->iar_client)
      return curr;
  }
  return NULL;
}

static void iauth_dispose_request(struct IAuth *iauth, struct IAuthRequest *iar)
{
  assert(iar->iar_client != NULL);
  if (iar->iar_timed)
    timer_del(&i_request_timer(iauth));
  cli_iauth(iar->iar_client) = NULL;
  iar->iar_prev->iar_next = iar->iar_next;
  iar->iar_next->iar_prev = iar->iar_prev;
  MyFree(iar);
}

static void iauth_cmd_doneauth(struct IAuth *iauth, int argc, char *argv[])
{
  struct IAuthRequest *iar;
  struct Client *client;
  char *id;
  char *username;
  char *hostname;
  char *c_class;
  char *account;

  if (argc < 5) {
    iauth_protocol_violation(iauth, "Only %d parameters for DoneAuth (expected >=5)", argc);
    return;
  }
  id = argv[1];
  username = argv[2];
  hostname = argv[3];
  c_class = argv[4];
  account = (argc > 5) ? argv[5] : 0;
  iar = iauth_find_request(iauth, id);
  if (!iar) {
    iauth_protocol_violation(iauth, "Got unexpected DoneAuth for id %s", id);
    return;
  }
  client = iar->iar_client;
  ircd_strncpy(cli_username(client), username, USERLEN);
  ircd_strncpy(cli_user(client)->host, hostname, HOSTLEN);
  if (account) {
    ircd_strncpy(cli_user(client)->account, account, ACCOUNTLEN);
    SetAccount(client);
  }
  SetIAuthed(client);
  iauth_dispose_request(iauth, iar);
  register_user(client, client, cli_name(client), username);
}

static void iauth_cmd_badauth(struct IAuth *iauth, int argc, char *argv[])
{
  struct IAuthRequest *iar;
  struct Client *client;
  char *id;
  char *reason;

  if (argc < 3) {
    iauth_protocol_violation(iauth, "Only %d parameters for BadAuth (expected >=3)", argc);
    return;
  }
  id = argv[1];
  reason = argv[2];
  if (EmptyString(reason)) {
    iauth_protocol_violation(iauth, "Empty BadAuth reason for id %s", id);
    return;
  }
  iar = iauth_find_request(iauth, id);
  if (!iar) {
    iauth_protocol_violation(iauth, "Got unexpected BadAuth for id %s", id);
    return;
  }
  client = iar->iar_client;
  iauth_dispose_request(iauth, iar);
  exit_client(client, client, &me, reason);
}

static const struct IAuthCmd iauth_cmdtab[] = {
  { "DoneAuth", iauth_cmd_doneauth },
  { "BadAuth", iauth_cmd_badauth },
  { NULL, NULL }
};
