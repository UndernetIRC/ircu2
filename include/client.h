/*
 * IRC - Internet Relay Chat, include/client.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
 *
 * $Id$
 */
#ifndef INCLUDED_client_h
#define INCLUDED_client_h
#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"
#endif
#ifndef INCLUDED_config_h
#include "config.h"
#endif
#ifndef INCLUDED_dbuf_h
#include "dbuf.h"
#endif
#ifndef INCLUDED_msgq_h
#include "msgq.h"
#endif
#ifndef INCLUDED_ircd_handler_h
#include "ircd_handler.h"
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>          /* time_t, size_t */
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_netinet_in_h
#include <netinet/in.h>         /* in_addr */
#define INCLUDED_netinet_in_h
#endif

struct ConfItem;
struct Listener;
struct ListingArgs;
struct SLink;
struct Server;
struct User;
struct Whowas;
struct DNSReply;
struct hostent;

/*-----------------------------------------------------------------------------
 * Macros
 */
#define CLIENT_LOCAL_SIZE sizeof(struct Client)
#define CLIENT_REMOTE_SIZE offsetof(struct Client, count)

/*
 * Structures
 *
 * Only put structures here that are being used in a very large number of
 * source files. Other structures go in the header file of there corresponding
 * source file, or in the source file itself (when only used in that file).
 */

struct Client {
  struct Client* next;          /* link in GlobalClientList */
  struct Client* prev;          /* link in GlobalClientList */
  struct Client* hnext;         /* link in hash table bucket or this */
  struct Client* from;          /* == self, if Local Client, *NEVER* NULL! */
  struct User*   user;          /* ...defined, if this is a User */
  struct Server* serv;          /* ...defined, if this is a server */
  struct Whowas* whowas;        /* Pointer to ww struct to be freed on quit */
  char           yxx[4];        /* Numeric Nick: YMM if this is a server,
                                   XX0 if this is a user */
  /*
   * XXX - move these to local part for next release
   * (lasttime, since)
   */
  time_t         lasttime;      /* last time data read from socket */
  time_t         since;         /* last time we parsed something, flood control */

  time_t         firsttime;     /* time client was created */
  time_t         lastnick;      /* TimeStamp on nick */
  int            marker;        /* /who processing marker */
  unsigned int   flags;         /* client flags */
  unsigned int   hopcount;      /* number of servers to this 0 = local */
  struct in_addr ip;            /* Real ip# NOT defined for remote servers! */
  short          status;        /* Client type */
  unsigned char  local;         /* local or remote client */
  char name[HOSTLEN + 1];       /* Unique name of the client, nick or host */
  char username[USERLEN + 1];   /* username here now for auth stuff */
  char info[REALLEN + 1];       /* Free form additional client information */
  /*
   *  The following fields are allocated only for local clients
   *  (directly connected to *this* server with a socket.
   *  The first of them *MUST* be the "count"--it is the field
   *  to which the allocation is tied to! *Never* refer to
   *  these fields, if (from != self).
   */
  unsigned int count;            /* Amount of data in buffer, DON'T PUT
                                    variables ABOVE this one! */
  int                 fd;        /* >= 0, for local clients */
  int                 error;     /* last socket level error for client */
  unsigned int        snomask;   /* mask for server messages */
  time_t              nextnick;  /* Next time a nick change is allowed */
  time_t              nexttarget; /* Next time a target change is allowed */
  unsigned int        cookie;    /* Random number the user must PONG */
  struct MsgQ         sendQ;     /* Outgoing message queue--if socket full */
  struct DBuf         recvQ;     /* Hold for data incoming yet to be parsed */
  unsigned int        sendM;     /* Statistics: protocol messages send */
  unsigned int        sendK;     /* Statistics: total k-bytes send */
  unsigned int        receiveM;  /* Statistics: protocol messages received */
  unsigned int        receiveK;  /* Statistics: total k-bytes received */
  unsigned short      sendB;     /* counters to count upto 1-k lots of bytes */
  unsigned short      receiveB;  /* sent and received. */
  struct Listener*    listener;  /* listening client which we accepted from */
  struct SLink*       confs;     /* Configuration record associated */
  HandlerType         handler;   /* message index into command table for parsing */
  struct DNSReply*    dns_reply; /* DNS reply used during client registration */
  struct ListingArgs* listing;
  unsigned int        max_sendq; /* cached max send queue for client */
  unsigned int        ping_freq; /* cached ping freq from client conf class */
  unsigned short      lastsq;    /* # 2k blocks when sendqueued called last */
  unsigned short      port;      /* and the remote port# too :-) */
  unsigned char       targets[MAXTARGETS]; /* Hash values of current targets */
  char sock_ip[SOCKIPLEN + 1];  /* this is the ip address as a string */
  char sockhost[HOSTLEN + 1];   /* This is the host name from the socket and
                                   after which the connection was accepted. */
  char passwd[PASSWDLEN + 1];
  char buffer[BUFSIZE];         /* Incoming message buffer; or the error that
                                   caused this clients socket to be `dead' */
};

#define cli_next(cli)		((cli)->next)
#define cli_prev(cli)		((cli)->prev)
#define cli_hnext(cli)		((cli)->hnext)
#define cli_from(cli)		((cli)->from)
#define cli_user(cli)		((cli)->user)
#define cli_serv(cli)		((cli)->serv)
#define cli_whowas(cli)		((cli)->whowas)
#define cli_yxx(cli)		((cli)->yxx)
#define cli_lasttime(cli)	((cli)->lasttime)
#define cli_since(cli)		((cli)->since)
#define cli_firsttime(cli)	((cli)->firsttime)
#define cli_lastnick(cli)	((cli)->lastnick)
#define cli_marker(cli)		((cli)->marker)
#define cli_flags(cli)		((cli)->flags)
#define cli_hopcount(cli)	((cli)->hopcount)
#define cli_ip(cli)		((cli)->ip)
#define cli_status(cli)		((cli)->status)
#define cli_local(cli)		((cli)->local)
#define cli_name(cli)		((cli)->name)
#define cli_username(cli)	((cli)->username)
#define cli_info(cli)		((cli)->info)

#define cli_count(cli)		((cli)->count)
#define cli_fd(cli)		((cli)->fd)
#define cli_error(cli)		((cli)->error)
#define cli_snomask(cli)	((cli)->snomask)
#define cli_nextnick(cli)	((cli)->nextnick)
#define cli_nexttarget(cli)	((cli)->nexttarget)
#define cli_cookie(cli)		((cli)->cookie)
#define cli_sendQ(cli)		((cli)->sendQ)
#define cli_recvQ(cli)		((cli)->recvQ)
#define cli_sendM(cli)		((cli)->sendM)
#define cli_sendK(cli)		((cli)->sendK)
#define cli_receiveM(cli)	((cli)->receiveM)
#define cli_receiveK(cli)	((cli)->receiveK)
#define cli_sendB(cli)		((cli)->sendB)
#define cli_receiveB(cli)	((cli)->receiveB)
#define cli_listener(cli)	((cli)->listener)
#define cli_confs(cli)		((cli)->confs)
#define cli_handler(cli)	((cli)->handler)
#define cli_dns_reply(cli)	((cli)->dns_reply)
#define cli_listing(cli)	((cli)->listing)
#define cli_max_sendq(cli)	((cli)->max_sendq)
#define cli_ping_freq(cli)	((cli)->ping_freq)
#define cli_lastsq(cli)		((cli)->lastsq)
#define cli_port(cli)		((cli)->port)
#define cli_targets(cli)	((cli)->targets)
#define cli_sock_ip(cli)	((cli)->sock_ip)
#define cli_sockhost(cli)	((cli)->sockhost)
#define cli_passwd(cli)		((cli)->passwd)
#define cli_buffer(cli)		((cli)->buffer)

#define STAT_CONNECTING         0x001 /* connecting to another server */
#define STAT_HANDSHAKE          0x002 /* pass - server sent */
#define STAT_ME                 0x004 /* this server */
#define STAT_UNKNOWN            0x008 /* unidentified connection */
#define STAT_UNKNOWN_USER       0x010 /* Connect to client port */
#define STAT_UNKNOWN_SERVER     0x020 /* Connect to server port */
#define STAT_SERVER             0x040
#define STAT_USER               0x080

/*
 * status macros.
 */
#define IsRegistered(x)         (cli_status(x) & (STAT_SERVER | STAT_USER))
#define IsConnecting(x)         (cli_status(x) == STAT_CONNECTING)
#define IsHandshake(x)          (cli_status(x) == STAT_HANDSHAKE)
#define IsMe(x)                 (cli_status(x) == STAT_ME)
#define IsUnknown(x)            (cli_status(x) & \
        (STAT_UNKNOWN | STAT_UNKNOWN_USER | STAT_UNKNOWN_SERVER))

#define IsServerPort(x)         (cli_status(x) == STAT_UNKNOWN_SERVER )
#define IsUserPort(x)           (cli_status(x) == STAT_UNKNOWN_USER )
#define IsClient(x)             (cli_status(x) & \
        (STAT_HANDSHAKE | STAT_ME | STAT_UNKNOWN |\
         STAT_UNKNOWN_USER | STAT_UNKNOWN_SERVER | STAT_SERVER | STAT_USER))

#define IsTrusted(x)            (cli_status(x) & \
        (STAT_CONNECTING | STAT_HANDSHAKE | STAT_ME | STAT_SERVER))

#define IsServer(x)             (cli_status(x) == STAT_SERVER)
#define IsUser(x)               (cli_status(x) == STAT_USER)


#define SetConnecting(x)        (cli_status(x) = STAT_CONNECTING)
#define SetHandshake(x)         (cli_status(x) = STAT_HANDSHAKE)
#define SetServer(x)            (cli_status(x) = STAT_SERVER)
#define SetMe(x)                (cli_status(x) = STAT_ME)
#define SetUser(x)              (cli_status(x) = STAT_USER)

#define MyConnect(x)    (cli_from(x) == (x))
#define MyUser(x)       (MyConnect(x) && IsUser(x))
#define MyOper(x)       (MyConnect(x) && IsOper(x))
#define Protocol(x)     ((cli_serv(x))->prot)

#define PARSE_AS_SERVER(x) (cli_status(x) & \
            (STAT_SERVER | STAT_CONNECTING | STAT_HANDSHAKE))

/*
 * FLAGS macros
 */
#define FLAGS_PINGSENT   0x0001 /* Unreplied ping sent */
#define FLAGS_DEADSOCKET 0x0002 /* Local socket is dead--Exiting soon */
#define FLAGS_KILLED     0x0004 /* Prevents "QUIT" from being sent for this */
#define FLAGS_OPER       0x0008 /* Operator */
#define FLAGS_LOCOP      0x0010 /* Local operator -- SRB */
#define FLAGS_INVISIBLE  0x0020 /* makes user invisible */
#define FLAGS_WALLOP     0x0040 /* send wallops to them */
#define FLAGS_SERVNOTICE 0x0080 /* server notices such as kill */
#define FLAGS_BLOCKED    0x0100 /* socket is in a blocked condition */
#define FLAGS_CLOSING    0x0400 /* set when closing to suppress errors */
#define FLAGS_UPING      0x0800 /* has active UDP ping request */
#define FLAGS_CHKACCESS  0x1000 /* ok to check clients access if set */
#define FLAGS_LOCAL     0x00010000      /* set for local clients */
#define FLAGS_GOTID     0x00020000      /* successful ident lookup achieved */
#define FLAGS_DOID      0x00040000      /* I-lines say must use ident return */
#define FLAGS_NONL      0x00080000      /* No \n in buffer */
#define FLAGS_TS8       0x00100000      /* Why do you want to know? */
#define FLAGS_MAP       0x00800000      /* Show server on the map */
#define FLAGS_JUNCTION  0x01000000      /* Junction causing the net.burst */
#define FLAGS_DEAF      0x02000000      /* Makes user deaf */
#define FLAGS_CHSERV    0x04000000      /* Disallow KICK or MODE -o on the user;
                                           don't display channels in /whois */
#define FLAGS_BURST     0x08000000      /* Server is receiving a net.burst */
#define FLAGS_BURST_ACK 0x10000000      /* Server is waiting for eob ack */
#define FLAGS_DEBUG     0x20000000      /* send global debug/anti-hack info */
#define FLAGS_IPCHECK   0x40000000      /* Added or updated IPregistry data */

#define SEND_UMODES \
    (FLAGS_INVISIBLE|FLAGS_OPER|FLAGS_WALLOP|FLAGS_DEAF|FLAGS_CHSERV|FLAGS_DEBUG)
#define ALL_UMODES (SEND_UMODES|FLAGS_SERVNOTICE|FLAGS_LOCOP)
#define FLAGS_ID (FLAGS_DOID|FLAGS_GOTID)

/*
 * flags macros.
 */
#define DoAccess(x)             (cli_flags(x) & FLAGS_CHKACCESS)
#define IsAnOper(x)             (cli_flags(x) & (FLAGS_OPER|FLAGS_LOCOP))
#define IsBlocked(x)            (cli_flags(x) & FLAGS_BLOCKED)
#define IsBurst(x)              (cli_flags(x) & FLAGS_BURST)
#define IsBurstAck(x)           (cli_flags(x) & FLAGS_BURST_ACK)
#define IsBurstOrBurstAck(x)    (cli_flags(x) & (FLAGS_BURST|FLAGS_BURST_ACK))
#define IsChannelService(x)     (cli_flags(x) & FLAGS_CHSERV)
#define IsDead(x)               (cli_flags(x) & FLAGS_DEADSOCKET)
#define IsDeaf(x)               (cli_flags(x) & FLAGS_DEAF)
#define IsIPChecked(x)          (cli_flags(x) & FLAGS_IPCHECK)
#define IsIdented(x)            (cli_flags(x) & FLAGS_GOTID)
#define IsInvisible(x)          (cli_flags(x) & FLAGS_INVISIBLE)
#define IsJunction(x)           (cli_flags(x) & FLAGS_JUNCTION)
#define IsLocOp(x)              (cli_flags(x) & FLAGS_LOCOP)
#define IsLocal(x)              (cli_flags(x) & FLAGS_LOCAL)
#define IsOper(x)               (cli_flags(x) & FLAGS_OPER)
#define IsUPing(x)              (cli_flags(x) & FLAGS_UPING)
#define NoNewLine(x)            (cli_flags(x) & FLAGS_NONL)
#define SendDebug(x)            (cli_flags(x) & FLAGS_DEBUG)
#define SendServNotice(x)       (cli_flags(x) & FLAGS_SERVNOTICE)
#define SendWallops(x)          (cli_flags(x) & FLAGS_WALLOP)

#define IsPrivileged(x)         (IsAnOper(x) || IsServer(x))

#define SetAccess(x)            (cli_flags(x) |= FLAGS_CHKACCESS)
#define SetBurst(x)             (cli_flags(x) |= FLAGS_BURST)
#define SetBurstAck(x)          (cli_flags(x) |= FLAGS_BURST_ACK)
#define SetChannelService(x)    (cli_flags(x) |= FLAGS_CHSERV)
#define SetDeaf(x)              (cli_flags(x) |= FLAGS_DEAF)
#define SetDebug(x)             (cli_flags(x) |= FLAGS_DEBUG)
#define SetGotId(x)             (cli_flags(x) |= FLAGS_GOTID)
#define SetIPChecked(x)         (cli_flags(x) |= FLAGS_IPCHECK)
#define SetInvisible(x)         (cli_flags(x) |= FLAGS_INVISIBLE)
#define SetJunction(x)          (cli_flags(x) |= FLAGS_JUNCTION)
#define SetLocOp(x)             (cli_flags(x) |= FLAGS_LOCOP)
#define SetOper(x)              (cli_flags(x) |= FLAGS_OPER)
#define SetUPing(x)             (cli_flags(x) |= FLAGS_UPING)
#define SetWallops(x)           (cli_flags(x) |= FLAGS_WALLOP)

#define ClearAccess(x)          (cli_flags(x) &= ~FLAGS_CHKACCESS)
#define ClearBurst(x)           (cli_flags(x) &= ~FLAGS_BURST)
#define ClearBurstAck(x)        (cli_flags(x) &= ~FLAGS_BURST_ACK)
#define ClearChannelService(x)  (cli_flags(x) &= ~FLAGS_CHSERV)
#define ClearDeaf(x)            (cli_flags(x) &= ~FLAGS_DEAF)
#define ClearDebug(x)           (cli_flags(x) &= ~FLAGS_DEBUG)
#define ClearIPChecked(x)       (cli_flags(x) &= ~FLAGS_IPCHECK)
#define ClearInvisible(x)       (cli_flags(x) &= ~FLAGS_INVISIBLE)
#define ClearLocOp(x)           (cli_flags(x) &= ~FLAGS_LOCOP)
#define ClearOper(x)            (cli_flags(x) &= ~FLAGS_OPER)
#define ClearUPing(x)           (cli_flags(x) &= ~FLAGS_UPING)
#define ClearWallops(x)         (cli_flags(x) &= ~FLAGS_WALLOP)

/* server notice stuff */

#define SNO_ADD         1
#define SNO_DEL         2
#define SNO_SET         3
                                /* DON'T CHANGE THESE VALUES ! */
                                /* THE CLIENTS DEPEND ON IT  ! */
#define SNO_OLDSNO      0x1     /* unsorted old messages */
#define SNO_SERVKILL    0x2     /* server kills (nick collisions) */
#define SNO_OPERKILL    0x4     /* oper kills */
#define SNO_HACK2       0x8     /* desyncs */
#define SNO_HACK3       0x10    /* temporary desyncs */
#define SNO_UNAUTH      0x20    /* unauthorized connections */
#define SNO_TCPCOMMON   0x40    /* common TCP or socket errors */
#define SNO_TOOMANY     0x80    /* too many connections */
#define SNO_HACK4       0x100   /* Uworld actions on channels */
#define SNO_GLINE       0x200   /* glines */
#define SNO_NETWORK     0x400   /* net join/break, etc */
#define SNO_IPMISMATCH  0x800   /* IP mismatches */
#define SNO_THROTTLE    0x1000  /* host throttle add/remove notices */
#define SNO_OLDREALOP   0x2000  /* old oper-only messages */
#define SNO_CONNEXIT    0x4000  /* client connect/exit (ugh) */
#define SNO_DEBUG       0x8000  /* debugging messages (DEBUGMODE only) */

#ifdef DEBUGMODE
# define SNO_ALL        0xffff  /* Don't make it larger then significant,
                                 * that looks nicer */
#else
# define SNO_ALL        0x7fff
#endif

#define SNO_USER        (SNO_ALL & ~SNO_OPER)

#define SNO_DEFAULT (SNO_NETWORK|SNO_OPERKILL|SNO_GLINE)
#define SNO_OPERDEFAULT (SNO_DEFAULT|SNO_HACK2|SNO_HACK4|SNO_THROTTLE|SNO_OLDSNO)
#define SNO_OPER (SNO_CONNEXIT|SNO_OLDREALOP)
#define SNO_NOISY (SNO_SERVKILL|SNO_UNAUTH)

typedef enum ShowIPType {
  HIDE_IP,
  SHOW_IP,
  MASK_IP
} ShowIPType;

extern const char* get_client_name(const struct Client* sptr, int showip);
extern int client_get_ping(const struct Client* local_client);


#endif /* INCLUDED_client_h */

