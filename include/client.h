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
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>          /* time_t, size_t */
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_netinet_in_h
#include <netinet/in.h>         /* in_addr */
#define INCLUDED_netinet_in_h
#endif
#ifndef INCLUDED_dbuf_h
#include "dbuf.h"
#endif
#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"
#endif
#ifndef INCLUDED_ircd_handler_h
#include "ircd_handler.h"
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
  struct DBuf         sendQ;     /* Outgoing message queue--if socket full */
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
#define IsRegistered(x)         ((x)->status & (STAT_SERVER | STAT_USER))
#define IsConnecting(x)         ((x)->status == STAT_CONNECTING)
#define IsHandshake(x)          ((x)->status == STAT_HANDSHAKE)
#define IsMe(x)                 ((x)->status == STAT_ME)
#define IsUnknown(x)            ((x)->status & \
        (STAT_UNKNOWN | STAT_UNKNOWN_USER | STAT_UNKNOWN_SERVER))

#define IsServerPort(x)         ((x)->status == STAT_UNKNOWN_SERVER )
#define IsUserPort(x)           ((x)->status == STAT_UNKNOWN_USER )
#define IsClient(x)             ((x)->status & \
        (STAT_HANDSHAKE | STAT_ME | STAT_UNKNOWN |\
         STAT_UNKNOWN_USER | STAT_UNKNOWN_SERVER | STAT_SERVER | STAT_USER))

#define IsTrusted(x)            ((x)->status & \
        (STAT_CONNECTING | STAT_HANDSHAKE | STAT_ME | STAT_SERVER))

#define IsServer(x)             ((x)->status == STAT_SERVER)
#define IsUser(x)               ((x)->status == STAT_USER)


#define SetConnecting(x)        ((x)->status = STAT_CONNECTING)
#define SetHandshake(x)         ((x)->status = STAT_HANDSHAKE)
#define SetServer(x)            ((x)->status = STAT_SERVER)
#define SetMe(x)                ((x)->status = STAT_ME)
#define SetUser(x)              ((x)->status = STAT_USER)

#define MyConnect(x)    ((x)->from == (x))
#define MyUser(x)       (MyConnect(x) && IsUser(x))
#define MyOper(x)       (MyConnect(x) && IsOper(x))
#define Protocol(x)     ((x)->serv->prot)

#define PARSE_AS_SERVER(x) ((x)->status & \
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
#define DoAccess(x)             ((x)->flags & FLAGS_CHKACCESS)
#define IsAnOper(x)             ((x)->flags & (FLAGS_OPER|FLAGS_LOCOP))
#define IsBlocked(x)            ((x)->flags & FLAGS_BLOCKED)
#define IsBurst(x)              ((x)->flags & FLAGS_BURST)
#define IsBurstAck(x)           ((x)->flags & FLAGS_BURST_ACK)
#define IsBurstOrBurstAck(x)    ((x)->flags & (FLAGS_BURST|FLAGS_BURST_ACK))
#define IsChannelService(x)     ((x)->flags & FLAGS_CHSERV)
#define IsDead(x)               ((x)->flags & FLAGS_DEADSOCKET)
#define IsDeaf(x)               ((x)->flags & FLAGS_DEAF)
#define IsIPChecked(x)          ((x)->flags & FLAGS_IPCHECK)
#define IsIdented(x)            ((x)->flags & FLAGS_GOTID)
#define IsInvisible(x)          ((x)->flags & FLAGS_INVISIBLE)
#define IsJunction(x)           ((x)->flags & FLAGS_JUNCTION)
#define IsLocOp(x)              ((x)->flags & FLAGS_LOCOP)
#define IsLocal(x)              ((x)->flags & FLAGS_LOCAL)
#define IsOper(x)               ((x)->flags & FLAGS_OPER)
#define IsUPing(x)              ((x)->flags & FLAGS_UPING)
#define NoNewLine(x)            ((x)->flags & FLAGS_NONL)
#define SendDebug(x)            ((x)->flags & FLAGS_DEBUG)
#define SendServNotice(x)       ((x)->flags & FLAGS_SERVNOTICE)
#define SendWallops(x)          ((x)->flags & FLAGS_WALLOP)

#define IsPrivileged(x)         (IsAnOper(x) || IsServer(x))

#define SetAccess(x)            ((x)->flags |= FLAGS_CHKACCESS)
#define SetBurst(x)             ((x)->flags |= FLAGS_BURST)
#define SetBurstAck(x)          ((x)->flags |= FLAGS_BURST_ACK)
#define SetChannelService(x)    ((x)->flags |= FLAGS_CHSERV)
#define SetDeaf(x)              ((x)->flags |= FLAGS_DEAF)
#define SetDebug(x)             ((x)->flags |= FLAGS_DEBUG)
#define SetGotId(x)             ((x)->flags |= FLAGS_GOTID)
#define SetIPChecked(x)         ((x)->flags |= FLAGS_IPCHECK)
#define SetInvisible(x)         ((x)->flags |= FLAGS_INVISIBLE)
#define SetJunction(x)          ((x)->flags |= FLAGS_JUNCTION)
#define SetLocOp(x)             ((x)->flags |= FLAGS_LOCOP)
#define SetOper(x)              ((x)->flags |= FLAGS_OPER)
#define SetUPing(x)             ((x)->flags |= FLAGS_UPING)
#define SetWallops(x)           ((x)->flags |= FLAGS_WALLOP)

#define ClearAccess(x)          ((x)->flags &= ~FLAGS_CHKACCESS)
#define ClearBurst(x)           ((x)->flags &= ~FLAGS_BURST)
#define ClearBurstAck(x)        ((x)->flags &= ~FLAGS_BURST_ACK)
#define ClearChannelService(x)  ((x)->flags &= ~FLAGS_CHSERV)
#define ClearDeaf(x)            ((x)->flags &= ~FLAGS_DEAF)
#define ClearDebug(x)           ((x)->flags &= ~FLAGS_DEBUG)
#define ClearIPChecked(x)       ((x)->flags &= ~FLAGS_IPCHECK)
#define ClearInvisible(x)       ((x)->flags &= ~FLAGS_INVISIBLE)
#define ClearLocOp(x)           ((x)->flags &= ~FLAGS_LOCOP)
#define ClearOper(x)            ((x)->flags &= ~FLAGS_OPER)
#define ClearUPing(x)           ((x)->flags &= ~FLAGS_UPING)
#define ClearWallops(x)         ((x)->flags &= ~FLAGS_WALLOP)

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

#define SNO_ALL         0x7fff  /* Don't make it larger then significant,
                                 * that looks nicer */

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


#endif /* INCLUDED_client_h */

