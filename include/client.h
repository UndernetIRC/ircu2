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
struct Privs;

/*
 * Structures
 *
 * Only put structures here that are being used in a very large number of
 * source files. Other structures go in the header file of there corresponding
 * source file, or in the source file itself (when only used in that file).
 */

#define PRIV_CHAN_LIMIT		 1 /* no channel limit on oper */
#define PRIV_MODE_LCHAN		 2 /* oper can mode local chans */
#define PRIV_WALK_LCHAN		 3 /* oper can walk thru local modes */
#define PRIV_DEOP_LCHAN		 4 /* no deop oper on local chans */
#define PRIV_SHOW_INVIS		 5 /* show local invisible users */
#define PRIV_SHOW_ALL_INVIS	 6 /* show all invisible users */
#define PRIV_UNLIMIT_QUERY	 7 /* unlimit who queries */

#define PRIV_KILL		 8 /* oper can KILL */
#define PRIV_LOCAL_KILL		 9 /* oper can local KILL */
#define PRIV_REHASH		10 /* oper can REHASH */
#define PRIV_RESTART		11 /* oper can RESTART */
#define PRIV_DIE		12 /* oper can DIE */
#define PRIV_GLINE		13 /* oper can GLINE */
#define PRIV_LOCAL_GLINE	14 /* oper can local GLINE */
#define PRIV_JUPE		15 /* oper can JUPE */
#define PRIV_LOCAL_JUPE		16 /* oper can local JUPE */
#define PRIV_OPMODE		17 /* oper can OP/CLEARMODE */
#define PRIV_LOCAL_OPMODE	18 /* oper can local OP/CLEARMODE */
#define PRIV_SET		19 /* oper can SET */
#define PRIV_WHOX		20 /* oper can use /who x */
#define PRIV_BADCHAN		21 /* oper can BADCHAN */
#define PRIV_LOCAL_BADCHAN	22 /* oper can local BADCHAN */
#define PRIV_SEE_CHAN		23 /* oper can see in secret chans */

#define PRIV_PROPAGATE		24 /* propagate oper status */
#define PRIV_DISPLAY		25 /* "Is an oper" displayed */
#define PRIV_SEE_OPERS		26 /* display hidden opers */

#define PRIV_LAST_PRIV		26 /* must be the same as the last priv */

#define _PRIV_NBITS		(8 * sizeof(unsigned long))

#define _PRIV_IDX(priv)		((priv) / _PRIV_NBITS)
#define _PRIV_BIT(priv)		(1 << ((priv) % _PRIV_NBITS))

struct Privs {
  unsigned long priv_mask[(PRIV_LAST_PRIV / _PRIV_NBITS) + 1];
};

struct Connection {
  /*
   *  The following fields are allocated only for local clients
   *  (directly connected to *this* server with a socket.
   *  The first of them *MUST* be the "count"--it is the field
   *  to which the allocation is tied to! *Never* refer to
   *  these fields, if (from != self).
   */
  struct Connection*  con_next;  /* Next connection with queued data */
  struct Connection** con_prev_p; /* What points to us */
  struct Client*      con_client; /* Client associated with connection */
  unsigned int        con_count; /* Amount of data in buffer */
  int                 con_fd;    /* >= 0, for local clients */
  int                 con_error; /* last socket level error for client */
  unsigned int        con_snomask; /* mask for server messages */
  time_t              con_nextnick; /* Next time a nick change is allowed */
  time_t              con_nexttarget;/* Next time a target change is allowed */
  unsigned int        con_cookie; /* Random number the user must PONG */
  struct MsgQ         con_sendQ; /* Outgoing message queue--if socket full */
  struct DBuf         con_recvQ; /* Hold for data incoming yet to be parsed */
  unsigned int        con_sendM; /* Statistics: protocol messages send */
  unsigned int        con_sendK; /* Statistics: total k-bytes send */
  unsigned int        con_receiveM;/* Statistics: protocol messages received */
  unsigned int        con_receiveK; /* Statistics: total k-bytes received */
  unsigned short      con_sendB; /* counters to count upto 1-k lots of bytes */
  unsigned short      con_receiveB; /* sent and received. */
  struct Listener*    con_listener; /* listening client which we accepted
				       from */
  struct SLink*       con_confs; /* Configuration record associated */
  HandlerType         con_handler; /* message index into command table
				      for parsing */
  struct DNSReply*    con_dns_reply; /* DNS reply used during client
					registration */
  struct ListingArgs* con_listing;
  unsigned int        con_max_sendq; /* cached max send queue for client */
  unsigned int        con_ping_freq; /* cached ping freq from client conf
					class */
  unsigned short      con_lastsq; /* # 2k blocks when sendqueued called last */
  unsigned short      con_port;  /* and the remote port# too :-) */
  unsigned char       con_targets[MAXTARGETS]; /* Hash values of current
						  targets */
  char con_sock_ip[SOCKIPLEN + 1]; /* this is the ip address as a string */
  char con_sockhost[HOSTLEN + 1]; /* This is the host name from the socket and
				    after which the connection was accepted. */
  char con_passwd[PASSWDLEN + 1];
  char con_buffer[BUFSIZE];     /* Incoming message buffer; or the error that
                                   caused this clients socket to be `dead' */
};

struct Client {
  struct Client* cli_next;      /* link in GlobalClientList */
  struct Client* cli_prev;      /* link in GlobalClientList */
  struct Client* cli_hnext;     /* link in hash table bucket or this */
  struct Connection* cli_connect; /* Connection structure associated with us */
  struct User*   cli_user;      /* ...defined, if this is a User */
  struct Server* cli_serv;      /* ...defined, if this is a server */
  struct Whowas* cli_whowas;    /* Pointer to ww struct to be freed on quit */
  char           cli_yxx[4];    /* Numeric Nick: YMM if this is a server,
                                   XX0 if this is a user */
  /*
   * XXX - move these to local part for next release
   * (lasttime, since)
   */
  time_t         cli_lasttime;  /* last time data read from socket */
  time_t         cli_since;     /* last time we parsed something, flood control */
				
  time_t         cli_firsttime; /* time client was created */
  time_t         cli_lastnick;  /* TimeStamp on nick */
  int            cli_marker;    /* /who processing marker */
  unsigned int   cli_flags;     /* client flags */
  unsigned int   cli_hopcount;  /* number of servers to this 0 = local */
  struct in_addr cli_ip;        /* Real ip# NOT defined for remote servers! */
  short          cli_status;    /* Client type */
  unsigned char  cli_local;     /* local or remote client */
  struct Privs   cli_privs;     /* Oper privileges */
  char cli_name[HOSTLEN + 1];   /* Unique name of the client, nick or host */
  char cli_username[USERLEN + 1]; /* username here now for auth stuff */
  char cli_info[REALLEN + 1];   /* Free form additional client information */
};

#define cli_next(cli)		((cli)->cli_next)
#define cli_prev(cli)		((cli)->cli_prev)
#define cli_hnext(cli)		((cli)->cli_hnext)
#define cli_connect(cli)	((cli)->cli_connect)
#define cli_from(cli)		((cli)->cli_connect->con_client)
#define cli_user(cli)		((cli)->cli_user)
#define cli_serv(cli)		((cli)->cli_serv)
#define cli_whowas(cli)		((cli)->cli_whowas)
#define cli_yxx(cli)		((cli)->cli_yxx)
#define cli_lasttime(cli)	((cli)->cli_lasttime)
#define cli_since(cli)		((cli)->cli_since)
#define cli_firsttime(cli)	((cli)->cli_firsttime)
#define cli_lastnick(cli)	((cli)->cli_lastnick)
#define cli_marker(cli)		((cli)->cli_marker)
#define cli_flags(cli)		((cli)->cli_flags)
#define cli_hopcount(cli)	((cli)->cli_hopcount)
#define cli_ip(cli)		((cli)->cli_ip)
#define cli_status(cli)		((cli)->cli_status)
#define cli_local(cli)		((cli)->cli_local)
#define cli_privs(cli)		((cli)->cli_privs)
#define cli_name(cli)		((cli)->cli_name)
#define cli_username(cli)	((cli)->cli_username)
#define cli_info(cli)		((cli)->cli_info)

#define cli_count(cli)		((cli)->cli_connect->con_count)
#define cli_fd(cli)		((cli)->cli_connect->con_fd)
#define cli_error(cli)		((cli)->cli_connect->con_error)
#define cli_snomask(cli)	((cli)->cli_connect->con_snomask)
#define cli_nextnick(cli)	((cli)->cli_connect->con_nextnick)
#define cli_nexttarget(cli)	((cli)->cli_connect->con_nexttarget)
#define cli_cookie(cli)		((cli)->cli_connect->con_cookie)
#define cli_sendQ(cli)		((cli)->cli_connect->con_sendQ)
#define cli_recvQ(cli)		((cli)->cli_connect->con_recvQ)
#define cli_sendM(cli)		((cli)->cli_connect->con_sendM)
#define cli_sendK(cli)		((cli)->cli_connect->con_sendK)
#define cli_receiveM(cli)	((cli)->cli_connect->con_receiveM)
#define cli_receiveK(cli)	((cli)->cli_connect->con_receiveK)
#define cli_sendB(cli)		((cli)->cli_connect->con_sendB)
#define cli_receiveB(cli)	((cli)->cli_connect->con_receiveB)
#define cli_listener(cli)	((cli)->cli_connect->con_listener)
#define cli_confs(cli)		((cli)->cli_connect->con_confs)
#define cli_handler(cli)	((cli)->cli_connect->con_handler)
#define cli_dns_reply(cli)	((cli)->cli_connect->con_dns_reply)
#define cli_listing(cli)	((cli)->cli_connect->con_listing)
#define cli_max_sendq(cli)	((cli)->cli_connect->con_max_sendq)
#define cli_ping_freq(cli)	((cli)->cli_connect->con_ping_freq)
#define cli_lastsq(cli)		((cli)->cli_connect->con_lastsq)
#define cli_port(cli)		((cli)->cli_connect->con_port)
#define cli_targets(cli)	((cli)->cli_connect->con_targets)
#define cli_sock_ip(cli)	((cli)->cli_connect->con_sock_ip)
#define cli_sockhost(cli)	((cli)->cli_connect->con_sockhost)
#define cli_passwd(cli)		((cli)->cli_connect->con_passwd)
#define cli_buffer(cli)		((cli)->cli_connect->con_buffer)

#define con_next(con)		((con)->con_next)
#define con_prev_p(con)		((con)->con_prev_p)
#define con_client(con)		((con)->con_client)
#define con_count(con)		((con)->con_count)
#define con_fd(con)		((con)->con_fd)
#define con_error(con)		((con)->con_error)
#define con_snomask(con)	((con)->con_snomask)
#define con_nextnick(con)	((con)->con_nextnick)
#define con_nexttarget(con)	((con)->con_nexttarget)
#define con_cookie(con)		((con)->con_cookie)
#define con_sendQ(con)		((con)->con_sendQ)
#define con_recvQ(con)		((con)->con_recvQ)
#define con_sendM(con)		((con)->con_sendM)
#define con_sendK(con)		((con)->con_sendK)
#define con_receiveM(con)	((con)->con_receiveM)
#define con_receiveK(con)	((con)->con_receiveK)
#define con_sendB(con)		((con)->con_sendB)
#define con_receiveB(con)	((con)->con_receiveB)
#define con_listener(con)	((con)->con_listener)
#define con_confs(con)		((con)->con_confs)
#define con_handler(con)	((con)->con_handler)
#define con_dns_reply(con)	((con)->con_dns_reply)
#define con_listing(con)	((con)->con_listing)
#define con_max_sendq(con)	((con)->con_max_sendq)
#define con_ping_freq(con)	((con)->con_ping_freq)
#define con_lastsq(con)		((con)->con_lastsq)
#define con_port(con)		((con)->con_port)
#define con_targets(con)	((con)->con_targets)
#define con_sock_ip(con)	((con)->con_sock_ip)
#define con_sockhost(con)	((con)->con_sockhost)
#define con_passwd(con)		((con)->con_passwd)
#define con_buffer(con)		((con)->con_buffer)

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
#define SetServNotice(x)        (cli_flags(x) |= FLAGS_SERVNOTICE)

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
#define ClearServNotice(x)      (cli_flags(x) &= ~FLAGS_SERVNOTICE)

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

#define PrivSet(pset, priv)	((pset)->priv_mask[_PRIV_IDX(priv)] |= \
				 _PRIV_BIT(priv))
#define PrivClr(pset, priv)	((pset)->priv_mask[_PRIV_IDX(priv)] &= \
				 ~(_PRIV_BIT(priv)))
#define PrivHas(pset, priv)	((pset)->priv_mask[_PRIV_IDX(priv)] & \
				 _PRIV_BIT(priv))

#define GrantPriv(cli, priv)	(PrivSet(&(cli_privs(cli)), priv))
#define RevokePriv(cli, priv)	(PrivClr(&(cli_privs(cli)), priv))
#define HasPriv(cli, priv)	(PrivHas(&(cli_privs(cli)), priv))

typedef enum ShowIPType {
  HIDE_IP,
  SHOW_IP,
  MASK_IP
} ShowIPType;

extern const char* get_client_name(const struct Client* sptr, int showip);
extern int client_get_ping(const struct Client* local_client);
extern void client_drop_sendq(struct Connection* con);
extern void client_add_sendq(struct Connection* con,
			     struct Connection** con_p);
extern void client_set_privs(struct Client* client);
extern int client_report_privs(struct Client* to, struct Client* client);

#endif /* INCLUDED_client_h */

