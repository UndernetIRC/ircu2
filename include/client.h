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
#ifndef INCLUDED_ircd_events_h
#include "ircd_events.h"
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
struct AuthRequest;

/*
 * Structures
 *
 * Only put structures here that are being used in a very large number of
 * source files. Other structures go in the header file of there corresponding
 * source file, or in the source file itself (when only used in that file).
 */

enum Priv {
  PRIV_CHAN_LIMIT,	/* no channel limit on oper */
  PRIV_MODE_LCHAN,	/* oper can mode local chans */
  PRIV_WALK_LCHAN,	/* oper can walk thru local modes */
  PRIV_DEOP_LCHAN,	/* no deop oper on local chans */
  PRIV_SHOW_INVIS,	/* show local invisible users */
  PRIV_SHOW_ALL_INVIS,	/* show all invisible users */
  PRIV_UNLIMIT_QUERY,	/* unlimit who queries */

  PRIV_KILL,		/* oper can KILL */
  PRIV_LOCAL_KILL,	/* oper can local KILL */
  PRIV_REHASH,		/* oper can REHASH */
  PRIV_RESTART,		/* oper can RESTART */
  PRIV_DIE,		/* oper can DIE */
  PRIV_GLINE,		/* oper can GLINE */
  PRIV_LOCAL_GLINE,	/* oper can local GLINE */
  PRIV_JUPE,		/* oper can JUPE */
  PRIV_LOCAL_JUPE,	/* oper can local JUPE */
  PRIV_OPMODE,		/* oper can OP/CLEARMODE */
  PRIV_LOCAL_OPMODE,	/* oper can local OP/CLEARMODE */
  PRIV_SET,		/* oper can SET */
  PRIV_WHOX,		/* oper can use /who x */
  PRIV_BADCHAN,		/* oper can BADCHAN */
  PRIV_LOCAL_BADCHAN,	/* oper can local BADCHAN */
  PRIV_SEE_CHAN,	/* oper can see in secret chans */

  PRIV_PROPAGATE,	/* propagate oper status */
  PRIV_DISPLAY,		/* "Is an oper" displayed */
  PRIV_SEE_OPERS,	/* display hidden opers */

  PRIV_WIDE_GLINE,	/* oper can set wider G-lines */

  PRIV_FORCE_OPMODE,	/* oper can override a Q-line */
  PRIV_FORCE_LOCAL_OPMODE,/* oper can override a local channel Q-line */

  PRIV_LAST_PRIV	/* must be the same as the last priv */
};

#define _PRIV_NBITS		(8 * sizeof(unsigned long))

#define _PRIV_IDX(priv)		((priv) / _PRIV_NBITS)
#define _PRIV_BIT(priv)		(1 << ((priv) % _PRIV_NBITS))

struct Privs {
  unsigned long priv_mask[(PRIV_LAST_PRIV + _PRIV_NBITS - 1) / _PRIV_NBITS];
};

enum Flag {
    FLAG_PINGSENT,                  /* Unreplied ping sent */
    FLAG_DEADSOCKET,                /* Local socket is dead--Exiting soon */
    FLAG_KILLED,                    /* Prevents "QUIT" from being sent for this */
    FLAG_BLOCKED,                   /* socket is in a blocked condition */
    FLAG_CLOSING,                   /* set when closing to suppress errors */
    FLAG_UPING,                     /* has active UDP ping request */
    FLAG_CHKACCESS,                 /* ok to check clients access if set */
    FLAG_HUB,                       /* server is a hub */
    FLAG_SERVICE,                   /* server is a service */
    FLAG_LOCAL,                     /* set for local clients */
    FLAG_GOTID,                     /* successful ident lookup achieved */
    FLAG_DOID,                      /* I-lines say must use ident return */
    FLAG_NONL,                      /* No \n in buffer */
    FLAG_TS8,                       /* Why do you want to know? */
    FLAG_MAP,                       /* Show server on the map */
    FLAG_JUNCTION,                  /* Junction causing the net.burst */
    FLAG_BURST,                     /* Server is receiving a net.burst */
    FLAG_BURST_ACK,                 /* Server is waiting for eob ack */
    FLAG_IPCHECK,                   /* Added or updated IPregistry data */

    FLAG_LOCOP,                     /* Local operator -- SRB */
    FLAG_SERVNOTICE,                /* server notices such as kill */
    FLAG_OPER,                      /* Operator */
    FLAG_INVISIBLE,                 /* makes user invisible */
    FLAG_WALLOP,                    /* send wallops to them */
    FLAG_DEAF,                      /* Makes user deaf */
    FLAG_CHSERV,                    /* Disallow KICK or MODE -o on the user;
                                       don't display channels in /whois */
    FLAG_DEBUG,                     /* send global debug/anti-hack info */
    FLAG_ACCOUNT,                   /* account name has been set */
    FLAG_HIDDENHOST,                /* user's host is hidden */

    _FLAG_COUNT,
    FLAG_LOCAL_UMODES = FLAG_LOCOP, /* First local mode flag */
    FLAG_GLOBAL_UMODES = FLAG_OPER  /* First global mode flag */
};

struct Flags {
  unsigned long flag_bits[((_FLAG_COUNT + _PRIV_NBITS - 1) / _PRIV_NBITS)];
};

struct Connection {
  /*
   *  The following fields are allocated only for local clients
   *  (directly connected to *this* server with a socket.
   *  The first of them *MUST* be the "count"--it is the field
   *  to which the allocation is tied to! *Never* refer to
   *  these fields, if (from != self).
   */
  unsigned long       con_magic; /* magic number */
  struct Connection*  con_next;  /* Next connection with queued data */
  struct Connection** con_prev_p; /* What points to us */
  struct Client*      con_client; /* Client associated with connection */
  unsigned int        con_count; /* Amount of data in buffer */
  int                 con_fd;    /* >= 0, for local clients */
  int                 con_freeflag; /* indicates if connection can be freed */
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
  struct Socket       con_socket; /* socket descriptor for client */
  struct Timer        con_proc; /* process latent messages from client */
  struct AuthRequest* con_auth; /* auth request for client */
};

#define CONNECTION_MAGIC 0x12f955f3

struct Client {
  unsigned long  cli_magic;     /* magic number */
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
  struct Flags   cli_flags;     /* client flags */
  unsigned int   cli_hopcount;  /* number of servers to this 0 = local */
  struct in_addr cli_ip;        /* Real ip# NOT defined for remote servers! */
  short          cli_status;    /* Client type */
  unsigned char  cli_local;     /* local or remote client */
  struct Privs   cli_privs;     /* Oper privileges */
  char cli_name[HOSTLEN + 1];   /* Unique name of the client, nick or host */
  char cli_username[USERLEN + 1]; /* username here now for auth stuff */
  char cli_info[REALLEN + 1];   /* Free form additional client information */
};

#define CLIENT_MAGIC 0x4ca08286

#define cli_verify(cli)		((cli)->cli_magic == CLIENT_MAGIC)
#define cli_magic(cli)		((cli)->cli_magic)
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
#define cli_freeflag(cli)	((cli)->cli_connect->con_freeflag)
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
#define cli_socket(cli)		((cli)->cli_connect->con_socket)
#define cli_proc(cli)		((cli)->cli_connect->con_proc)
#define cli_auth(cli)		((cli)->cli_connect->con_auth)

#define con_verify(con)		((con)->con_magic == CONNECTION_MAGIC)
#define con_magic(con)		((con)->con_magic)
#define con_next(con)		((con)->con_next)
#define con_prev_p(con)		((con)->con_prev_p)
#define con_client(con)		((con)->con_client)
#define con_count(con)		((con)->con_count)
#define con_fd(con)		((con)->con_fd)
#define con_freeflag(con)	((con)->con_freeflag)
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
#define con_socket(con)		((con)->con_socket)
#define con_proc(con)		((con)->con_proc)
#define con_auth(con)		((con)->con_auth)

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
 * flags macros.
 */
#define FlagSet(fset, flag)     ((fset)->flag_bits[_PRIV_IDX(flag)] |= \
                                 _PRIV_BIT(flag))
#define FlagClr(fset, flag)     ((fset)->flag_bits[_PRIV_IDX(flag)] &= \
                                 ~(_PRIV_BIT(flag)))
#define FlagHas(fset, flag)     ((fset)->flag_bits[_PRIV_IDX(flag)] & \
                                 _PRIV_BIT(flag))
#define SetFlag(cli, flag)      FlagSet(&cli_flags(cli), flag)
#define ClrFlag(cli, flag)      FlagClr(&cli_flags(cli), flag)
#define HasFlag(cli, flag)      FlagHas(&cli_flags(cli), flag)

#define DoAccess(x)             HasFlag(x, FLAG_CHKACCESS)
#define IsAnOper(x)             (HasFlag(x, FLAG_OPER) || HasFlag(x, FLAG_LOCOP))
#define IsBlocked(x)            HasFlag(x, FLAG_BLOCKED)
#define IsBurst(x)              HasFlag(x, FLAG_BURST)
#define IsBurstAck(x)           HasFlag(x, FLAG_BURST_ACK)
#define IsBurstOrBurstAck(x)    (HasFlag(x, FLAG_BURST) || HasFlag(x, FLAG_BURST_ACK))
#define IsChannelService(x)     HasFlag(x, FLAG_CHSERV)
#define IsDead(x)               HasFlag(x, FLAG_DEADSOCKET)
#define IsDeaf(x)               HasFlag(x, FLAG_DEAF)
#define IsIPChecked(x)          HasFlag(x, FLAG_IPCHECK)
#define IsIdented(x)            HasFlag(x, FLAG_GOTID)
#define IsInvisible(x)          HasFlag(x, FLAG_INVISIBLE)
#define IsJunction(x)           HasFlag(x, FLAG_JUNCTION)
#define IsLocOp(x)              HasFlag(x, FLAG_LOCOP)
#define IsLocal(x)              HasFlag(x, FLAG_LOCAL)
#define IsOper(x)               HasFlag(x, FLAG_OPER)
#define IsUPing(x)              HasFlag(x, FLAG_UPING)
#define NoNewLine(x)            HasFlag(x, FLAG_NONL)
#define SendDebug(x)            HasFlag(x, FLAG_DEBUG)
#define SendServNotice(x)       HasFlag(x, FLAG_SERVNOTICE)
#define SendWallops(x)          HasFlag(x, FLAG_WALLOP)
#define IsHub(x)                HasFlag(x, FLAG_HUB)
#define IsService(x)            HasFlag(x, FLAG_SERVICE)
#define IsAccount(x)            HasFlag(x, FLAG_ACCOUNT)
#define IsHiddenHost(x)		HasFlag(x, FLAG_HIDDENHOST)
#define HasHiddenHost(x)	(IsAccount(x) && IsHiddenHost(x))

#define IsPrivileged(x)         (IsAnOper(x) || IsServer(x))

#define SetAccess(x)            SetFlag(x, FLAG_CHKACCESS)
#define SetBurst(x)             SetFlag(x, FLAG_BURST)
#define SetBurstAck(x)          SetFlag(x, FLAG_BURST_ACK)
#define SetChannelService(x)    SetFlag(x, FLAG_CHSERV)
#define SetDeaf(x)              SetFlag(x, FLAG_DEAF)
#define SetDebug(x)             SetFlag(x, FLAG_DEBUG)
#define SetGotId(x)             SetFlag(x, FLAG_GOTID)
#define SetIPChecked(x)         SetFlag(x, FLAG_IPCHECK)
#define SetInvisible(x)         SetFlag(x, FLAG_INVISIBLE)
#define SetJunction(x)          SetFlag(x, FLAG_JUNCTION)
#define SetLocOp(x)             SetFlag(x, FLAG_LOCOP)
#define SetOper(x)              SetFlag(x, FLAG_OPER)
#define SetUPing(x)             SetFlag(x, FLAG_UPING)
#define SetWallops(x)           SetFlag(x, FLAG_WALLOP)
#define SetServNotice(x)        SetFlag(x, FLAG_SERVNOTICE)
#define SetHub(x)               SetFlag(x, FLAG_HUB)
#define SetService(x)           SetFlag(x, FLAG_SERVICE)
#define SetAccount(x)           SetFlag(x, FLAG_ACCOUNT)
#define SetHiddenHost(x)	SetFlag(x, FLAG_HIDDENHOST)

#define ClearAccess(x)          ClrFlag(x, FLAG_CHKACCESS)
#define ClearBurst(x)           ClrFlag(x, FLAG_BURST)
#define ClearBurstAck(x)        ClrFlag(x, FLAG_BURST_ACK)
#define ClearChannelService(x)  ClrFlag(x, FLAG_CHSERV)
#define ClearDeaf(x)            ClrFlag(x, FLAG_DEAF)
#define ClearDebug(x)           ClrFlag(x, FLAG_DEBUG)
#define ClearIPChecked(x)       ClrFlag(x, FLAG_IPCHECK)
#define ClearInvisible(x)       ClrFlag(x, FLAG_INVISIBLE)
#define ClearLocOp(x)           ClrFlag(x, FLAG_LOCOP)
#define ClearOper(x)            ClrFlag(x, FLAG_OPER)
#define ClearUPing(x)           ClrFlag(x, FLAG_UPING)
#define ClearWallops(x)         ClrFlag(x, FLAG_WALLOP)
#define ClearServNotice(x)      ClrFlag(x, FLAG_SERVNOTICE)
#define ClearHiddenHost(x)	ClrFlag(x, FLAG_HIDDENHOST)

/* free flags */
#define FREEFLAG_SOCKET	0x0001	/* socket needs to be freed */
#define FREEFLAG_TIMER	0x0002	/* timer needs to be freed */

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
#define SNO_AUTO        0x8000  /* AUTO G-Lines */
#define SNO_DEBUG       0x10000  /* debugging messages (DEBUGMODE only) */

#ifdef DEBUGMODE
# define SNO_ALL        0x1ffff  /* Don't make it larger than significant,
                                 * that looks nicer */
#else
# define SNO_ALL        0xffff
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

