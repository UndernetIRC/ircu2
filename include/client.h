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
 */
/** @file
 * @brief Structures and functions for handling local clients.
 * @version $Id$
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
#ifndef INCLUDED_res_h
#include "res.h"
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>          /* time_t, size_t */
#define INCLUDED_sys_types_h
#endif

struct ConfItem;
struct Listener;
struct ListingArgs;
struct SLink;
struct Server;
struct User;
struct Whowas;
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

/** Single element in a flag bitset array. */
typedef unsigned long flagpage_t;

/** Number of bits in a flagpage_t. */
#define FLAGSET_NBITS (8 * sizeof(flagpage_t))
/** Element number for flag \a flag. */
#define FLAGSET_INDEX(flag) ((flag) / FLAGSET_NBITS)
/** Element bit for flag \a flag. */
#define FLAGSET_MASK(flag) (1ul<<((flag) % FLAGSET_NBITS))

/** Declare a flagset structure of a particular size. */
#define DECLARE_FLAGSET(name,max) \
  struct name \
  { \
    unsigned long bits[((max + FLAGSET_NBITS - 1) / FLAGSET_NBITS)]; \
  }

/** Test whether a flag is set in a flagset. */
#define FlagHas(set,flag) ((set)->bits[FLAGSET_INDEX(flag)] & FLAGSET_MASK(flag))
/** Set a flag in a flagset. */
#define FlagSet(set,flag) ((set)->bits[FLAGSET_INDEX(flag)] |= FLAGSET_MASK(flag))
/** Clear a flag in a flagset. */
#define FlagClr(set,flag) ((set)->bits[FLAGSET_INDEX(flag)] &= ~FLAGSET_MASK(flag))

/** String containing valid user modes, in no particular order. */
#define infousermodes "diOoswkgx"

/** Operator privileges. */
enum Priv
  {
    PRIV_CHAN_LIMIT, /**< no channel limit on oper */
    PRIV_MODE_LCHAN, /**< oper can mode local chans */
    PRIV_WALK_LCHAN, /**< oper can walk through local modes */
    PRIV_DEOP_LCHAN, /**< no deop oper on local chans */
    PRIV_SHOW_INVIS, /**< show local invisible users */
    PRIV_SHOW_ALL_INVIS, /**< show all invisible users */
    PRIV_UNLIMIT_QUERY, /**< unlimit who queries */
    PRIV_KILL, /**< oper can KILL */
    PRIV_LOCAL_KILL, /**< oper can local KILL */
    PRIV_REHASH, /**< oper can REHASH */
    PRIV_RESTART, /**< oper can RESTART */
    PRIV_DIE, /**< oper can DIE */
    PRIV_GLINE, /**< oper can GLINE */
    PRIV_LOCAL_GLINE, /**< oper can local GLINE */
    PRIV_JUPE, /**< oper can JUPE */
    PRIV_LOCAL_JUPE, /**< oper can local JUPE */
    PRIV_OPMODE, /**< oper can OP/CLEARMODE */
    PRIV_LOCAL_OPMODE, /**< oper can local OP/CLEARMODE */
    PRIV_SET,  /**< oper can SET */
    PRIV_WHOX, /**< oper can use /who x */
    PRIV_BADCHAN, /**< oper can BADCHAN */
    PRIV_LOCAL_BADCHAN, /**< oper can local BADCHAN */
    PRIV_SEE_CHAN, /**< oper can see in secret chans */
    PRIV_PROPAGATE, /**< propagate oper status */
    PRIV_DISPLAY, /**< "Is an oper" displayed */
    PRIV_SEE_OPERS, /**< display hidden opers */
    PRIV_WIDE_GLINE, /**< oper can set wider G-lines */
    PRIV_LIST_CHAN, /**< oper can list secret channels */
    PRIV_FORCE_OPMODE, /**< can hack modes on quarantined channels */
    PRIV_FORCE_LOCAL_OPMODE, /**< can hack modes on quarantined local channels */
    PRIV_APASS_OPMODE, /**< can hack modes +A/-A/+U/-U */
    PRIV_LAST_PRIV /**< number of privileges */
  };

/** Client flags and modes.
 * Note that flags at least FLAG_LOCAL_UMODES but less than
 * FLAG_GLOBAL_UMODES are treated as local modes, and flags at least
 * FLAG_GLOBAL_UMODES (but less than FLAG_LAST_FLAG) are treated as
 * global modes.
 */
enum Flag
  {
    FLAG_PINGSENT,                  /**< Unreplied ping sent */
    FLAG_DEADSOCKET,                /**< Local socket is dead--Exiting soon */
    FLAG_KILLED,                    /**< Prevents "QUIT" from being sent for this */
    FLAG_BLOCKED,                   /**< socket is in a blocked condition */
    FLAG_CLOSING,                   /**< set when closing to suppress errors */
    FLAG_UPING,                     /**< has active UDP ping request */
    FLAG_HUB,                       /**< server is a hub */
    FLAG_IPV6,                      /**< server understands P10 IPv6 addrs */
    FLAG_SERVICE,                   /**< server is a service */
    FLAG_GOTID,                     /**< successful ident lookup achieved */
    FLAG_NONL,                      /**< No \n in buffer */
    FLAG_TS8,                       /**< Why do you want to know? */
    FLAG_MAP,                       /**< Show server on the map */
    FLAG_JUNCTION,                  /**< Junction causing the net.burst. */
    FLAG_BURST,                     /**< Server is receiving a net.burst */
    FLAG_BURST_ACK,                 /**< Server is waiting for eob ack */
    FLAG_IPCHECK,                   /**< Added or updated IPregistry data */
    FLAG_IAUTH_STATS,               /**< Wanted IAuth statistics */
    FLAG_LOCOP,                     /**< Local operator -- SRB */
    FLAG_SERVNOTICE,                /**< server notices such as kill */
    FLAG_OPER,                      /**< Operator */
    FLAG_INVISIBLE,                 /**< makes user invisible */
    FLAG_WALLOP,                    /**< send wallops to them */
    FLAG_DEAF,                      /**< Makes user deaf */
    FLAG_CHSERV,                    /**< Disallow KICK or MODE -o on the user;
                                       don't display channels in /whois */
    FLAG_DEBUG,                     /**< send global debug/anti-hack info */
    FLAG_ACCOUNT,                   /**< account name has been set */
    FLAG_HIDDENHOST,                /**< user's host is hidden */
    FLAG_LAST_FLAG,                 /**< number of flags */
    FLAG_LOCAL_UMODES = FLAG_LOCOP, /**< First local mode flag */
    FLAG_GLOBAL_UMODES = FLAG_OPER  /**< First global mode flag */
  };

/** Declare flagset type for operator privileges. */
DECLARE_FLAGSET(Privs, PRIV_LAST_PRIV);
/** Declare flagset type for user flags. */
DECLARE_FLAGSET(Flags, FLAG_LAST_FLAG);

#include "capab.h" /* client capabilities */

/** Represents a local connection.
 * This contains a lot of stuff irrelevant to server connections, but
 * those are so rare as to not be worth special-casing.
 */
struct Connection
{
  unsigned long       con_magic;     /**< magic number */
  struct Connection*  con_next;      /**< Next connection with queued data */
  struct Connection** con_prev_p;    /**< What points to us */
  struct Client*      con_client;    /**< Client associated with connection */
  unsigned int        con_count;     /**< Amount of data in buffer */
  int                 con_freeflag;  /**< indicates if connection can be freed */
  int                 con_error;     /**< last socket level error for client */
  int                 con_sentalong; /**< sentalong marker for connection */
  unsigned int        con_snomask;   /**< mask for server messages */
  time_t              con_nextnick;  /**< Next time a nick change is allowed */
  time_t              con_nexttarget;/**< Next time a target change is allowed */
  time_t              con_lasttime;  /**< Last time data read from socket */
  time_t              con_since;     /**< Last time we accepted a command */
  struct MsgQ         con_sendQ;     /**< Outgoing message queue */
  struct DBuf         con_recvQ;     /**< Incoming data yet to be parsed */
  unsigned int        con_sendM;     /**< Stats: protocol messages sent */
  unsigned int        con_receiveM;  /**< Stats: protocol messages received */
  uint64_t            con_sendB;     /**< Bytes sent. */
  uint64_t            con_receiveB;  /**< Bytes received. */
  struct Listener*    con_listener;  /**< Listening socket which we accepted
                                        from. */
  struct SLink*       con_confs;     /**< Associated configuration records. */
  HandlerType         con_handler;   /**< Message index into command table
                                        for parsing. */
  struct ListingArgs* con_listing;   /**< Current LIST status. */
  unsigned int        con_max_sendq; /**< cached max send queue for client */
  unsigned int        con_ping_freq; /**< cached ping freq */
  unsigned short      con_lastsq;    /**< # 2k blocks when sendqueued
                                        called last. */
  unsigned char       con_targets[MAXTARGETS]; /**< Hash values of
						  current targets. */
  char con_sock_ip[SOCKIPLEN + 1];   /**< Remote IP address as a string. */
  char con_sockhost[HOSTLEN + 1];    /**< This is the host name from
                                        the socket and after which the
                                        connection was accepted. */
  char con_passwd[PASSWDLEN + 1];    /**< Password given by user. */
  char con_buffer[BUFSIZE];          /**< Incoming message buffer; or
                                        the error that caused this
                                        clients socket to close. */
  struct Socket       con_socket;    /**< socket descriptor for
                                      client */
  struct Timer        con_proc;      /**< process latent messages from
                                      client */
  struct Privs        con_privs;     /**< Oper privileges */
  struct CapSet       con_capab;     /**< Client capabilities (from us) */
  struct CapSet       con_active;    /**< Active capabilities (to us) */
  struct AuthRequest* con_auth;      /**< Auth request for client */
  const struct wline* con_wline;     /**< WebIRC authorization for client */
};

/** Magic constant to identify valid Connection structures. */
#define CONNECTION_MAGIC 0x12f955f3

/** Represents a client anywhere on the network. */
struct Client {
  unsigned long  cli_magic;       /**< magic number */
  struct Client* cli_next;        /**< link in GlobalClientList */
  struct Client* cli_prev;        /**< link in GlobalClientList */
  struct Client* cli_hnext;       /**< link in hash table bucket or this */
  struct Connection* cli_connect; /**< Connection structure associated with us */
  struct User*   cli_user;        /**< Defined if this client is a user */
  struct Server* cli_serv;        /**< Defined if this client is a server */
  struct Whowas* cli_whowas;      /**< Pointer to ww struct to be freed on quit */
  char           cli_yxx[4];      /**< Numeric Nick: YY if this is a
                                     server, XXX if this is a user */
  time_t         cli_firsttime;   /**< time client was created */
  time_t         cli_lastnick;    /**< TimeStamp on nick */
  int            cli_marker;      /**< /who processing marker */
  struct Flags   cli_flags;       /**< client flags */
  unsigned int   cli_hopcount;    /**< number of servers to this 0 = local */
  struct irc_in_addr cli_ip;      /**< Real IP of client */
  short          cli_status;      /**< Client type */
  char cli_name[HOSTLEN + 1];     /**< Unique name of the client, nick or host */
  char cli_username[USERLEN + 1]; /**< Username determined by ident lookup */
  char cli_info[REALLEN + 1];     /**< Free form additional client information */
};

/** Magic constant to identify valid Client structures. */
#define CLIENT_MAGIC 0x4ca08286

/** Verify that a client is valid. */
#define cli_verify(cli)		((cli)->cli_magic == CLIENT_MAGIC)
/** Get client's magic number. */
#define cli_magic(cli)		((cli)->cli_magic)
/** Get global next client. */
#define cli_next(cli)		((cli)->cli_next)
/** Get global previous client. */
#define cli_prev(cli)		((cli)->cli_prev)
/** Get next client in hash bucket chain. */
#define cli_hnext(cli)		((cli)->cli_hnext)
/** Get connection associated with client. */
#define cli_connect(cli)	((cli)->cli_connect)
/** Get local client that links us to \a cli. */
#define cli_from(cli)		con_client(cli_connect(cli))
/** Get User structure for client, if client is a user. */
#define cli_user(cli)		((cli)->cli_user)
/** Get Server structure for client, if client is a server. */
#define cli_serv(cli)		((cli)->cli_serv)
/** Get Whowas link for client. */
#define cli_whowas(cli)		((cli)->cli_whowas)
/** Get client numnick. */
#define cli_yxx(cli)		((cli)->cli_yxx)
/** Get time we last read data from the client socket. */
#define cli_lasttime(cli)	con_lasttime(cli_connect(cli))
/** Get time we last parsed something from the client. */
#define cli_since(cli)		con_since(cli_connect(cli))
/** Get time client was created. */
#define cli_firsttime(cli)	((cli)->cli_firsttime)
/** Get time client last changed nickname. */
#define cli_lastnick(cli)	((cli)->cli_lastnick)
/** Get WHO marker for client. */
#define cli_marker(cli)		((cli)->cli_marker)
/** Get flags flagset for client. */
#define cli_flags(cli)		((cli)->cli_flags)
/** Get hop count to client. */
#define cli_hopcount(cli)	((cli)->cli_hopcount)
/** Get client IP address. */
#define cli_ip(cli)		((cli)->cli_ip)
/** Get status bitmask for client. */
#define cli_status(cli)		((cli)->cli_status)
/** Return non-zero if the client is local. */
#define cli_local(cli)          (cli_from(cli) == cli)
/** Get oper privileges for client. */
#define cli_privs(cli)		con_privs(cli_connect(cli))
/** Get client capabilities for client */
#define cli_capab(cli)		con_capab(cli_connect(cli))
/** Get active client capabilities for client */
#define cli_active(cli)		con_active(cli_connect(cli))
/** Get client name. */
#define cli_name(cli)		((cli)->cli_name)
/** Get client username (ident). */
#define cli_username(cli)	((cli)->cli_username)
/** Get client realname (information field). */
#define cli_info(cli)		((cli)->cli_info)
/** Get client account string. */
#define cli_account(cli)	(cli_user(cli) ? cli_user(cli)->account : "0")

/** Get number of incoming bytes queued for client. */
#define cli_count(cli)		con_count(cli_connect(cli))
/** Get file descriptor for sending in client's direction. */
#define cli_fd(cli)		con_fd(cli_connect(cli))
/** Get free flags for the client's connection. */
#define cli_freeflag(cli)	con_freeflag(cli_connect(cli))
/** Get last error code for the client's connection. */
#define cli_error(cli)		con_error(cli_connect(cli))
/** Get server notice mask for the client. */
#define cli_snomask(cli)	con_snomask(cli_connect(cli))
/** Get next time a nick change is allowed for the client. */
#define cli_nextnick(cli)	con_nextnick(cli_connect(cli))
/** Get next time a target change is allowed for the client. */
#define cli_nexttarget(cli)	con_nexttarget(cli_connect(cli))
/** Get SendQ for client. */
#define cli_sendQ(cli)		con_sendQ(cli_connect(cli))
/** Get RecvQ for client. */
#define cli_recvQ(cli)		con_recvQ(cli_connect(cli))
/** Get count of messages sent to client. */
#define cli_sendM(cli)		con_sendM(cli_connect(cli))
/** Get number of messages received from client. */
#define cli_receiveM(cli)	con_receiveM(cli_connect(cli))
/** Get number of bytes (modulo 1024) sent to client. */
#define cli_sendB(cli)		con_sendB(cli_connect(cli))
/** Get number of bytes (modulo 1024) received from client. */
#define cli_receiveB(cli)	con_receiveB(cli_connect(cli))
/** Get listener that accepted the client's connection. */
#define cli_listener(cli)	con_listener(cli_connect(cli))
/** Get list of attached conf lines. */
#define cli_confs(cli)		con_confs(cli_connect(cli))
/** Get handler type for client. */
#define cli_handler(cli)	con_handler(cli_connect(cli))
/** Get LIST status for client. */
#define cli_listing(cli)	con_listing(cli_connect(cli))
/** Get cached max SendQ for client. */
#define cli_max_sendq(cli)	con_max_sendq(cli_connect(cli))
/** Get ping frequency for client. */
#define cli_ping_freq(cli)	con_ping_freq(cli_connect(cli))
/** Get lastsq for client's connection. */
#define cli_lastsq(cli)		con_lastsq(cli_connect(cli))
/** Get the array of current targets for the client.  */
#define cli_targets(cli)	con_targets(cli_connect(cli))
/** Get the string form of the client's IP address. */
#define cli_sock_ip(cli)	con_sock_ip(cli_connect(cli))
/** Get the resolved hostname for the client. */
#define cli_sockhost(cli)	con_sockhost(cli_connect(cli))
/** Get the client's password. */
#define cli_passwd(cli)		con_passwd(cli_connect(cli))
/** Get the unprocessed input buffer for a client's connection.  */
#define cli_buffer(cli)		con_buffer(cli_connect(cli))
/** Get the Socket structure for sending to a client. */
#define cli_socket(cli)		con_socket(cli_connect(cli))
/** Get Timer for processing waiting messages from the client. */
#define cli_proc(cli)		con_proc(cli_connect(cli))
/** Get auth request for client. */
#define cli_auth(cli)		con_auth(cli_connect(cli))
/** Get WebIRC authorization for client. */
#define cli_wline(cli)          con_wline(cli_connect(cli))
/** Get sentalong marker for client. */
#define cli_sentalong(cli)      con_sentalong(cli_connect(cli))

/** Verify that a connection is valid. */
#define con_verify(con)		((con)->con_magic == CONNECTION_MAGIC)
/** Get connection's magic number. */
#define con_magic(con)		((con)->con_magic)
/** Get global next connection. */
#define con_next(con)		((con)->con_next)
/** Get global previous connection. */
#define con_prev_p(con)		((con)->con_prev_p)
/** Get locally connected client for connection. */
#define con_client(con)		((con)->con_client)
/** Get number of unprocessed data bytes from connection. */
#define con_count(con)		((con)->con_count)
/** Get file descriptor for connection. */
#define con_fd(con)		s_fd(&(con)->con_socket)
/** Get freeable flags for connection. */
#define con_freeflag(con)	((con)->con_freeflag)
/** Get last error code on connection. */
#define con_error(con)		((con)->con_error)
/** Get sentalong marker for connection. */
#define con_sentalong(con)      ((con)->con_sentalong)
/** Get server notice mask for connection. */
#define con_snomask(con)	((con)->con_snomask)
/** Get next nick change time for connection. */
#define con_nextnick(con)	((con)->con_nextnick)
/** Get next new target time for connection. */
#define con_nexttarget(con)	((con)->con_nexttarget)
/** Get last time we read from the connection. */
#define con_lasttime(con)       ((con)->con_lasttime)
/** Get last time we accepted a command from the connection. */
#define con_since(con)          ((con)->con_since)
/** Get SendQ for connection. */
#define con_sendQ(con)		((con)->con_sendQ)
/** Get RecvQ for connection. */
#define con_recvQ(con)		((con)->con_recvQ)
/** Get number of messages sent to connection. */
#define con_sendM(con)		((con)->con_sendM)
/** Get number of messages received from connection. */
#define con_receiveM(con)	((con)->con_receiveM)
/** Get number of bytes (modulo 1024) sent to connection. */
#define con_sendB(con)		((con)->con_sendB)
/** Get number of bytes (modulo 1024) received from connection. */
#define con_receiveB(con)	((con)->con_receiveB)
/** Get listener that accepted the connection. */
#define con_listener(con)	((con)->con_listener)
/** Get list of ConfItems attached to the connection. */
#define con_confs(con)		((con)->con_confs)
/** Get command handler for the connection. */
#define con_handler(con)	((con)->con_handler)
/** Get the LIST status for the connection. */
#define con_listing(con)	((con)->con_listing)
/** Get the maximum permitted SendQ size for the connection. */
#define con_max_sendq(con)	((con)->con_max_sendq)
/** Get the ping frequency for the connection. */
#define con_ping_freq(con)	((con)->con_ping_freq)
/** Get the lastsq for the connection. */
#define con_lastsq(con)		((con)->con_lastsq)
/** Get the current targets array for the connection. */
#define con_targets(con)	((con)->con_targets)
/** Get the string-formatted IP address for the connection. */
#define con_sock_ip(con)	((con)->con_sock_ip)
/** Get the resolved hostname for the connection. */
#define con_sockhost(con)	((con)->con_sockhost)
/** Get the password sent by the remote end of the connection.  */
#define con_passwd(con)		((con)->con_passwd)
/** Get the buffer of unprocessed incoming data from the connection. */
#define con_buffer(con)		((con)->con_buffer)
/** Get the Socket for the connection. */
#define con_socket(con)		((con)->con_socket)
/** Get the Timer for processing more data from the connection. */
#define con_proc(con)		((con)->con_proc)
/** Get the oper privilege set for the connection. */
#define con_privs(con)          (&(con)->con_privs)
/** Get the peer's capabilities for the connection. */
#define con_capab(con)          (&(con)->con_capab)
/** Get the active capabilities for the connection. */
#define con_active(con)         (&(con)->con_active)
/** Get the auth request for the connection. */
#define con_auth(con)		((con)->con_auth)
/** Get the WebIRC block (if any) used by the connection. */
#define con_wline(con)          ((con)->con_wline)

#define STAT_CONNECTING         0x001 /**< connecting to another server */
#define STAT_HANDSHAKE          0x002 /**< pass - server sent */
#define STAT_ME                 0x004 /**< this server */
#define STAT_UNKNOWN            0x008 /**< unidentified connection */
#define STAT_UNKNOWN_USER       0x010 /**< connection on a client port */
#define STAT_UNKNOWN_SERVER     0x020 /**< connection on a server port */
#define STAT_SERVER             0x040 /**< fully registered server */
#define STAT_USER               0x080 /**< fully registered user */
#define STAT_WEBIRC             0x100 /**< connection on a webirc port */

/*
 * status macros.
 */
/** Return non-zero if the client is registered. */
#define IsRegistered(x)         (cli_status(x) & (STAT_SERVER | STAT_USER))
/** Return non-zero if the client is an outbound connection that is
 * still connecting. */
#define IsConnecting(x)         (cli_status(x) == STAT_CONNECTING)
/** Return non-zero if the client is an outbound connection that has
 * sent our password. */
#define IsHandshake(x)          (cli_status(x) == STAT_HANDSHAKE)
/** Return non-zero if the client is this server. */
#define IsMe(x)                 (cli_status(x) == STAT_ME)
/** Return non-zero if the client has not yet registered. */
#define IsUnknown(x)            (cli_status(x) & \
        (STAT_UNKNOWN | STAT_UNKNOWN_USER | STAT_UNKNOWN_SERVER | STAT_WEBIRC))
/** Return non-zero if the client is an unregistered connection on a
 * server port. */
#define IsServerPort(x)         (cli_status(x) == STAT_UNKNOWN_SERVER )
/** Return non-zero if the client is an unregistered connection on a
 * user port. */
#define IsUserPort(x)           (cli_status(x) == STAT_UNKNOWN_USER )
/** Return non-zero if the client is an unregistered connection on a
 * WebIRC port that has not yet sent WEBIRC. */
#define IsWebircPort(x)         (cli_status(x) == STAT_WEBIRC)
/** Return non-zero if the client is a real client connection. */
#define IsClient(x)             (cli_status(x) & \
        (STAT_HANDSHAKE | STAT_ME | STAT_UNKNOWN |\
         STAT_UNKNOWN_USER | STAT_UNKNOWN_SERVER | STAT_SERVER | STAT_USER))
/** Return non-zero if the client ignores flood limits. */
#define IsTrusted(x)            (cli_status(x) & \
        (STAT_CONNECTING | STAT_HANDSHAKE | STAT_ME | STAT_SERVER))
/** Return non-zero if the client is a registered server. */
#define IsServer(x)             (cli_status(x) == STAT_SERVER)
/** Return non-zero if the client is a registered user. */
#define IsUser(x)               (cli_status(x) == STAT_USER)


/** Mark a client with STAT_CONNECTING. */
#define SetConnecting(x)        (cli_status(x) = STAT_CONNECTING)
/** Mark a client with STAT_HANDSHAKE. */
#define SetHandshake(x)         (cli_status(x) = STAT_HANDSHAKE)
/** Mark a client with STAT_SERVER. */
#define SetServer(x)            (cli_status(x) = STAT_SERVER)
/** Mark a client with STAT_ME. */
#define SetMe(x)                (cli_status(x) = STAT_ME)
/** Mark a client with STAT_USER. */
#define SetUser(x)              (cli_status(x) = STAT_USER)

/** Return non-zero if a client is directly connected to me. */
#define MyConnect(x)    (cli_from(x) == (x))
/** Return non-zero if a client is a locally connected user. */
#define MyUser(x)       (MyConnect(x) && IsUser(x))
/** Return non-zero if a client is a locally connected IRC operator. */
#define MyOper(x)       (MyConnect(x) && IsOper(x))
/** Return protocol version used by a server. */
#define Protocol(x)     ((cli_serv(x))->prot)

/*
 * flags macros
 */
/** Set a flag in a client's flags. */
#define SetFlag(cli, flag)  FlagSet(&cli_flags(cli), flag)
/** Clear a flag from a client's flags. */
#define ClrFlag(cli, flag)  FlagClr(&cli_flags(cli), flag)
/** Return non-zero if a flag is set in a client's flags. */
#define HasFlag(cli, flag)  FlagHas(&cli_flags(cli), flag)

/** Return non-zero if the client is an IRC operator (global or local). */
#define IsAnOper(x)             (IsOper(x) || IsLocOp(x))
/** Return non-zero if the client's connection is blocked. */
#define IsBlocked(x)            HasFlag(x, FLAG_BLOCKED)
/** Return non-zero if the client's connection is still being burst. */
#define IsBurst(x)              HasFlag(x, FLAG_BURST)
/** Return non-zero if we have received the peer's entire burst but
 * not their EOB ack. */
#define IsBurstAck(x)           HasFlag(x, FLAG_BURST_ACK)
/** Return non-zero if we are still bursting to the client. */
#define IsBurstOrBurstAck(x)    (HasFlag(x, FLAG_BURST) || HasFlag(x, FLAG_BURST_ACK))
/** Return non-zero if the client has set mode +k (channel service). */
#define IsChannelService(x)     HasFlag(x, FLAG_CHSERV)
/** Return non-zero if the client's socket is disconnected. */
#define IsDead(x)               HasFlag(x, FLAG_DEADSOCKET)
/** Return non-zero if the client has set mode +d (deaf). */
#define IsDeaf(x)               HasFlag(x, FLAG_DEAF)
/** Return non-zero if the client has been IP-checked for clones. */
#define IsIPChecked(x)          HasFlag(x, FLAG_IPCHECK)
/** Return non-zero if we have received an ident response for the client. */
#define IsGotId(x)              HasFlag(x, FLAG_GOTID)
/** Return non-zero if the client has set mode +i (invisible). */
#define IsInvisible(x)          HasFlag(x, FLAG_INVISIBLE)
/** Return non-zero if the client caused a net.burst. */
#define IsJunction(x)           HasFlag(x, FLAG_JUNCTION)
/** Return non-zero if the client has set mode +O (local operator) locally. */
#define IsLocOp(x)              (MyConnect(x) && HasFlag(x, FLAG_LOCOP))
/** Return non-zero if the client has set mode +o (global operator). */
#define IsOper(x)               HasFlag(x, FLAG_OPER)
/** Return non-zero if the client has an active UDP ping request. */
#define IsUPing(x)              HasFlag(x, FLAG_UPING)
/** Return non-zero if the client has no '\n' in its buffer. */
#define NoNewLine(x)            HasFlag(x, FLAG_NONL)
/** Return non-zero if the client has requested IAuth statistics. */
#define IsIAuthStats(x)         HasFlag(x, FLAG_IAUTH_STATS)
/** Return non-zero if the client has set mode +g (debugging). */
#define SendDebug(x)            HasFlag(x, FLAG_DEBUG)
/** Return non-zero if the client has set mode +s (server notices). */
#define SendServNotice(x)       HasFlag(x, FLAG_SERVNOTICE)
/** Return non-zero if the client has set mode +w (wallops). */
#define SendWallops(x)          HasFlag(x, FLAG_WALLOP)
/** Return non-zero if the client claims to be a hub. */
#define IsHub(x)                HasFlag(x, FLAG_HUB)
/** Return non-zero if the client understands IPv6 addresses in P10. */
#define IsIPv6(x)               HasFlag(x, FLAG_IPV6)
/** Return non-zero if the client claims to be a services server. */
#define IsService(x)            HasFlag(x, FLAG_SERVICE)
/** Return non-zero if the client has an account stamp. */
#define IsAccount(x)            HasFlag(x, FLAG_ACCOUNT)
/** Return non-zero if the client has set mode +x (hidden host). */
#define IsHiddenHost(x)         HasFlag(x, FLAG_HIDDENHOST)
/** Return non-zero if the client has an active PING request. */
#define IsPingSent(x)           HasFlag(x, FLAG_PINGSENT)

/** Return non-zero if the client has operator or server privileges. */
#define IsPrivileged(x)         (IsAnOper(x) || IsServer(x))
/** Return non-zero if the client's host is hidden. */
#define HasHiddenHost(x)        (IsHiddenHost(x) && IsAccount(x))

/** Mark a client as having an in-progress net.burst. */
#define SetBurst(x)             SetFlag(x, FLAG_BURST)
/** Mark a client as being between EOB and EOB ACK. */
#define SetBurstAck(x)          SetFlag(x, FLAG_BURST_ACK)
/** Mark a client as having mode +k (channel service). */
#define SetChannelService(x)    SetFlag(x, FLAG_CHSERV)
/** Mark a client as having mode +d (deaf). */
#define SetDeaf(x)              SetFlag(x, FLAG_DEAF)
/** Mark a client as having mode +g (debugging). */
#define SetDebug(x)             SetFlag(x, FLAG_DEBUG)
/** Mark a client as having ident looked up. */
#define SetGotId(x)             SetFlag(x, FLAG_GOTID)
/** Mark a client as being IP-checked. */
#define SetIPChecked(x)         SetFlag(x, FLAG_IPCHECK)
/** Mark a client as having mode +i (invisible). */
#define SetInvisible(x)         SetFlag(x, FLAG_INVISIBLE)
/** Mark a client as causing a net.join. */
#define SetJunction(x)          SetFlag(x, FLAG_JUNCTION)
/** Mark a client as having mode +O (local operator). */
#define SetLocOp(x)             SetFlag(x, FLAG_LOCOP)
/** Mark a client as having mode +o (global operator). */
#define SetOper(x)              SetFlag(x, FLAG_OPER)
/** Mark a client as having a pending UDP ping. */
#define SetUPing(x)             SetFlag(x, FLAG_UPING)
/** Mark a client as having mode +w (wallops). */
#define SetWallops(x)           SetFlag(x, FLAG_WALLOP)
/** Mark a client as having mode +s (server notices). */
#define SetServNotice(x)        SetFlag(x, FLAG_SERVNOTICE)
/** Mark a client as being a hub server. */
#define SetHub(x)               SetFlag(x, FLAG_HUB)
/** Mark a client as being an IPv6-grokking server. */
#define SetIPv6(x)              SetFlag(x, FLAG_IPV6)
/** Mark a client as being a services server. */
#define SetService(x)           SetFlag(x, FLAG_SERVICE)
/** Mark a client as having an account stamp. */
#define SetAccount(x)           SetFlag(x, FLAG_ACCOUNT)
/** Mark a client as having mode +x (hidden host). */
#define SetHiddenHost(x)        SetFlag(x, FLAG_HIDDENHOST)
/** Mark a client as having a pending PING. */
#define SetPingSent(x)          SetFlag(x, FLAG_PINGSENT)

/** Return non-zero if \a sptr sees \a acptr as an operator. */
#define SeeOper(sptr,acptr) (IsAnOper(acptr) && (HasPriv(acptr, PRIV_DISPLAY) \
                            || HasPriv(sptr, PRIV_SEE_OPERS)))

/** Clear the client's net.burst in-progress flag. */
#define ClearBurst(x)           ClrFlag(x, FLAG_BURST)
/** Clear the client's between EOB and EOB ACK flag. */
#define ClearBurstAck(x)        ClrFlag(x, FLAG_BURST_ACK)
/** Remove mode +k (channel service) from the client. */
#define ClearChannelService(x)  ClrFlag(x, FLAG_CHSERV)
/** Remove mode +d (deaf) from the client. */
#define ClearDeaf(x)            ClrFlag(x, FLAG_DEAF)
/** Remove mode +g (debugging) from the client. */
#define ClearDebug(x)           ClrFlag(x, FLAG_DEBUG)
/** Remove the client's IP-checked flag. */
#define ClearIPChecked(x)       ClrFlag(x, FLAG_IPCHECK)
/** Remove mode +i (invisible) from the client. */
#define ClearInvisible(x)       ClrFlag(x, FLAG_INVISIBLE)
/** Remove mode +O (local operator) from the client. */
#define ClearLocOp(x)           ClrFlag(x, FLAG_LOCOP)
/** Remove mode +o (global operator) from the client. */
#define ClearOper(x)            ClrFlag(x, FLAG_OPER)
/** Clear the client's pending UDP ping flag. */
#define ClearUPing(x)           ClrFlag(x, FLAG_UPING)
/** Remove mode +w (wallops) from the client. */
#define ClearWallops(x)         ClrFlag(x, FLAG_WALLOP)
/** Remove mode +s (server notices) from the client. */
#define ClearServNotice(x)      ClrFlag(x, FLAG_SERVNOTICE)
/** Remove mode +x (hidden host) from the client. */
#define ClearHiddenHost(x)      ClrFlag(x, FLAG_HIDDENHOST)
/** Clear the client's pending PING flag. */
#define ClearPingSent(x)        ClrFlag(x, FLAG_PINGSENT)
/** Clear the client's HUB flag. */
#define ClearHub(x)             ClrFlag(x, FLAG_HUB)

/* free flags */
#define FREEFLAG_SOCKET	0x0001	/**< socket needs to be freed */
#define FREEFLAG_TIMER	0x0002	/**< timer needs to be freed */

/* server notice stuff */

#define SNO_ADD         1       /**< Perform "or" on server notice mask. */
#define SNO_DEL         2       /**< Perform "and ~x" on server notice mask. */
#define SNO_SET         3       /**< Set server notice mask. */
                                /* DON'T CHANGE THESE VALUES ! */
                                /* THE CLIENTS DEPEND ON IT  ! */
#define SNO_OLDSNO      0x1     /**< unsorted old messages */
#define SNO_SERVKILL    0x2     /**< server kills (nick collisions) */
#define SNO_OPERKILL    0x4     /**< oper kills */
#define SNO_HACK2       0x8     /**< desyncs */
#define SNO_HACK3       0x10    /**< temporary desyncs */
#define SNO_UNAUTH      0x20    /**< unauthorized connections */
#define SNO_TCPCOMMON   0x40    /**< common TCP or socket errors */
#define SNO_TOOMANY     0x80    /**< too many connections */
#define SNO_HACK4       0x100   /**< Uworld actions on channels */
#define SNO_GLINE       0x200   /**< glines */
#define SNO_NETWORK     0x400   /**< net join/break, etc */
#define SNO_IPMISMATCH  0x800   /**< IP mismatches */
#define SNO_THROTTLE    0x1000  /**< host throttle add/remove notices */
#define SNO_OLDREALOP   0x2000  /**< old oper-only messages */
#define SNO_CONNEXIT    0x4000  /**< client connect/exit (ugh) */
#define SNO_AUTO        0x8000  /**< AUTO G-Lines */
#define SNO_DEBUG       0x10000 /**< debugging messages (DEBUGMODE only) */
#define SNO_AUTH        0x20000 /**< IAuth notices */

/** Bitmask of all valid server notice bits. */
#ifdef DEBUGMODE
# define SNO_ALL        0x3ffff
#else
# define SNO_ALL        0x2ffff
#endif

/** Server notice bits allowed to normal users. */
#define SNO_USER        (SNO_ALL & ~SNO_OPER)

/** Server notice bits enabled by default for normal users. */
#define SNO_DEFAULT (SNO_NETWORK|SNO_OPERKILL|SNO_GLINE)
/** Server notice bits enabled by default for IRC operators. */
#define SNO_OPERDEFAULT (SNO_DEFAULT|SNO_HACK2|SNO_HACK4|SNO_THROTTLE|SNO_OLDSNO)
/** Server notice bits reserved to IRC operators. */
#define SNO_OPER (SNO_CONNEXIT|SNO_OLDREALOP|SNO_AUTH)
/** Noisy server notice bits that cause other bits to be cleared during connect. */
#define SNO_NOISY (SNO_SERVKILL|SNO_UNAUTH)

/** Test whether a privilege has been granted to a client. */
#define HasPriv(cli, priv)  FlagHas(cli_privs(cli), priv)
/** Grant a privilege to a client. */
#define SetPriv(cli, priv)  FlagSet(cli_privs(cli), priv)
/** Revoke a privilege from a client. */
#define ClrPriv(cli, priv)  FlagClr(cli_privs(cli), priv)

/** Test whether a client has a capability */
#define HasCap(cli, cap)    CapHas(cli_capab(cli), (cap))
/** Test whether a client has the capability active */
#define CapActive(cli, cap) CapHas(cli_active(cli), (cap))

#define HIDE_IP 0 /**< Do not show IP address in get_client_name() */
#define SHOW_IP 1 /**< Show ident and IP address in get_client_name() */

extern const char* get_client_name(const struct Client* sptr, int showip);
extern const char* client_get_default_umode(const struct Client* sptr);
extern int client_get_ping(const struct Client* local_client);
extern void client_drop_sendq(struct Connection* con);
extern void client_add_sendq(struct Connection* con,
			     struct Connection** con_p);
extern void client_set_privs(struct Client *client, struct ConfItem *oper,
			     int forceOper);
extern int client_report_privs(struct Client* to, struct Client* client);

#endif /* INCLUDED_client_h */

