#ifndef S_BSD_H
#define S_BSD_H

#include <netdb.h>
#include "s_conf.h"

/*=============================================================================
 * Macro's
 */

#define FLAGS_PINGSENT	 0x0001	/* Unreplied ping sent */
#define FLAGS_DEADSOCKET 0x0002	/* Local socket is dead--Exiting soon */
#define FLAGS_KILLED	 0x0004	/* Prevents "QUIT" from being sent for this */
#define FLAGS_OPER	 0x0008	/* Operator */
#define FLAGS_LOCOP	 0x0010	/* Local operator -- SRB */
#define FLAGS_INVISIBLE	 0x0020	/* makes user invisible */
#define FLAGS_WALLOP	 0x0040	/* send wallops to them */
#define FLAGS_SERVNOTICE 0x0080	/* server notices such as kill */
#define FLAGS_BLOCKED	 0x0100	/* socket is in a blocked condition */
#define FLAGS_UNIX	 0x0200	/* socket is in the unix domain, not inet */
#define FLAGS_CLOSING	 0x0400	/* set when closing to suppress errors */
#define FLAGS_LISTEN	 0x0800	/* used to mark clients which we listen() on */
#define FLAGS_CHKACCESS	 0x1000	/* ok to check clients access if set */
#define FLAGS_DOINGDNS	 0x2000	/* client is waiting for a DNS response */
#define FLAGS_AUTH	 0x4000	/* client is waiting on rfc931 response */
#define FLAGS_WRAUTH	 0x8000	/* set if we havent writen to ident server */
#define FLAGS_LOCAL	0x00010000	/* set for local clients */
#define FLAGS_GOTID	0x00020000	/* successful ident lookup achieved */
#define FLAGS_DOID	0x00040000	/* I-lines say must use ident return */
#define FLAGS_NONL	0x00080000	/* No \n in buffer */
#define FLAGS_TS8      	0x00100000	/* Why do you want to know? */
#define FLAGS_PING	0x00200000	/* Socket needs to send udp pings */
#define FLAGS_ASKEDPING	0x00400000	/* Client asked for udp ping */
#define FLAGS_MAP	0x00800000	/* Show server on the map */
#define FLAGS_JUNCTION	0x01000000	/* Junction causing the net.burst */
#define FLAGS_DEAF	0x02000000	/* Makes user deaf */
#define FLAGS_CHSERV	0x04000000	/* Disallow KICK or MODE -o on the user;
					   don't display channels in /whois */
#define FLAGS_BURST	0x08000000	/* Server is receiving a net.burst */
#define FLAGS_BURST_ACK	0x10000000	/* Server is waiting for eob ack */
#define FLAGS_DEBUG	0x20000000	/* send global debug/anti-hack info */
#define FLAGS_IPCHECK	0x40000000	/* Added or updated IPregistry data */

#define SEND_UMODES \
    (FLAGS_INVISIBLE|FLAGS_OPER|FLAGS_WALLOP|FLAGS_DEAF|FLAGS_CHSERV|FLAGS_DEBUG)
#define ALL_UMODES (SEND_UMODES|FLAGS_SERVNOTICE|FLAGS_LOCOP)
#define FLAGS_ID (FLAGS_DOID|FLAGS_GOTID)

/*
 * flags macros.
 */
#define IsOper(x)		((x)->flags & FLAGS_OPER)
#define IsLocOp(x)		((x)->flags & FLAGS_LOCOP)
#define IsInvisible(x)		((x)->flags & FLAGS_INVISIBLE)
#define IsDeaf(x)		((x)->flags & FLAGS_DEAF)
#define IsChannelService(x)	((x)->flags & FLAGS_CHSERV)
#define IsAnOper(x)		((x)->flags & (FLAGS_OPER|FLAGS_LOCOP))
#define IsPrivileged(x)		(IsAnOper(x) || IsServer(x))
#define SendWallops(x)		((x)->flags & FLAGS_WALLOP)
#define SendDebug(x)            ((x)->flags & FLAGS_DEBUG)
#define SendServNotice(x)	((x)->flags & FLAGS_SERVNOTICE)
#define IsUnixSocket(x)		((x)->flags & FLAGS_UNIX)
#define IsListening(x)		((x)->flags & FLAGS_LISTEN)
#define DoAccess(x)		((x)->flags & FLAGS_CHKACCESS)
#define IsLocal(x)		((x)->flags & FLAGS_LOCAL)
#define IsDead(x)		((x)->flags & FLAGS_DEADSOCKET)
#define IsJunction(x)		((x)->flags & FLAGS_JUNCTION)
#define IsBurst(x)		((x)->flags & FLAGS_BURST)
#define IsBurstAck(x)		((x)->flags & FLAGS_BURST_ACK)
#define IsBurstOrBurstAck(x)	((x)->flags & (FLAGS_BURST|FLAGS_BURST_ACK))
#define IsIPChecked(x)		((x)->flags & FLAGS_IPCHECK)

#define SetOper(x)		((x)->flags |= FLAGS_OPER)
#define SetLocOp(x)		((x)->flags |= FLAGS_LOCOP)
#define SetInvisible(x)		((x)->flags |= FLAGS_INVISIBLE)
#define SetWallops(x)		((x)->flags |= FLAGS_WALLOP)
#define SetDebug(x)             ((x)->flags |= FLAGS_DEBUG)
#define SetUnixSock(x)		((x)->flags |= FLAGS_UNIX)
#define SetDNS(x)		((x)->flags |= FLAGS_DOINGDNS)
#define DoingDNS(x)		((x)->flags & FLAGS_DOINGDNS)
#define SetAccess(x)		((x)->flags |= FLAGS_CHKACCESS)
#define DoingAuth(x)		((x)->flags & FLAGS_AUTH)
#define NoNewLine(x)		((x)->flags & FLAGS_NONL)
#define DoPing(x)		((x)->flags & FLAGS_PING)
#define SetAskedPing(x)		((x)->flags |= FLAGS_ASKEDPING)
#define AskedPing(x)		((x)->flags & FLAGS_ASKEDPING)
#define SetJunction(x)		((x)->flags |= FLAGS_JUNCTION)
#define SetBurst(x)		((x)->flags |= FLAGS_BURST)
#define SetBurstAck(x)		((x)->flags |= FLAGS_BURST_ACK)
#define SetIPChecked(x)		((x)->flags |= FLAGS_IPCHECK)

#define ClearOper(x)		((x)->flags &= ~FLAGS_OPER)
#define ClearLocOp(x)		((x)->flags &= ~FLAGS_LOCOP)
#define ClearInvisible(x)	((x)->flags &= ~FLAGS_INVISIBLE)
#define ClearWallops(x)		((x)->flags &= ~FLAGS_WALLOP)
#define ClearDebug(x)           ((x)->flags &= ~FLAGS_DEBUG)
#define ClearDNS(x)		((x)->flags &= ~FLAGS_DOINGDNS)
#define ClearAuth(x)		((x)->flags &= ~FLAGS_AUTH)
#define ClearAccess(x)		((x)->flags &= ~FLAGS_CHKACCESS)
#define ClearPing(x)		((x)->flags &= ~FLAGS_PING)
#define ClearAskedPing(x)	((x)->flags &= ~FLAGS_ASKEDPING)
#define ClearBurst(x)		((x)->flags &= ~FLAGS_BURST)
#define ClearBurstAck(x)	((x)->flags &= ~FLAGS_BURST_ACK)

/* used for async dns values */

#define ASYNC_NONE	0
#define ASYNC_CLIENT	1
#define ASYNC_CONNECT	2
#define ASYNC_CONF	3
#define ASYNC_PING	4

/* server notice stuff */

#define SNO_ADD		1
#define SNO_DEL		2
#define SNO_SET		3
				/* DON'T CHANGE THESE VALUES ! */
				/* THE CLIENTS DEPEND ON IT  ! */
#define SNO_OLDSNO	0x1	/* unsorted old messages */
#define SNO_SERVKILL	0x2	/* server kills (nick collisions) */
#define SNO_OPERKILL	0x4	/* oper kills */
#define SNO_HACK2	0x8	/* desyncs */
#define SNO_HACK3	0x10	/* temporary desyncs */
#define SNO_UNAUTH	0x20	/* unauthorized connections */
#define SNO_TCPCOMMON	0x40	/* common TCP or socket errors */
#define SNO_TOOMANY	0x80	/* too many connections */
#define SNO_HACK4	0x100	/* Uworld actions on channels */
#define SNO_GLINE	0x200	/* glines */
#define SNO_NETWORK	0x400	/* net join/break, etc */
#define SNO_IPMISMATCH	0x800	/* IP mismatches */
#define SNO_THROTTLE	0x1000	/* host throttle add/remove notices */
#define SNO_OLDREALOP	0x2000	/* old oper-only messages */
#define SNO_CONNEXIT	0x4000	/* client connect/exit (ugh) */

#define SNO_ALL		0x7fff	/* Don't make it larger then significant,
				 * that looks nicer */

#define SNO_USER	(SNO_ALL & ~SNO_OPER)

#define SNO_DEFAULT (SNO_NETWORK|SNO_OPERKILL|SNO_GLINE)
#define SNO_OPERDEFAULT (SNO_DEFAULT|SNO_HACK2|SNO_HACK4|SNO_THROTTLE|SNO_OLDSNO)
#define SNO_OPER (SNO_CONNEXIT|SNO_OLDREALOP)
#define SNO_NOISY (SNO_SERVKILL|SNO_UNAUTH)

/*
 * simple defines to differentiate between a tty and socket for
 * add_connection()  -Simon
 */

#define ADCON_TTY 0
#define ADCON_SOCKET 1

/*=============================================================================
 * Proto types
 */

extern int setsnomask(aClient *cptr, snomask_t newmask, int what);
extern snomask_t umode_make_snomask(snomask_t oldmask, char *arg, int what);
extern int connect_server(aConfItem *aconf, aClient *by, struct hostent *hp);
extern void report_error(char *text, aClient *cptr);
extern int inetport(aClient *cptr, char *name, char *bind_addr, unsigned short int port);
extern int add_listener(aConfItem *aconf);
extern void close_listeners(void);
extern void init_sys(void);
extern void write_pidfile(void);
extern enum AuthorizationCheckResult check_client(aClient *cptr);
extern int check_server(aClient *cptr);
extern void close_connection(aClient *cptr);
extern int get_sockerr(aClient *cptr);
extern void set_non_blocking(int fd, aClient *cptr);
extern aClient *add_connection(aClient *cptr, int fd, int type);
extern int read_message(time_t delay);
extern void get_my_name(aClient *cptr, char *name, size_t len);
extern int setup_ping(void);

extern int highest_fd, resfd;
extern unsigned int readcalls;
extern aClient *loc_clients[MAXCONNECTIONS];
extern struct sockaddr_in vserv;
extern struct sockaddr_in cserv;

#endif /* S_BSD_H */
