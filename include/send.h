/** @file send.h
 * @brief Send messages to certain targets.
 * @version $Id$
 */
#ifndef INCLUDED_send_h
#define INCLUDED_send_h
#ifndef INCLUDED_stdarg_h
#include <stdarg.h>         /* va_list */
#define INCLUDED_stdarg_h 
#endif
#ifndef INCLUDED_time_h
#include <time.h>	/* time_t */
#define INCLUDED_time_h
#endif

struct Channel;
struct Client;
struct DBuf;
struct MsgBuf;

/*
 * Prototypes
 */
extern struct SLink *opsarray[];

extern void send_buffer(struct Client* to, struct MsgBuf* buf, int prio);

extern void kill_highest_sendq(int servers_too);
extern void flush_connections(struct Client* cptr);
extern void send_queued(struct Client *to);

/* Send a raw message to one client; USE ONLY IF YOU MUST SEND SOMETHING
 * WITHOUT A PREFIX!
 */
extern void sendrawto_one(struct Client *to, const char *pattern, ...);

/* Send a command to one client */
extern void sendcmdto_one(struct Client *from, const char *cmd,
			  const char *tok, struct Client *to,
			  const char *pattern, ...);

/* Same as above, except it puts the message on the priority queue */
extern void sendcmdto_prio_one(struct Client *from, const char *cmd,
			       const char *tok, struct Client *to,
			       const char *pattern, ...);

/* Send command to servers by flags except one */
extern void sendcmdto_flag_serv_butone(struct Client *from, const char *cmd,
                                       const char *tok, struct Client *one,
                                       int require, int forbid,
                                       const char *pattern, ...);

/* Send command to all servers except one */
extern void sendcmdto_serv_butone(struct Client *from, const char *cmd,
				  const char *tok, struct Client *one,
				  const char *pattern, ...);

/* Send command to all channels user is on */
extern void sendcmdto_common_channels_butone(struct Client *from,
					     const char *cmd,
					     const char *tok,
					     struct Client *one,
					     const char *pattern, ...);

/* Send command to all channel users on this server */
extern void sendcmdto_channel_butserv_butone(struct Client *from,
					     const char *cmd,
					     const char *tok,
					     struct Channel *to,
					     struct Client *one,
                                             unsigned int skip,
					     const char *pattern, ...);

/* Send command to all servers interested in a channel */
extern void sendcmdto_channel_servers_butone(struct Client *from,
                                             const char *cmd,
                                             const char *tok,
                                             struct Channel *to,
                                             struct Client *one,
                                             unsigned int skip,
                                             const char *pattern, ...);

/* Send command to all interested channel users */
extern void sendcmdto_channel_butone(struct Client *from, const char *cmd,
				     const char *tok, struct Channel *to,
				     struct Client *one, unsigned int skip,
				     const char *pattern, ...);

#define SKIP_DEAF	0x01	/**< skip users that are +d */
#define SKIP_BURST	0x02	/**< skip users that are bursting */
#define SKIP_NONOPS	0x04	/**< skip users that aren't chanops */
#define SKIP_NONVOICES  0x08    /**< skip users that aren't voiced (includes
                                   chanops) */

/* Send command to all users having a particular flag set */
extern void sendwallto_group_butone(struct Client *from, int type, 
				    struct Client *one, const char *pattern,
				    ...);

#define WALL_DESYNCH	1       /**< send as a DESYNCH message */
#define WALL_WALLOPS	2       /**< send to all +w opers */
#define WALL_WALLUSERS	3       /**< send to all +w users */

/* Send command to all matching clients */
extern void sendcmdto_match_butone(struct Client *from, const char *cmd,
				   const char *tok, const char *to,
				   struct Client *one, unsigned int who,
				   const char *pattern, ...);

/* Send server notice to opers but one--one can be NULL */
extern void sendto_opmask_butone(struct Client *one, unsigned int mask,
				 const char *pattern, ...);

/* Same as above, but rate limited */
extern void sendto_opmask_butone_ratelimited(struct Client *one,
					     unsigned int mask, time_t *rate,
					     const char *pattern, ...);

/* Same as above, but with variable argument list */
extern void vsendto_opmask_butone(struct Client *one, unsigned int mask,
				  const char *pattern, va_list vl);

#endif /* INCLUDED_send_h */
