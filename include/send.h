/*
 * send.h
 *
 * $Id$
 */
#ifndef INCLUDED_send_h
#define INCLUDED_send_h
#ifndef INCLUDED_stdarg_h
#include <stdarg.h>         /* va_list */
#define INCLUDED_stdarg_h 
#endif

struct Channel;
struct Client;
struct DBuf;
struct MsgBuf;

/*
 * Prototypes
 */
extern void send_buffer(struct Client* to, struct MsgBuf* buf, int prio);

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


/* Same as above, except it takes a va_list */
extern void vsendcmdto_one(struct Client *from, const char *cmd,
			   const char *tok, struct Client *to,
			   const char *pattern, va_list vl);

/* Send command to all servers except one */
extern void sendcmdto_serv_butone(struct Client *from, const char *cmd,
				  const char *tok, struct Client *one,
				  const char *pattern, ...);

/* Send command to all channels user is on */
extern void sendcmdto_common_channels(struct Client *from, const char *cmd,
				      const char *tok, const char *pattern,
				      ...);


/* Send command to all channel users on this server */
extern void sendcmdto_channel_butserv(struct Client *from, const char *cmd,
				      const char *tok, struct Channel *to,
				      const char *pattern, ...);

/* Send command to all interested channel users */
extern void sendcmdto_channel_butone(struct Client *from, const char *cmd,
				     const char *tok, struct Channel *to,
				     struct Client *one, unsigned int skip,
				     const char *pattern, ...);

#define SKIP_DEAF	0x01	/* skip users that are +d */
#define SKIP_BURST	0x02	/* skip users that are bursting */
#define SKIP_NONOPS	0x04	/* skip users that aren't chanops */

/* Send command to all users having a particular flag set */
extern void sendcmdto_flag_butone(struct Client *from, const char *cmd,
				  const char *tok, struct Client *one,
				  unsigned int flag, const char *pattern, ...);

/* Send command to all matching clients */
extern void sendcmdto_match_butone(struct Client *from, const char *cmd,
				   const char *tok, const char *to,
				   struct Client *one, unsigned int who,
				   const char *pattern, ...);

/* Send server notice to opers but one--one can be NULL */
extern void sendto_opmask_butone(struct Client *one, unsigned int mask,
				 const char *pattern, ...);

/* Same as above, but with variable argument list */
extern void vsendto_opmask_butone(struct Client *one, unsigned int mask,
				  const char *pattern, va_list vl);

#endif /* INCLUDED_send_h */
