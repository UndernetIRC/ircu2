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


/*
 * Prototypes
 */
extern void send_buffer(struct Client* to, char* buf);
extern void flush_sendq_except(const struct DBuf* one);

extern void sendto_one(struct Client *to, const char* fmt, ...);
extern void sendbufto_one(struct Client *to);
extern void sendto_ops(const char* fmt, ...);
extern void sendto_channel_butserv(struct Channel *chptr, struct Client *from,
                                   const char* fmt, ...);
extern void sendto_serv_butone(struct Client *one, const char* fmt, ...);
extern void sendto_match_servs(struct Channel* chptr, struct Client* from,
                               const char* fmt, ...);
extern void sendto_lowprot_butone(struct Client *cptr, int p,
                                  const char* fmt, ...);
extern void sendto_highprot_butone(struct Client *cptr, int p,
                                   const char* fmt, ...);
extern void sendto_prefix_one(struct Client *to, struct Client *from,
                              const char* fmt, ...);
extern void flush_connections(struct Client* cptr);
extern void send_queued(struct Client *to);
extern void vsendto_one(struct Client *to, const char* fmt, va_list vl);
extern void sendto_channel_butone(struct Client *one, struct Client *from,
                                  struct Channel *chptr, const char* fmt, ...);
extern void sendmsgto_channel_butone(struct Client *one, struct Client *from,
                                  struct Channel *chptr, const char *sender,
                                  const char *cmd, const char *chname, const char *msg);
extern void sendto_lchanops_butone(struct Client *one, struct Client *from,
                                   struct Channel *chptr, const char* fmt, ...);
extern void sendto_chanopsserv_butone(struct Client *one, struct Client *from,
                                   struct Channel *chptr, const char* fmt, ...);
extern void sendto_common_channels(struct Client *user, const char* fmt, ...);
extern void sendto_match_butone(struct Client *one, struct Client *from,
                                const char *mask, int what, const char* fmt, ...);
extern void sendto_lops_butone(struct Client *one, const char* fmt, ...);
extern void vsendto_ops(const char *pattern, va_list vl);
extern void sendto_ops_butone(struct Client *one, struct Client *from,
                              const char* fmt, ...);
extern void sendto_g_serv_butone(struct Client *one, const char* fmt, ...);
extern void sendto_realops(const char* fmt, ...);
extern void vsendto_op_mask(unsigned int mask,
                            const char* fmt, va_list vl);
extern void sendto_op_mask(unsigned int mask, const char* fmt, ...);
extern void sendbufto_op_mask(unsigned int mask);
extern void sendbufto_serv_butone(struct Client *one);

extern char sendbuf[2048];

#define IRC_BUFSIZE	512

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
