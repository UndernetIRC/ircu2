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

extern void sendcmdto_one(struct Client *one, const char *cmd,
			  const char *tok, struct Client *from,
			  const char *fmt, ...);
extern void vsendcmdto_one(struct Client *one, const char *cmd,
			   const char *tok, struct Client *from,
			   const char *fmt, va_list vl);
extern void sendcmdto_serv_butone(struct Client *one, const char *cmd,
				  const char *tok, struct Client *from,
				  const char *fmt, ...);

#endif /* INCLUDED_send_h */
