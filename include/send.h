#ifndef SEND_H
#define SEND_H

/*=============================================================================
 * Macros
 */

#define LastDeadComment(cptr) ((cptr)->info)

/*=============================================================================
 * Proto types
 */

extern void sendto_one(aClient *to, char *pattern, ...)
    __attribute__ ((format(printf, 2, 3)));
extern void sendbufto_one(aClient *to);
extern void sendto_ops(const char *pattern, ...)
    __attribute__ ((format(printf, 1, 2)));
extern void sendto_channel_butserv(aChannel *chptr, aClient *from,
    char *pattern, ...) __attribute__ ((format(printf, 3, 4)));
extern void sendto_serv_butone(aClient *one, char *pattern, ...)
    __attribute__ ((format(printf, 2, 3)));
extern void sendto_match_servs(aChannel *chptr, aClient *from,
    char *format, ...) __attribute__ ((format(printf, 3, 4)));
extern void sendto_lowprot_butone(aClient *cptr, int p, char *pattern, ...)
    __attribute__ ((format(printf, 3, 4)));
extern void sendto_highprot_butone(aClient *cptr, int p, char *pattern, ...)
    __attribute__ ((format(printf, 3, 4)));
extern void sendto_prefix_one(Reg1 aClient *to, Reg2 aClient *from,
    char *pattern, ...) __attribute__ ((format(printf, 3, 4)));
extern void flush_connections(int fd);
extern void send_queued(aClient *to);
extern void vsendto_one(aClient *to, char *pattern, va_list vl);
extern void sendto_channel_butone(aClient *one, aClient *from,
    aChannel *chptr, char *pattern, ...) __attribute__ ((format(printf, 4, 5)));
extern void sendto_lchanops_butone(aClient *one, aClient *from,
    aChannel *chptr, char *pattern, ...) __attribute__ ((format(printf, 4, 5)));
extern void sendto_chanopsserv_butone(aClient *one, aClient *from,
    aChannel *chptr, char *pattern, ...) __attribute__ ((format(printf, 4, 5)));
extern void sendto_common_channels(aClient *user, char *pattern, ...)
    __attribute__ ((format(printf, 2, 3)));
extern void sendto_match_butone(aClient *one, aClient *from, char *mask,
    int what, char *pattern, ...) __attribute__ ((format(printf, 5, 6)));
extern void sendto_lops_butone(aClient *one, char *pattern, ...)
    __attribute__ ((format(printf, 2, 3)));
extern void vsendto_ops(const char *pattern, va_list vl);
extern void sendto_ops_butone(aClient *one, aClient *from, char *pattern, ...)
    __attribute__ ((format(printf, 3, 4)));
extern void sendto_g_serv_butone(aClient *one, char *pattern, ...)
    __attribute__ ((format(printf, 2, 3)));
extern void sendto_realops(const char *pattern, ...)
    __attribute__ ((format(printf, 1, 2)));
extern void vsendto_op_mask(register snomask_t mask,
    const char *pattern, va_list vl);
extern void sendto_op_mask(snomask_t mask, const char *pattern, ...)
    __attribute__ ((format(printf, 2, 3)));
extern void sendbufto_op_mask(snomask_t mask);
extern void sendbufto_serv_butone(aClient *one);

extern char sendbuf[2048];

#endif /* SEND_H */
