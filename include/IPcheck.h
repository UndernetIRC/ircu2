/** @file IPcheck.h
 * @brief Interface to count users connected from particular IP addresses.
 * @version $Id$
 */
#ifndef INCLUDED_ipcheck_h
#define INCLUDED_ipcheck_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>          /* time_t, size_t */
#define INCLUDED_sys_types_h
#endif

struct Client;
struct irc_in_addr;

/*
 * Prototypes
 */
extern void IPcheck_init(void);
extern int IPcheck_local_connect(const struct irc_in_addr *ip, time_t *next_target_out);
extern void IPcheck_connect_fail(const struct Client *cptr, int disconnect);
extern void IPcheck_connect_succeeded(struct Client *cptr);
extern int IPcheck_remote_connect(struct Client *cptr, int is_burst);
extern void IPcheck_disconnect(struct Client *cptr);
extern unsigned short IPcheck_nr(struct Client* cptr);

#endif /* INCLUDED_ipcheck_h */
