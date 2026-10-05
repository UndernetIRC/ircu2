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

/** Results of IPcheck_local_connect(). */
#define IPCHECK_REFUSED 0 /**< Too many recent connections: refuse. */
#define IPCHECK_COUNTED 1 /**< Accepted and recorded; mark client IPChecked. */
#define IPCHECK_EXEMPT  2 /**< Accepted, address exempt; not recorded. */

/*
 * Prototypes
 */
extern void IPcheck_init(void);
extern void IPcheck_clear_config(void);
extern int IPcheck_except(const char *ip_mask);
extern int IPcheck_local_connect(const struct irc_in_addr *ip, time_t *next_target_out);
extern void IPcheck_connect_fail(const struct Client *cptr, int disconnect);
extern void IPcheck_connect_succeeded(struct Client *cptr);
extern int IPcheck_remote_connect(struct Client *cptr, int is_burst);
extern void IPcheck_disconnect(struct Client *cptr);
extern unsigned short IPcheck_nr(struct Client* cptr);

#endif /* INCLUDED_ipcheck_h */
