/*
 * IPcheck.h
 *
 * $Id$
 */
#ifndef INCLUDED_ipcheck_h
#define INCLUDED_ipcheck_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>          /* time_t, size_t */
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_netinet_in_h
#include <netinet/in.h>         /* in_addr */
#define INCLUDED_netinet_in_h
#endif

struct Client;

/*
 * Prototypes
 */
extern void IPcheck_init(void);
extern int IPcheck_local_connect(struct in_addr ip, time_t* next_target_out);
extern void IPcheck_connect_fail(struct in_addr ip);
extern void IPcheck_connect_succeeded(struct Client *cptr);
extern int IPcheck_remote_connect(struct Client *cptr, int is_burst);
extern void IPcheck_disconnect(struct Client *cptr);
extern unsigned short IPcheck_nr(struct Client* cptr);

#endif /* INCLUDED_ipcheck_h */
