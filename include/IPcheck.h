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

struct Client;

/*----------------------------------------------------------------------------
 * Prototypes
 *--------------------------------------------------------------------------*/
extern int  ip_registry_check_local(unsigned int addr, time_t* next_target_out);
extern void ip_registry_local_connect(struct Client *cptr);
extern void ip_registry_connect_fail(unsigned int addr);
extern void ip_registry_expire(void);
extern void ip_registry_disconnect(struct Client *cptr);
extern int  ip_registry_count(unsigned int addr);
extern int  ip_registry_check_remote(struct Client *cptr, int is_burst);
extern void ip_registry_connect_succeeded(struct Client *cptr);

#endif /* INCLUDED_ipcheck_h */

