#ifndef RES_H
#define RES_H

#include <netinet/in.h>
#include <netdb.h>
#ifdef HPUX
#ifndef h_errno
extern int h_errno;
#endif
#endif
#include "list.h"

/*=============================================================================
 * General defines
 */

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

/*=============================================================================
 * Proto types
 */

extern int init_resolver(void);
extern time_t timeout_query_list(void);
extern void del_queries(char *cp);
extern void add_local_domain(char *hname, int size);
extern struct hostent *gethost_byname(char *name, Link *lp);
extern struct hostent *gethost_byaddr(struct in_addr *addr, Link *lp);
extern struct hostent *get_res(char *lp);
extern time_t expire_cache(void);
extern void flush_cache(void);
extern int m_dns(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern size_t cres_mem(aClient *sptr);

#endif /* RES_H */
