/*
 * irc2.7.2/ircd/res.h (C)opyright 1992 Darren Reed.
 *
 * $Id$
 */
#ifndef INCLUDED_res_h
#define INCLUDED_res_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>       /* time_t */
#define INCLUDED_sys_types_h
#endif

struct Client;
struct hostent;

struct DNSReply {
  struct hostent* hp;        /* hostent struct  */
  int             ref_count; /* reference count */
};

struct DNSQuery {
  void* vptr;               /* pointer used by callback to identify request */
  void (*callback)(void* vptr, struct DNSReply* reply); /* callback to call */
};

extern int ResolverFileDescriptor;  /* GLOBAL - file descriptor (s_bsd.c) */

extern void get_res(void);
extern struct DNSReply* gethost_byname(const char* name, 
                                       const struct DNSQuery* req);
extern struct DNSReply* gethost_byaddr(const char* name, 
                                       const struct DNSQuery* req);
extern int             init_resolver(void);
extern void            restart_resolver(void);
extern time_t          timeout_resolver(time_t now);
/*
 * delete_resolver_queries - delete all outstanding queries for the
 * pointer arg, DO NOT call this from a resolver callback function the
 * resolver will delete the query itself for the affected client.
 */
extern void     delete_resolver_queries(const void* vptr);
extern size_t   cres_mem(struct Client* cptr);
extern int      m_dns(struct Client* cptr, struct Client* sptr,
                             int parc, char* parv[]);
extern int      resolver_read(void);
extern void     resolver_read_multiple(int count);
extern void     flush_resolver_cache(void);

#endif /* INCLUDED_res_h */

