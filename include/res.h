/*
 * include/ircd_res.h for referencing functions in ircd/ircd_res.c
 *
 * $Id$
 */

#ifndef INCLUDED_res_h
#define INCLUDED_res_h

#ifndef INCLUDED_config_h
#include "config.h"
#endif

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

#ifndef INCLUDED_sys_socket_h
#include <sys/socket.h>
#define INCLUDED_sys_socket_h
#endif

#include <netdb.h>

#ifndef INCLUDED_netinet_in_h
#include <netinet/in.h>
#define INCLUDED_netinet_in_h
#endif

#ifdef HAVE_STDINT_H
#ifndef INCLUDED_stdint_h
#include <stdint.h>
#define INCLUDED_stdint_h
#endif
#endif

struct Client;
struct StatDesc;

/* Here we define some values lifted from nameser.h */
#define NS_NOTIFY_OP 4
#define NS_INT16SZ 2
#define NS_IN6ADDRSZ    16
#define NS_INADDRSZ	 4
#define NS_INT32SZ 4
#define NS_CMPRSFLGS    0xc0
#define NS_MAXCDNAME 255
#define QUERY 0
#define IQUERY 1
#define NO_ERRORS 0
#define SERVFAIL 2
#define T_A 1
#define T_AAAA 28
#define T_PTR 12
#define T_CNAME 5
#define T_NULL 10
#define C_IN 1
#define QFIXEDSZ 4
#define RRFIXEDSZ 10
#define HFIXEDSZ 12

struct irc_in_addr
{
  unsigned short in6_16[8];
};

struct irc_sockaddr
{
  struct irc_in_addr addr;
  unsigned short port;
};

struct DNSReply
{
  char *h_name;
  int h_addrtype;
  struct irc_in_addr addr;
};

struct DNSQuery
{
  void *vptr; /* pointer used by callback to identify request */
  void (*callback)(void* vptr, struct DNSReply *reply); /* callback to call */
};

typedef struct
{
	unsigned	id :16;		/* query identification number */
#ifdef WORDS_BIGENDIAN
			/* fields in third byte */
	unsigned	qr: 1;		/* response flag */
	unsigned	opcode: 4;	/* purpose of message */
	unsigned	aa: 1;		/* authoritive answer */
	unsigned	tc: 1;		/* truncated message */
	unsigned	rd: 1;		/* recursion desired */
			/* fields in fourth byte */
	unsigned	ra: 1;		/* recursion available */
	unsigned	unused :1;	/* unused bits (MBZ as of 4.9.3a3) */
	unsigned	ad: 1;		/* authentic data from named */
	unsigned	cd: 1;		/* checking disabled by resolver */
	unsigned	rcode :4;	/* response code */
#else
			/* fields in third byte */
	unsigned	rd :1;		/* recursion desired */
	unsigned	tc :1;		/* truncated message */
	unsigned	aa :1;		/* authoritive answer */
	unsigned	opcode :4;	/* purpose of message */
	unsigned	qr :1;		/* response flag */
			/* fields in fourth byte */
	unsigned	rcode :4;	/* response code */
	unsigned	cd: 1;		/* checking disabled by resolver */
	unsigned	ad: 1;		/* authentic data from named */
	unsigned	unused :1;	/* unused bits (MBZ as of 4.9.3a3) */
	unsigned	ra :1;		/* recursion available */
#endif
			/* remaining bytes */
	unsigned	qdcount :16;	/* number of question entries */
	unsigned	ancount :16;	/* number of answer entries */
	unsigned	nscount :16;	/* number of authority entries */
	unsigned	arcount :16;	/* number of resource entries */
} HEADER;

extern int init_resolver(void);
extern void restart_resolver(void);
extern void add_local_domain(char *hname, size_t size);
extern size_t cres_mem(struct Client* cptr);
extern void delete_resolver_queries(const void *vptr);
extern void report_dns_servers(struct Client *source_p, const struct StatDesc *sd, char *param);
extern void gethost_byname(const char *name, const struct DNSQuery *query);
extern void gethost_byaddr(const struct irc_in_addr *addr, const struct DNSQuery *query);

extern int irc_in_addr_valid(const struct irc_in_addr *addr);
extern int irc_in_addr_cmp(const struct irc_in_addr *a, const struct irc_in_addr *b);
extern int irc_in_addr_is_ipv4(const struct irc_in_addr *addr);
extern int irc_in_addr_is_loopback(const struct irc_in_addr *addr);

#endif
