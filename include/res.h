/*
 * include/ircd_res.h for referencing functions in ircd/ircd_res.c
 *
 * $Id$
 */

#ifndef INCLUDED_res_h
#define INCLUDED_res_h

#include "listener.h"
#include "ircd_addrinfo.h"

#ifndef INADDR_NONE
#define INADDR_NONE ((uint32_t)-1)
#endif

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

struct irc_ssaddr
{
  struct sockaddr_storage ss;
  size_t ss_len;
};

struct DNSReply
{
  char *h_name;
  int h_addrtype;
  struct irc_ssaddr addr;
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
extern void report_dns_servers(struct Client *source_p, struct StatDesc *sd, int stat, char *param);
extern void gethost_byname_type(const char *name, const struct DNSQuery *query, int type);
extern void gethost_byname(const char *name, const struct DNSQuery *query);
extern void gethost_byaddr(const struct irc_ssaddr *addr, const struct DNSQuery *query);
extern void gethost_byinaddr(const struct in_addr *addr, const struct DNSQuery *query);

#endif
