/** @file
 * @brief IRC resolver API.
 * @version $Id$
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
#define NS_INT16SZ 2 /**< Size of a 16-bit value. */
#define NS_INT32SZ 4 /**< Size of a 32-bit value. */
#define NS_CMPRSFLGS 0xc0 /**< Prefix flags that indicate special types */
#define NS_MAXCDNAME 255 /**< Maximum length of a compressed domain name. */
#define QUERY 0      /**< Forward (normal) DNS query operation. */
#define NO_ERRORS 0  /**< No errors processing a query. */
#define SERVFAIL 2   /**< Server error while processing a query. */
#define NXDOMAIN 3   /**< Domain name in query does not exist. */
#define T_A 1        /**< Hostname -> IPv4 query type. */
#define T_AAAA 28    /**< Hostname -> IPv6 query type. */
#define T_PTR 12     /**< IP(v4 or v6) -> hostname query type. */
#define T_CNAME 5    /**< Canonical name resolution query type. */
#define C_IN 1       /**< Internet query class. */
#define QFIXEDSZ 4   /**< Length of fixed-size part of query. */
#define HFIXEDSZ 12  /**< Length of fixed-size DNS header. */

/** Structure to store an IP address. */
struct irc_in_addr
{
  unsigned short in6_16[8]; /**< IPv6 encoded parts, little-endian. */
};

/** Structure to store an IP address and port number. */
struct irc_sockaddr
{
  struct irc_in_addr addr; /**< IP address. */
  unsigned short port;     /**< Port number, host-endian. */
};

/** DNS callback function signature. */
typedef void (*dns_callback_f)(void *vptr, const struct irc_in_addr *addr, const char *h_name);

/** DNS query and response header. */
typedef struct
{
	unsigned	id :16;		/**< query identification number */
#ifdef WORDS_BIGENDIAN
			/* fields in third byte */
	unsigned	qr: 1;		/**< response flag */
	unsigned	opcode: 4;	/**< purpose of message */
	unsigned	aa: 1;		/**< authoritive answer */
	unsigned	tc: 1;		/**< truncated message */
	unsigned	rd: 1;		/**< recursion desired */
			/* fields in fourth byte */
	unsigned	ra: 1;		/**< recursion available */
	unsigned	unused :1;	/**< unused bits (MBZ as of 4.9.3a3) */
	unsigned	ad: 1;		/**< authentic data from named */
	unsigned	cd: 1;		/**< checking disabled by resolver */
	unsigned	rcode :4;	/**< response code */
#else
			/* fields in third byte */
	unsigned	rd :1;		/**< recursion desired */
	unsigned	tc :1;		/**< truncated message */
	unsigned	aa :1;		/**< authoritive answer */
	unsigned	opcode :4;	/**< purpose of message */
	unsigned	qr :1;		/**< response flag */
			/* fields in fourth byte */
	unsigned	rcode :4;	/**< response code */
	unsigned	cd: 1;		/**< checking disabled by resolver */
	unsigned	ad: 1;		/**< authentic data from named */
	unsigned	unused :1;	/**< unused bits (MBZ as of 4.9.3a3) */
	unsigned	ra :1;		/**< recursion available */
#endif
			/* remaining bytes */
	unsigned	qdcount :16;	/**< number of question entries */
	unsigned	ancount :16;	/**< number of answer entries */
	unsigned	nscount :16;	/**< number of authority entries */
	unsigned	arcount :16;	/**< number of resource entries */
} HEADER;

extern void restart_resolver(void);
extern void clear_nameservers(void);
extern void add_nameserver(const char *ipaddr);
extern void add_local_domain(char *hname, size_t size);
extern size_t cres_mem(struct Client* cptr);
extern void delete_resolver_queries(const void *vptr);
extern void report_dns_servers(struct Client *source_p, const struct StatDesc *sd, char *param);
extern void gethost_byname(const char *name, dns_callback_f callback, void *ctx);
extern void gethost_byaddr(const struct irc_in_addr *addr, dns_callback_f callback, void *ctx);

/** Evaluate to non-zero if \a ADDR is an unspecified (all zeros) address. */
#define irc_in_addr_unspec(ADDR) (((ADDR)->in6_16[0] == 0) \
                                  && ((ADDR)->in6_16[1] == 0) \
                                  && ((ADDR)->in6_16[2] == 0) \
                                  && ((ADDR)->in6_16[3] == 0) \
                                  && ((ADDR)->in6_16[4] == 0) \
                                  && ((ADDR)->in6_16[6] == 0) \
                                  && ((ADDR)->in6_16[7] == 0) \
                                  && ((ADDR)->in6_16[5] == 0 \
                                      || (ADDR)->in6_16[5] == 65535))
/** Evaluate to non-zero if \a ADDR is a valid address (not all 0s and not all 1s). */
#define irc_in_addr_valid(ADDR) (((ADDR)->in6_16[0] && ~(ADDR)->in6_16[0]) \
                                 || (ADDR)->in6_16[1] != (ADDR)->in6_16[0] \
                                 || (ADDR)->in6_16[2] != (ADDR)->in6_16[0] \
                                 || (ADDR)->in6_16[3] != (ADDR)->in6_16[0] \
                                 || (ADDR)->in6_16[4] != (ADDR)->in6_16[0] \
                                 || (ADDR)->in6_16[5] != (ADDR)->in6_16[0] \
                                 || (ADDR)->in6_16[6] != (ADDR)->in6_16[0] \
                                 || (ADDR)->in6_16[7] != (ADDR)->in6_16[0])
/** Evaluate to non-zero if \a ADDR (of type struct irc_in_addr) is an IPv4 address. */
#define irc_in_addr_is_ipv4(ADDR) (!(ADDR)->in6_16[0] && !(ADDR)->in6_16[1] && !(ADDR)->in6_16[2] \
                                   && !(ADDR)->in6_16[3] && !(ADDR)->in6_16[4] \
                                   && ((!(ADDR)->in6_16[5] && (ADDR)->in6_16[6]) \
                                       || (ADDR)->in6_16[5] == 65535))
/** Evaluate to non-zero if \a A is a different IP than \a B. */
#define irc_in_addr_cmp(A,B) (irc_in_addr_is_ipv4(A) ? ((A)->in6_16[6] != (B)->in6_16[6] \
                                  || (A)->in6_16[7] != (B)->in6_16[7] || !irc_in_addr_is_ipv4(B)) \
                              : memcmp((A), (B), sizeof(struct irc_in_addr)))
/** Evaluate to non-zero if \a ADDR is a loopback address. */
#define irc_in_addr_is_loopback(ADDR) (!(ADDR)->in6_16[0] && !(ADDR)->in6_16[1] && !(ADDR)->in6_16[2] \
                                       && !(ADDR)->in6_16[3] && !(ADDR)->in6_16[4] \
                                       && ((!(ADDR)->in6_16[5] \
                                            && ((!(ADDR)->in6_16[6] && (ADDR)->in6_16[7] == htons(1)) \
                                                || (ntohs((ADDR)->in6_16[6]) & 0xff00) == 0x7f00)) \
                                           || (((ADDR)->in6_16[5] == 65535) \
                                               && (ntohs((ADDR)->in6_16[6]) & 0xff00) == 0x7f00)))

#endif
