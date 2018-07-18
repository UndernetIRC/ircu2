/*
 * A rewrite of Darren Reed's original res.c As there is nothing
 * left of Darren's original code, this is now licensed by the hybrid group.
 * (Well, some of the function names are the same, and bits of the structs..)
 * You can use it where it is useful, free even. Buy us a beer and stuff.
 *
 * The authors takes no responsibility for any damage or loss
 * of property which results from the use of this software.
 *
 * July 1999 - Rewrote a bunch of stuff here. Change hostent builder code,
 *     added callbacks and reference counting of returned hostents.
 *     --Bleep (Thomas Helvey <tomh@inxpress.net>)
 *
 * This was all needlessly complicated for irc. Simplified. No more hostent
 * All we really care about is the IP -> hostname mappings. Thats all.
 *
 * Apr 28, 2003 --cryogen and Dianora
 */
/** @file
 * @brief IRC resolver functions.
 * @version $Id$
 */

#include "client.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_osdep.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "ircd.h"
#include "numeric.h"
#include "fileio.h" /* for fbopen / fbclose / fbputs */
#include "random.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_stats.h"
#include "send.h"
#include "sys.h"
#include "res.h"
#include "ircd_reslib.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <time.h>

#if (CHAR_BIT != 8)
#error this code needs to be able to address individual octets 
#endif

/** IPv4 resolver UDP socket. */
static struct Socket res_socket_v4;
/** IPv6 resolver UDP socket. */
static struct Socket res_socket_v6;
/** Next DNS lookup timeout. */
static struct Timer res_timeout;
/** Local address for IPv4 DNS lookups. */
struct irc_sockaddr VirtualHost_dns_v4;
/** Local address for IPv6 DNS lookups. */
struct irc_sockaddr VirtualHost_dns_v6;
/** Check for whether the resolver has been initialized yet. */
#define resolver_started() (request_list.next != NULL)

/** Maximum DNS packet length.
 * RFC says 512, but we add extra for expanded names.
 */
#define MAXPACKET      1024
#define AR_TTL         600   /**< TTL in seconds for dns cache entries */

/* RFC 1104/1105 wasn't very helpful about what these fields
 * should be named, so for now, we'll just name them this way.
 * we probably should look at what named calls them or something.
 */
/** Size of TYPE field of a DNS RR header. */
#define TYPE_SIZE         (size_t)2
/** Size of CLASS field of a DNS RR header. */
#define CLASS_SIZE        (size_t)2
/** Size of TTL field of a DNS RR header. */
#define TTL_SIZE          (size_t)4
/** Size of RDLENGTH field of a DNS RR header. */
#define RDLENGTH_SIZE     (size_t)2
/** Size of fixed-format part of a DNS RR header. */
#define ANSWER_FIXED_SIZE (TYPE_SIZE + CLASS_SIZE + TTL_SIZE + RDLENGTH_SIZE)

/** Current request state. */
typedef enum
{
  REQ_IDLE,  /**< We're doing not much at all. */
  REQ_PTR,   /**< Looking up a PTR. */
  REQ_A,     /**< Looking up an A, possibly because AAAA failed. */
  REQ_AAAA,  /**< Looking up an AAAA. */
  REQ_CNAME, /**< We got a CNAME in response, we better get a real answer next. */
  REQ_INT    /**< ip6.arpa failed, falling back to ip6.int. */
} request_state;

/** Doubly linked list node. */
struct dlink
{
    struct dlink *prev; /**< Previous element in list. */
    struct dlink *next; /**< Next element in list. */
};

/** A single resolver request.
 * (Do not be fooled by the "list" in the name.)
 */
struct reslist
{
  struct dlink node;       /**< Doubly linked list node. */
  int id;                  /**< Request ID (from request header). */
  int sent;                /**< Number of requests sent. */
  request_state state;     /**< State the resolver machine is in. */
  char type;               /**< Current request type. */
  char retries;            /**< Retry counter. */
  char sends;              /**< Number of sends (>1 means resent). */
  char resend;             /**< Send flag; 0 == don't resend. */
  time_t sentat;           /**< Timestamp we last sent this request. */
  time_t timeout;          /**< When this request times out. */
  struct irc_in_addr addr; /**< Address for this request. */
  char *name;              /**< Hostname for this request. */
  dns_callback_f callback; /**< Callback function on completion. */
  void *callback_ctx;      /**< Context pointer for callback. */
};

/** Base of request list. */
static struct dlink request_list;

static void rem_request(struct reslist *request);
static struct reslist *make_request(dns_callback_f callback, void *ctx);
static void do_query_name(dns_callback_f callback, void *ctx,
                          const char* name, struct reslist *request, int);
static void do_query_number(dns_callback_f callback, void *ctx,
                            const struct irc_in_addr *,
                            struct reslist *request);
static void query_name(const char *name, int query_class, int query_type,
                       struct reslist *request);
static int send_res_msg(const char *buf, int len, int count);
static void resend_query(struct reslist *request);
static int proc_answer(struct reslist *request, HEADER *header, char *, char *);
static struct reslist *find_id(int id);
static void res_readreply(struct Event *ev);
static void timeout_resolver(struct Event *notused);

extern struct irc_sockaddr irc_nsaddr_list[IRCD_MAXNS];
extern int irc_nscount;
extern char irc_domain[HOSTLEN + 1];

/** Prepare the resolver library to (optionally) accept a list of
 * DNS servers through add_dns_server().
 */
void clear_nameservers(void)
{
  irc_nscount = 0;
  memset(&VirtualHost_dns_v4, 0, sizeof(VirtualHost_dns_v4));
  memset(&VirtualHost_dns_v6, 0, sizeof(VirtualHost_dns_v6));
}

/** Check whether \a inp is a nameserver we use.
 * @param[in] inp Nameserver address.
 * @return Non-zero if we trust \a inp; zero if not.
 */
static int
res_ourserver(const struct irc_sockaddr *inp)
{
  int ns;

  for (ns = 0;  ns < irc_nscount;  ns++)
    if (!irc_in_addr_cmp(&inp->addr, &irc_nsaddr_list[ns].addr)
        && inp->port == irc_nsaddr_list[ns].port)
      return 1;

  return(0);
}

/** Start (or re-start) resolver.
 * This means read resolv.conf, initialize the list of pending
 * requests, open the resolver socket and initialize its timeout.
 */
void
restart_resolver(void)
{
  int need_v4;
  int need_v6;
  int ns;

  irc_res_init();

  if (!request_list.next)
    request_list.next = request_list.prev = &request_list;

  /* Check which address family (or families) our nameservers use. */
  for (need_v4 = need_v6 = ns = 0; ns < irc_nscount; ns++)
  {
    if (irc_in_addr_is_ipv4(&irc_nsaddr_list[ns].addr))
      need_v4 = 1;
    else
      need_v6 = 1;
  }

  /* If we need an IPv4 socket, and don't have one, open it. */
  if (need_v4 && !s_active(&res_socket_v4))
  {
    int fd = os_socket(&VirtualHost_dns_v4, SOCK_DGRAM, "Resolver UDPv4 socket", AF_INET);
    if (fd >= 0)
      socket_add(&res_socket_v4, res_readreply, NULL,
                 SS_DATAGRAM, SOCK_EVENT_READABLE, fd);
  }

#ifdef AF_INET6
  /* If we need an IPv6 socket, and don't have one, open it. */
  if (need_v6 && !s_active(&res_socket_v6))
  {
    int fd = os_socket(&VirtualHost_dns_v6, SOCK_DGRAM, "Resolver UDPv6 socket", AF_INET6);
    if (fd >= 0)
      socket_add(&res_socket_v6, res_readreply, NULL,
                 SS_DATAGRAM, SOCK_EVENT_READABLE, fd);
  }
#endif

  if (s_active(&res_socket_v4) || s_active(&res_socket_v6))
    timer_init(&res_timeout);
}

/** Append local domain to hostname if needed.
 * If \a hname does not contain any '.'s, append #irc_domain to it.
 * @param[in,out] hname Hostname to check.
 * @param[in] size Length of \a hname buffer.
 */
void
add_local_domain(char* hname, size_t size)
{
  /* try to fix up unqualified names 
   */
  if (strchr(hname, '.') == NULL)
  {
    if (irc_domain[0])
    {
      size_t len = strlen(hname);

      if ((strlen(irc_domain) + len + 2) < size)
      {
        hname[len++] = '.';
        strcpy(hname + len, irc_domain);
      }
    }
  }
}

/** Add a node to a doubly linked list.
 * @param[in,out] node Node to add to list.
 * @param[in,out] next Add \a node before this one.
 */
static void
add_dlink(struct dlink *node, struct dlink *next)
{
    node->prev = next->prev;
    node->next = next;
    node->prev->next = node;
    node->next->prev = node;
}

/** Remove a request from the list and free it.
 * @param[in] request Node to free.
 */
static void
rem_request(struct reslist *request)
{
  /* remove from dlist */
  request->node.prev->next = request->node.next;
  request->node.next->prev = request->node.prev;
  /* free memory */
  MyFree(request->name);
  MyFree(request);
}

/** Create a DNS request record for the server.
 * @param[in] query Callback information for caller.
 * @return Newly allocated and linked-in reslist.
 */
static struct reslist *
make_request(dns_callback_f callback, void *ctx)
{
  struct reslist *request;

  if (!resolver_started())
    restart_resolver();

  request = (struct reslist *)MyMalloc(sizeof(struct reslist));
  memset(request, 0, sizeof(struct reslist));

  request->state   = REQ_IDLE;
  request->sentat  = CurrentTime;
  request->retries = feature_int(FEAT_IRCD_RES_RETRIES);
  request->resend  = 1;
  request->timeout = feature_int(FEAT_IRCD_RES_TIMEOUT);
  memset(&request->addr, 0, sizeof(request->addr));
  request->callback = callback;
  request->callback_ctx = ctx;

  add_dlink(&request->node, &request_list);
  return(request);
}

/** Make sure that a timeout event will happen by the given time.
 * @param[in] when Latest time for timeout to run.
 */
static void
check_resolver_timeout(time_t when)
{
  if (when > CurrentTime + AR_TTL)
    when = CurrentTime + AR_TTL;
  /* TODO after 2.10.12: Rewrite the timer API because there should be
   * no need for clients to know this kind of implementation detail. */
  if (when > t_expire(&res_timeout))
    /* do nothing */;
  else if (t_onqueue(&res_timeout) && !(res_timeout.t_header.gh_flags & GEN_MARKED))
    timer_chg(&res_timeout, TT_ABSOLUTE, when);
  else
    timer_add(&res_timeout, timeout_resolver, NULL, TT_ABSOLUTE, when);
}

/** Drop pending DNS lookups which have timed out.
 * @param[in] ev Timer event data (ignored).
 */
static void
timeout_resolver(struct Event *ev)
{
  struct dlink *ptr, *next_ptr;
  struct reslist *request;
  time_t next_time = 0;
  time_t timeout   = 0;

  if (ev_type(ev) != ET_EXPIRE)
    return;

  for (ptr = request_list.next; ptr != &request_list; ptr = next_ptr)
  {
    next_ptr = ptr->next;
    request = (struct reslist*)ptr;
    timeout = request->sentat + request->timeout;

    if (CurrentTime >= timeout)
    {
      if (--request->retries <= 0)
      {
        Debug((DEBUG_DNS, "Request %p out of retries; destroying", request));
        (*request->callback)(request->callback_ctx, NULL, NULL);
        rem_request(request);
        continue;
      }
      else
      {
        request->sentat = CurrentTime;
        request->timeout += request->timeout;
        resend_query(request);
      }
    }

    if ((next_time == 0) || timeout < next_time)
    {
      next_time = timeout;
    }
  }

  if (next_time <= CurrentTime)
    next_time = CurrentTime + AR_TTL;
  check_resolver_timeout(next_time);
}

/** Drop queries that are associated with a particular pointer.
 * This is used to clean up lookups for clients or conf blocks
 * that went away.
 * @param[in] vptr User callback pointer to search for.
 */
void
delete_resolver_queries(const void *vptr)
{
  struct dlink *ptr, *next_ptr;
  struct reslist *request;

  if (request_list.next) {
    for (ptr = request_list.next; ptr != &request_list; ptr = next_ptr)
    {
      next_ptr = ptr->next;
      request = (struct reslist*)ptr;
      if (vptr == request->callback_ctx) {
        Debug((DEBUG_DNS, "Removing request %p with vptr %p", request, vptr));
        rem_request(request);
      }
    }
  }
}

/** Send a message to all of our nameservers.
 * @param[in] msg Message to send.
 * @param[in] len Length of message.
 * @param[in] rcount Maximum number of servers to ask.
 * @return Number of servers that were successfully asked.
 */
static int
send_res_msg(const char *msg, int len, int rcount)
{
  int i;
  int sent = 0;
  int max_queries = IRCD_MIN(irc_nscount, rcount);

  /* RES_PRIMARY option is not implemented
   * if (res.options & RES_PRIMARY || 0 == max_queries)
   */
  if (max_queries == 0)
    max_queries = 1;

  for (i = 0; i < max_queries; i++) {
    int fd = irc_in_addr_is_ipv4(&irc_nsaddr_list[i].addr) ? s_fd(&res_socket_v4) : s_fd(&res_socket_v6);
    if (os_sendto_nonb(fd, msg, len, NULL, 0, &irc_nsaddr_list[i]) == IO_SUCCESS)
      ++sent;
  }

  return(sent);
}

/** Find a DNS request by ID.
 * @param[in] id Identifier to find.
 * @return Matching DNS request, or NULL if none are found.
 */
static struct reslist *
find_id(int id)
{
  struct dlink *ptr;
  struct reslist *request;

  for (ptr = request_list.next; ptr != &request_list; ptr = ptr->next)
  {
    request = (struct reslist*)ptr;

    if (request->id == id) {
      Debug((DEBUG_DNS, "find_id(%d) -> %p", id, request));
      return(request);
    }
  }

  Debug((DEBUG_DNS, "find_id(%d) -> NULL", id));
  return(NULL);
}

/** Try to look up address for a hostname, trying IPv6 (T_AAAA) first.
 * @param[in] name Hostname to look up.
 * @param[in] query Callback information.
 */
void
gethost_byname(const char *name, dns_callback_f callback, void *ctx)
{
  do_query_name(callback, ctx, name, NULL, T_AAAA);
}

/** Try to look up hostname for an address.
 * @param[in] addr Address to look up.
 * @param[in] query Callback information.
 */
void
gethost_byaddr(const struct irc_in_addr *addr, dns_callback_f callback, void *ctx)
{
  do_query_number(callback, ctx, addr, NULL);
}

/** Send a query to look up the address for a name.
 * @param[in] query Callback information.
 * @param[in] name Hostname to look up.
 * @param[in] request DNS lookup structure (may be NULL).
 * @param[in] type Preferred request type.
 */
static void
do_query_name(dns_callback_f callback, void *ctx, const char *name,
              struct reslist *request, int type)
{
  char host_name[HOSTLEN + 1];

  ircd_strncpy(host_name, name, HOSTLEN);
  add_local_domain(host_name, HOSTLEN);

  if (request == NULL)
  {
    request       = make_request(callback, ctx);
    DupString(request->name, host_name);
#ifdef IPV6
    if (type != T_A)
      request->state = REQ_AAAA;
    else
#endif
    request->state = REQ_A;
  }

  request->type = type;
  Debug((DEBUG_DNS, "Requesting DNS %s %s as %p", (request->state == REQ_AAAA ? "AAAA" : "A"), host_name, request));
  query_name(host_name, C_IN, type, request);
}

/** Send a query to look up the name for an address.
 * @param[in] query Callback information.
 * @param[in] addr Address to look up.
 * @param[in] request DNS lookup structure (may be NULL).
 */
static void
do_query_number(dns_callback_f callback, void *ctx, const struct irc_in_addr *addr,
                struct reslist *request)
{
  char ipbuf[128];
  const unsigned char *cp;

  if (irc_in_addr_is_ipv4(addr))
  {
    cp = (const unsigned char*)&addr->in6_16[6];
    ircd_snprintf(NULL, ipbuf, sizeof(ipbuf), "%u.%u.%u.%u.in-addr.arpa.",
                  (unsigned int)(cp[3]), (unsigned int)(cp[2]),
                  (unsigned int)(cp[1]), (unsigned int)(cp[0]));
  }
  else
  {
    const char *intarpa;

    if (request != NULL && request->state == REQ_INT)
      intarpa = "int";
    else
      intarpa = "arpa";

    cp = (const unsigned char *)&addr->in6_16[0];
    ircd_snprintf(NULL, ipbuf, sizeof(ipbuf),
                  "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
                  "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.ip6.%s.",
                  (unsigned int)(cp[15]&0xf), (unsigned int)(cp[15]>>4),
                  (unsigned int)(cp[14]&0xf), (unsigned int)(cp[14]>>4),
                  (unsigned int)(cp[13]&0xf), (unsigned int)(cp[13]>>4),
                  (unsigned int)(cp[12]&0xf), (unsigned int)(cp[12]>>4),
                  (unsigned int)(cp[11]&0xf), (unsigned int)(cp[11]>>4),
                  (unsigned int)(cp[10]&0xf), (unsigned int)(cp[10]>>4),
                  (unsigned int)(cp[9]&0xf), (unsigned int)(cp[9]>>4),
                  (unsigned int)(cp[8]&0xf), (unsigned int)(cp[8]>>4),
                  (unsigned int)(cp[7]&0xf), (unsigned int)(cp[7]>>4),
                  (unsigned int)(cp[6]&0xf), (unsigned int)(cp[6]>>4),
                  (unsigned int)(cp[5]&0xf), (unsigned int)(cp[5]>>4),
                  (unsigned int)(cp[4]&0xf), (unsigned int)(cp[4]>>4),
                  (unsigned int)(cp[3]&0xf), (unsigned int)(cp[3]>>4),
                  (unsigned int)(cp[2]&0xf), (unsigned int)(cp[2]>>4),
                  (unsigned int)(cp[1]&0xf), (unsigned int)(cp[1]>>4),
                  (unsigned int)(cp[0]&0xf), (unsigned int)(cp[0]>>4), intarpa);
  }
  if (request == NULL)
  {
    request       = make_request(callback, ctx);
    request->state= REQ_PTR;
    request->type = T_PTR;
    memcpy(&request->addr, addr, sizeof(request->addr));
    request->name = (char *)MyMalloc(HOSTLEN + 1);
  }
  Debug((DEBUG_DNS, "Requesting DNS PTR %s as %p", ipbuf, request));
  query_name(ipbuf, C_IN, T_PTR, request);
}

/** Generate a query based on class, type and name.
 * @param[in] name Domain name to look up.
 * @param[in] query_class Query class (see RFC 1035).
 * @param[in] type Query type (see RFC 1035).
 * @param[in] request DNS request structure.
 */
static void
query_name(const char *name, int query_class, int type,
           struct reslist *request)
{
  char buf[MAXPACKET];
  int request_len = 0;

  memset(buf, 0, sizeof(buf));

  if ((request_len = irc_res_mkquery(name, query_class, type,
      (unsigned char *)buf, sizeof(buf))) > 0)
  {
    HEADER *header = (HEADER *)buf;

    /*
     * generate an unique id
     * NOTE: we don't have to worry about converting this to and from
     * network byte order, the nameserver does not interpret this value
     * and returns it unchanged
     */
    do
    {
      header->id = (header->id + ircrandom()) & 0xffff;
    } while (find_id(header->id));
    request->id = header->id;
    ++request->sends;

    request->sent += send_res_msg(buf, request_len, request->sends);
    check_resolver_timeout(request->sentat + request->timeout);
  }
}

/** Send a failed DNS lookup request again.
 * @param[in] request Request to resend.
 */
static void
resend_query(struct reslist *request)
{
  if (request->resend == 0)
    return;

  switch(request->type)
  {
    case T_PTR:
      do_query_number(NULL, NULL, &request->addr, request);
      break;
    case T_A:
      do_query_name(NULL, NULL, request->name, request, request->type);
      break;
    case T_AAAA:
      /* didn't work, try A */
      if (request->state == REQ_AAAA)
        do_query_name(NULL, NULL, request->name, request, T_A);
    default:
      break;
  }
}

/** Process the answer for a lookup request.
 * @param[in] request DNS request that got an answer.
 * @param[in] header Header of DNS response.
 * @param[in] buf DNS response body.
 * @param[in] eob Pointer to end of DNS response.
 * @return Number of answers read from \a buf.
 */
static int
proc_answer(struct reslist *request, HEADER* header, char* buf, char* eob)
{
  char hostbuf[HOSTLEN + 100]; /* working buffer */
  unsigned char *current;      /* current position in buf */
  int type;                    /* answer type */
  int n;                       /* temp count */
  int rd_length;

  current = (unsigned char *)buf + sizeof(HEADER);

  for (; header->qdcount > 0; --header->qdcount)
  {
    if ((n = irc_dn_skipname(current, (unsigned char *)eob)) < 0)
      break;

    current += (size_t) n + QFIXEDSZ;
  }

  /*
   * process each answer sent to us blech.
   */
  while (header->ancount > 0 && (char *)current < eob)
  {
    header->ancount--;

    n = irc_dn_expand((unsigned char *)buf, (unsigned char *)eob, current,
        hostbuf, sizeof(hostbuf));

    if (n < 0)
    {
      /*
       * broken message
       */
      return(0);
    }
    else if (n == 0)
    {
      /*
       * no more answers left
       */
      return(0);
    }

    hostbuf[HOSTLEN] = '\0';

    /* With Address arithmetic you have to be very anal
     * this code was not working on alpha due to that
     * (spotted by rodder/jailbird/dianora)
     */
    current += (size_t) n;

    if (!(((char *)current + ANSWER_FIXED_SIZE) < eob))
      break;

    type = irc_ns_get16(current);
    current += TYPE_SIZE;

    /* We do not use the class or TTL values. */
    current += CLASS_SIZE;
    current += TTL_SIZE;

    rd_length = irc_ns_get16(current);
    current += RDLENGTH_SIZE;

    /*
     * Wait to set request->type until we verify this structure
     */
    switch (type)
    {
      case T_A:
        if (request->type != T_A)
          return(0);

        /*
         * check for invalid rd_length or too many addresses
         */
        if (rd_length != sizeof(struct in_addr))
          return(0);
        memset(&request->addr, 0, sizeof(request->addr));
        memcpy(&request->addr.in6_16[6], current, sizeof(struct in_addr));
        return(1);
        break;
      case T_AAAA:
        if (request->type != T_AAAA)
          return(0);
        if (rd_length != sizeof(struct irc_in_addr))
          return(0);
        memcpy(&request->addr, current, sizeof(struct irc_in_addr));
        return(1);
        break;
      case T_PTR:
        if (request->type != T_PTR)
          return(0);
        n = irc_dn_expand((unsigned char *)buf, (unsigned char *)eob,
            current, hostbuf, sizeof(hostbuf));
        if (n < 0)
          return(0); /* broken message */
        else if (n == 0)
          return(0); /* no more answers left */

        ircd_strncpy(request->name, hostbuf, HOSTLEN);

        return(1);
        break;
      case T_CNAME: /* first check we already haven't started looking
                       into a cname */
        if (request->state == REQ_CNAME)
        {
          n = irc_dn_expand((unsigned char *)buf, (unsigned char *)eob,
                            current, hostbuf, sizeof(hostbuf));

          if (n < 0)
            return(0);
          return(1);
        }

        request->state = REQ_CNAME;
        current += rd_length;
        break;

      default:
        /* XXX I'd rather just throw away the entire bogus thing
         * but its possible its just a broken nameserver with still
         * valid answers. But lets do some rudimentary logging for now...
         */
        log_write(LS_RESOLVER, L_ERROR, 0, "irc_res.c bogus type %d", type);

        if ((char*)current + rd_length >= (char*)current)
          current += rd_length;
        else
          return(0);

        break;
    }
  }

  return(1);
}

/** Read a DNS reply from the nameserver and process it.
 * @param[in] ev I/O activity event for resolver socket.
 */
static void
res_readreply(struct Event *ev)
{
  struct irc_sockaddr lsin;
  struct Socket *sock;
  char buf[sizeof(HEADER) + MAXPACKET];
  HEADER *header;
  struct reslist *request = NULL;
  unsigned int rc;
  int answer_count;

  assert((ev_socket(ev) == &res_socket_v4) || (ev_socket(ev) == &res_socket_v6));
  sock = ev_socket(ev);

  if (IO_SUCCESS != os_recvfrom_nonb(s_fd(sock), buf, sizeof(buf), &rc, &lsin)
      || (rc <= sizeof(HEADER)))
    return;

  /*
   * check against possibly fake replies
   */
  if (!res_ourserver(&lsin))
    return;

  /*
   * convert DNS reply reader from Network byte order to CPU byte order.
   */
  header = (HEADER *)buf;
  header->ancount = ntohs(header->ancount);
  header->qdcount = ntohs(header->qdcount);
  header->nscount = ntohs(header->nscount);
  header->arcount = ntohs(header->arcount);

  /*
   * response for an id which we have already received an answer for
   * just ignore this response.
   */
  if (0 == (request = find_id(header->id)))
    return;

  if ((header->rcode != NO_ERRORS) || (header->ancount == 0))
  {
    if (SERVFAIL == header->rcode || NXDOMAIN == header->rcode)
    {
        /*
         * If a bad error was returned, we stop here and don't send
         * send any more (no retries granted).
         */
        Debug((DEBUG_DNS, "Request %p has bad response (state %d type %d rcode %d)", request, request->state, request->type, header->rcode));
        (*request->callback)(request->callback_ctx, NULL, NULL);
	rem_request(request);
    }
    else
    {
      /*
       * If we haven't already tried this, and we're looking up AAAA, try A
       * now
       */

      if (request->state == REQ_AAAA && request->type == T_AAAA)
      {
        request->timeout += feature_int(FEAT_IRCD_RES_TIMEOUT);
        resend_query(request);
      }
      else if (request->type == T_PTR && request->state != REQ_INT &&
               !irc_in_addr_is_ipv4(&request->addr))
      {
        request->state = REQ_INT;
        request->timeout += feature_int(FEAT_IRCD_RES_TIMEOUT);
        resend_query(request);
      }
    }

    return;
  }
  /*
   * If this fails there was an error decoding the received packet,
   * try it again and hope it works the next time.
   */
  answer_count = proc_answer(request, header, buf, buf + rc);

  if (answer_count)
  {
    if (request->type == T_PTR)
    {
      if (request->name == NULL)
      {
        /*
         * got a PTR response with no name, something bogus is happening
         * don't bother trying again, the client address doesn't resolve
         */
        Debug((DEBUG_DNS, "Request %p PTR had empty name", request));
        (*request->callback)(request->callback_ctx, NULL, NULL);
        rem_request(request);
        return;
      }

      /*
       * Lookup the 'authoritative' name that we were given for the
       * ip#.
       */
#ifdef IPV6
      if (!irc_in_addr_is_ipv4(&request->addr))
        do_query_name(request->callback, request->callback_ctx, request->name, NULL, T_AAAA);
      else
#endif
      do_query_name(request->callback, request->callback_ctx, request->name, NULL, T_A);
      Debug((DEBUG_DNS, "Request %p switching to forward resolution", request));
      rem_request(request);
    }
    else
    {
      /*
       * got a name and address response, client resolved
       */
      (*request->callback)(request->callback_ctx, &request->addr, request->name);
      Debug((DEBUG_DNS, "Request %p got forward resolution", request));
      rem_request(request);
    }
  }
  else if (!request->sent)
  {
    /* XXX - we got a response for a query we didn't send with a valid id?
     * this should never happen, bail here and leave the client unresolved
     */
    assert(0);

    /* XXX don't leak it */
    Debug((DEBUG_DNS, "Request %p was unexpected(!)", request));
    rem_request(request);
  }
}

/** Statistics callback to list DNS servers.
 * @param[in] source_p Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
void
report_dns_servers(struct Client *source_p, const struct StatDesc *sd, char *param)
{
  int i;
  char ipaddr[128];

  for (i = 0; i < irc_nscount; i++)
  {
    ircd_ntoa_r(ipaddr, &irc_nsaddr_list[i].addr);
    send_reply(source_p, RPL_STATSALINE, ipaddr);
  }
}

/** Report memory usage to a client.
 * @param[in] sptr Client requesting information.
 * @return Total memory used by pending requests.
 */
size_t
cres_mem(struct Client* sptr)
{
  struct dlink *dlink;
  struct reslist *request;
  size_t request_mem   = 0;
  int    request_count = 0;

  if (request_list.next) {
    for (dlink = request_list.next; dlink != &request_list; dlink = dlink->next) {
      request = (struct reslist*)dlink;
      request_mem += sizeof(*request);
      if (request->name)
        request_mem += strlen(request->name) + 1;
      ++request_count;
    }
  }

  send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Resolver: requests %d(%d)", request_count, request_mem);
  return request_mem;
}
