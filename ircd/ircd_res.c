/*
 * A rewrite of Darren Reeds original res.c As there is nothing
 * left of Darrens original code, this is now licensed by the hybrid group.
 * (Well, some of the function names are the same, and bits of the structs..)
 * You can use it where it is useful, free even. Buy us a beer and stuff.
 *
 * The authors takes no responsibility for any damage or loss
 * of property which results from the use of this software.
 *
 * $Id$
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
#include "s_bsd.h"
#include "s_stats.h"
#include "send.h"
#include "sys.h"
#include "res.h"
#include "ircd_reslib.h"
#include "ircd_addrinfo.h"

#include <assert.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <time.h>

#if (CHAR_BIT != 8)
#error this code needs to be able to address individual octets 
#endif

static struct Socket res_socket;
static struct Timer res_timeout;

#define MAXPACKET      1024  /* rfc sez 512 but we expand names so ... */
#define RES_MAXALIASES 35    /* maximum aliases allowed */
#define RES_MAXADDRS   35    /* maximum addresses allowed */
#define AR_TTL         600   /* TTL in seconds for dns cache entries */

/* RFC 1104/1105 wasn't very helpful about what these fields
 * should be named, so for now, we'll just name them this way.
 * we probably should look at what named calls them or something.
 */
#define TYPE_SIZE         (size_t)2
#define CLASS_SIZE        (size_t)2
#define TTL_SIZE          (size_t)4
#define RDLENGTH_SIZE     (size_t)2
#define ANSWER_FIXED_SIZE (TYPE_SIZE + CLASS_SIZE + TTL_SIZE + RDLENGTH_SIZE)

typedef enum 
{
  REQ_IDLE,  /* We're doing not much at all */
  REQ_PTR,   /* Looking up a PTR */
  REQ_A,     /* Looking up an A, possibly because AAAA failed */
#ifdef IPV6
  REQ_AAAA,  /* Looking up an AAAA */
#endif
  REQ_CNAME, /* We got a CNAME in response, we better get a real answer next */
  REQ_INT    /* ip6.arpa failed, falling back to ip6.int */
} request_state;

struct dlink
{
    struct dlink *prev;
    struct dlink *next;
};

struct reslist 
{
  struct dlink node;
  int id;
  int sent;                /* number of requests sent */
  request_state state;     /* State the resolver machine is in */
  time_t ttl;
  char type;
  char retries;            /* retry counter */
  char sends;              /* number of sends (>1 means resent) */
  char resend;             /* send flag. 0 == dont resend */
  time_t sentat;
  time_t timeout;
  struct irc_ssaddr addr;
  char *name;
  struct DNSQuery query;   /* query callback for this request */
};

static struct dlink request_list;

static void rem_request(struct reslist *request);
static struct reslist *make_request(const struct DNSQuery *query);
static void do_query_name(const struct DNSQuery *query,
                          const char* name, struct reslist *request, int);
static void do_query_number(const struct DNSQuery *query,
                            const struct irc_ssaddr *,
                            struct reslist *request);
static void query_name(const char *name, int query_class, int query_type, 
                       struct reslist *request);
static int send_res_msg(const char *buf, int len, int count);
static void resend_query(struct reslist *request);
static int proc_answer(struct reslist *request, HEADER *header, char *, char *);
static struct reslist *find_id(int id);
static struct DNSReply *make_dnsreply(struct reslist *request);
static void res_readreply(struct Event *ev);
static void timeout_resolver(struct Event *notused);

extern struct irc_ssaddr irc_nsaddr_list[IRCD_MAXNS];
extern int irc_nscount;
extern char irc_domain[HOSTLEN];

/*
 * int
 * res_ourserver(inp)
 *      looks up "inp" in irc_nsaddr_list[]
 * returns:
 *      0  : not found
 *      >0 : found
 * author:
 *      paul vixie, 29may94
 *      revised for ircd, cryogen(stu) may03
 */
static int
res_ourserver(const struct irc_ssaddr *inp) 
{
#ifdef IPV6
  struct sockaddr_in6 *v6;
  struct sockaddr_in6 *v6in = (struct sockaddr_in6 *)inp;
#endif
  struct sockaddr_in *v4;
  struct sockaddr_in *v4in = (struct sockaddr_in *)inp; 
  int ns;

  for (ns = 0;  ns < irc_nscount;  ns++)
  {
    const struct irc_ssaddr *srv = &irc_nsaddr_list[ns];
#ifdef IPV6
    v6 = (struct sockaddr_in6 *)srv;
#endif
    v4 = (struct sockaddr_in *)srv;

    /* could probably just memcmp(srv, inp, srv.ss_len) here
     * but we'll air on the side of caution - stu
     *
     */
    switch (srv->ss.ss_family)
    {
#ifdef IPV6
      case AF_INET6:
        if (srv->ss.ss_family == inp->ss.ss_family)
          if (v6->sin6_port == v6in->sin6_port)
            if ((memcmp(&v6->sin6_addr.s6_addr, &v6in->sin6_addr.s6_addr, 
                    sizeof(struct in6_addr)) == 0) || 
                (memcmp(&v6->sin6_addr.s6_addr, &in6addr_any, 
                        sizeof(struct in6_addr)) == 0))
              return(1);
        break;
#endif
      case AF_INET:
        if (srv->ss.ss_family == inp->ss.ss_family)
          if (v4->sin_port == v4in->sin_port)
            if ((v4->sin_addr.s_addr == INADDR_ANY) || 
                (v4->sin_addr.s_addr == v4in->sin_addr.s_addr))
              return(1);
        break;
      default:
        break;
    }
  }

  return(0);
}

/*
 * start_resolver - do everything we need to read the resolv.conf file
 * and initialize the resolver file descriptor if needed
 */
static void
start_resolver(void)
{
  irc_res_init();

  if (!request_list.next)
      request_list.next = request_list.prev = &request_list;

  if (!s_active(&res_socket))
  {
    int fd;
    fd = socket(irc_nsaddr_list[0].ss.ss_family, SOCK_DGRAM, 0);
    if (fd < 0) {} /* TODO: bail on socket() failure */
    if (!os_set_nonblocking(fd)) {} /* TODO: bail on failure */
    if (!socket_add(&res_socket, res_readreply, NULL, SS_DATAGRAM,
                    SOCK_EVENT_READABLE, fd)) {} /* TODO: bail on socket_add() failure */
    timer_init(&res_timeout);
    timer_add(&res_timeout, timeout_resolver, NULL, TT_PERIODIC, 1);
  }
}

/*
 * init_resolver - initialize resolver and resolver library
 */
int
init_resolver(void)
{
#ifdef LRAND48
  srand48(CurrentTime);
#endif
  start_resolver();
  return(s_fd(&res_socket));
}

/*
 * restart_resolver - reread resolv.conf, reopen socket
 */
void
restart_resolver(void)
{
  start_resolver();
}

/*
 * add_local_domain - Add the domain to hostname, if it is missing
 * (as suggested by eps@TOASTER.SFSU.EDU)
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

/*
 * remove_dlink - remove a link from a doubly linked list
 */
static void
remove_dlink(struct dlink *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;
}

/*
 * add_dlink - add a link to a doubly linked list
 */
static void
add_dlink(struct dlink *node, struct dlink *next)
{
    node->prev = next->prev;
    node->next = next;
    node->prev->next = node;
    node->next->prev = node;
}

/*
 * rem_request - remove a request from the list. 
 * This must also free any memory that has been allocated for 
 * temporary storage of DNS results.
 */
static void
rem_request(struct reslist *request)
{
  remove_dlink(&request->node);
  MyFree(request->name);
  MyFree(request);
}

/*
 * make_request - Create a DNS request record for the server.
 */
static struct reslist *
make_request(const struct DNSQuery* query)
{
  struct reslist *request;

  request = (struct reslist *)MyMalloc(sizeof(struct reslist));
  memset(request, 0, sizeof(struct reslist));

  request->sentat  = CurrentTime;
  request->retries = 3;
  request->resend  = 1;
  request->timeout = 4;    /* start at 4 and exponential inc. */
  memset(&request->addr, 0, sizeof(request->addr));
  request->query.vptr     = query->vptr;
  request->query.callback = query->callback;
  request->state          = REQ_IDLE;

  add_dlink(&request->node, &request_list);
  return(request);
}

/*
 * timeout_query_list - Remove queries from the list which have been 
 * there too long without being resolved.
 */
static time_t
timeout_query_list(time_t now)
{
  struct dlink *ptr, *next_ptr;
  struct reslist *request;
  time_t next_time = 0;
  time_t timeout   = 0;

  for (ptr = request_list.next; ptr != &request_list; ptr = next_ptr)
  {
    next_ptr = ptr->next;
    request = (struct reslist*)ptr;
    timeout = request->sentat + request->timeout;

    if (now >= timeout)
    {
      if (--request->retries <= 0)
      {
        (*request->query.callback)(request->query.vptr, 0);
        rem_request(request);
        continue;
      }
      else
      {
        request->sentat = now;
        request->timeout += request->timeout;
        resend_query(request);
      }
    }

    if ((next_time == 0) || timeout < next_time)
    {
      next_time = timeout;
    }
  }

  return((next_time > now) ? next_time : (now + AR_TTL));
}

/*
 * timeout_resolver - check request list
 */
static void
timeout_resolver(struct Event *notused)
{
  timeout_query_list(CurrentTime);
}

/*
 * delete_resolver_queries - cleanup outstanding queries 
 * for which there no longer exist clients or conf lines.
 */
void
delete_resolver_queries(const void *vptr)
{
  struct dlink *ptr, *next_ptr;
  struct reslist *request;

  for (ptr = request_list.next; ptr != &request_list; ptr = next_ptr)
  {
    next_ptr = ptr->next;
    request = (struct reslist*)ptr;
    if (vptr == request->query.vptr)
      rem_request(request);
  }
}

/*
 * send_res_msg - sends msg to all nameservers found in the "_res" structure.
 * This should reflect /etc/resolv.conf. We will get responses
 * which arent needed but is easier than checking to see if nameserver
 * isnt present. Returns number of messages successfully sent to 
 * nameservers or -1 if no successful sends.
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

  for (i = 0; i < max_queries; i++)
  {
    if (sendto(s_fd(&res_socket), msg, len, 0, 
        (struct sockaddr*)&(irc_nsaddr_list[i]), 
        irc_nsaddr_list[i].ss_len) == len) 
      ++sent;
  }

  return(sent);
}

/*
 * find_id - find a dns request id (id is determined by dn_mkquery)
 */
static struct reslist *
find_id(int id)
{
  struct dlink *ptr;
  struct reslist *request;

  for (ptr = request_list.next; ptr != &request_list; ptr = ptr->next)
  {
    request = (struct reslist*)ptr;

    if (request->id == id)
      return(request);
  }

  return(NULL);
}

/* 
 * gethost_byname_type - get host address from name
 *
 */
void
gethost_byname_type(const char *name, const struct DNSQuery *query, int type)
{
  assert(name != 0);
  do_query_name(query, name, NULL, type);
}

/*
 * gethost_byname - wrapper for _type - send T_AAAA first
 */
void
gethost_byname(const char *name, const struct DNSQuery *query)
{
  gethost_byname_type(name, query, T_AAAA);
}

/*
 * gethost_byaddr - get host name from address
 */
void
gethost_byaddr(const struct irc_ssaddr *addr, const struct DNSQuery *query)
{
  do_query_number(query, addr, NULL);
}

/*
 * gethost_byinaddr - kludgy hack for IPv4-only compatibility
 */
void
gethost_byinaddr(const struct in_addr *addr, const struct DNSQuery *query)
{
  struct irc_ssaddr new_addr;
  struct sockaddr_in *sin;
  memset(&new_addr, 0, sizeof(new_addr));
  sin = (struct sockaddr_in*)&new_addr.ss;
  sin->sin_family = AF_INET;
  memcpy(&sin->sin_addr, addr, sizeof(sin->sin_addr));
  new_addr.ss_len = sizeof(*sin);
  gethost_byaddr(&new_addr, query);
}

/*
 * do_query_name - nameserver lookup name
 */
static void
do_query_name(const struct DNSQuery *query, const char *name,
              struct reslist *request, int type)
{
  char host_name[HOSTLEN + 1];

  ircd_strncpy(host_name, name, HOSTLEN);
  add_local_domain(host_name, HOSTLEN);

  if (request == NULL)
  {
    request       = make_request(query);
    request->name = (char *)MyMalloc(strlen(host_name) + 1);
    request->type = type;
    strcpy(request->name, host_name);
#ifdef IPV6
    if (type != T_A)
      request->state = REQ_AAAA;
    else
#endif
    request->state = REQ_A;
  }

  request->type = type;
  query_name(host_name, C_IN, type, request);
}

/*
 * do_query_number - Use this to do reverse IP# lookups.
 */
static void
do_query_number(const struct DNSQuery *query, const struct irc_ssaddr *addr,
                struct reslist *request)
{
  char ipbuf[128];
  const unsigned char *cp;
#ifdef IPV6
  const char *intarpa;
#endif
  if (addr->ss.ss_family == AF_INET)
  {
    struct sockaddr_in *v4 = (struct sockaddr_in *)addr;
    cp = (const unsigned char*)&v4->sin_addr.s_addr;

    ircd_snprintf(NULL, ipbuf, sizeof(ipbuf),
                  "%u.%u.%u.%u.in-addr.arpa.",
                  (unsigned int)(cp[3]), (unsigned int)(cp[2]),
                  (unsigned int)(cp[1]), (unsigned int)(cp[0]));
  }
#ifdef IPV6
  else if (addr->ss.ss_family == AF_INET6)
  {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)addr;
    cp = (const unsigned char *)&v6->sin6_addr.s6_addr;

    if (request != NULL && request->state == REQ_INT)
      intarpa = "int";
    else
      intarpa = "arpa";

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
#endif
  if (request == NULL)
  {
    request       = make_request(query);
    request->type = T_PTR;
    memcpy(&request->addr, addr, sizeof(struct irc_ssaddr));
    request->name = (char *)MyMalloc(HOSTLEN + 1);
  }

  query_name(ipbuf, C_IN, T_PTR, request);
}

/*
 * query_name - generate a query based on class, type and name.
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
#ifndef LRAND48
    int k = 0;
    struct timeval tv;
#endif
    /*
     * generate an unique id
     * NOTE: we don't have to worry about converting this to and from
     * network byte order, the nameserver does not interpret this value
     * and returns it unchanged
     */
#ifdef LRAND48
    do
    {
      header->id = (header->id + lrand48()) & 0xffff;
    } while (find_id(header->id));
#else
    gettimeofday(&tv, NULL);

    do
    {
      header->id = (header->id + k + tv.tv_usec) & 0xffff;
      k++;
    } while (find_id(header->id));
#endif /* LRAND48 */
    request->id = header->id;
    ++request->sends;

    request->sent += send_res_msg(buf, request_len, request->sends);
  }
}

static void
resend_query(struct reslist *request)
{
  if (request->resend == 0)
    return;

  switch(request->type)
  {
    case T_PTR:
      do_query_number(NULL, &request->addr, request);
      break;
    case T_A:
      do_query_name(NULL, request->name, request, request->type);
      break;
#ifdef IPV6
    case T_AAAA:
      /* didnt work, try A */
      if (request->state == REQ_AAAA)
        do_query_name(NULL, request->name, request, T_A);
#endif
    default:
      break;
  }
}

/*
 * proc_answer - process name server reply
 */
static int
proc_answer(struct reslist *request, HEADER* header, char* buf, char* eob)
{
  char hostbuf[HOSTLEN + 100]; /* working buffer */
  unsigned char *current;      /* current position in buf */
  int query_class;             /* answer class */
  int type;                    /* answer type */
  int n;                       /* temp count */
  int rd_length;
  struct sockaddr_in *v4;      /* conversion */
#ifdef IPV6
  struct sockaddr_in6 *v6;
#endif
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

    query_class = irc_ns_get16(current);
    current += CLASS_SIZE;

    request->ttl = irc_ns_get32(current);
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
        v4 = (struct sockaddr_in *)&request->addr;
        request->addr.ss_len = sizeof(struct sockaddr_in);
        v4->sin_family = AF_INET;
        memcpy(&v4->sin_addr, current, sizeof(struct in_addr));
        return(1);
        break;
#ifdef IPV6
      case T_AAAA:
        if (request->type != T_AAAA)
          return(0);
        if (rd_length != sizeof(struct in6_addr))
          return(0);
        request->addr.ss_len = sizeof(struct sockaddr_in6);
        v6 = (struct sockaddr_in6 *)&request->addr;
        v6->sin6_family = AF_INET6;
        memcpy(&v6->sin6_addr, current, sizeof(struct in6_addr));
        return(1);
        break;
#endif
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
      case T_CNAME: /* first check we already havent started looking 
                       into a cname */
        if (request->type != T_PTR) 
          return(0);

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
        break;
    }
  }

  return(1);
}

/*
 * res_readreply - read a dns reply from the nameserver and process it.
 */
static void
res_readreply(struct Event *ev)
{
  struct Socket *sock;
  char buf[sizeof(HEADER) + MAXPACKET];
  HEADER *header;
  struct reslist *request = NULL;
  struct DNSReply *reply  = NULL;
  int rc;
  int answer_count;
  socklen_t len = sizeof(struct irc_ssaddr);
  struct irc_ssaddr lsin;

  assert(ev_socket(ev) == &res_socket);
  sock = ev_socket(ev);

  rc = recvfrom(s_fd(sock), buf, sizeof(buf), 0, (struct sockaddr *)&lsin, &len);
  /* Better to cast the sizeof instead of rc */
  if (rc <= (int)(sizeof(HEADER)))
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

  /*
   * check against possibly fake replies
   */
  if (!res_ourserver(&lsin))
    return;

  if ((header->rcode != NO_ERRORS) || (header->ancount == 0))
  {
    if (SERVFAIL == header->rcode)
      resend_query(request);
    else
    {
      /* 
       * If we havent already tried this, and we're looking up AAAA, try A
       * now
       */

#ifdef IPV6
      if (request->state == REQ_AAAA && request->type == T_AAAA)
      {
        request->timeout += 4;
        resend_query(request);
      }
      else if (request->type == T_PTR && request->state != REQ_INT &&
               request->addr.ss.ss_family == AF_INET6)
      {
        request->state = REQ_INT;
        request->timeout += 4;
        resend_query(request);
      }
      else
#endif
      {
        /*
         * If a bad error was returned, we stop here and dont send
         * send any more (no retries granted).
         */
        (*request->query.callback)(request->query.vptr, 0);
	rem_request(request);
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
        (*request->query.callback)(request->query.vptr, reply);
        rem_request(request);
        return;
      }

      /*
       * Lookup the 'authoritative' name that we were given for the
       * ip#. 
       *
       */
#ifdef IPV6
      if (request->addr.ss.ss_family == AF_INET6)
        gethost_byname_type(request->name, &request->query, T_AAAA);
      else
#endif
      gethost_byname_type(request->name, &request->query, T_A);
      rem_request(request);
    }
    else
    {
      /*
       * got a name and address response, client resolved
       */
      reply = make_dnsreply(request);
      (*request->query.callback)(request->query.vptr, (reply) ? reply : 0);
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
    rem_request(request);
  }
}

static struct DNSReply *
make_dnsreply(struct reslist *request)
{
  struct DNSReply *cp;
  assert(request != 0);

  cp = (struct DNSReply *)MyMalloc(sizeof(struct DNSReply));

  DupString(cp->h_name, request->name);
  memcpy(&cp->addr, &request->addr, sizeof(cp->addr));
  return(cp);
}

void
report_dns_servers(struct Client *source_p, struct StatDesc *sd, int stat, char *param)
{
  int i;
  char ipaddr[128];

  for (i = 0; i < irc_nscount; i++)
  {
    irc_getnameinfo((struct sockaddr *)&(irc_nsaddr_list[i]),
                    irc_nsaddr_list[i].ss_len, ipaddr, sizeof(ipaddr), NULL, 0,
                    NI_NUMERICHOST);
    send_reply(source_p, RPL_STATSALINE, ipaddr); 
  }
}

size_t
cres_mem(struct Client* sptr)
{
  struct dlink *dlink;
  struct reslist *request;
  size_t request_mem   = 0;
  int    request_count = 0;

  for (dlink = request_list.next; dlink != &request_list; dlink = dlink->next) {
    request = (struct reslist*)dlink;
    request_mem += sizeof(*request);
    if (request->name)
      request_mem += strlen(request->name) + 1; 
    ++request_count;
  }

  send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Resolver: requests %d(%d)", request_count, request_mem);
  return request_mem;
}
