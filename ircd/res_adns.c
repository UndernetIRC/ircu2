/*
 * src/res.c (C)opyright 1992 Darren Reed. All rights reserved.
 * This file may not be distributed without the author's permission in any
 * shape or form. The author takes no responsibility for any damage or loss
 * of property which results from the use of this software.
 *
 * $Id$
 *
 * July 1999 - Rewrote a bunch of stuff here. Change hostent builder code,
 *     added callbacks and reference counting of returned hostents.
 *     --Bleep (Thomas Helvey <tomh@inxpress.net>)
 */
#include "config.h"

#include "adns.h"
#include "res.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_log.h"
#include "ircd_osdep.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "support.h"
#include "sys.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <regex.h>

#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <limits.h>
#if (CHAR_BIT != 8)
#error this code needs to be able to address individual octets 
#endif

/*
 * Some systems do not define INADDR_NONE (255.255.255.255)
 * INADDR_NONE is actually a valid address, but it should never
 * be returned from any nameserver.
 * NOTE: The bit pattern for INADDR_NONE and INADDR_ANY (0.0.0.0) should be 
 * the same on all hosts so we shouldn't need to use htonl or ntohl to
 * compare or set the values.
 */ 
#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned int) 0xffffffff)
#endif

#define MAXPACKET       1024  /* rfc sez 512 but we expand names so ... */
#define RES_MAXALIASES  35    /* maximum aliases allowed */
#define RES_MAXADDRS    35    /* maximum addresses allowed */
/*
 * OSF1 doesn't have RES_NOALIASES
 */
#ifndef RES_NOALIASES
#define RES_NOALIASES 0
#endif

/*
 * macros used to calulate offsets into fixed query buffer
 */
#define ALIAS_BLEN  ((RES_MAXALIASES + 1) * sizeof(char*))
#define ADDRS_BLEN  ((RES_MAXADDRS + 1) * sizeof(struct in_addr*))

#define ADDRS_OFFSET   (ALIAS_BLEN + ADDRS_BLEN)
#define ADDRS_DLEN     (RES_MAXADDRS * sizeof(struct in_addr))
#define NAMES_OFFSET   (ADDRS_OFFSET + ADDRS_DLEN)
#define MAXGETHOSTLEN  (NAMES_OFFSET + MAXPACKET)

#define AR_TTL          600   /* TTL in seconds for dns cache entries */

/*
 * the following values should be prime
 */
#define ARES_CACSIZE    307
#define MAXCACHED       17
//#define MAXCACHED       281

/*
 * Building the Hostent
 * The Hostent struct is arranged like this:
 *          +-------------------------------+
 * Hostent: | struct hostent h              |
 *          |-------------------------------|
 *          | char *buf                     |
 *          +-------------------------------+
 *
 * allocated:
 *
 *          +-------------------------------+
 * buf:     | h_aliases pointer array       | Max size: ALIAS_BLEN;
 *          | NULL                          | contains `char *'s
 *          |-------------------------------|
 *          | h_addr_list pointer array     | Max size: ADDRS_BLEN;
 *          | NULL                          | contains `struct in_addr *'s
 *          |-------------------------------|
 *          | h_addr_list addresses         | Max size: ADDRS_DLEN;
 *          |                               | contains `struct in_addr's
 *          |-------------------------------|
 *          | storage for hostname strings  | Max size: ALIAS_DLEN;
 *          +-------------------------------+ contains `char's
 *
 *  For requests the size of the h_aliases, and h_addr_list pointer
 *  array sizes are set to MAXALISES and MAXADDRS respectively, and
 *  buf is a fixed size with enough space to hold the largest expected
 *  reply from a nameserver, see RFC 1034 and RFC 1035.
 *  For cached entries the sizes are dependent on the actual number
 *  of aliases and addresses. If new aliases and addresses are found
 *  for cached entries, the buffer is grown and the new entries are added.
 *  The hostent struct is filled in with the addresses of the entries in
 *  the Hostent buf as follows:
 *  h_name      - contains a pointer to the start of the hostname string area,
 *                or NULL if none is set.  The h_name is followed by the
 *                aliases, in the storage for hostname strings area.
 *  h_aliases   - contains a pointer to the start of h_aliases pointer array.
 *                This array contains pointers to the storage for hostname
 *                strings area and is terminated with a NULL.  The first alias
 *                is stored directly after the h_name.
 *  h_addr_list - contains a pointer to the start of h_addr_list pointer array.
 *                This array contains pointers to in_addr structures in the
 *                h_addr_list addresses area and is terminated with a NULL.
 *
 *  Filling the buffer this way allows for proper alignment of the h_addr_list
 *  addresses.
 *
 *  This arrangement allows us to alias a Hostent struct pointer as a
 *  real struct hostent* without lying. It also allows us to change the
 *  values contained in the cached entries and requests without changing
 *  the actual hostent pointer, which is saved in a client struct and can't
 *  be changed without blowing things up or a lot more fiddling around.
 *  It also allows for defered allocation of the fixed size buffers until
 *  they are really needed.
 *  Nov. 17, 1997 --Bleep
 */

struct Hostent {
  struct hostent h;      /* the hostent struct we are passing around */
  char*          buf;    /* buffer for data pointed to from hostent */
};

struct ResRequest {
  struct ResRequest* next;

  adns_rrtype        type;
  adns_query         aq;

  struct in_addr     addr;
  char*              name;
  struct DNSQuery    query;         /* query callback for this request */
  struct Hostent     he;
};

struct CacheEntry {
  struct CacheEntry* hname_next;
  struct CacheEntry* hnum_next;
  struct CacheEntry* list_next;
  time_t             expireat;
  time_t             ttl;
  struct Hostent     he;
  struct DNSReply    reply;
};

struct CacheTable {
  struct CacheEntry* num_list;
  struct CacheEntry* name_list;
};


int ResolverFileDescriptor    = -1;   /* GLOBAL - used in s_bsd.c */

static struct Socket resSock;		/* Socket describing resolver */
static struct Timer  resExpireDNS;	/* Timer for DNS expiration */
static struct Timer  resExpireCache;	/* Timer for cache expiration */
static adns_state adns = NULL;

/*
 * Keep a spare file descriptor open. res_init calls fopen to read the
 * resolv.conf file. If ircd is hogging all the file descriptors below 256,
 * on systems with crippled FILE structures this will cause wierd bugs.
 * This is definitely needed for Solaris which uses an unsigned char to
 * hold the file descriptor.  --Dianora
 */ 
static int                spare_fd = -1;

static int                cachedCount = 0;
static struct CacheTable  hashtable[ARES_CACSIZE];
static struct CacheEntry* cacheTop;
static struct ResRequest* requestListHead;   /* head of resolver request list */
static struct ResRequest* requestListTail;   /* tail of resolver request list */


static void     add_request(struct ResRequest* request);
static void     rem_request(struct ResRequest* request);
static struct ResRequest*   make_request(const struct DNSQuery* query);
static time_t   timeout_query_list(time_t now);
static time_t   expire_cache(time_t now);
static void     rem_cache(struct CacheEntry*);
static void     do_query_name(const struct DNSQuery* query, 
                              const char* name, 
                              struct ResRequest* request);
static void     do_query_number(const struct DNSQuery* query,
                                const struct in_addr*, 
                                struct ResRequest* request);
static struct CacheEntry*  make_cache(struct ResRequest* request);
static struct CacheEntry*  find_cache_name(const char* name);
static struct CacheEntry*  find_cache_number(struct ResRequest* request, 
                                             const char* addr);
static void res_adns_callback(adns_state state, adns_query q, void *context);

static struct cacheinfo {
  int  ca_adds;
  int  ca_dels;
  int  ca_expires;
  int  ca_lookups;
  int  ca_na_hits;
  int  ca_nu_hits;
  int  ca_updates;
} cainfo;

static  struct  resinfo {
  int  re_errors;
  int  re_nu_look;
  int  re_na_look;
  int  re_replies;
  int  re_requests;
  int  re_resends;
  int  re_sent;
  int  re_timeouts;
  int  re_shortttl;
  int  re_unkrep;
} reinfo;


/*
 * int
 * res_isourserver(ina)
 *      looks up "ina" in _res.ns_addr_list[]
 * returns:
 *      0  : not found
 *      >0 : found
 * author:
 *      paul vixie, 29may94
 */
static int
res_ourserver(const struct __res_state* statp, const struct sockaddr_in* inp) 
{
  struct sockaddr_in ina;
  int ns;

  ina = *inp;
  for (ns = 0;  ns < statp->nscount;  ns++) {
    const struct sockaddr_in *srv = &statp->nsaddr_list[ns];

    if (srv->sin_family == ina.sin_family &&
         srv->sin_port == ina.sin_port &&
         (srv->sin_addr.s_addr == INADDR_ANY ||
          srv->sin_addr.s_addr == ina.sin_addr.s_addr))
             return (1);
  }
  return (0);
}

/* Socket callback for resolver */
static void res_socket_callback(struct Event* ev)
{
  struct timeval tv;

  assert(ev_type(ev) == ET_READ || ev_type(ev) == ET_ERROR);

  tv.tv_sec = CurrentTime;
  tv.tv_usec = 0;
  adns_processreadable(adns, ResolverFileDescriptor, &tv);
}

/*
 * start_resolver - do everything we need to read the resolv.conf file
 * and initialize the resolver file descriptor if needed
 */
static void start_resolver(void)
{
  int res;

  Debug((DEBUG_DNS, "Resolver: start_resolver"));
  /*
   * close the spare file descriptor so res_init can read resolv.conf
   * successfully. Needed on Solaris
   */
  if (spare_fd > -1)
    close(spare_fd);

  /*
   * make sure we have a valid file descriptor below 256 so we can
   * do this again. Needed on Solaris
   */
  spare_fd = open("/dev/null",O_RDONLY,0);
  if ((spare_fd < 0) || (spare_fd > 255)) {
    char sparemsg[80];
    ircd_snprintf(0, sparemsg, sizeof(sparemsg), "invalid spare_fd %d",
		  spare_fd);
    server_restart(sparemsg);
  }

  if (adns)
    return;

  if ((res = adns_init(&adns, adns_if_debug /*| adns_if_noautosys*/, NULL))) {
    report_error("Resolver: error initializing adns for %s: %s", cli_name(&me), res);
    errno = res;
    return;
  }
  errno = 0;
  
  ResolverFileDescriptor = adns_get_fd(adns);

  if (!socket_add(&resSock, res_socket_callback, 0, SS_DATAGRAM,
		  SOCK_EVENT_READABLE, ResolverFileDescriptor))
    report_error("Resolver: unable to queue resolver file descriptor for %s",
		 cli_name(&me), ENFILE);
}

/* Call the query timeout function */
static void expire_DNS_callback(struct Event* ev)
{
  time_t next;

  next = timeout_query_list(CurrentTime);

  timer_add(&resExpireDNS, expire_DNS_callback, 0, TT_ABSOLUTE, next);
}

/* Call the cache expire function */
static void expire_cache_callback(struct Event* ev)
{
  time_t next;

  next = expire_cache(CurrentTime);

  timer_add(&resExpireCache, expire_cache_callback, 0, TT_ABSOLUTE, next);
}

/*
 * init_resolver - initialize resolver and resolver library
 */
int init_resolver(void)
{
  Debug((DEBUG_DNS, "Resolver: init_resolver"));
#ifdef  LRAND48
  srand48(CurrentTime);
#endif
  memset(&cainfo,   0, sizeof(cainfo));
  memset(hashtable, 0, sizeof(hashtable));
  memset(&reinfo,   0, sizeof(reinfo));

  requestListHead = requestListTail = 0;

  /* initiate the resolver timers */
  timer_add(timer_init(&resExpireDNS), expire_DNS_callback, 0,
	    TT_RELATIVE, 1);
  timer_add(timer_init(&resExpireCache), expire_cache_callback, 0,
	    TT_RELATIVE, 1);

  errno = h_errno = 0;

  start_resolver();
  Debug((DEBUG_DNS, "Resolver: fd %d errno: %d h_errno: %d: %s",
         ResolverFileDescriptor, errno, h_errno, 
         (strerror(errno)) ? strerror(errno) : "Unknown"));
  return ResolverFileDescriptor;
}

/*
 * restart_resolver - flush the cache, reread resolv.conf, reopen socket
 */
void restart_resolver(void)
{
  /* flush_cache();  flush the dns cache */
  start_resolver();
}

/*
 * add_request - place a new request in the request list
 */
static void add_request(struct ResRequest* request)
{
  assert(0 != request);
  if (!requestListHead)
    requestListHead = requestListTail = request;
  else {
    requestListTail->next = request;
    requestListTail = request;
  }
  request->next = NULL;
  ++reinfo.re_requests;
}

/*
 * rem_request - remove a request from the list. 
 * This must also free any memory that has been allocated for 
 * temporary storage of DNS results.
 */
static void rem_request(struct ResRequest* request)
{
  struct ResRequest** current;
  struct ResRequest*  prev = NULL;

  assert(0 != request);
  for (current = &requestListHead; *current; ) {
    if (*current == request) {
      *current = request->next;
      if (requestListTail == request)
        requestListTail = prev;
      break;
    } 
    prev    = *current;
    current = &(*current)->next;
  }
  if (request->aq)
    adns_cancel(request->aq);
  MyFree(request->he.buf);
  MyFree(request->name);
  MyFree(request);
}

/*
 * make_request - Create a DNS request record for the server.
 */
static struct ResRequest* make_request(const struct DNSQuery* query)
{
  struct ResRequest* request;
  assert(0 != query);
  request = (struct ResRequest*) MyMalloc(sizeof(struct ResRequest));
  memset(request, 0, sizeof(struct ResRequest));

  request->addr.s_addr      = INADDR_NONE;
  request->he.h.h_addrtype  = AF_INET;
  request->he.h.h_length    = sizeof(struct in_addr);
  request->query.vptr       = query->vptr;
  request->query.callback   = query->callback;

#if defined(NULL_POINTER_NOT_ZERO)
  request->next             = NULL;
  request->he.buf           = NULL;
  request->he.h.h_name      = NULL;
  request->he.h.h_aliases   = NULL;
  request->he.h.h_addr_list = NULL;
#endif
  add_request(request);
  return request;
}

/*
 * timeout_query_list - Remove queries from the list which have been 
 * there too long without being resolved.
 */
static time_t timeout_query_list(time_t now)
{
  struct timeval tv, tv_buf, *tv_mod = NULL;
  time_t next;
  
  Debug((DEBUG_DNS, "Resolver: timeout_query_list at %s", myctime(now)));

  tv.tv_sec = now;
  tv.tv_usec = 0;
  adns_processtimeouts(adns, &tv);
  adns_firsttimeout(adns, &tv_mod, &tv_buf, tv);
  next = tv_mod ? tv_mod->tv_sec : AR_TTL;
  if (!next)
    next = 1;

  Debug((DEBUG_DNS, "Resolver: next timeout_query_list in %d seconds", next));
  return now + next;
}

/*
 * expire_cache - removes entries from the cache which are older 
 * than their expiry times. returns the time at which the server 
 * should next poll the cache.
 */
static time_t expire_cache(time_t now)
{
  struct CacheEntry* cp;
  struct CacheEntry* cp_next;
  time_t             expire = 0;

  Debug((DEBUG_DNS, "Resolver: expire_cache at %s", myctime(now)));
  for (cp = cacheTop; cp; cp = cp_next) {
    cp_next = cp->list_next;
    if (cp->expireat < now) {
      ++cainfo.ca_expires;
      rem_cache(cp);
    }
    else if (!expire || expire > cp->expireat)
      expire = cp->expireat;
  }
  return (expire > now) ? expire : (now + AR_TTL);
}

/*
 * delete_resolver_queries - cleanup outstanding queries 
 * for which there no longer exist clients or conf lines.
 */
void delete_resolver_queries(const void* vptr)
{
  struct ResRequest* request;
  struct ResRequest* next_request;

  for (request = requestListHead; request; request = next_request) {
    next_request = request->next;
    if (vptr == request->query.vptr)
      rem_request(request);
  }
}

/*
 * gethost_byname - get host address from name
 */
struct DNSReply* gethost_byname(const char* name, 
                               const struct DNSQuery* query)
{
  struct CacheEntry* cp;
  assert(0 != name);

  Debug((DEBUG_DNS, "Resolver: gethost_byname %s", name));
  ++reinfo.re_na_look;
  if ((cp = find_cache_name(name)))
    return &(cp->reply);

  do_query_name(query, name, NULL);
  return NULL;
}

/*
 * gethost_byaddr - get host name from address
 */
struct DNSReply* gethost_byaddr(const char* addr,
                                const struct DNSQuery* query)
{
  struct CacheEntry *cp;

  assert(0 != addr);

  Debug((DEBUG_DNS, "Resolver: gethost_byaddr %s", ircd_ntoa(addr)));

  ++reinfo.re_nu_look;
  if ((cp = find_cache_number(NULL, addr)))
    return &(cp->reply);

  do_query_number(query, (const struct in_addr*) addr, NULL);
  return NULL;
}

/*
 * do_query_name - nameserver lookup name
 */
static void do_query_name(const struct DNSQuery* query, 
                          const char* name, struct ResRequest* request)
{
  char  hname[HOSTLEN + 1];
  int	res;
  assert(0 != name);

  ircd_strncpy(hname, name, HOSTLEN);
  hname[HOSTLEN] = '\0';

  if (!request) {
    request       = make_request(query);
    request->type = adns_r_a;
    request->name = (char*) MyMalloc(strlen(hname) + 1);
    strcpy(request->name, hname);
  }
  res = adns_submit_callback(adns, hname, adns_r_a, adns_qf_owner, request, &request->aq, res_adns_callback);
  assert(!res);
  timer_chg(&resExpireDNS, TT_RELATIVE, 1);
}

/*
 * do_query_number - Use this to do reverse IP# lookups.
 */
static void do_query_number(const struct DNSQuery* query, 
                            const struct in_addr* addr,
                            struct ResRequest* request)
{
  char  ipbuf[32];
  const unsigned char* cp;
  int	res;

  assert(0 != addr);
  cp = (const unsigned char*) &addr->s_addr;
  ircd_snprintf(0, ipbuf, sizeof(ipbuf), "%u.%u.%u.%u.in-addr.arpa.",
		(unsigned int)(cp[3]), (unsigned int)(cp[2]),
		(unsigned int)(cp[1]), (unsigned int)(cp[0]));

  if (!request) {
    request              = make_request(query);
    request->type        = adns_r_ptr;
    request->addr.s_addr = addr->s_addr;
  }
  res = adns_submit_callback(adns, ipbuf, adns_r_ptr, adns_qf_owner, request, &request->aq, res_adns_callback);
  assert(!res);
  timer_chg(&resExpireDNS, TT_RELATIVE, 1);
}

/* Returns true if this is a valid name */
static int validate_name(char *name)
{
  while (*name) {
    if ((*name<'A' || *name>'Z') 
     && (*name<'a' || *name>'z') 
     && (*name<'0' || *name>'9')
     && (*name!='-')) {
      return 0;
    }
    name++;
  }
  return 1;
}

static void res_adns_callback(adns_state state, adns_query q, void *context)
{
  struct ResRequest *request = (struct ResRequest *) context;
  adns_answer *answer = NULL;
  int res, k;
  struct hostent* hp;          /* hostent getting filled */
  char** alias;                /* alias list */
  char** addr;                 /* address list */
  char** base_addr;            /* original pointer to address list */
  char*  name;                 /* pointer to name string */
  char*  address;              /* pointer to address */
  char*  base_address;         /* original pointer to address */
  char*  endp;                 /* end of our buffer */
  int    addr_count  = 0;      /* number of addresses in hostent */
  int    alias_count = 0;      /* number of aliases in hostent */
  struct CacheEntry* cp           = 0;
  
  assert(request);
  assert(q);
  assert(request->aq == q);
  res = adns_check(adns, &q, &answer, NULL);
  request->aq = NULL;

  if (res) {
    /* adns_check returned an error, bail */
    Debug((DEBUG_DNS, "Resolver: adns_check result %d", res));

    (*request->query.callback)(request->query.vptr, 0);
    rem_request(request);
    return;
  }

  Debug((DEBUG_DNS, "Resolver: adns_check status %d nrrs %d", answer->status, answer->nrrs));
  
  /* No error, we have a valid answer structure */
  if (answer->status != adns_s_ok || !answer->nrrs) {
    /* Status is not 'ok', or there were no RRs found */
    ++reinfo.re_errors;
    (*request->query.callback)(request->query.vptr, 0);
  } else {
    ++reinfo.re_replies;
    hp = &(request->he.h);    
    if (!request->he.buf) {
      request->he.buf = (char*) MyMalloc(MAXGETHOSTLEN + 1);
      request->he.buf[MAXGETHOSTLEN] = '\0';
      /*
       * array of alias list pointers starts at beginning of buf
       */
      hp->h_aliases = (char**) request->he.buf;
      hp->h_aliases[0] = NULL;
      /*
       * array of address list pointers starts after alias list pointers
       * the actual addresses follow the the address list pointers
       */ 
      hp->h_addr_list = (char**)(request->he.buf + ALIAS_BLEN);
      /*
       * don't copy the host address to the beginning of h_addr_list
       */
      hp->h_addr_list[0] = NULL;
    }

    hp->h_addrtype = AF_INET;

    endp = request->he.buf + MAXGETHOSTLEN;
    /*
     * find the end of the address list
     */
    addr = hp->h_addr_list;
    while (*addr) {
      ++addr;
      ++addr_count;
    }
    base_addr = addr;
    /*
     * make address point to first available address slot
     */
    address = request->he.buf + ADDRS_OFFSET +
                      (sizeof(struct in_addr) * addr_count);
    base_address = address;

    /*
     * find the end of the alias list
     */
    alias = hp->h_aliases;
    while (*alias) {
      ++alias;
      ++alias_count;
    }
    /*
     * make name point to first available space in request->buf
     */
    if (alias_count > 0) {
      name = hp->h_aliases[alias_count - 1];
      name += (strlen(name) + 1);
    }
    else if (hp->h_name)
      name = hp->h_name + strlen(hp->h_name) + 1;
    else
      name = request->he.buf + ADDRS_OFFSET + ADDRS_DLEN;

    switch (request->type) {
    case adns_r_a:
      for (k = 0; k < answer->nrrs; k++) {
        if (++addr_count < RES_MAXADDRS) {
          memcpy(address, &answer->rrs.inaddr[k], sizeof(struct in_addr));
          *addr++ = address;
          *addr = 0;
          address += sizeof(struct in_addr);
	}
        Debug((DEBUG_DNS, "Resolver: A %s for %s", ircd_ntoa((char*) &answer->rrs.inaddr[k]), answer->owner));
      }
      if (!hp->h_name) {
        strcpy(name, answer->owner);
        hp->h_name = name;
        name += strlen(name) + 1;
      }
      break;
    case adns_r_ptr:
      strcpy(name, answer->rrs.str[0]);
      hp->h_name = name;
      name += strlen(name) + 1;

      Debug((DEBUG_DNS, "Resolver: PTR %s for %s", hp->h_name, answer->owner));
      break;
    default:
      /* ignore */
      break;
    }

    if (answer->cname) {
      alias_count++;
      ircd_strncpy(name, answer->cname, endp - name);
      *alias++ = name;
      *alias   = 0;
      name += strlen(name) + 1;
      Debug((DEBUG_DNS, "Resolver: CNAME %s for %s", answer->cname, answer->owner));
    }

    if (request->type == adns_r_ptr) {
      struct DNSReply* reply;

      Debug((DEBUG_DNS, "relookup %s <-> %s",
             request->he.h.h_name, ircd_ntoa((char*) &request->addr)));
      /*
       * Lookup the 'authoritive' name that we were given for the
       * ip#.  By using this call rather than regenerating the
       * type we automatically gain the use of the cache with no
       * extra kludges.
       */
      reply = gethost_byname(request->he.h.h_name, &request->query);
      if (reply) {
        (*request->query.callback)(request->query.vptr, reply);
      } else {
        /*
         * If name wasn't found, a request has been queued and it will
         * be the last one queued.  This is rather nasty way to keep
         * a host alias with the query. -avalon
         */
        MyFree(requestListTail->he.buf);
        requestListTail->he.buf = request->he.buf;
        request->he.buf = 0;
        memcpy(&requestListTail->he.h, &request->he.h, sizeof(struct hostent));
      }
    } else {
      /*
       * got a name and address response, client resolved
       * XXX - Bug found here by Dianora -
       * make_cache() occasionally returns a NULL pointer when a
       * PTR returned a CNAME, cp was not checked before so the
       * callback was being called with a value of 0x2C != NULL.
       */
      struct DNSReply* reply = 0;
      if ((cp = make_cache(request)))
        reply = &cp->reply;
      (*request->query.callback)(request->query.vptr, reply);
    }
  }
  
  rem_request(request);
  
  /*
   * adns doesn't use MyMalloc, so we don't use MyFree
   */
  free(answer);
}


static size_t calc_hostent_buffer_size(const struct hostent* hp)
{
  char** p;
  size_t count = 0;
  assert(0 != hp);

  /*
   * space for name
   */
  count += (strlen(hp->h_name) + 1);
  /*
   * space for aliases
   */
  for (p = hp->h_aliases; *p; ++p)
    count += (strlen(*p) + 1 + sizeof(char*));
  /*
   * space for addresses
   */
  for (p = hp->h_addr_list; *p; ++p)
    count += (hp->h_length + sizeof(char*));
  /*
   * space for 2 nulls to terminate h_aliases and h_addr_list 
   */
  count += (2 * sizeof(char*));
  return count;
}


/*
 * dup_hostent - Duplicate a hostent struct, allocate only enough memory for
 * the data we're putting in it.
 */
static void dup_hostent(struct Hostent* new_hp, struct hostent* hp)
{
  char*  p;
  char** ap;
  char** pp;
  int    alias_count = 0;
  int    addr_count = 0;
  size_t bytes_needed = 0;

  assert(0 != new_hp);
  assert(0 != hp);

  /* how much buffer do we need? */
  bytes_needed += (strlen(hp->h_name) + 1);

  pp = hp->h_aliases;
  while (*pp) {
    bytes_needed += (strlen(*pp++) + 1 + sizeof(char*));
    ++alias_count;
  }
  pp = hp->h_addr_list;
  while (*pp++) {
    bytes_needed += (hp->h_length + sizeof(char*));
    ++addr_count;
  }
  /* Reserve space for 2 nulls to terminate h_aliases and h_addr_list */
  bytes_needed += (2 * sizeof(char*));

  /* Allocate memory */
  new_hp->buf = (char*) MyMalloc(bytes_needed);

  new_hp->h.h_addrtype = hp->h_addrtype;
  new_hp->h.h_length = hp->h_length;

  /* first write the address list */
  pp = hp->h_addr_list;
  ap = new_hp->h.h_addr_list =
      (char**)(new_hp->buf + ((alias_count + 1) * sizeof(char*)));
  p = (char*)ap + ((addr_count + 1) * sizeof(char*));
  while (*pp)
  {
    *ap++ = p;
    memcpy(p, *pp++, hp->h_length);
    p += hp->h_length;
  }
  *ap = 0;
  /* next write the name */
  new_hp->h.h_name = p;
  strcpy(p, hp->h_name);
  p += (strlen(p) + 1);

  /* last write the alias list */
  pp = hp->h_aliases;
  ap = new_hp->h.h_aliases = (char**) new_hp->buf;
  while (*pp) {
    *ap++ = p;
    strcpy(p, *pp++);
    p += (strlen(p) + 1);
  }
  *ap = 0;
}

/*
 * update_hostent - Add records to a Hostent struct in place.
 */
static void update_hostent(struct Hostent* hp, char** addr, char** alias)
{
  char*  p;
  char** ap;
  char** pp;
  int    alias_count = 0;
  int    addr_count = 0;
  char*  buf = NULL;
  size_t bytes_needed = 0;

  if (!hp || !hp->buf)
    return;

  /* how much buffer do we need? */
  bytes_needed = strlen(hp->h.h_name) + 1;
  pp = hp->h.h_aliases;
  while (*pp) {
    bytes_needed += (strlen(*pp++) + 1 + sizeof(char*));
    ++alias_count;
  }
  if (alias) {
    pp = alias;
    while (*pp) {
      bytes_needed += (strlen(*pp++) + 1 + sizeof(char*));
      ++alias_count;
    }
  }
  pp = hp->h.h_addr_list;
  while (*pp++) {
    bytes_needed += (hp->h.h_length + sizeof(char*));
    ++addr_count;
  }
  if (addr) {
    pp = addr;
    while (*pp++) {
      bytes_needed += (hp->h.h_length + sizeof(char*));
      ++addr_count;
    }
  }
  /* Reserve space for 2 nulls to terminate h_aliases and h_addr_list */
  bytes_needed += 2 * sizeof(char*);

  /* Allocate memory */
  buf = (char*) MyMalloc(bytes_needed);
  assert(0 != buf);

  /* first write the address list */
  pp = hp->h.h_addr_list;
  ap = hp->h.h_addr_list =
      (char**)(buf + ((alias_count + 1) * sizeof(char*)));
  p = (char*)ap + ((addr_count + 1) * sizeof(char*));
  while (*pp) {
    memcpy(p, *pp++, hp->h.h_length);
    *ap++ = p;
    p += hp->h.h_length;
  }
  if (addr) {
    while (*addr) {
      memcpy(p, *addr++, hp->h.h_length);
      *ap++ = p;
      p += hp->h.h_length;
    }
  }
  *ap = 0;

  /* next write the name */
  strcpy(p, hp->h.h_name);
  hp->h.h_name = p;
  p += (strlen(p) + 1);

  /* last write the alias list */
  pp = hp->h.h_aliases;
  ap = hp->h.h_aliases = (char**) buf;
  while (*pp) {
    strcpy(p, *pp++);
    *ap++ = p;
    p += (strlen(p) + 1);
  }
  if (alias) {
    while (*alias) {
      strcpy(p, *alias++);
      *ap++ = p;
      p += (strlen(p) + 1);
    }
  }
  *ap = 0;
  /* release the old buffer */
  p = hp->buf;
  hp->buf = buf;
  MyFree(p);
}

/*
 * hash_number - IP address hash function
 */
static int hash_number(const unsigned char* ip)
{
  /* could use loop but slower */
  unsigned int hashv;
  const u_char* p = (const u_char*) ip;

  assert(0 != p);

  hashv = *p++;
  hashv += hashv + *p++;
  hashv += hashv + *p++;
  hashv += hashv + *p;
  hashv %= ARES_CACSIZE;
  return hashv;
}

/*
 * hash_name - hostname hash function
 */
static int hash_name(const char* name)
{
  unsigned int hashv = 0;
  const u_char* p = (const u_char*) name;

  assert(0 != p);

  for (; *p && *p != '.'; ++p)
    hashv += *p;
  hashv %= ARES_CACSIZE;
  return hashv;
}

/*
 * add_to_cache - Add a new cache item to the queue and hash table.
 */
static struct CacheEntry* add_to_cache(struct CacheEntry* ocp)
{
  int  hashv;

  assert(0 != ocp);

  ocp->list_next = cacheTop;
  cacheTop = ocp;

  hashv = hash_name(ocp->he.h.h_name);

  ocp->hname_next = hashtable[hashv].name_list;
  hashtable[hashv].name_list = ocp;

  hashv = hash_number((const unsigned char*) ocp->he.h.h_addr);

  ocp->hnum_next = hashtable[hashv].num_list;
  hashtable[hashv].num_list = ocp;

  /*
   * LRU deletion of excessive cache entries.
   */
  if (++cachedCount > MAXCACHED) {
    struct CacheEntry* cp;
    struct CacheEntry* cp_next;
    for (cp = ocp->list_next; cp; cp = cp_next) {
      cp_next = cp->list_next;
      rem_cache(cp);
    }
  }
  ++cainfo.ca_adds;
  return ocp;
}

/*
 * update_list - does not alter the cache structure passed. It is assumed that
 * it already contains the correct expire time, if it is a new entry. Old
 * entries have the expirey time updated.
*/
static void update_list(struct ResRequest* request, struct CacheEntry* cachep)
{
  struct CacheEntry*  cp = cachep;
  char*    s;
  char*    t;
  int      i;
  int      j;
  char**   ap;
  char*    addrs[RES_MAXADDRS + 1];
  char*    aliases[RES_MAXALIASES + 1];

  /*
   * search for the new cache item in the cache list by hostname.
   * If found, move the entry to the top of the list and return.
   */
  ++cainfo.ca_updates;

  if (!request)
    return;
  /*
   * Compare the cache entry against the new record.  Add any
   * previously missing names for this entry.
   */
  *aliases = 0;
  ap = aliases;
  for (i = 0, s = request->he.h.h_name; s; s = request->he.h.h_aliases[i++]) {
    for (j = 0, t = cp->he.h.h_name; t; t = cp->he.h.h_aliases[j++]) {
      if (0 == ircd_strcmp(t, s))
        break;
    }
    if (!t) {
      *ap++ = s;
      *ap = 0;
    }
  }
  /*
   * Do the same again for IP#'s.
   */
  *addrs = 0;
  ap = addrs;
  for (i = 0; (s = request->he.h.h_addr_list[i]); i++) {
    for (j = 0; (t = cp->he.h.h_addr_list[j]); j++) {
      if (!memcmp(t, s, sizeof(struct in_addr)))
        break;
    }
    if (!t) {
      *ap++ = s;
      *ap = 0;
    }
  }
  if (*addrs || *aliases)
    update_hostent(&cp->he, addrs, aliases);
}

/*
 * find_cache_name - find name in nameserver cache
 */
static struct CacheEntry* find_cache_name(const char* name)
{
  struct CacheEntry* cp;
  char*   s;
  int     hashv;
  int     i;

  assert(0 != name);
  hashv = hash_name(name);

  cp = hashtable[hashv].name_list;

  for (; cp; cp = cp->hname_next) {
    for (i = 0, s = cp->he.h.h_name; s; s = cp->he.h.h_aliases[i++]) {
      if (0 == ircd_strcmp(s, name)) {
        ++cainfo.ca_na_hits;
        return cp;
      }
    }
  }

  for (cp = cacheTop; cp; cp = cp->list_next) {
    /*
     * if no aliases or the hash value matches, we've already
     * done this entry and all possiblilities concerning it.
     */
    if (!cp->he.h.h_name || hashv == hash_name(cp->he.h.h_name))
      continue;
    for (i = 0, s = cp->he.h.h_aliases[i]; s; s = cp->he.h.h_aliases[++i]) {
      if (0 == ircd_strcmp(name, s)) {
        ++cainfo.ca_na_hits;
        return cp;
      }
    }
  }
  return NULL;
}

/*
 * find_cache_number - find a cache entry by ip# and update its expire time
 */
static struct CacheEntry* find_cache_number(struct ResRequest* request,
                                            const char* addr)
{
  struct CacheEntry* cp;
  int     hashv;
  int     i;

  assert(0 != addr);
  hashv = hash_number((const unsigned char*) addr);
  cp = hashtable[hashv].num_list;

  for (; cp; cp = cp->hnum_next) {
    for (i = 0; cp->he.h.h_addr_list[i]; ++i) {
      if (!memcmp(cp->he.h.h_addr_list[i], addr, sizeof(struct in_addr))) {
        ++cainfo.ca_nu_hits;
        return cp;
      }
    }
  }
  for (cp = cacheTop; cp; cp = cp->list_next) {
    /*
     * single address entry...would have been done by hashed
     * search above...
     * if the first IP# has the same hashnumber as the IP# we
     * are looking for, its been done already.
     */
    if (!cp->he.h.h_addr_list[1] || 
        hashv == hash_number((const unsigned char*) cp->he.h.h_addr_list[0]))
      continue;
    for (i = 1; cp->he.h.h_addr_list[i]; ++i) {
      if (!memcmp(cp->he.h.h_addr_list[i], addr, sizeof(struct in_addr))) {
        ++cainfo.ca_nu_hits;
        return cp;
      }
    }
  }
  return NULL;
}

static struct CacheEntry* make_cache(struct ResRequest* request)
{
  struct CacheEntry* cp;
  int     i;
  struct hostent* hp;
  assert(0 != request);

  hp = &request->he.h;
  /*
   * shouldn't happen but it just might...
   */
  assert(0 != hp->h_name);
/*    assert(0 != hp->h_addr_list[0]); */
  if (!hp->h_name || !hp->h_addr_list[0])
    return NULL;
  /*
   * Make cache entry.  First check to see if the cache already exists
   * and if so, return a pointer to it.
   */
  for (i = 0; hp->h_addr_list[i]; ++i) {
    if ((cp = find_cache_number(request, hp->h_addr_list[i]))) {
      update_list(request, cp);
      return cp;
    }
  }
  /*
   * a matching entry wasnt found in the cache so go and make one up.
   */ 
  cp = (struct CacheEntry*) MyMalloc(sizeof(struct CacheEntry));
  assert(0 != cp);

  memset(cp, 0, sizeof(struct CacheEntry));
  dup_hostent(&cp->he, hp);
  cp->reply.hp = &cp->he.h;
  /*
   * hmmm... we could time out the cache after 10 minutes regardless
   * would that be reasonable since we don't save the reply?
   */ 
#if 0
  if (request->ttl < AR_TTL) {
    ++reinfo.re_shortttl;
    cp->ttl = AR_TTL;
  }
  else
    cp->ttl = request->ttl;
#else
  cp->ttl = AR_TTL;
#endif
  cp->expireat = CurrentTime + cp->ttl;
  return add_to_cache(cp);
}

/*
 * rem_cache - delete a cache entry from the cache structures 
 * and lists and return all memory used for the cache back to the memory pool.
 */
static void rem_cache(struct CacheEntry* ocp)
{
  struct CacheEntry** cp;
  int                 hashv;
  struct hostent*     hp;
  assert(0 != ocp);


  if (0 < ocp->reply.ref_count) {
    if (ocp->expireat < CurrentTime) {
      ocp->expireat = CurrentTime + AR_TTL;
      Debug((DEBUG_DNS, "Resolver: referenced cache entry not removed for: %s",
            ocp->he.h.h_name));
    }
    return;
  }
  /*
   * remove cache entry from linked list
   */
  for (cp = &cacheTop; *cp; cp = &((*cp)->list_next)) {
    if (*cp == ocp) {
      *cp = ocp->list_next;
      break;
    }
  }
  hp = &ocp->he.h;
  /*
   * remove cache entry from hashed name list
   */
  assert(0 != hp->h_name);
  hashv = hash_name(hp->h_name);

  for (cp = &hashtable[hashv].name_list; *cp; cp = &((*cp)->hname_next)) {
    if (*cp == ocp) {
      *cp = ocp->hname_next;
      break;
    }
  }
  /*
   * remove cache entry from hashed number list
   */
  hashv = hash_number((const unsigned char*) hp->h_addr);
  assert(-1 < hashv);

  for (cp = &hashtable[hashv].num_list; *cp; cp = &((*cp)->hnum_next)) {
    if (*cp == ocp) {
      *cp = ocp->hnum_next;
      break;
    }
  }
  /*
   * free memory used to hold the various host names and the array
   * of alias pointers.
   */
  MyFree(ocp->he.buf);
  MyFree(ocp);
  --cachedCount;
  ++cainfo.ca_dels;
}

void flush_resolver_cache(void)
{
  /*
   * stubbed - iterate cache and remove everything that isn't referenced
   */
}

/*
 * m_dns - dns status query
 */
int m_dns(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
#if !defined(NDEBUG)
  struct CacheEntry* cp;
  int     i;
  struct hostent* hp;

  if (parv[1] && *parv[1] == 'l') {
    for(cp = cacheTop; cp; cp = cp->list_next) {
      hp = &cp->he.h;
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Ex %d ttl %d host %s(%s)",
		    sptr, cp->expireat - CurrentTime, cp->ttl,
		    hp->h_name, ircd_ntoa(hp->h_addr));
      for (i = 0; hp->h_aliases[i]; i++)
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C : %s = %s (CN)", sptr,
		      hp->h_name, hp->h_aliases[i]);
      for (i = 1; hp->h_addr_list[i]; i++)
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C : %s = %s (IP)", sptr,
		      hp->h_name, ircd_ntoa(hp->h_addr_list[i]));
    }
    return 0;
  }
  if (parv[1] && *parv[1] == 'd') {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :ResolverFileDescriptor = %d", 
		  sptr, ResolverFileDescriptor);
    return 0;
  }
  sendcmdto_one(&me, CMD_NOTICE, sptr,"%C :Ca %d Cd %d Ce %d Cl %d Ch %d:%d "
		"Cu %d", sptr,
		cainfo.ca_adds, cainfo.ca_dels, cainfo.ca_expires,
		cainfo.ca_lookups, cainfo.ca_na_hits, cainfo.ca_nu_hits, 
		cainfo.ca_updates);
  
  sendcmdto_one(&me, CMD_NOTICE, sptr,"%C :Re %d Rl %d/%d Rp %d Rq %d",
		sptr, reinfo.re_errors, reinfo.re_nu_look,
		reinfo.re_na_look, reinfo.re_replies, reinfo.re_requests);
  sendcmdto_one(&me, CMD_NOTICE, sptr,"%C :Ru %d Rsh %d Rs %d(%d) Rt %d", sptr,
		reinfo.re_unkrep, reinfo.re_shortttl, reinfo.re_sent,
		reinfo.re_resends, reinfo.re_timeouts);
#endif
  return 0;
}

size_t cres_mem(struct Client* sptr)
{
  struct CacheEntry* entry;
  struct ResRequest* request;
  size_t cache_mem     = 0;
  size_t request_mem   = 0;
  int    cache_count   = 0;
  int    request_count = 0;

  for (entry = cacheTop; entry; entry = entry->list_next) {
    cache_mem += sizeof(struct CacheEntry);
    cache_mem += calc_hostent_buffer_size(&entry->he.h); 
    ++cache_count;
  }
  for (request = requestListHead; request; request = request->next) {
    request_mem += sizeof(struct ResRequest);
    if (request->name)
      request_mem += strlen(request->name) + 1; 
    if (request->he.buf)
      request_mem += MAXGETHOSTLEN + 1;
    ++request_count;
  }

  if (cachedCount != cache_count) {
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
	       ":Resolver: cache count mismatch: %d != %d", cachedCount,
	       cache_count);
    assert(cachedCount == cache_count);
  }
  send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Resolver: cache %d(%d) requests %d(%d)", cache_count,
	     cache_mem, request_count, request_mem);
  return cache_mem + request_mem;
}

