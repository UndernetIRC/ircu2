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
  struct hostent h;        /* the hostent struct we are passing around */
  char           buf[1];   /* buffer for data pointed to from hostent */
};

struct ResRequest {
  struct ResRequest* next;

  adns_rrtype        type;
  adns_query         aq;

  struct in_addr     addr;
  char*              name;
  struct DNSQuery    query;         /* query callback for this request */
  struct hostent     he;
  char*              buf;
};

int ResolverFileDescriptor    = -1;   /* GLOBAL - used in s_bsd.c */

static struct Socket resSock;		/* Socket describing resolver */
static struct Timer  resExpireDNS;	/* Timer for DNS expiration */
static adns_state adns = NULL;

/*
 * Keep a spare file descriptor open. res_init calls fopen to read the
 * resolv.conf file. If ircd is hogging all the file descriptors below 256,
 * on systems with crippled FILE structures this will cause wierd bugs.
 * This is definitely needed for Solaris which uses an unsigned char to
 * hold the file descriptor.  --Dianora
 */ 
static int                spare_fd = -1;

static struct ResRequest* requestListHead;   /* head of resolver request list */
static struct ResRequest* requestListTail;   /* tail of resolver request list */


static void     add_request(struct ResRequest* request);
static void     rem_request(struct ResRequest* request);
static struct ResRequest*   make_request(const struct DNSQuery* query);
static time_t   timeout_query_list(time_t now);
static void     do_query_name(const struct DNSQuery* query, 
                              const char* name, 
                              struct ResRequest* request);
static void     do_query_number(const struct DNSQuery* query,
                                const struct in_addr*, 
                                struct ResRequest* request);
static void res_adns_callback(adns_state state, adns_query q, void *context);

static struct  resinfo {
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
    report_error("Resolver: error initializing adns for %s: %s",
                 cli_name(&me), res);
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

/*
 * init_resolver - initialize resolver and resolver library
 */
int init_resolver(void)
{
  Debug((DEBUG_DNS, "Resolver: init_resolver"));
#ifdef  LRAND48
  srand48(CurrentTime);
#endif
  memset(&reinfo,   0, sizeof(reinfo));

  requestListHead = requestListTail = 0;

  /* initiate the resolver timers */
  timer_add(timer_init(&resExpireDNS), expire_DNS_callback, 0,
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
  MyFree(request->buf);
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

  request->addr.s_addr    = INADDR_NONE;
  request->he.h_addrtype  = AF_INET;
  request->he.h_length    = sizeof(struct in_addr);
  request->query.vptr     = query->vptr;
  request->query.callback = query->callback;

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
void gethost_byname(const char* name, const struct DNSQuery* query)
{
  assert(0 != name);

  Debug((DEBUG_DNS, "Resolver: gethost_byname %s", name));
  ++reinfo.re_na_look;
  do_query_name(query, name, NULL);
}

/*
 * gethost_byaddr - get host name from address
 */
void gethost_byaddr(const char* addr, const struct DNSQuery* query)
{
  assert(0 != addr);
  Debug((DEBUG_DNS, "Resolver: gethost_byaddr %s", ircd_ntoa(addr)));
  ++reinfo.re_nu_look;
  do_query_number(query, (const struct in_addr*) addr, NULL);
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
  res = adns_submit_callback(adns, hname, adns_r_a, adns_qf_owner,
                             request, &request->aq, res_adns_callback);
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
  res = adns_submit_callback(adns, ipbuf, adns_r_ptr, adns_qf_owner,
                             request, &request->aq, res_adns_callback);
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

/*
 * dup_hostent - Duplicate a hostent struct, allocate only enough memory for
 * the data we're putting in it.
 */
static struct hostent* dup_hostent(struct hostent* hp)
{
  char*  p;
  char** ap;
  char** pp;
  int    alias_count = 0;
  int    addr_count = 0;
  size_t bytes_needed = 0;
  struct Hostent* new_hp = 0;

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
  new_hp = (struct Hostent*) MyMalloc(sizeof(struct Hostent) + bytes_needed);

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
  return (struct hostent*) new_hp;
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

  Debug((DEBUG_DNS, "Resolver: adns_check status %d nrrs %d",
        answer->status, answer->nrrs));
  
  /* No error, we have a valid answer structure */
  if (answer->status != adns_s_ok || !answer->nrrs) {
    /* Status is not 'ok', or there were no RRs found */
    ++reinfo.re_errors;
    (*request->query.callback)(request->query.vptr, 0);
  } else {
    ++reinfo.re_replies;
    hp = &(request->he);    
    if (!request->buf) {
      request->buf = (char*) MyMalloc(MAXGETHOSTLEN + 1);
      request->buf[MAXGETHOSTLEN] = '\0';
      /*
       * array of alias list pointers starts at beginning of buf
       */
      hp->h_aliases = (char**) request->buf;
      hp->h_aliases[0] = NULL;
      /*
       * array of address list pointers starts after alias list pointers
       * the actual addresses follow the the address list pointers
       */ 
      hp->h_addr_list = (char**)(request->buf + ALIAS_BLEN);
      /*
       * don't copy the host address to the beginning of h_addr_list
       */
      hp->h_addr_list[0] = NULL;
    }

    hp->h_addrtype = AF_INET;

    endp = request->buf + MAXGETHOSTLEN;
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
    address = request->buf + ADDRS_OFFSET +
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
      name = request->buf + ADDRS_OFFSET + ADDRS_DLEN;

    switch (request->type) {
    case adns_r_a:
      for (k = 0; k < answer->nrrs; k++) {
        if (++addr_count < RES_MAXADDRS) {
          memcpy(address, &answer->rrs.inaddr[k], sizeof(struct in_addr));
          *addr++ = address;
          *addr = 0;
          address += sizeof(struct in_addr);
	}
        Debug((DEBUG_DNS, "Resolver: A %s for %s",
              ircd_ntoa((char*) &answer->rrs.inaddr[k]), answer->owner));
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
      Debug((DEBUG_DNS, "Resolver: CNAME %s for %s",
            answer->cname, answer->owner));
    }

    if (request->type == adns_r_ptr) {

      Debug((DEBUG_DNS, "relookup %s <-> %s",
             request->he.h_name, ircd_ntoa((char*) &request->addr)));
      /*
       * Lookup the 'authoritive' name that we were given for the
       * ip#.  By using this call rather than regenerating the
       * type we automatically gain the use of the cache with no
       * extra kludges.
       */
      gethost_byname(request->he.h_name, &request->query);
      /*
       * If name wasn't found, a request has been queued and it will
       * be the last one queued.  This is rather nasty way to keep
       * a host alias with the query. -avalon
       */
      MyFree(requestListTail->buf);
      requestListTail->buf = request->buf;
      request->buf = 0;
      memcpy(&requestListTail->he, &request->he, sizeof(struct hostent));
    } else {
      /*
       * got a name and address response, client resolved
       * XXX - Bug found here by Dianora -
       * make_cache() occasionally returns a NULL pointer when a
       * PTR returned a CNAME, cp was not checked before so the
       * callback was being called with a value of 0x2C != NULL.
       */
      struct hostent* he = dup_hostent(&request->he);
      (*request->query.callback)(request->query.vptr, he);
    }
  }
  
  rem_request(request);
  
  /*
   * adns doesn't use MyMalloc, so we don't use MyFree
   */
  free(answer);
}

/*
 * m_dns - dns status query
 */
int m_dns(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
#if !defined(NDEBUG)
  if (parv[1] && *parv[1] == 'd') {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :ResolverFileDescriptor = %d", 
		  sptr, ResolverFileDescriptor);
    return 0;
  }
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
  struct ResRequest* request;
  size_t request_mem   = 0;
  int    request_count = 0;

  for (request = requestListHead; request; request = request->next) {
    request_mem += sizeof(struct ResRequest);
    if (request->name)
      request_mem += strlen(request->name) + 1; 
    if (request->buf)
      request_mem += MAXGETHOSTLEN + 1;
    ++request_count;
  }

  send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Resolver: requests %d(%d)", request_count, request_mem);
  return request_mem;
}

