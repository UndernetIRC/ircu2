/*
 * ircd/res.c (C)opyright 1992, 1993, 1994 Darren Reed. All rights reserved.
 * This file may not be distributed without the author's prior permission in
 * any shape or form. The author takes no responsibility for any damage or
 * loss of property which results from the use of this software.  Distribution
 * of this file must include this notice.
 */

#include "sys.h"
#include <signal.h>
#include <sys/socket.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
/* dn_skipname is really an internal function,
   we shouldn't be using it in res.c */
#if !defined(dn_skipname) && !defined(__dn_skipname)
extern int dn_skipname(const unsigned char *, const unsigned char *);
#endif
#include "h.h"
#include "res.h"
#include "struct.h"
#include "numeric.h"
#include "send.h"
#include "s_misc.h"
#include "s_bsd.h"
#include "ircd.h"
#include "s_ping.h"
#include "support.h"
#include "common.h"
#include "sprintf_irc.h"

RCSTAG_CC("$Id$");

#define MAXPACKET	1024

#define RES_MAXADDRS	35
#define RES_MAXALIASES	35

#define ALIASBLEN ((RES_MAXALIASES + 1) * sizeof(char *))
#define ADDRSBLEN ((RES_MAXADDRS + 1) * sizeof(struct in_addr *))
#define ADDRSDLEN (RES_MAXADDRS * sizeof(struct in_addr))
#define ALIASDLEN (MAXPACKET)
#define MAXGETHOSTLEN (ALIASBLEN + ADDRSBLEN + ADDRSDLEN + ALIASDLEN)

#define AR_TTL		600	/* TTL in seconds for dns cache entries */

#define ARES_CACSIZE	512
#define MAXCACHED	2048

#ifndef INT16SZ
#define INT16SZ 2
#endif
#ifndef INT32SZ
#define INT32SZ 4
#endif

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
 * buf:     | h_aliases pointer array       | Max size: ALIASBLEN;
 *          | NULL                          | contains `char *'s
 *          |-------------------------------|
 *          | h_addr_list pointer array     | Max size: ADDRSBLEN;
 *          | NULL                          | contains `struct in_addr *'s
 *          |-------------------------------|
 *          | h_addr_list addresses         | Max size: ADDRSDLEN;
 *          |                               | contains `struct in_addr's
 *          |-------------------------------|
 *          | storage for hostname strings  | Max size: ALIASDLEN;
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

typedef struct Hostent {
  struct hostent h;
  char *buf;
} aHostent;

typedef struct reslist {
  int id;
  int sent;			/* number of requests sent */
  int srch;
  time_t ttl;
  char type;
  char retries;			/* retry counter */
  char sends;			/* number of sends (>1 means resent) */
  char resend;			/* send flag. 0 == dont resend */
  time_t sentat;
  time_t timeout;
  struct in_addr addr;
  char *name;
  struct reslist *next;
  Link cinfo;
  aHostent he;
} ResRQ;

typedef struct cache {
  time_t expireat;
  time_t ttl;
  aHostent he;
  struct cache *hname_next, *hnum_next, *list_next;
} aCache;

typedef struct cachetable {
  aCache *num_list;
  aCache *name_list;
} CacheTable;

extern int resfd;		/* defined in s_bsd.c */

static char hostbuf[HOSTLEN + 1];
static char dot[] = ".";
static int incache = 0;
static CacheTable hashtable[ARES_CACSIZE];
static aCache *cachetop = NULL;
static ResRQ *last, *first;

static void rem_cache(aCache *);
static void rem_request(ResRQ *);
static int do_query_name(Link *, char *, ResRQ *);
static int do_query_number(Link *, struct in_addr *, ResRQ *);
static void resend_query(ResRQ *);
static int proc_answer(ResRQ *, HEADER *, unsigned char *, unsigned char *);
static int query_name(char *, int, int, ResRQ *);
static aCache *make_cache(ResRQ *);
static aCache *find_cache_name(char *);
static aCache *find_cache_number(ResRQ *, struct in_addr *);
static int add_request(ResRQ *);
static ResRQ *make_request(Link *);
static int send_res_msg(char *, int, int);
static ResRQ *find_id(int);
static int hash_number(unsigned char *);
static void update_list(ResRQ *, aCache *);
static int hash_name(const char *);

static struct cacheinfo {
  int ca_adds;
  int ca_dels;
  int ca_expires;
  int ca_lookups;
  int ca_na_hits;
  int ca_nu_hits;
  int ca_updates;
} cainfo;

static struct resinfo {
  int re_errors;
  int re_nu_look;
  int re_na_look;
  int re_replies;
  int re_requests;
  int re_resends;
  int re_sent;
  int re_timeouts;
  int re_shortttl;
  int re_unkrep;
} reinfo;

int init_resolver(void)
{
  int on = 1;
  int fd = -1;

  memset(&reinfo, 0, sizeof(reinfo));
  memset(&cainfo, 0, sizeof(cainfo));
  memset(hashtable, 0, sizeof(hashtable));

  first = last = NULL;

  /* res_init() always returns 0 */
  (void)res_init();

  if (!_res.nscount)
  {
    _res.nscount = 1;
    _res.nsaddr_list[0].sin_addr.s_addr = inet_addr("127.0.0.1");
  }
#ifdef DEBUGMODE
  _res.options |= RES_DEBUG;
#endif

  alarm(2);
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  alarm(0);
  if (fd < 0)
  {
    if (errno == EMFILE || errno == ENOBUFS)
    {
      /*
       * Only try this one more time, if we can't create the resolver
       * socket at initialization time, it's pointless to continue.
       */
      alarm(2);
      if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
      {
	alarm(0);
	Debug((DEBUG_ERROR, "init_resolver: socket: No more sockets"));
	return -1;
      }
      alarm(0);
    }
    else
    {
      Debug((DEBUG_ERROR, "init_resolver: socket: %s", strerror(errno)));
      return -1;
    }
  }
  setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (OPT_TYPE *)&on, sizeof(on));
  return fd;
}

static int add_request(ResRQ *new_request)
{
  if (!new_request)
    return -1;
  if (!first)
    first = last = new_request;
  else
  {
    last->next = new_request;
    last = new_request;
  }
  new_request->next = NULL;
  reinfo.re_requests++;
  return 0;
}

/*
 * Remove a request from the list. This must also free any memory that has
 * been allocated for temporary storage of DNS results.
 */
static void rem_request(ResRQ *old_request)
{
  ResRQ **rptr;
  ResRQ *r2ptr = NULL;

  if (old_request)
  {
    for (rptr = &first; *rptr; r2ptr = *rptr, rptr = &(*rptr)->next)
    {
      if (*rptr == old_request)
      {
	*rptr = old_request->next;
	if (last == old_request)
	  last = r2ptr;
	break;
      }
    }
    Debug((DEBUG_DNS, "rem_request:Remove %p at %p %p",
	old_request, *rptr, r2ptr));

    if (old_request->he.buf)
      RunFree(old_request->he.buf);
    if (old_request->name)
      RunFree(old_request->name);
    RunFree(old_request);
  }
}

/*
 * Create a DNS request record for the server.
 */
static ResRQ *make_request(Link *lp)
{
  ResRQ *nreq;

  if ((nreq = (ResRQ *)RunMalloc(sizeof(ResRQ))) == NULL)
    return NULL;
  memset(nreq, 0, sizeof(ResRQ));
  nreq->sentat = now;
  nreq->retries = 3;
  nreq->resend = 1;
  nreq->srch = -1;
  if (lp)
    memcpy(&nreq->cinfo, lp, sizeof(Link));
  else
    memset(&nreq->cinfo, 0, sizeof(Link));
  nreq->timeout = 4;		/* start at 4 and exponential inc. */
  nreq->addr.s_addr = INADDR_NONE;

  nreq->he.h.h_addrtype = AF_INET;
  nreq->he.h.h_length = sizeof(struct in_addr);
  add_request(nreq);
  return nreq;
}

/*
 * Remove queries from the list which have been there too long without
 * being resolved.
 */
time_t timeout_query_list(void)
{
  ResRQ *rptr;
  ResRQ *r2ptr;
  time_t next = 0;
  time_t tout = 0;
  aClient *cptr;

  Debug((DEBUG_DNS, "timeout_query_list at %s", myctime(now)));
  for (rptr = first; rptr; rptr = r2ptr)
  {
    r2ptr = rptr->next;
    tout = rptr->sentat + rptr->timeout;
    if (now >= tout)
    {
      if (--rptr->retries <= 0)
      {
	Debug((DEBUG_DNS, "timeout %p now " TIME_T_FMT " cptr %p",
	    rptr, now, rptr->cinfo.value.cptr));
	reinfo.re_timeouts++;
	cptr = rptr->cinfo.value.cptr;
	switch (rptr->cinfo.flags)
	{
	  case ASYNC_CLIENT:
	    ClearDNS(cptr);
	    if (!DoingAuth(cptr))
	      SetAccess(cptr);
	    break;
	  case ASYNC_PING:
	    sendto_ops("Host %s unknown", rptr->name);
	    end_ping(cptr);
	    break;
	  case ASYNC_CONNECT:
	    sendto_ops("Host %s unknown", rptr->name);
	    break;
	}
	rem_request(rptr);
	rptr = NULL;
	continue;
      }
      else
      {
	rptr->sentat = now;
	rptr->timeout += rptr->timeout;
	resend_query(rptr);
	tout = now + rptr->timeout;
	Debug((DEBUG_DNS, "r %p now " TIME_T_FMT " retry %d c %p",
	    rptr, now, rptr->retries, rptr->cinfo.value.cptr));
      }
    }
    if (!next || tout < next)
      next = tout;
  }
  Debug((DEBUG_DNS, "Next timeout_query_list() at %s, %ld",
      myctime((next > now) ? next : (now + AR_TTL)),
      (next > now) ? (next - now) : AR_TTL));
  return (next > now) ? next : (now + AR_TTL);
}

/*
 * del_queries
 *
 * Called by the server to cleanup outstanding queries for
 * which there no longer exist clients or conf lines.
 */
void del_queries(char *cp)
{
  ResRQ *rptr, *r2ptr;

  for (rptr = first; rptr; rptr = r2ptr)
  {
    r2ptr = rptr->next;
    if (cp == rptr->cinfo.value.cp)
      rem_request(rptr);
  }
}

/*
 * send_res_msg
 *
 * sends msg to all nameservers found in the "_res" structure.
 * This should reflect /etc/resolv.conf. We will get responses
 * which arent needed but is easier than checking to see if nameserver
 * isnt present. Returns number of messages successfully sent to
 * nameservers or -1 if no successful sends.
 */
static int send_res_msg(char *msg, int len, int rcount)
{
  int i;
  int sent = 0, max;

  if (!msg)
    return -1;

  max = MIN(_res.nscount, rcount);
  if (_res.options & RES_PRIMARY)
    max = 1;
  if (!max)
    max = 1;

  for (i = 0; i < max; ++i)
  {
    _res.nsaddr_list[i].sin_family = AF_INET;
    if (sendto(resfd, msg, len, 0, (struct sockaddr *)&(_res.nsaddr_list[i]),
	sizeof(struct sockaddr)) == len)
    {
      reinfo.re_sent++;
      sent++;
    }
    else
      Debug((DEBUG_ERROR, "s_r_m:sendto: %s on %d", strerror(errno), resfd));
  }
  return (sent) ? sent : -1;
}

/*
 * find a dns request id (id is determined by dn_mkquery)
 */
static ResRQ *find_id(int id)
{
  ResRQ *rptr;

  for (rptr = first; rptr; rptr = rptr->next)
    if (rptr->id == id)
      return rptr;
  return NULL;
}

/*
 * add_local_domain
 *
 * Add the domain to hostname, if it is missing
 * (as suggested by eps@TOASTER.SFSU.EDU)
 */
void add_local_domain(char *hname, int size)
{
  /* try to fix up unqualified names */
  if (!strchr(hname, '.'))
  {
    if (_res.defdname[0] && size > 0)
    {
      strcat(hname, ".");
      strncat(hname, _res.defdname, size - 1);
    }
  }
}

struct hostent *gethost_byname(char *name, Link *lp)
{
  aCache *cp;

  reinfo.re_na_look++;
  if ((cp = find_cache_name(name)))
    return &cp->he.h;
  if (lp)
    do_query_name(lp, name, NULL);
  return NULL;
}

struct hostent *gethost_byaddr(struct in_addr *addr, Link *lp)
{
  aCache *cp;

  reinfo.re_nu_look++;
  if ((cp = find_cache_number(NULL, addr)))
    return &cp->he.h;
  if (!lp)
    return NULL;
  do_query_number(lp, addr, NULL);
  return NULL;
}

static int do_query_name(Link *lp, char *name, ResRQ *rptr)
{
  char hname[HOSTLEN + 1];
  int len;

  strncpy(hname, name, sizeof(hname) - 1);
  hname[sizeof(hname) - 1] = 0;
  len = strlen(hname);

  if (rptr && !strchr(hname, '.') && _res.options & RES_DEFNAMES)
  {
    strncat(hname, dot, sizeof(hname) - len - 1);
    len++;
    strncat(hname, _res.defdname, sizeof(hname) - len - 1);
  }

  /*
   * Store the name passed as the one to lookup and generate other host
   * names to pass onto the nameserver(s) for lookups.
   */
  if (!rptr)
  {
    if ((rptr = make_request(lp)) == NULL)
      return -1;
    rptr->type = T_A;
    rptr->name = (char *)RunMalloc(strlen(name) + 1);
    strcpy(rptr->name, name);
  }
  return (query_name(hname, C_IN, T_A, rptr));
}

/*
 * Use this to do reverse IP# lookups.
 */
static int do_query_number(Link *lp, struct in_addr *numb, ResRQ *rptr)
{
  char ipbuf[32];
  Reg2 unsigned char *cp = (unsigned char *)&numb->s_addr;

  sprintf_irc(ipbuf, "%u.%u.%u.%u.in-addr.arpa.",
      (unsigned int)(cp[3]), (unsigned int)(cp[2]),
      (unsigned int)(cp[1]), (unsigned int)(cp[0]));

  if (!rptr)
  {
    if ((rptr = make_request(lp)) == NULL)
      return -1;
    rptr->type = T_PTR;
    rptr->addr.s_addr = numb->s_addr;
  }
  return (query_name(ipbuf, C_IN, T_PTR, rptr));
}

/*
 * generate a query based on class, type and name.
 */
static int query_name(char *name, int q_class, int type, ResRQ *rptr)
{
  struct timeval tv;
  char buf[MAXPACKET];
  int r, s, k = 0;
  HEADER *hptr;

  Debug((DEBUG_DNS, "query_name: na %s cl %d ty %d", name, q_class, type));
  memset(buf, 0, sizeof(buf));
  r = res_mkquery(QUERY, name, q_class, type, NULL, 0, NULL,
      (unsigned char *)buf, sizeof(buf));
  if (r <= 0)
  {
    h_errno = NO_RECOVERY;
    return r;
  }
  hptr = (HEADER *) buf;
  gettimeofday(&tv, NULL);
  do
  {
    /* htons/ntohs can be assembler macros, which cannot
       be nested. Thus two lines.   -Vesa */
    unsigned short int nstmp = ntohs(hptr->id) + k
	+ (unsigned short int)(tv.tv_usec & 0xffff);
    hptr->id = htons(nstmp);
    k++;
  }
  while (find_id(ntohs(hptr->id)));
  rptr->id = ntohs(hptr->id);
  rptr->sends++;
  s = send_res_msg(buf, r, rptr->sends);
  if (s == -1)
  {
    h_errno = TRY_AGAIN;
    return -1;
  }
  else
    rptr->sent += s;
  return 0;
}

static void resend_query(ResRQ *rptr)
{
  if (rptr->resend == 0)
    return;
  reinfo.re_resends++;
  switch (rptr->type)
  {
    case T_PTR:
      do_query_number(NULL, &rptr->addr, rptr);
      break;
    case T_A:
      do_query_name(NULL, rptr->name, rptr);
      break;
    default:
      break;
  }
  return;
}

/*
 * proc_answer
 *
 * Process name server reply.
 */
static int proc_answer(ResRQ *rptr, HEADER * hptr, unsigned char *buf,
    unsigned char *eob)
{
  unsigned char *cp = buf + sizeof(HEADER);
  char **alias;
  char **addr;
  char *p;			/* pointer to strings */
  char *a;			/* pointer to address list */
  char *endp;			/* end of our buffer */
  struct hostent *hp = &rptr->he.h;
  int addr_class, type, dlen, ans = 0, n;
  int addr_count = 0;
  int alias_count = 0;

  /*
   * Lazy allocation of rptr->he.buf, we don't allocate a buffer
   * unless there's something to put in it.
   */
  if (!rptr->he.buf)
  {
    if ((rptr->he.buf = (char *)RunMalloc(MAXGETHOSTLEN)) == NULL)
      return 0;
    /* 
     * Array of alias list pointers starts at beginning of buf 
     */
    rptr->he.h.h_aliases = (char **)rptr->he.buf;
    rptr->he.h.h_aliases[0] = NULL;
    /* 
     * Array of address list pointers starts after alias list pointers.
     * The actual addresses follow the address list pointers.
     */
    rptr->he.h.h_addr_list = (char **)(rptr->he.buf + ALIASBLEN);
    a = (char *)rptr->he.h.h_addr_list + ADDRSBLEN;
    /*
       * don't copy the host address to the beginning of h_addr_list
       * make it just a little bit harder for the script kiddies
     */
    rptr->he.h.h_addr_list[0] = NULL;
  }
  endp = &rptr->he.buf[MAXGETHOSTLEN];

  /* find the end of the address list */
  addr = hp->h_addr_list;
  while (*addr)
  {
    ++addr;
    ++addr_count;
  }
  /* make 'a' point to the first available empty address slot */
  a = (char *)hp->h_addr_list + ADDRSBLEN +
      (addr_count * sizeof(struct in_addr));

  /* find the end of the alias list */
  alias = hp->h_aliases;
  while (*alias)
  {
    ++alias;
    ++alias_count;
  }
  /* make p point to the first available space in rptr->buf */
  if (alias_count > 0)
  {
    p = (char *)hp->h_aliases[alias_count - 1];
    p += (strlen(p) + 1);
  }
  else if (hp->h_name)
    p = (char *)(hp->h_name + strlen(hp->h_name) + 1);
  else
    p = (char *)rptr->he.h.h_addr_list + ADDRSBLEN + ADDRSDLEN;

  /*
   * Skip past query's
   */
#ifdef SOL2			/* brain damaged compiler (Solaris2) it seems */
  for (; hptr->qdcount > 0; hptr->qdcount--)
#else
  while (hptr->qdcount-- > 0)
#endif
  {
    if ((n = dn_skipname(cp, eob)) == -1)
      break;
    else
      cp += (n + QFIXEDSZ);
  }
  /*
   * Proccess each answer sent to us blech.
   */
  while (hptr->ancount-- > 0 && cp && cp < eob && p < endp)
  {
    if ((n = dn_expand(buf, eob, cp, hostbuf, sizeof(hostbuf))) <= 0)
    {
      Debug((DEBUG_DNS, "dn_expand failed"));
      break;
    }

    cp += n;
    /* XXX magic numbers, this checks for truncated packets */
    if ((cp + INT16SZ + INT16SZ + INT32SZ + INT16SZ) >= eob)
      break;

    /*
     * I have no idea why - maybe a bug in the linker? But _getshort
     * and _getlong don't work anymore.  So lets do it ourselfs:
     * --Run
     */

    type = ((u_int16_t) cp[0] << 8) | ((u_int16_t) cp[1]);
    cp += INT16SZ;
    addr_class = ((u_int16_t) cp[0] << 8) | ((u_int16_t) cp[1]);
    cp += INT16SZ;
    rptr->ttl =
	((u_int32_t) cp[0] << 24) | ((u_int32_t) cp[1] << 16) | ((u_int32_t)
	cp[2] << 8) | ((u_int32_t) cp[3]);
    cp += INT32SZ;
    dlen = ((u_int16_t) cp[0] << 8) | ((u_int16_t) cp[1]);
    cp += INT16SZ;

    rptr->type = type;

    /* check for bad dlen */
    if ((cp + dlen) > eob)
      break;

    /* 
     * Add default domain name to returned host name if host name
     * doesn't contain any dot separators.
     * Name server never returns with trailing '.'
     */
    if (!strchr(hostbuf, '.') && (_res.options & RES_DEFNAMES))
    {
      strcat(hostbuf, dot);
      strncat(hostbuf, _res.defdname, HOSTLEN - strlen(hostbuf));
      hostbuf[HOSTLEN] = 0;
    }

    switch (type)
    {
      case T_A:
	/* check for invalid dlen or too many addresses */
	if (dlen != sizeof(struct in_addr) || ++addr_count >= RES_MAXADDRS)
	  break;
	if (ans == 1)
	  hp->h_addrtype = (addr_class == C_IN) ? AF_INET : AF_UNSPEC;

	memcpy(a, cp, sizeof(struct in_addr));
	*addr++ = a;
	*addr = 0;
	a += sizeof(struct in_addr);

	if (!hp->h_name)
	{
	  strncpy(p, hostbuf, endp - p);
	  hp->h_name = p;
	  p += (strlen(p) + 1);
	}
	cp += dlen;
	Debug((DEBUG_DNS, "got ip # %s for %s",
	    inetntoa(*((struct in_addr *)hp->h_addr_list[addr_count - 1])),
	    hostbuf));
	ans++;
	break;
      case T_PTR:
	if ((n = dn_expand(buf, eob, cp, hostbuf, sizeof(hostbuf))) < 0)
	{
	  cp = NULL;
	  break;
	}
	cp += n;
	Debug((DEBUG_DNS, "got host %s", hostbuf));
	/*
	 * Copy the returned hostname into the host name or alias field if
	 * there is a known hostname already.
	 */
	if (hp->h_name)
	{
	  if (++alias_count >= RES_MAXALIASES)
	    break;
	  strncpy(p, hostbuf, endp - p);
	  endp[-1] = 0;
	  *alias++ = p;
	  *alias = NULL;
	}
	else
	{
	  strncpy(p, hostbuf, endp - p);
	  hp->h_name = p;
	}
	p += (strlen(p) + 1);
	ans++;
	break;
      case T_CNAME:
	cp += dlen;
	Debug((DEBUG_DNS, "got cname %s", hostbuf));
	if (++alias_count >= RES_MAXALIASES)
	  break;
	strncpy(p, hostbuf, endp - p);
	endp[-1] = 0;
	*alias++ = p;
	*alias = NULL;
	p += (strlen(p) + 1);
	ans++;
	break;
      default:
	Debug((DEBUG_DNS, "proc_answer: type:%d for:%s", type, hostbuf));
	break;
    }
  }
  return ans;
}

/*
 * Read a dns reply from the nameserver and process it.
 */
struct hostent *get_res(char *lp)
{
  static unsigned char buf[sizeof(HEADER) + MAXPACKET];
  Reg1 HEADER *hptr;
  Reg2 ResRQ *rptr = NULL;
  aCache *cp = NULL;
  struct sockaddr_in sin;
  int a, max;
  size_t rc, len = sizeof(sin);

  alarm(4);
  rc = recvfrom(resfd, buf, sizeof(buf), 0, (struct sockaddr *)&sin, &len);
  alarm(0);

  if (rc <= sizeof(HEADER))
    return NULL;
  /*
   * Convert DNS reply reader from Network byte order to CPU byte order.
   */
  hptr = (HEADER *) buf;
  hptr->id = ntohs(hptr->id);
  hptr->ancount = ntohs(hptr->ancount);
  hptr->qdcount = ntohs(hptr->qdcount);
  hptr->nscount = ntohs(hptr->nscount);
  hptr->arcount = ntohs(hptr->arcount);
#ifdef	DEBUG
  Debug((DEBUG_NOTICE, "get_res:id = %d rcode = %d ancount = %d",
      hptr->id, hptr->rcode, hptr->ancount));
#endif
  reinfo.re_replies++;
  /*
   * Response for an id which we have already received an answer for
   * just ignore this response.
   */
  if ((rptr = find_id(hptr->id)) == NULL)
  {
    Debug((DEBUG_DNS, "find_id %d failed", hptr->id));
    return NULL;
  }
  /*
   * Check against possibly fake replies
   */
  max = MIN(_res.nscount, rptr->sends);
  if (!max)
    max = 1;

  for (a = 0; a < max; a++)
  {
    if (!_res.nsaddr_list[a].sin_addr.s_addr ||
	!memcmp((char *)&sin.sin_addr, (char *)&_res.nsaddr_list[a].sin_addr,
	sizeof(struct in_addr)))
      break;
  }
  if (a == max)
  {
    reinfo.re_unkrep++;
    Debug((DEBUG_DNS, "got response from unknown ns"));
    goto getres_err;
  }

  if ((hptr->rcode != NOERROR) || (hptr->ancount == 0))
  {
    switch (hptr->rcode)
    {
      case NXDOMAIN:
	h_errno = TRY_AGAIN;
	break;
      case SERVFAIL:
	h_errno = TRY_AGAIN;
	break;
      case NOERROR:
	h_errno = NO_DATA;
	break;
      case FORMERR:
      case NOTIMP:
      case REFUSED:
      default:
	h_errno = NO_RECOVERY;
	break;
    }
    reinfo.re_errors++;
    /*
     * If a bad error was returned, we stop here and dont send
     * send any more (no retries granted).
     */
    if (h_errno != TRY_AGAIN)
    {
      Debug((DEBUG_DNS, "Fatal DNS error %d for %d", h_errno, hptr->rcode));
      rptr->resend = 0;
      rptr->retries = 0;
    }
    goto getres_err;
  }
  /* 
   * If this fails we didn't get a buffer to hold the hostent or
   * there was an error decoding the received packet, try it again
   * and hope it works the next time.
   */
  a = proc_answer(rptr, hptr, buf, &buf[rc]);
  Debug((DEBUG_DNS, "get_res:Proc answer = %d", a));

  if (a && rptr->type == T_PTR)
  {
    struct hostent *hp2 = NULL;

    if (BadPtr(rptr->he.h.h_name))	/* Kludge!      960907/Vesa */
      goto getres_err;

    Debug((DEBUG_DNS, "relookup %s <-> %s", rptr->he.h.h_name,
	inetntoa(rptr->addr)));
    /*
     * Lookup the 'authoritive' name that we were given for the
     * ip#.  By using this call rather than regenerating the
     * type we automatically gain the use of the cache with no
     * extra kludges.
     */
    if ((hp2 = gethost_byname((char *)rptr->he.h.h_name, &rptr->cinfo)))
    {
      if (lp)
	memcpy(lp, &rptr->cinfo, sizeof(Link));
    }
    /*
     * If name wasn't found, a request has been queued and it will
     * be the last one queued.  This is rather nasty way to keep
     * a host alias with the query. -avalon
     */
    else if (*rptr->he.h.h_aliases)
    {
      if (last->he.buf)
	RunFree(last->he.buf);
      last->he.buf = rptr->he.buf;
      rptr->he.buf = NULL;
      memcpy(&last->he.h, &rptr->he.h, sizeof(struct hostent));
    }
    rem_request(rptr);
    return hp2;
  }

  if (a > 0)
  {
    if (lp)
      memcpy(lp, &rptr->cinfo, sizeof(Link));
    cp = make_cache(rptr);
    Debug((DEBUG_DNS, "get_res:cp=%p rptr=%p (made)", cp, rptr));
    rem_request(rptr);
  }
  else if (!rptr->sent)
    rem_request(rptr);
  return cp ? &cp->he.h : NULL;

getres_err:
  /*
   * Reprocess an error if the nameserver didnt tell us to "TRY_AGAIN".
   */
  if (rptr)
  {
    if (h_errno != TRY_AGAIN)
    {
      /*
       * If we havent tried with the default domain and its
       * set, then give it a try next.
       */
      if (_res.options & RES_DEFNAMES && ++rptr->srch == 0)
      {
	rptr->retries = _res.retry;
	rptr->sends = 0;
	rptr->resend = 1;
	resend_query(rptr);
      }
      else
	resend_query(rptr);
    }
    else if (lp)
      memcpy(lp, &rptr->cinfo, sizeof(Link));
  }
  return NULL;
}

/*
 * Duplicate a hostent struct, allocate only enough memory for
 * the data we're putting in it.
 */
static int dup_hostent(aHostent *new_hp, struct hostent *hp)
{
  char *p;
  char **ap;
  char **pp;
  int alias_count = 0;
  int addr_count = 0;
  size_t bytes_needed = 0;

  if (!new_hp || !hp)
    return 0;

  /* how much buffer do we need? */
  bytes_needed += (strlen(hp->h_name) + 1);

  pp = hp->h_aliases;
  while (*pp)
  {
    bytes_needed += (strlen(*pp++) + 1 + sizeof(void *));
    ++alias_count;
  }
  pp = hp->h_addr_list;
  while (*pp++)
  {
    bytes_needed += (hp->h_length + sizeof(void *));
    ++addr_count;
  }
  /* Reserve space for 2 nulls to terminate h_aliases and h_addr_list */
  bytes_needed += (2 * sizeof(void *));

  /* Allocate memory */
  if ((new_hp->buf = (char *)RunMalloc(bytes_needed)) == NULL)
    return -1;

  new_hp->h.h_addrtype = hp->h_addrtype;
  new_hp->h.h_length = hp->h_length;

  /* first write the address list */
  pp = hp->h_addr_list;
  ap = new_hp->h.h_addr_list =
      (char **)(new_hp->buf + ((alias_count + 1) * sizeof(void *)));
  p = (char *)ap + ((addr_count + 1) * sizeof(void *));
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
  ap = new_hp->h.h_aliases = (char **)new_hp->buf;
  while (*pp)
  {
    *ap++ = p;
    strcpy(p, *pp++);
    p += (strlen(p) + 1);
  }
  *ap = 0;

  return 0;
}

/*
 * Add records to a Hostent struct in place.
 */
static int update_hostent(aHostent *hp, char **addr, char **alias)
{
  char *p;
  char **ap;
  char **pp;
  int alias_count = 0;
  int addr_count = 0;
  char *buf = NULL;
  size_t bytes_needed = 0;

  if (!hp || !hp->buf)
    return -1;

  /* how much buffer do we need? */
  bytes_needed = strlen(hp->h.h_name) + 1;
  pp = hp->h.h_aliases;
  while (*pp)
  {
    bytes_needed += (strlen(*pp++) + 1 + sizeof(void *));
    ++alias_count;
  }
  if (alias)
  {
    pp = alias;
    while (*pp)
    {
      bytes_needed += (strlen(*pp++) + 1 + sizeof(void *));
      ++alias_count;
    }
  }
  pp = hp->h.h_addr_list;
  while (*pp++)
  {
    bytes_needed += (hp->h.h_length + sizeof(void *));
    ++addr_count;
  }
  if (addr)
  {
    pp = addr;
    while (*pp++)
    {
      bytes_needed += (hp->h.h_length + sizeof(void *));
      ++addr_count;
    }
  }
  /* Reserve space for 2 nulls to terminate h_aliases and h_addr_list */
  bytes_needed += 2 * sizeof(void *);

  /* Allocate memory */
  if ((buf = (char *)RunMalloc(bytes_needed)) == NULL)
    return -1;

  /* first write the address list */
  pp = hp->h.h_addr_list;
  ap = hp->h.h_addr_list =
      (char **)(buf + ((alias_count + 1) * sizeof(void *)));
  p = (char *)ap + ((addr_count + 1) * sizeof(void *));
  while (*pp)
  {
    memcpy(p, *pp++, hp->h.h_length);
    *ap++ = p;
    p += hp->h.h_length;
  }
  if (addr)
  {
    while (*addr)
    {
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
  ap = hp->h.h_aliases = (char **)buf;
  while (*pp)
  {
    strcpy(p, *pp++);
    *ap++ = p;
    p += (strlen(p) + 1);
  }
  if (alias)
  {
    while (*alias)
    {
      strcpy(p, *alias++);
      *ap++ = p;
      p += (strlen(p) + 1);
    }
  }
  *ap = 0;
  /* release the old buffer */
  p = hp->buf;
  hp->buf = buf;
  RunFree(p);
  return 0;
}

static int hash_number(unsigned char *ip)
{
  unsigned int hashv = 0;

  /* could use loop but slower */
  hashv += (int)*ip++;
  hashv += hashv + (int)*ip++;
  hashv += hashv + (int)*ip++;
  hashv += hashv + (int)*ip++;
  hashv %= ARES_CACSIZE;
  return (hashv);
}

static int hash_name(const char *name)
{
  unsigned int hashv = 0;

  for (; *name && *name != '.'; name++)
    hashv += *name;
  hashv %= ARES_CACSIZE;
  return (hashv);
}

/*
 * Add a new cache item to the queue and hash table.
 */
static aCache *add_to_cache(aCache *ocp)
{
  aCache *cp = NULL;
  int hashv;

  Debug((DEBUG_DNS,
      "add_to_cache:ocp %p he %p name %p addrl %p 0 %p",
      ocp, &ocp->he, ocp->he.h.h_name, ocp->he.h.h_addr_list,
      ocp->he.h.h_addr_list[0]));

  ocp->list_next = cachetop;
  cachetop = ocp;

  hashv = hash_name(ocp->he.h.h_name);
  ocp->hname_next = hashtable[hashv].name_list;
  hashtable[hashv].name_list = ocp;

  hashv = hash_number((unsigned char *)ocp->he.h.h_addr_list[0]);
  ocp->hnum_next = hashtable[hashv].num_list;
  hashtable[hashv].num_list = ocp;

  Debug((DEBUG_DNS, "add_to_cache:added %s[%p] cache %p.",
      ocp->he.h.h_name, ocp->he.h.h_addr_list[0], ocp));
  Debug((DEBUG_DNS,
      "add_to_cache:h1 %d h2 %#x lnext %p namnext %p numnext %p",
      hash_name(ocp->he.h.h_name), hashv, ocp->list_next,
      ocp->hname_next, ocp->hnum_next));

  /*
   * LRU deletion of excessive cache entries.
   */
  if (++incache > MAXCACHED)
  {
    for (cp = cachetop; cp->list_next; cp = cp->list_next);
    rem_cache(cp);
  }
  cainfo.ca_adds++;

  return ocp;
}

/*
 * update_list
 *
 * Does not alter the cache structure passed. It is assumed that
 * it already contains the correct expire time, if it is a new entry. Old
 * entries have the expirey time updated.
 */
static void update_list(ResRQ *rptr, aCache *cp)
{
  aCache **cpp;
  char *s;
  char **ap;
  const char *t;
  int i, j;
  static char *addrs[RES_MAXADDRS + 1];
  static char *aliases[RES_MAXALIASES + 1];

  /*
   * Search for the new cache item in the cache list by hostname.
   * If found, move the entry to the top of the list and return.
   */
  cainfo.ca_updates++;

  for (cpp = &cachetop; *cpp; cpp = &((*cpp)->list_next))
  {
    if (cp == *cpp)
      break;
  }
  if (!*cpp)
    return;
  *cpp = cp->list_next;
  cp->list_next = cachetop;
  cachetop = cp;
  if (!rptr)
    return;

  Debug((DEBUG_DNS, "u_l:cp %p na %p al %p ad %p",
      cp, cp->he.h.h_name, cp->he.h.h_aliases, cp->he.h.h_addr_list[0]));
  Debug((DEBUG_DNS, "u_l:rptr %p h_n %p", rptr, rptr->he.h.h_name));
  /*
   * Compare the cache entry against the new record.  Add any
   * previously missing names for this entry.
   */

  *aliases = 0;
  ap = aliases;
  for (i = 0, s = (char *)rptr->he.h.h_name; s; s = rptr->he.h.h_aliases[i++])
  {
    for (j = 0, t = cp->he.h.h_name; t; t = cp->he.h.h_aliases[j++])
    {
      if (!strCasediff(t, s))
	break;
    }
    if (!t)
    {
      *ap++ = s;
      *ap = 0;
    }
  }

  /*
   * Do the same again for IP#'s.
   */
  *addrs = 0;
  ap = addrs;
  for (i = 0; (s = rptr->he.h.h_addr_list[i]); i++)
  {
    for (j = 0; (t = cp->he.h.h_addr_list[j]); j++)
    {
      if (!memcmp(t, s, sizeof(struct in_addr)))
	break;
    }
    if (!t)
    {
      *ap++ = s;
      *ap = 0;
    }
  }
  if (*addrs || *aliases)
    update_hostent(&cp->he, addrs, aliases);
}

static aCache *find_cache_name(char *name)
{
  aCache *cp;
  const char *s;
  int hashv;
  int i;

  hashv = hash_name(name);

  cp = hashtable[hashv].name_list;
  Debug((DEBUG_DNS, "find_cache_name:find %s : hashv = %d", name, hashv));

  for (; cp; cp = cp->hname_next)
  {
    for (i = 0, s = cp->he.h.h_name; s; s = cp->he.h.h_aliases[i++])
    {
      if (strCasediff(s, name) == 0)
      {
	cainfo.ca_na_hits++;
	update_list(0, cp);
	return cp;
      }
    }
  }

  for (cp = cachetop; cp; cp = cp->list_next)
  {
    /*
     * If no aliases or the hash value matches, we've already
     * done this entry and all possiblilities concerning it.
     */
    if (!*cp->he.h.h_aliases)
      continue;
    if (hashv == hash_name(cp->he.h.h_name))
      continue;
    for (i = 0; (s = cp->he.h.h_aliases[i]); ++i)
    {
      if (!strCasediff(name, s))
      {
	cainfo.ca_na_hits++;
	update_list(0, cp);
	return cp;
      }
    }
  }
  return NULL;
}

/*
 * Find a cache entry by ip# and update its expire time
 */
static aCache *find_cache_number(ResRQ *rptr, struct in_addr *numb)
{
  Reg1 aCache *cp;
  Reg2 int hashv, i;

  hashv = hash_number((unsigned char *)numb);

  cp = hashtable[hashv].num_list;
  Debug((DEBUG_DNS, "find_cache_number:find %s[%08x]: hashv = %d",
      inetntoa(*numb), ntohl(numb->s_addr), hashv));

  for (; cp; cp = cp->hnum_next)
  {
    for (i = 0; cp->he.h.h_addr_list[i]; ++i)
    {
      if (!memcmp(cp->he.h.h_addr_list[i], (char *)numb,
	  sizeof(struct in_addr)))
      {
	cainfo.ca_nu_hits++;
	update_list(rptr, cp);
	return cp;
      }
    }
  }

  for (cp = cachetop; cp; cp = cp->list_next)
  {
    /*
     * Single address entry...would have been done by hashed search above...
     */
    if (!cp->he.h.h_addr_list[1])
      continue;
    /*
     * If the first IP# has the same hashnumber as the IP# we
     * are looking for, its been done already.
     */
    if (hashv == hash_number((unsigned char *)cp->he.h.h_addr_list[0]))
      continue;
    for (i = 1; cp->he.h.h_addr_list[i]; ++i)
    {
      if (!memcmp(cp->he.h.h_addr_list[i], (char *)numb,
	  sizeof(struct in_addr)))
      {
	cainfo.ca_nu_hits++;
	update_list(rptr, cp);
	return cp;
      }
    }
  }
  return NULL;
}

static aCache *make_cache(ResRQ *rptr)
{
  aCache *cp;
  int i;
  struct hostent *hp = &rptr->he.h;

  /*
   * Shouldn't happen but it just might...
   */
  if (!hp->h_name || !hp->h_addr_list[0])
    return NULL;
  /*
   * Make cache entry.  First check to see if the cache already exists
   * and if so, return a pointer to it.
   */
  for (i = 0; hp->h_addr_list[i]; ++i)
  {
    if ((cp = find_cache_number(rptr, (struct in_addr *)hp->h_addr_list[i])))
      return cp;
  }

  /*
   * A matching entry wasnt found in the cache so go and make one up.
   */
  if ((cp = (aCache *)RunMalloc(sizeof(aCache))) == NULL)
    return NULL;
  memset(cp, 0, sizeof(aCache));
  dup_hostent(&cp->he, hp);

  if (rptr->ttl < 600)
  {
    reinfo.re_shortttl++;
    cp->ttl = 600;
  }
  else
    cp->ttl = rptr->ttl;
  cp->expireat = now + cp->ttl;
  Debug((DEBUG_INFO, "make_cache:made cache %p", cp));
  return add_to_cache(cp);
}

/*
 * rem_cache
 *
 * Delete a cache entry from the cache structures and lists and return
 * all memory used for the cache back to the memory pool.
 */
static void rem_cache(aCache *ocp)
{
  aCache **cp;
  struct hostent *hp = &ocp->he.h;
  int hashv;
  aClient *cptr;

  Debug((DEBUG_DNS, "rem_cache: ocp %p hp %p l_n %p aliases %p",
      ocp, hp, ocp->list_next, hp->h_aliases));

  /*
   * Cleanup any references to this structure by destroying the pointer.
   */
  for (hashv = highest_fd; hashv >= 0; --hashv)
  {
    if ((cptr = loc_clients[hashv]) && (cptr->hostp == hp))
      cptr->hostp = NULL;
  }
  /*
   * Remove cache entry from linked list.
   */
  for (cp = &cachetop; *cp; cp = &((*cp)->list_next))
  {
    if (*cp == ocp)
    {
      *cp = ocp->list_next;
      break;
    }
  }
  /*
   * Remove cache entry from hashed name lists.
   */
  hashv = hash_name(hp->h_name);

  Debug((DEBUG_DNS, "rem_cache: h_name %s hashv %d next %p first %p",
      hp->h_name, hashv, ocp->hname_next, hashtable[hashv].name_list));

  for (cp = &hashtable[hashv].name_list; *cp; cp = &((*cp)->hname_next))
  {
    if (*cp == ocp)
    {
      *cp = ocp->hname_next;
      break;
    }
  }
  /*
   * Remove cache entry from hashed number list
   */
  hashv = hash_number((unsigned char *)hp->h_addr_list[0]);

  Debug((DEBUG_DNS, "rem_cache: h_addr %s hashv %d next %p first %p",
      inetntoa(*((struct in_addr *)hp->h_addr_list[0])), hashv,
      ocp->hnum_next, hashtable[hashv].num_list));
  for (cp = &hashtable[hashv].num_list; *cp; cp = &((*cp)->hnum_next))
  {
    if (*cp == ocp)
    {
      *cp = ocp->hnum_next;
      break;
    }
  }

  if (ocp->he.buf)
    RunFree(ocp->he.buf);
  RunFree((char *)ocp);

  incache--;
  cainfo.ca_dels++;
}

/*
 * Removes entries from the cache which are older than their expirey times.
 * returns the time at which the server should next poll the cache.
 */
time_t expire_cache(void)
{
  Reg1 aCache *cp, *cp2;
  Reg2 time_t next = 0;

  for (cp = cachetop; cp; cp = cp2)
  {
    cp2 = cp->list_next;

    if (now >= cp->expireat)
    {
      cainfo.ca_expires++;
      rem_cache(cp);
    }
    else if (!next || next > cp->expireat)
      next = cp->expireat;
  }
  return (next > now) ? next : (now + AR_TTL);
}

/*
 * Remove all dns cache entries.
 */
void flush_cache(void)
{
  Reg1 aCache *cp;

  while ((cp = cachetop))
    rem_cache(cp);
}

int m_dns(aClient *cptr, aClient *sptr, int UNUSED(parc), char *parv[])
{
  aCache *cp;
  int i;
  struct hostent *h;

  if (parv[1] && *parv[1] == 'l')
  {
    if (!IsAnOper(cptr))
    {
      return 0;
    }
    for (cp = cachetop; cp; cp = cp->list_next)
    {
      h = &cp->he.h;
      sendto_one(sptr, "NOTICE %s :Ex %d ttl %d host %s(%s)",
	  parv[0], (int)(cp->expireat - now), (int)cp->ttl,
	  h->h_name, inetntoa(*((struct in_addr *)h->h_addr_list[0])));
      for (i = 0; h->h_aliases[i]; i++)
	sendto_one(sptr, "NOTICE %s : %s = %s (CN)",
	    parv[0], h->h_name, h->h_aliases[i]);
      for (i = 1; h->h_addr_list[i]; i++)
	sendto_one(sptr, "NOTICE %s : %s = %s (IP)", parv[0],
	    h->h_name, inetntoa(*((struct in_addr *)h->h_addr_list[i])));
    }
    return 0;
  }
  sendto_one(sptr, "NOTICE %s :Ca %d Cd %d Ce %d Cl %d Ch %d:%d Cu %d",
      sptr->name, cainfo.ca_adds, cainfo.ca_dels, cainfo.ca_expires,
      cainfo.ca_lookups, cainfo.ca_na_hits, cainfo.ca_nu_hits,
      cainfo.ca_updates);
  sendto_one(sptr, "NOTICE %s :Re %d Rl %d/%d Rp %d Rq %d",
      sptr->name, reinfo.re_errors, reinfo.re_nu_look,
      reinfo.re_na_look, reinfo.re_replies, reinfo.re_requests);
  sendto_one(sptr, "NOTICE %s :Ru %d Rsh %d Rs %d(%d) Rt %d", sptr->name,
      reinfo.re_unkrep, reinfo.re_shortttl, reinfo.re_sent,
      reinfo.re_resends, reinfo.re_timeouts);
  return 0;
}

size_t cres_mem(aClient *sptr)
{
  aCache *c = cachetop;
  struct hostent *h;
  int i;
  size_t nm = 0, im = 0, sm = 0, ts = 0;

  for (; c; c = c->list_next)
  {
    sm += sizeof(*c);
    h = &c->he.h;
    for (i = 0; h->h_addr_list[i]; i++)
    {
      im += sizeof(char *);
      im += sizeof(struct in_addr);
    }
    im += sizeof(char *);
    for (i = 0; h->h_aliases[i]; i++)
    {
      nm += sizeof(char *);
      nm += strlen(h->h_aliases[i]);
    }
    nm += i - 1;
    nm += sizeof(char *);
    if (h->h_name)
      nm += strlen(h->h_name);
  }
  ts = ARES_CACSIZE * sizeof(CacheTable);
  sendto_one(sptr, ":%s %d %s :RES table " SIZE_T_FMT,
      me.name, RPL_STATSDEBUG, sptr->name, ts);
  sendto_one(sptr, ":%s %d %s :Structs " SIZE_T_FMT
      " IP storage " SIZE_T_FMT " Name storage " SIZE_T_FMT,
      me.name, RPL_STATSDEBUG, sptr->name, sm, im, nm);
  return ts + sm + im + nm;
}
