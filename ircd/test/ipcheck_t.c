/* ipcheck_t.c - unit tests for the IPcheck connection-rate registry.
 *
 * Exercises ircd/IPcheck.c through its public API with a fake clock and
 * fake feature values: per-address clone limit and period, the boot grace
 * period (IPCHECK_CLONE_DELAY), connect_fail() undo, disconnect() and
 * IPcheck_nr() accounting, exemption netblocks, remote vs. burst
 * introductions, the IPv6 /48 limit, address canonicalisation (IPv4 /32,
 * IPv6 /64), free-target bookkeeping, registry expiry, the 32-bit
 * last_connect clock wrap, and the "connected" counter overflow guard.
 */

#include "IPcheck.h"
#include "client.h"
#include "ircd.h"
#include "ircd_defs.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "s_user.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- globals IPcheck.o expects from the rest of ircd --------------------- */

time_t CurrentTime;
extern struct Client me;

static int f_clone_limit  = 4;
static int f_clone_period = 40;
static int f_48_limit     = 50;
static int f_48_period    = 10;
static int f_clone_delay  = 600;

int feature_int(enum Feature feat)
{
  switch (feat) {
  case FEAT_IPCHECK_CLONE_LIMIT:     return f_clone_limit;
  case FEAT_IPCHECK_CLONE_PERIOD:    return f_clone_period;
  case FEAT_IPCHECK_48_CLONE_LIMIT:  return f_48_limit;
  case FEAT_IPCHECK_48_CLONE_PERIOD: return f_48_period;
  case FEAT_IPCHECK_CLONE_DELAY:     return f_clone_delay;
  default:                           return 0;
  }
}

/* IPcheck_init() registers a periodic expiry timer; capture the callback so
 * the tests can run an expiry pass on demand. */
static EventCallBack expire_cb;

struct Timer *timer_init(struct Timer *timer) { return timer; }
void timer_add(struct Timer *timer, EventCallBack call, void *data,
               enum TimerType type, time_t value)
{
  (void)timer; (void)data; (void)type; (void)value;
  expire_cb = call;
}

/* IPcheck_connect_succeeded() sends "on %u ca %u(%u) ft %u(%u)%s"; capture
 * the values so tests can assert on the registry state it reports. */
static struct {
  int calls;
  unsigned int connected, attempts, limit, free_targets, start_targets;
  int has_tr;
} notice;

void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...)
{
  va_list ap;
  (void)from; (void)cmd; (void)tok; (void)to;

  if (strcmp(pattern, "%C :on %u ca %u(%u) ft %u(%u)%s")) {
    fprintf(stderr, "unexpected sendcmdto_one pattern: %s\n", pattern);
    abort();
  }
  va_start(ap, pattern);
  (void)va_arg(ap, struct Client *);
  notice.connected     = va_arg(ap, unsigned int);
  notice.attempts      = va_arg(ap, unsigned int);
  notice.limit         = va_arg(ap, unsigned int);
  notice.free_targets  = va_arg(ap, unsigned int);
  notice.start_targets = va_arg(ap, unsigned int);
  notice.has_tr        = !!strcmp(va_arg(ap, const char *), "");
  va_end(ap);
  notice.calls++;
}

/* --- tiny test framework ------------------------------------------------ */

static int failures;
static const char *current;

#define CHECK(cond) do {                                                   \
  if (!(cond)) {                                                           \
    failures++;                                                            \
    fprintf(stderr, "FAIL %s:%d [%s]: %s\n", __FILE__, __LINE__, current,  \
            #cond);                                                        \
  }                                                                        \
} while (0)

#define CHECK_EQ(a, b) do {                                                \
  long _a = (long)(a), _b = (long)(b);                                     \
  if (_a != _b) {                                                          \
    failures++;                                                            \
    fprintf(stderr, "FAIL %s:%d [%s]: %s == %ld, expected %s == %ld\n",    \
            __FILE__, __LINE__, current, #a, _a, #b, _b);                  \
  }                                                                        \
} while (0)

/* --- helpers ------------------------------------------------------------ */

static struct Connection me_con;

/* Pool of fake clients; each gets its own Connection so cli_* accessors
 * work and MyConnect() can be controlled. */
#define NCLIENTS 64
static struct Client     clients[NCLIENTS];
static struct Connection conns[NCLIENTS];
static int               nclients;

static struct Client *mk_client(const char *ip, int local)
{
  struct Client *cptr;
  struct Connection *con;

  if (nclients >= NCLIENTS) {
    fprintf(stderr, "client pool exhausted\n");
    abort();
  }
  cptr = &clients[nclients];
  con  = &conns[nclients];
  nclients++;
  memset(cptr, 0, sizeof(*cptr));
  memset(con, 0, sizeof(*con));
  cli_connect(cptr) = con;
  /* MyConnect(cptr) is cli_from(cptr) == cptr; a remote client's "from" is
   * the server it came in through. */
  con_client(con) = local ? cptr : &me;
  cli_firsttime(cptr) = CurrentTime;
  cli_nexttarget(cptr) = CurrentTime - TARGET_DELAY * STARTTARGETS;
  if (!ircd_aton(&cli_ip(cptr), ip)) {
    fprintf(stderr, "bad test address %s\n", ip);
    abort();
  }
  return cptr;
}

static struct irc_in_addr addr_of(const char *ip)
{
  struct irc_in_addr a;
  if (!ircd_aton(&a, ip)) {
    fprintf(stderr, "bad test address %s\n", ip);
    abort();
  }
  return a;
}

/* Simulate the accept path: IPcheck_local_connect() and, when the address
 * was recorded, the flag add_connection() sets.  Returns the client
 * (accepted) or NULL (refused). */
static struct Client *local_connect(const char *ip, time_t *next_target)
{
  struct irc_in_addr a = addr_of(ip);
  time_t nt;
  struct Client *cptr;
  int res = IPcheck_local_connect(&a, next_target ? next_target : &nt);

  if (res == IPCHECK_REFUSED)
    return NULL;
  cptr = mk_client(ip, 1);
  if (res == IPCHECK_COUNTED)
    SetIPChecked(cptr);
  return cptr;
}

/* Disconnect the way s_misc.c does: only counted clients touch the
 * registry. */
static void disconnect(struct Client *cptr)
{
  if (IsIPChecked(cptr))
    IPcheck_disconnect(cptr);
}

/* Count of clients IPcheck knows for \a ip. */
static unsigned int nr(const char *ip)
{
  struct Client probe;
  memset(&probe, 0, sizeof(probe));
  cli_ip(&probe) = addr_of(ip);
  return IPcheck_nr(&probe);
}

/* Fresh registry state between tests: distinct address per test avoids
 * cross-talk, and the fake clock keeps moving forward. */
static void begin(const char *name)
{
  current = name;
  nclients = 0;
  memset(&notice, 0, sizeof(notice));
  f_clone_limit  = 4;
  f_clone_period = 40;
  f_48_limit     = 50;
  f_48_period    = 10;
  f_clone_delay  = 600;
  CurrentTime += 10000;           /* well past every period and expiry */
  cli_since(&me) = CurrentTime - 100000; /* "booted long ago" by default */
  IPcheck_clear_config();
}

/* --- tests -------------------------------------------------------------- */

/* Up to IPCHECK_CLONE_LIMIT-1 connects within a period are accepted, the
 * next is refused and does not count as connected, and the counter resets
 * once the address has been idle for more than the period. */
static void test_clone_limit_and_period(void)
{
  int i;
  begin("clone_limit_and_period");

  for (i = 1; i < f_clone_limit; i++)
    CHECK(local_connect("10.1.0.1", NULL) != NULL);
  CHECK_EQ(nr("10.1.0.1"), f_clone_limit - 1);

  CHECK(local_connect("10.1.0.1", NULL) == NULL);   /* attempt == limit */
  CHECK_EQ(nr("10.1.0.1"), f_clone_limit - 1);      /* refusal not counted */
  CHECK(local_connect("10.1.0.1", NULL) == NULL);   /* still refused */

  /* A refused attempt restarts the period too: exactly one period after
   * the last refusal is still inside it, one second more is not. */
  CurrentTime += f_clone_period;
  CHECK(local_connect("10.1.0.1", NULL) == NULL);
  CurrentTime += f_clone_period;
  CHECK(local_connect("10.1.0.1", NULL) == NULL);
  CurrentTime += f_clone_period + 1;
  CHECK(local_connect("10.1.0.1", NULL) != NULL);
  CHECK_EQ(nr("10.1.0.1"), f_clone_limit);
}

/* Other addresses are unaffected by one address hitting its limit. */
static void test_addresses_are_independent(void)
{
  int i;
  begin("addresses_are_independent");

  for (i = 1; i < f_clone_limit; i++)
    CHECK(local_connect("10.2.0.1", NULL) != NULL);
  CHECK(local_connect("10.2.0.1", NULL) == NULL);
  CHECK(local_connect("10.2.0.2", NULL) != NULL);
  CHECK_EQ(nr("10.2.0.2"), 1);
  CHECK_EQ(nr("10.2.0.1"), f_clone_limit - 1);
}

/* IPCHECK_CLONE_DELAY: nothing is refused until the server has been up
 * for longer than the delay (attempts are still counted). */
static void test_boot_grace(void)
{
  int i;
  begin("boot_grace");
  f_clone_delay = 30;                    /* shorter than the clone period */
  cli_since(&me) = CurrentTime;          /* just booted */

  for (i = 0; i < 3 * f_clone_limit; i++)
    CHECK(local_connect("10.3.0.1", NULL) != NULL);
  CHECK_EQ(nr("10.3.0.1"), 3 * f_clone_limit);

  /* Grace over, still inside the clone period: the accumulated attempts
   * now bite. */
  CurrentTime += f_clone_delay + 1;
  CHECK(local_connect("10.3.0.1", NULL) == NULL);
}

/* IPcheck_connect_fail() gives back the attempt (and optionally the
 * connected slot) for a rejection that was not the client's fault. */
static void test_connect_fail_undo(void)
{
  struct Client *c1, *c2, *c3;
  begin("connect_fail_undo");

  c1 = local_connect("10.4.0.1", NULL);
  c2 = local_connect("10.4.0.1", NULL);
  c3 = local_connect("10.4.0.1", NULL);
  CHECK(c1 && c2 && c3);           /* attempts == limit - 1 */

  /* Registration of c3 failed through no fault of its own, but it is
   * still connected: one attempt returned, still 3 connected, so one more
   * connect fits before the limit. */
  IPcheck_connect_fail(c3, 0);
  CHECK_EQ(nr("10.4.0.1"), 3);
  CHECK(local_connect("10.4.0.1", NULL) != NULL);
  CHECK(local_connect("10.4.0.1", NULL) == NULL);

  /* disconnect=1 also releases the connected slot. */
  IPcheck_connect_fail(c2, 1);
  CHECK_EQ(nr("10.4.0.1"), 3);
}

/* IPcheck_disconnect() decrements the connected count; when the last
 * client leaves after a long connection the attempt counter is cleared so
 * an immediate reconnect is not penalised for ancient history. */
static void test_disconnect_accounting(void)
{
  struct Client *c1, *c2;
  begin("disconnect_accounting");

  c1 = local_connect("10.5.0.1", NULL);
  c2 = local_connect("10.5.0.1", NULL);
  CHECK(c1 && c2);
  CHECK_EQ(nr("10.5.0.1"), 2);

  IPcheck_disconnect(c1);
  CHECK_EQ(nr("10.5.0.1"), 1);

  /* Reconnecting right away continues the attempt count (2 -> 3). */
  c1 = local_connect("10.5.0.1", NULL);
  CHECK(c1 != NULL);
  CHECK(local_connect("10.5.0.1", NULL) == NULL);

  /* Everyone leaves after being connected longer than limit*period: the
   * last disconnect resets the attempts (and stamps last_connect), so an
   * immediate reconnect burst is allowed again.  Without that reset the
   * three old attempts would still count and the first reconnect would be
   * refused, since no period has elapsed since the disconnect. */
  CurrentTime += f_clone_limit * f_clone_period + 1;
  IPcheck_disconnect(c1);
  IPcheck_disconnect(c2);
  CHECK_EQ(nr("10.5.0.1"), 0);
  CHECK(local_connect("10.5.0.1", NULL) != NULL);
  CHECK(local_connect("10.5.0.1", NULL) != NULL);
  CHECK(local_connect("10.5.0.1", NULL) != NULL);
  CHECK(local_connect("10.5.0.1", NULL) == NULL);
}

/* IPCheck { except ... } netblocks bypass the limit entirely, for local
 * and remote clients, until the config is cleared. */
static void test_exemptions(void)
{
  int i;
  struct Client *r;
  begin("exemptions");

  CHECK_EQ(IPcheck_except("10.6.0.0/16"), 0);
  CHECK_EQ(IPcheck_except("2001:db8:6::/48"), 0);
  CHECK(IPcheck_except("not an address") != 0);

  for (i = 0; i < 5 * f_clone_limit; i++) {
    struct Client *c = local_connect("10.6.1.1", NULL);
    CHECK(c != NULL);
    CHECK(!IsIPChecked(c));           /* accepted but not recorded */
  }
  {
    struct irc_in_addr a = addr_of("10.6.1.1");
    time_t nt = 0;
    CHECK_EQ(IPcheck_local_connect(&a, &nt), IPCHECK_EXEMPT);
  }
  for (i = 0; i < 5 * f_clone_limit; i++)
    CHECK(local_connect("2001:db8:6:1::1", NULL) != NULL);
  /* Exempt addresses are never entered in the registry. */
  CHECK_EQ(nr("10.6.1.1"), 0);

  /* Remote exempt clients are accepted but not recorded either. */
  r = mk_client("10.6.2.2", 0);
  CHECK(IPcheck_remote_connect(r, 0) != 0);
  CHECK(!IsIPChecked(r));
  CHECK_EQ(nr("10.6.2.2"), 0);

  /* Outside the block: normal limit. */
  for (i = 1; i < f_clone_limit; i++)
    CHECK(local_connect("10.7.0.1", NULL) != NULL);
  CHECK(local_connect("10.7.0.1", NULL) == NULL);

  /* Rehash without the block: exemption gone. */
  IPcheck_clear_config();
  for (i = 1; i < f_clone_limit; i++)
    CHECK(local_connect("10.6.1.1", NULL) != NULL);
  CHECK(local_connect("10.6.1.1", NULL) == NULL);
}

/* An address that becomes exempt while it already has a registry entry
 * (clients connected before the rehash, or remote users) must not have that
 * entry disturbed by exempt clients coming and going; and clients that were
 * counted before the exemption still release their slot afterwards. */
static void test_exempt_does_not_touch_existing_entry(void)
{
  struct Client *counted, *exempt1, *exempt2, *remote;
  begin("exempt_does_not_touch_existing_entry");

  counted = local_connect("10.14.0.1", NULL);
  remote  = mk_client("10.14.0.1", 0);
  CHECK(counted && IsIPChecked(counted));
  CHECK(IPcheck_remote_connect(remote, 0) != 0);
  CHECK_EQ(nr("10.14.0.1"), 2);

  CHECK_EQ(IPcheck_except("10.14.0.0/24"), 0);
  exempt1 = local_connect("10.14.0.1", NULL);
  exempt2 = local_connect("10.14.0.1", NULL);
  CHECK(exempt1 && exempt2);
  CHECK(!IsIPChecked(exempt1) && !IsIPChecked(exempt2));
  CHECK_EQ(nr("10.14.0.1"), 2);           /* untouched */

  disconnect(exempt1);
  disconnect(exempt2);
  CHECK_EQ(nr("10.14.0.1"), 2);           /* still untouched, no underflow */

  IPcheck_clear_config();                 /* exemption removed again */
  disconnect(counted);
  CHECK_EQ(nr("10.14.0.1"), 1);
  disconnect(remote);
  CHECK_EQ(nr("10.14.0.1"), 0);
}

/* Remote clients share the per-address entry: non-burst introductions
 * count as attempts (so they can exhaust the local limit) but are never
 * refused themselves; burst introductions count only as connected. */
static void test_remote_and_burst(void)
{
  int i;
  struct Client *r[8];
  begin("remote_and_burst");

  for (i = 0; i < 3; i++) {
    r[i] = mk_client("10.8.0.1", 0);
    CHECK(IPcheck_remote_connect(r[i], 0) != 0);
    CHECK(IsIPChecked(r[i]));
  }
  CHECK_EQ(nr("10.8.0.1"), 3);
  /* Three remote attempts + this one == limit. */
  CHECK(local_connect("10.8.0.1", NULL) == NULL);
  /* Remote is never rate-limited. */
  for (i = 3; i < 8; i++) {
    r[i] = mk_client("10.8.0.1", 0);
    CHECK(IPcheck_remote_connect(r[i], 0) != 0);
  }
  CHECK_EQ(nr("10.8.0.1"), 8);

  /* Burst: connected counts, attempts do not. */
  for (i = 0; i < 6; i++) {
    struct Client *b = mk_client("10.9.0.1", 0);
    CHECK(IPcheck_remote_connect(b, 1) != 0);
  }
  CHECK_EQ(nr("10.9.0.1"), 6);
  for (i = 1; i < f_clone_limit; i++)
    CHECK(local_connect("10.9.0.1", NULL) != NULL);
  CHECK(local_connect("10.9.0.1", NULL) == NULL);
  CHECK_EQ(nr("10.9.0.1"), 6 + f_clone_limit - 1);

  /* Remote clients disconnecting release their slots too. */
  for (i = 0; i < 8; i++)
    IPcheck_disconnect(r[i]);
  CHECK_EQ(nr("10.8.0.1"), 0);
}

/* IPv6 addresses are keyed on their /64, and a /48 has its own, separate
 * attempt limit across all of its /64s. */
static void test_ipv6_64_and_48(void)
{
  int i;
  begin("ipv6_64_and_48");

  /* Same /64, different host bits: one entry. */
  for (i = 1; i < f_clone_limit; i++)
    CHECK(local_connect("2001:db8:1:1::1", NULL) != NULL);
  CHECK(local_connect("2001:db8:1:1:ffff::2", NULL) == NULL);
  CHECK_EQ(nr("2001:db8:1:1::abcd"), f_clone_limit - 1);

  /* Different /64 in the same /48: separate entry, accepted. */
  CHECK(local_connect("2001:db8:1:2::1", NULL) != NULL);
  CHECK_EQ(nr("2001:db8:1:2::1"), 1);

  /* /48 limit: with limit 3, the third connect from any /64 of the /48
   * within the /48 period is refused, even for a never-seen /64. */
  f_48_limit = 3;
  CHECK(local_connect("2001:db8:2:1::1", NULL) != NULL);
  CHECK(local_connect("2001:db8:2:2::1", NULL) != NULL);
  CHECK(local_connect("2001:db8:2:3::1", NULL) == NULL);
  CHECK_EQ(nr("2001:db8:2:3::1"), 0);
  /* A /48 refusal for an existing /64 must not leak a connected slot. */
  CHECK(local_connect("2001:db8:2:1::1", NULL) == NULL);
  CHECK_EQ(nr("2001:db8:2:1::1"), 1);

  /* After the /48 period the /48 counter resets. */
  CurrentTime += f_48_period + 1;
  CHECK(local_connect("2001:db8:2:3::1", NULL) != NULL);

  /* Remote IPv6 clients count against the /48 too. */
  {
    struct Client *r = mk_client("2001:db8:3:1::1", 0);
    CHECK(IPcheck_remote_connect(r, 0) != 0);
    r = mk_client("2001:db8:3:2::1", 0);
    CHECK(IPcheck_remote_connect(r, 0) != 0);
    CHECK(local_connect("2001:db8:3:3::1", NULL) == NULL);
  }
}

/* IPv4 addresses are keyed on the full /32 (6to4 form, /48). */
static void test_ipv4_canonical_form(void)
{
  int i;
  begin("ipv4_canonical_form");

  for (i = 1; i < f_clone_limit; i++)
    CHECK(local_connect("192.0.2.10", NULL) != NULL);
  CHECK(local_connect("192.0.2.10", NULL) == NULL);
  /* Adjacent addresses are distinct entries. */
  CHECK(local_connect("192.0.2.11", NULL) != NULL);
  CHECK(local_connect("192.0.2.9", NULL) != NULL);
  CHECK_EQ(nr("192.0.2.11"), 1);
}

/* Free-target bookkeeping: a new address starts with STARTTARGETS, a
 * departing client leaves behind the smallest free-target count seen, the
 * next client from that address inherits it (and its target hashes), and
 * the count regenerates at one per TARGET_DELAY seconds of idle time. */
static void test_free_targets(void)
{
  struct Client *c;
  time_t nt = 0;
  begin("free_targets");

  c = local_connect("10.10.0.1", &nt);
  CHECK(c != NULL);
  CHECK_EQ(nt, 0);   /* new address: caller keeps the client default */
  IPcheck_connect_succeeded(c);
  CHECK_EQ(notice.calls, 1);
  CHECK_EQ(notice.connected, 1);
  CHECK_EQ(notice.attempts, 1);
  CHECK_EQ(notice.limit, f_clone_limit);
  CHECK_EQ(notice.free_targets, STARTTARGETS);
  CHECK_EQ(notice.start_targets, STARTTARGETS);
  CHECK(!notice.has_tr);

  /* The client used its targets: nexttarget 2 delays in the past means
   * 3 free targets at disconnect. */
  cli_nexttarget(c) = CurrentTime - 2 * TARGET_DELAY;
  memset(cli_targets(c), 0x5a, MAXTARGETS);
  IPcheck_disconnect(c);

  /* Next client inherits 3 free targets and the target hashes. */
  c = local_connect("10.10.0.1", &nt);
  CHECK(c != NULL);
  CHECK_EQ(nt, CurrentTime - (TARGET_DELAY * 3 - 1));
  IPcheck_connect_succeeded(c);
  CHECK_EQ(notice.free_targets, 3);
  CHECK(notice.has_tr);
  CHECK_EQ(cli_targets(c)[0], 0x5a);
  CHECK_EQ(cli_targets(c)[MAXTARGETS - 1], 0x5a);

  /* A client with no free targets left pins the count at 0. */
  cli_nexttarget(c) = CurrentTime + 5 * TARGET_DELAY;
  IPcheck_disconnect(c);
  c = local_connect("10.10.0.1", &nt);
  CHECK(c != NULL);
  CHECK_EQ(nt, CurrentTime + 1);
  IPcheck_connect_succeeded(c);
  CHECK_EQ(notice.free_targets, 0);
  IPcheck_disconnect(c);

  /* Regeneration: two delays of idle time give two targets back. */
  CurrentTime += 2 * TARGET_DELAY;
  c = local_connect("10.10.0.1", &nt);
  CHECK(c != NULL);
  CHECK_EQ(nt, CurrentTime - (TARGET_DELAY * 2 - 1));
  IPcheck_connect_succeeded(c);
  CHECK_EQ(notice.free_targets, 2);

  /* Long-lived clients earn a bonus: 10 minutes plus 4 delays online. */
  cli_firsttime(c) = CurrentTime - 600 - 4 * TARGET_DELAY;
  cli_nexttarget(c) = CurrentTime - 1;    /* 1 free target itself */
  IPcheck_disconnect(c);
  c = local_connect("10.10.0.1", &nt);
  CHECK(c != NULL);
  /* min(previous 2 regenerated, 1 + 4 bonus) == 2, capped by history. */
  IPcheck_connect_succeeded(c);
  CHECK_EQ(notice.free_targets, 2);

  /* Remote clients leave no target history. */
  {
    struct Client *r = mk_client("10.10.0.2", 0);
    CHECK(IPcheck_remote_connect(r, 0) != 0);
    cli_nexttarget(r) = CurrentTime + 5 * TARGET_DELAY;
    IPcheck_disconnect(r);
    c = local_connect("10.10.0.2", &nt);
    CHECK(c != NULL);
    CHECK_EQ(nt, CurrentTime - (TARGET_DELAY * STARTTARGETS - 1));
  }
}

/* The expiry pass drops target history after 120 s idle and the whole
 * entry after 600 s idle, but only for addresses with nothing connected. */
static void test_expiry(void)
{
  struct Client *c;
  time_t nt = 0;
  begin("expiry");
  CHECK(expire_cb != NULL);

  /* Leave zero free targets behind. */
  c = local_connect("10.11.0.1", &nt);
  CHECK(c != NULL);
  cli_nexttarget(c) = CurrentTime + 5 * TARGET_DELAY;
  IPcheck_disconnect(c);

  /* 100 s idle: history kept (0 targets, nt in the future). */
  {
    struct Event ev;
    struct Timer tim;
    memset(&ev, 0, sizeof(ev));
    ev.ev_type = ET_EXPIRE;
    ev.ev_gen.gen_timer = &tim;

    CurrentTime += 100;
    expire_cb(&ev);
    c = local_connect("10.11.0.1", &nt);
    CHECK(c != NULL);
    CHECK_EQ(nt, CurrentTime + 1);
    IPcheck_disconnect(c);

    /* > 120 s idle: target history expired, back to STARTTARGETS. */
    CurrentTime += 121;
    expire_cb(&ev);
    c = local_connect("10.11.0.1", &nt);
    CHECK(c != NULL);
    CHECK_EQ(nt, CurrentTime - (TARGET_DELAY * STARTTARGETS - 1));

    /* An address with a client still connected is never expired. */
    CurrentTime += 601;
    expire_cb(&ev);
    CHECK_EQ(nr("10.11.0.1"), 1);
    IPcheck_disconnect(c);

    /* > 600 s idle: entry dropped and the address behaves like a new
     * one (the attempt counter alone cannot tell this apart from the
     * period reset; this mainly checks the pass does not crash or drop
     * live entries). */
    c = local_connect("10.11.0.1", &nt);
    CHECK(c != NULL);
    IPcheck_disconnect(c);
    CHECK_EQ(nr("10.11.0.1"), 0);
    CurrentTime += 601;
    expire_cb(&ev);
    CHECK(local_connect("10.11.0.1", NULL) != NULL);
    CHECK(local_connect("10.11.0.1", NULL) != NULL);
    CHECK(local_connect("10.11.0.1", NULL) != NULL);
    CHECK(local_connect("10.11.0.1", NULL) == NULL);
  }
}

/* last_connect holds the low 32 bits of CurrentTime: a long idle time
 * must not alias to a short one, and "seconds since" must survive
 * CurrentTime crossing a multiple of 2^32. */
static void test_clock_wrap(void)
{
  begin("clock_wrap");

  /* Idle for 2^16 + 1 s with a client still connected (so the entry is
   * not expired).  A 16-bit stamp sees 1 s, keeps counting attempts and
   * refuses the reconnect; the entry must instead look idle and reset. */
  CHECK(local_connect("10.12.0.3", NULL) != NULL);
  CHECK(local_connect("10.12.0.3", NULL) != NULL);
  CHECK(local_connect("10.12.0.3", NULL) != NULL);
  CurrentTime += 0x10000 + 1;
  CHECK(local_connect("10.12.0.3", NULL) != NULL);
  CHECK(local_connect("10.12.0.3", NULL) != NULL);

  if (sizeof(time_t) <= 4)
    return;                       /* cannot place CurrentTime near 2^32 */

  /* Attempts on both sides of the 2^32 boundary still count together. */
  CurrentTime = (CurrentTime | 0xffffffff) - 5;  /* NOW == 0xfffffffa */
  cli_since(&me) = CurrentTime - 100000;
  CHECK(local_connect("10.12.0.1", NULL) != NULL); /* attempt 1 */
  CurrentTime += 11;                               /* NOW == 5, 11 s later */
  CHECK(local_connect("10.12.0.1", NULL) != NULL); /* attempt 2 */
  CurrentTime += 1;
  CHECK(local_connect("10.12.0.1", NULL) != NULL); /* attempt 3 */
  CurrentTime += 1;
  CHECK(local_connect("10.12.0.1", NULL) == NULL); /* attempt 4: limit */

  /* And an entry idle for longer than the period across the boundary
   * does reset. */
  CurrentTime = (CurrentTime | 0xffffffff) - 5;
  CHECK(local_connect("10.12.0.2", NULL) != NULL);
  CHECK(local_connect("10.12.0.2", NULL) != NULL);
  CHECK(local_connect("10.12.0.2", NULL) != NULL);
  CurrentTime += f_clone_period + 6;
  CHECK(local_connect("10.12.0.2", NULL) != NULL);
}

/* The 16-bit connected counter refuses rather than wrapping. */
static void test_connected_overflow(void)
{
  struct irc_in_addr a = addr_of("10.13.0.1");
  struct Client r;
  time_t nt;
  long i;
  begin("connected_overflow");
  cli_since(&me) = CurrentTime;   /* grace: nothing refused for rate */

  for (i = 0; i < 65535; i++)
    CHECK(IPcheck_local_connect(&a, &nt) != 0);
  CHECK_EQ(nr("10.13.0.1"), 65535);
  CHECK(IPcheck_local_connect(&a, &nt) == 0);
  CHECK_EQ(nr("10.13.0.1"), 65535);

  memset(&r, 0, sizeof(r));
  cli_ip(&r) = a;
  CHECK(IPcheck_remote_connect(&r, 1) == 0);
  CHECK_EQ(nr("10.13.0.1"), 65535);
  /* Refused, so not counted: its exit must not release a slot. */
  CHECK(!IsIPChecked(&r));
}

int main(void)
{
  memset(&me_con, 0, sizeof(me_con));
  cli_connect(&me) = &me_con;
  con_client(&me_con) = &me;
  CurrentTime = 1000000;
  IPcheck_init();

  test_clone_limit_and_period();
  test_addresses_are_independent();
  test_boot_grace();
  test_connect_fail_undo();
  test_disconnect_accounting();
  test_exemptions();
  test_exempt_does_not_touch_existing_entry();
  test_remote_and_burst();
  test_ipv6_64_and_48();
  test_ipv4_canonical_form();
  test_free_targets();
  test_expiry();
  test_clock_wrap();
  test_connected_overflow();

  if (failures) {
    fprintf(stderr, "ipcheck_t: %d failure(s)\n", failures);
    return 1;
  }
  printf("ipcheck_t: all tests passed\n");
  return 0;
}
