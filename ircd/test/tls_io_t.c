/* tls_io_t.c - unit tests for the core TLS I/O layer (tls_io.c).
 *
 * Drives tls_io through a scripted fake backend (tls_backend_*), covering:
 *   - the socket-interest model (tls_want_writable / tls_desired_events):
 *     full truth table of cross-direction blocking states;
 *   - the tls_io_sendv() drain: partial writes, con_rexmit parking and
 *     resumption, the rexmit-bytes-not-credited rule when a priority message
 *     jumps the queue, the zero-credit success (a rexmit drain that excised
 *     the last queued message is progress, not a block), and fatal teardown;
 *   - tls_io_recv() blocked-direction recording and fatal teardown;
 *   - fingerprint storage edge cases (length, hex form, Cloudflare ports);
 *   - the ircd_tls_negotiate() trust policy matrix over scripted tls_peer
 *     material (cert-required, verifypeer, fingerprint hand-off).
 *
 * Each sendv scenario mimics the real caller (send_queued/deliver_it):
 * msgq_delete(count_out) after any successful delivery, state carried
 * between calls.  The fake backend captures the exact byte stream "sent"
 * so ordering and duplication bugs are caught, not just return codes.
 */

#include "client.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "ircd_tls.h"
#include "listener.h"
#include "msgq.h"
#include "tls_io.h"

#include <stdio.h>
#include <string.h>
#include <sys/uio.h>

extern struct Client me;

/* --- stubs for symbols pulled in by msgq.o that these tests never reach --- */
int feature_bool(enum Feature feat) { (void)feat; return 0; }
/* Large enough for FEAT_BUFFERPOOL so msgq_alloc() actually allocates. */
int feature_int(enum Feature feat) { (void)feat; return 1 << 20; }
void flush_connections(struct Client *cptr) { (void)cptr; }
void kill_highest_sendq(int servers_too) { (void)servers_too; }
int send_reply(struct Client *to, int reply, ...) { (void)to; (void)reply; return 0; }
void server_panic(const char *message) { (void)message; }
const char *visible_username(const struct Client *cptr) { (void)cptr; return ""; }

/* --- settable policy predicates (real ones live in s_conf.c) --- */
static int fake_cert_required;
static int fake_verifypeer;
int ircd_tls_peer_cert_required(const struct Client *cptr)
{ (void)cptr; return fake_cert_required; }
int ircd_tls_verifypeer_enabled(const struct Client *cptr)
{ (void)cptr; return fake_verifypeer; }

/* --- scripted fake backend ------------------------------------------------ */

#define MAX_STEPS 16

/** One scripted outcome for a tls_backend_write() call. */
struct wstep {
  IOResult io;              /**< result to return */
  unsigned int accept;      /**< bytes to accept on IO_SUCCESS (capped to len) */
  enum ircd_tls_want want;  /**< blocked direction on IO_BLOCKED */
};

static struct wstep wsteps[MAX_STEPS];
static int wstep_next, wstep_count;

static char wire[4096];          /**< exact byte stream the backend accepted */
static unsigned int wire_len;

static struct {                  /**< scripted next tls_backend_read() result */
  IOResult io;
  const char *data;
  enum ircd_tls_want want;
} rstep;

static struct {                  /**< scripted next tls_backend_handshake() */
  IOResult io;
  struct tls_peer peer;
  const char *reason;
  enum ircd_tls_want want;
} hstep;

static int drop_calls;

static void script_reset(void)
{
  wstep_next = wstep_count = 0;
  wire_len = 0;
  drop_calls = 0;
  memset(&rstep, 0, sizeof(rstep));
  memset(&hstep, 0, sizeof(hstep));
}

static void script_write(IOResult io, unsigned int accept,
                         enum ircd_tls_want want)
{
  assert(wstep_count < MAX_STEPS);
  wsteps[wstep_count].io = io;
  wsteps[wstep_count].accept = accept;
  wsteps[wstep_count].want = want;
  ++wstep_count;
}

IOResult tls_backend_write(struct Client *cptr, const char *buf,
                           unsigned int len, unsigned int *written,
                           enum ircd_tls_want *want)
{
  struct wstep *s;

  (void)cptr;
  assert(len > 0);                    /* the core must never write 0 bytes */
  assert(wstep_next < wstep_count);   /* the script must cover every call */
  s = &wsteps[wstep_next++];
  *written = 0;
  if (s->io == IO_SUCCESS) {
    unsigned int n = s->accept < len ? s->accept : len;
    assert(n > 0);
    assert(wire_len + n <= sizeof(wire));
    memcpy(wire + wire_len, buf, n);
    wire_len += n;
    *written = n;
  }
  else if (s->io == IO_BLOCKED)
    *want = s->want;
  return s->io;
}

IOResult tls_backend_read(struct Client *cptr, char *buf, unsigned int length,
                          unsigned int *count_out, enum ircd_tls_want *want)
{
  (void)cptr;
  *count_out = 0;
  if (rstep.io == IO_SUCCESS) {
    unsigned int n = strlen(rstep.data);
    assert(n <= length);
    memcpy(buf, rstep.data, n);
    *count_out = n;
  }
  else if (rstep.io == IO_BLOCKED)
    *want = rstep.want;
  return rstep.io;
}

IOResult tls_backend_handshake(struct Client *cptr, struct tls_peer *peer,
                               char *reason, size_t reasonlen,
                               enum ircd_tls_want *want)
{
  (void)cptr;
  if (hstep.io == IO_SUCCESS)
    *peer = hstep.peer;
  else if (hstep.io == IO_BLOCKED)
    *want = hstep.want;
  else if (hstep.io == IO_FAILURE && hstep.reason && reason && reasonlen)
    ircd_strncpy(reason, hstep.reason, reasonlen - 1);
  return hstep.io;
}

void tls_backend_drop(struct Client *cptr)
{
  ++drop_calls;
  s_tls(&cli_socket(cptr)) = NULL;    /* mirror the real backends */
}

/* --- client/connection fixture ------------------------------------------- */

static struct Connection conn;
static struct Client cli;
static struct Listener lst;

static struct Client *fix(void)
{
  MsgQClear(&con_sendQ(&conn));       /* free MsgBufs from the prior test */
  memset(&conn, 0, sizeof(conn));
  memset(&cli, 0, sizeof(cli));
  memset(&lst, 0, sizeof(lst));
  cli.cli_connect = &conn;
  msgq_init(&con_sendQ(&conn));
  script_reset();
  fake_cert_required = fake_verifypeer = 0;
  return &cli;
}

/** Queue \a text (msgq_make appends CRLF); returns wire length of the msg. */
static unsigned int enq(struct Client *c, const char *text, int prio)
{
  msgq_add(&cli_sendQ(c), msgq_make(&me, "%s", text), prio);
  return strlen(text) + 2;
}

/** Call tls_io_sendv() and consume credited bytes exactly as send_queued /
 * deliver_it do (msgq_delete of count_out). */
static IOResult sendv_and_consume(struct Client *c, unsigned int *out)
{
  unsigned int count_in = 0, count_out = 0;
  IOResult io = tls_io_sendv(c, &cli_sendQ(c), &count_in, &count_out);

  if (count_out)
    msgq_delete(&cli_sendQ(c), count_out);
  *out = count_out;
  return io;
}

static int wire_is(const char *expect)
{
  unsigned int n = strlen(expect);
  return wire_len == n && !memcmp(wire, expect, n);
}

/* --- A: socket-interest truth table --------------------------------------- */

/* Every combination of blocked-direction state x queue x listing must map to
 * exactly one interest decision:
 *   - a read waiting to write, or a write waiting to write => writable;
 *   - otherwise a write waiting to read => NOT writable (level-triggered
 *     writable would spin);
 *   - otherwise the plaintext base rule (queued output or an active /LIST).
 * Readable is always wanted. */
static void test_interest_truth_table(void)
{
  static const enum ircd_tls_want wants[] =
    { IRCD_TLS_WANT_NONE, IRCD_TLS_WANT_READ, IRCD_TLS_WANT_WRITE };
  int ircd_wr, ircd_rd, queued, listing, cases = 0;

  for (ircd_rd = 0; ircd_rd < 3; ++ircd_rd)
    for (ircd_wr = 0; ircd_wr < 3; ++ircd_wr)
      for (queued = 0; queued < 2; ++queued)
        for (listing = 0; listing < 2; ++listing) {
          struct Client *c = fix();
          int base, expect;

          if (queued)
            enq(c, "MSG", 0);
          con_listing(&conn) = listing ? (struct ListingArgs *)&lst : 0;
          cli_tls_want_rd(c) = wants[ircd_rd];
          cli_tls_want_wr(c) = wants[ircd_wr];

          base = queued || listing;
          expect = (wants[ircd_rd] == IRCD_TLS_WANT_WRITE
                    || wants[ircd_wr] == IRCD_TLS_WANT_WRITE) ? 1
                 : (wants[ircd_wr] == IRCD_TLS_WANT_READ) ? 0
                 : base;

          assert(tls_want_writable(c) == expect);
          assert(tls_desired_events(c) ==
                 (SOCK_EVENT_READABLE | (expect ? SOCK_EVENT_WRITABLE : 0)));
          ++cases;
        }

  assert(cases == 36);
  printf("Passed: interest truth table (%d cases)\n", cases);
}

/* --- B: tls_io_sendv drain ------------------------------------------------ */

/* Two whole messages accepted in one pass: full credit, clean wants. */
static void test_sendv_clean_write(void)
{
  struct Client *c = fix();
  unsigned int out, len = 0;

  len += enq(c, "M1", 0);
  len += enq(c, "M2", 0);
  script_write(IO_SUCCESS, 4, IRCD_TLS_WANT_NONE);
  script_write(IO_SUCCESS, 4, IRCD_TLS_WANT_NONE);

  assert(sendv_and_consume(c, &out) == IO_SUCCESS);
  assert(out == len);
  assert(wire_is("M1\r\nM2\r\n"));
  assert(MsgQLength(&cli_sendQ(c)) == 0);
  assert(cli_tls_want_wr(c) == IRCD_TLS_WANT_NONE);
  assert(conn.con_rexmit == NULL);
  printf("Passed: sendv clean multi-message write\n");
}

/* A short record write is not a full socket: the remainder is parked in
 * con_rexmit and drained to completion within the same call, full credit. */
static void test_sendv_short_write_drained_in_call(void)
{
  struct Client *c = fix();
  unsigned int out, len;

  len = enq(c, "ABCDEFG", 0);              /* "ABCDEFG\r\n", 9 bytes */
  script_write(IO_SUCCESS, 3, IRCD_TLS_WANT_NONE);
  script_write(IO_SUCCESS, 9, IRCD_TLS_WANT_NONE);   /* remainder (6) */

  assert(sendv_and_consume(c, &out) == IO_SUCCESS);
  assert(out == len);
  assert(wire_is("ABCDEFG\r\n"));
  assert(conn.con_rexmit == NULL);
  assert(MsgQLength(&cli_sendQ(c)) == 0);
  printf("Passed: sendv short write drained within the call\n");
}

/* Short write, then block: partial credit, remainder parked, and the blocked
 * direction (a write waiting to READ) must drop writable interest even with
 * data still queued -- the anti-spin invariant.  Resuming after the "socket"
 * unblocks drains the parked remainder; with nothing else queued that is the
 * zero-credit success send_queued must treat as progress, not a block. */
static void test_sendv_block_resume_zero_credit(void)
{
  struct Client *c = fix();
  unsigned int out;

  enq(c, "ABCDEFG", 0);
  script_write(IO_SUCCESS, 3, IRCD_TLS_WANT_NONE);
  script_write(IO_BLOCKED, 0, IRCD_TLS_WANT_READ);

  assert(sendv_and_consume(c, &out) == IO_BLOCKED);
  assert(out == 3);
  assert(conn.con_rexmit != NULL);
  assert(conn.con_rexmit_len == 6);
  assert(!memcmp(conn.con_rexmit, "DEFG\r\n", 6));
  assert(cli_tls_want_wr(c) == IRCD_TLS_WANT_READ);
  assert(MsgQLength(&cli_sendQ(c)) == 6);  /* 3 credited bytes consumed */
  /* write-waiting-to-read: writable interest must be off despite the queue */
  assert(tls_want_writable(c) == 0);

  /* peer sent its records; the read side ran; now retry the drain */
  script_reset();
  script_write(IO_SUCCESS, 6, IRCD_TLS_WANT_NONE);

  assert(sendv_and_consume(c, &out) == IO_SUCCESS);
  assert(out == 0);                        /* rexmit bytes are never credited */
  assert(wire_is("DEFG\r\n"));
  assert(conn.con_rexmit == NULL);
  assert(MsgQLength(&cli_sendQ(c)) == 0);  /* excised by identity */
  assert(cli_tls_want_wr(c) == IRCD_TLS_WANT_NONE);
  printf("Passed: sendv block, resume, zero-credit success\n");
}

/* A priority message enqueued while the write was blocked: the rexmit drain
 * must not credit its bytes (msgq_delete would eat the priority message that
 * jumped ahead), the drained message leaves by identity (msgq_excise), and
 * the priority message goes out next with normal credit. */
static void test_sendv_rexmit_prio_jump(void)
{
  struct Client *c = fix();
  unsigned int out, ping_len;

  enq(c, "NORMALMSG", 0);                  /* 11 bytes on the wire */
  script_write(IO_BLOCKED, 0, IRCD_TLS_WANT_WRITE);

  assert(sendv_and_consume(c, &out) == IO_BLOCKED);
  assert(out == 0);
  assert(conn.con_rexmit != NULL && conn.con_rexmit_len == 11);
  assert(cli_tls_want_wr(c) == IRCD_TLS_WANT_WRITE);
  assert(tls_want_writable(c) == 1);       /* genuinely wants writable */

  ping_len = enq(c, "PING", 1);            /* prio jumps ahead while blocked */

  script_reset();
  script_write(IO_SUCCESS, 11, IRCD_TLS_WANT_NONE);  /* rexmit drain */
  script_write(IO_SUCCESS, 6, IRCD_TLS_WANT_NONE);   /* then the PING */

  assert(sendv_and_consume(c, &out) == IO_SUCCESS);
  assert(out == ping_len);                 /* ONLY the ping is credited */
  assert(wire_is("NORMALMSG\r\nPING\r\n"));  /* exact stream, no dup/reorder */
  assert(MsgQLength(&cli_sendQ(c)) == 0);
  assert(conn.con_rexmit == NULL);
  printf("Passed: sendv rexmit drain with priority jump-ahead\n");
}

/* A priority message enqueued after normal messages must still go out first:
 * msgq_mapiov order is (partial-normal, prio, normal), and tls_io_sendv sends
 * in mapped order. */
static void test_sendv_prio_transmits_first(void)
{
  struct Client *c = fix();
  unsigned int out, len = 0;

  len += enq(c, "N1", 0);
  len += enq(c, "N2", 0);
  len += enq(c, "PING", 1);                /* queued last, must send first */
  script_write(IO_SUCCESS, 64, IRCD_TLS_WANT_NONE);
  script_write(IO_SUCCESS, 64, IRCD_TLS_WANT_NONE);
  script_write(IO_SUCCESS, 64, IRCD_TLS_WANT_NONE);

  assert(sendv_and_consume(c, &out) == IO_SUCCESS);
  assert(out == len);
  assert(wire_is("PING\r\nN1\r\nN2\r\n"));
  assert(MsgQLength(&cli_sendQ(c)) == 0);
  printf("Passed: sendv priority message transmits first\n");
}

/* Full three-way order on the wire: a blocked message's remainder (the
 * partial-normal analog, via con_rexmit) drains first, then a priority
 * message that jumped ahead, then a normal message queued behind it --
 * with only the latter two credited. */
static void test_sendv_three_way_order(void)
{
  struct Client *c = fix();
  unsigned int out, credited = 0;

  enq(c, "NORMALMSG", 0);
  script_write(IO_BLOCKED, 0, IRCD_TLS_WANT_WRITE);
  assert(sendv_and_consume(c, &out) == IO_BLOCKED);
  assert(out == 0 && conn.con_rexmit != NULL);

  credited += enq(c, "PING", 1);           /* prio jumps ahead while blocked */
  credited += enq(c, "AFTER", 0);          /* normal queued behind it */

  script_reset();
  script_write(IO_SUCCESS, 64, IRCD_TLS_WANT_NONE);  /* rexmit drain */
  script_write(IO_SUCCESS, 64, IRCD_TLS_WANT_NONE);  /* PING */
  script_write(IO_SUCCESS, 64, IRCD_TLS_WANT_NONE);  /* AFTER */

  assert(sendv_and_consume(c, &out) == IO_SUCCESS);
  assert(out == credited);                 /* rexmit bytes never credited */
  assert(wire_is("NORMALMSG\r\nPING\r\nAFTER\r\n"));
  assert(MsgQLength(&cli_sendQ(c)) == 0);
  assert(conn.con_rexmit == NULL);
  printf("Passed: sendv three-way wire order (rexmit, prio, normal)\n");
}

/* Fatal backend error mid-queue: count_out is zeroed (nothing for the caller
 * to delete on a dead link), the session is dropped and the socket marked
 * dead, and both blocked-direction markers are cleared. */
static void test_sendv_fatal(void)
{
  struct Client *c = fix();
  unsigned int out;

  enq(c, "M1", 0);
  enq(c, "M2", 0);
  cli_tls_want_rd(c) = IRCD_TLS_WANT_WRITE;   /* must be wiped by teardown */
  script_write(IO_SUCCESS, 4, IRCD_TLS_WANT_NONE);
  script_write(IO_FAILURE, 0, IRCD_TLS_WANT_NONE);

  assert(sendv_and_consume(c, &out) == IO_FAILURE);
  assert(out == 0);
  assert(wire_is("M1\r\n"));               /* first message did go out */
  assert(HasFlag(c, FLAG_DEADSOCKET));
  assert(cli_tls_want_rd(c) == IRCD_TLS_WANT_NONE);
  assert(cli_tls_want_wr(c) == IRCD_TLS_WANT_NONE);
  assert(drop_calls == 1);
  printf("Passed: sendv fatal error teardown\n");
}

/* Fatal error while draining a parked remainder across calls. */
static void test_sendv_fatal_on_rexmit(void)
{
  struct Client *c = fix();
  unsigned int out;

  enq(c, "ABCDEF", 0);                     /* 8 bytes */
  script_write(IO_SUCCESS, 3, IRCD_TLS_WANT_NONE);
  script_write(IO_BLOCKED, 0, IRCD_TLS_WANT_WRITE);
  assert(sendv_and_consume(c, &out) == IO_BLOCKED);
  assert(out == 3);

  script_reset();
  script_write(IO_FAILURE, 0, IRCD_TLS_WANT_NONE);
  assert(sendv_and_consume(c, &out) == IO_FAILURE);
  assert(out == 0);
  assert(HasFlag(c, FLAG_DEADSOCKET));
  assert(drop_calls == 1);
  printf("Passed: sendv fatal error during rexmit drain\n");
}

/* --- C: tls_io_recv blocked-direction recording --------------------------- */

static void test_recv_directions(void)
{
  struct Client *c = fix();
  char buf[64];
  unsigned int n = 0;

  /* success clears the marker */
  cli_tls_want_rd(c) = IRCD_TLS_WANT_WRITE;
  rstep.io = IO_SUCCESS;
  rstep.data = "PONG\r\n";
  assert(tls_io_recv(c, buf, sizeof(buf), &n) == IO_SUCCESS);
  assert(n == 6 && !memcmp(buf, "PONG\r\n", 6));
  assert(cli_tls_want_rd(c) == IRCD_TLS_WANT_NONE);

  /* a read waiting to WRITE must assert writable with an empty sendq */
  rstep.io = IO_BLOCKED;
  rstep.want = IRCD_TLS_WANT_WRITE;
  assert(tls_io_recv(c, buf, sizeof(buf), &n) == IO_BLOCKED);
  assert(cli_tls_want_rd(c) == IRCD_TLS_WANT_WRITE);
  assert(MsgQLength(&cli_sendQ(c)) == 0);
  assert(tls_desired_events(c) == (SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE));

  /* a read waiting on its own direction wants readable only */
  rstep.want = IRCD_TLS_WANT_READ;
  assert(tls_io_recv(c, buf, sizeof(buf), &n) == IO_BLOCKED);
  assert(cli_tls_want_rd(c) == IRCD_TLS_WANT_READ);
  assert(tls_desired_events(c) == SOCK_EVENT_READABLE);

  /* fatal: teardown, marker wipe, session dropped */
  cli_tls_want_wr(c) = IRCD_TLS_WANT_READ;
  rstep.io = IO_FAILURE;
  assert(tls_io_recv(c, buf, sizeof(buf), &n) == IO_FAILURE);
  assert(HasFlag(c, FLAG_DEADSOCKET));
  assert(cli_tls_want_rd(c) == IRCD_TLS_WANT_NONE);
  assert(cli_tls_want_wr(c) == IRCD_TLS_WANT_NONE);
  assert(drop_calls == 1);
  printf("Passed: recv direction recording and fatal teardown\n");
}

/* --- D: fingerprint storage ----------------------------------------------- */

static const char zeros[65];

static void test_fingerprint_storage(void)
{
  struct Client *c = fix();
  unsigned char digest[32];
  char expect[65];
  unsigned int i;

  for (i = 0; i < 32; ++i) {
    digest[i] = (unsigned char)(i * 7 + 3);
    sprintf(expect + i * 2, "%02x", digest[i]);
  }
  expect[64] = '\0';

  tls_io_store_fingerprint(c, digest, 32);
  assert(!strcmp(cli_tls_fingerprint(c), expect));

  /* a non-SHA-256 digest length clears the slot */
  tls_io_store_fingerprint(c, digest, 20);
  assert(!memcmp(cli_tls_fingerprint(c), zeros, 65));

  /* Cloudflare ports suppress fingerprints entirely */
  tls_io_store_fingerprint(c, digest, 32);
  FlagSet(&lst.flags, LISTEN_CLOUDFLARE);
  con_listener(&conn) = &lst;
  tls_io_store_fingerprint(c, digest, 32);
  assert(!memcmp(cli_tls_fingerprint(c), zeros, 65));
  con_listener(&conn) = NULL;
  FlagClr(&lst.flags, LISTEN_CLOUDFLARE);

  /* pre-formatted hex: copied; NULL / empty / over-long cleared */
  tls_io_store_fingerprint_hex(c, "abc123");
  assert(!strcmp(cli_tls_fingerprint(c), "abc123"));
  tls_io_store_fingerprint_hex(c, NULL);
  assert(!memcmp(cli_tls_fingerprint(c), zeros, 65));
  tls_io_store_fingerprint_hex(c, "abc123");
  tls_io_store_fingerprint_hex(c, "");
  assert(!memcmp(cli_tls_fingerprint(c), zeros, 65));
  tls_io_store_fingerprint_hex(c, expect);       /* exactly 64: kept */
  assert(!strcmp(cli_tls_fingerprint(c), expect));
  {
    char toolong[80];
    memset(toolong, 'a', sizeof(toolong) - 1);
    toolong[sizeof(toolong) - 1] = '\0';
    tls_io_store_fingerprint_hex(c, toolong);    /* 79 chars: cleared */
    assert(!memcmp(cli_tls_fingerprint(c), zeros, 65));
  }
  printf("Passed: fingerprint storage edge cases\n");
}

/* --- E: negotiate trust policy over scripted peer material ----------------- */

/** Fresh fixture with a live dummy session mid-handshake. */
static struct Client *fix_negotiating(void)
{
  struct Client *c = fix();

  s_tls(&cli_socket(c)) = (void *)&lst;   /* any non-NULL session */
  SetNegotiatingTLS(c);
  return c;
}

static void test_negotiate_policy(void)
{
  char reason[TLS_REASON_LEN];
  enum ircd_tls_want want;
  struct Client *c;

  /* no session left: fail, never report success (or start_auth would loop) */
  c = fix_negotiating();
  s_tls(&cli_socket(c)) = NULL;
  strcpy(reason, "STALE");
  assert(ircd_tls_negotiate(c, reason, sizeof(reason), &want) == -1);
  assert(!strcmp(reason, "TLS setup failed (no session)"));
  assert(!IsNegotiatingTLS(c));

  /* in progress: report the blocked direction, reason stays empty */
  c = fix_negotiating();
  hstep.io = IO_BLOCKED;
  hstep.want = IRCD_TLS_WANT_WRITE;
  strcpy(reason, "STALE");
  assert(ircd_tls_negotiate(c, reason, sizeof(reason), &want) == 0);
  assert(want == IRCD_TLS_WANT_WRITE);
  assert(reason[0] == '\0');
  assert(IsNegotiatingTLS(c));

  /* backend failure: its reason survives to the caller */
  c = fix_negotiating();
  hstep.io = IO_FAILURE;
  hstep.reason = "handshake exploded";
  assert(ircd_tls_negotiate(c, reason, sizeof(reason), &want) == -1);
  assert(!strcmp(reason, "handshake exploded"));

  /* cert required, none presented */
  c = fix_negotiating();
  fake_cert_required = 1;
  hstep.io = IO_SUCCESS;
  assert(ircd_tls_negotiate(c, reason, sizeof(reason), &want) == -1);
  assert(strstr(reason, "no peer certificate") != NULL);

  /* cert presented but required only softly: PKIX advisory, accepted */
  c = fix_negotiating();
  fake_cert_required = 1;
  hstep.io = IO_SUCCESS;
  hstep.peer.have_cert = 1;
  hstep.peer.verified = 0;
  assert(ircd_tls_negotiate(c, reason, sizeof(reason), &want) == 1);
  assert(!IsNegotiatingTLS(c));

  /* verifypeer: unverified cert rejected with the backend's reason */
  c = fix_negotiating();
  fake_verifypeer = 1;
  hstep.io = IO_SUCCESS;
  hstep.peer.have_cert = 1;
  hstep.peer.verified = 0;
  strcpy(hstep.peer.verify_err, "self signed certificate");
  assert(ircd_tls_negotiate(c, reason, sizeof(reason), &want) == -1);
  assert(!strcmp(reason, "self signed certificate"));

  /* verifypeer: unverified with no backend detail gets the generic reason */
  c = fix_negotiating();
  fake_verifypeer = 1;
  hstep.io = IO_SUCCESS;
  hstep.peer.have_cert = 1;
  assert(ircd_tls_negotiate(c, reason, sizeof(reason), &want) == -1);
  assert(!strcmp(reason, "certificate verification failed"));

  /* verifypeer: verified cert accepted, raw digest becomes the fingerprint */
  c = fix_negotiating();
  fake_verifypeer = 1;
  hstep.io = IO_SUCCESS;
  hstep.peer.have_cert = 1;
  hstep.peer.verified = 1;
  memset(hstep.peer.digest, 0xab, 32);
  hstep.peer.digest_len = 32;
  assert(ircd_tls_negotiate(c, reason, sizeof(reason), &want) == 1);
  assert(!IsNegotiatingTLS(c));
  {
    char expect[65];
    int i;
    for (i = 0; i < 32; ++i)
      sprintf(expect + i * 2, "%02x", 0xab);
    expect[64] = '\0';
    assert(!strcmp(cli_tls_fingerprint(c), expect));
  }

  /* no raw digest: the backend's pre-formatted hex is used (libtls) */
  c = fix_negotiating();
  hstep.io = IO_SUCCESS;
  hstep.peer.have_cert = 1;
  strcpy(hstep.peer.fp_hex, "deadbeef");
  assert(ircd_tls_negotiate(c, reason, sizeof(reason), &want) == 1);
  assert(!strcmp(cli_tls_fingerprint(c), "deadbeef"));

  /* neither digest nor hex: fingerprint slot ends up cleared */
  c = fix_negotiating();
  hstep.io = IO_SUCCESS;
  hstep.peer.have_cert = 1;
  assert(ircd_tls_negotiate(c, reason, sizeof(reason), &want) == 1);
  assert(!memcmp(cli_tls_fingerprint(c), zeros, 65));

  /* no cert at all with everything off: plain accept (user TLS port) */
  c = fix_negotiating();
  hstep.io = IO_SUCCESS;
  assert(ircd_tls_negotiate(c, reason, sizeof(reason), &want) == 1);
  assert(!IsNegotiatingTLS(c));

  printf("Passed: negotiate trust policy matrix\n");
}

int
main(int argc, char *argv[])
{
  (void)argc;
  (void)argv;

  msgq_init(&con_sendQ(&conn));   /* so the first fix()'s MsgQClear is safe */

  test_interest_truth_table();

  test_sendv_clean_write();
  test_sendv_short_write_drained_in_call();
  test_sendv_block_resume_zero_credit();
  test_sendv_rexmit_prio_jump();
  test_sendv_prio_transmits_first();
  test_sendv_three_way_order();
  test_sendv_fatal();
  test_sendv_fatal_on_rexmit();

  test_recv_directions();

  test_fingerprint_storage();

  test_negotiate_policy();

  printf("All tls_io tests passed.\n");
  return 0;
}
