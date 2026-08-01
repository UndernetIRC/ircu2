/*
 * IRC - Internet Relay Chat, ircd/resume.c
 * Copyright (C) 2026 Undernet IRC development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief IRCv3 session resume (draft/resume-0.5).
 *
 * Issues a secure bearer token to a registered secure-WebSocket client and
 * keeps a lookup registry keyed by a random session id.  Handles detaching a
 * session on transport loss, resuming/reattaching a client to it, and safely
 * expiring detached sessions.
 */
#include "config.h"

#include "resume.h"
#include "capab.h"
#include "channel.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd_tls.h"
#include "msg.h"
#include "numeric.h"
#include "res.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "s_user.h"
#include "sasl.h"
#include "send.h"

#include <limits.h>
#include <string.h>

/** Number of buckets in the resume-session table (prime). */
#define RESUME_HASHSIZE 4001

/** Session id -> ResumeSession lookup, chained on ResumeSession.hnext. */
static struct ResumeSession *resumeTable[RESUME_HASHSIZE];

/** Live sessions currently in the table. */
static unsigned int resume_count;
/** Tokens issued, including rotations (statistics). */
static unsigned int resume_total_issued;
/** Sessions currently detached. */
static unsigned int resume_cur_detached;
/** Peak concurrent detached sessions. */
static unsigned int resume_peak_detached;
/** Total detachments over the server's lifetime. */
static unsigned int resume_total_detached;
/** Detached sessions that expired without being resumed. */
static unsigned int resume_total_expired;
/** Sessions successfully resumed onto a new connection. */
static unsigned int resume_total_resumed;

/** Cached, clamped copies of integer features.  Seeded at init and refreshed
 * by resume_feat_notify() on every set/rehash, because the feature framework
 * does not fire notify callbacks for defaults at startup. */
static int resume_timeout_v;
static int resume_max_detached_v;

/** URL-safe base64 alphabet (RFC 4648 §5), no padding. */
static const char resume_b64url[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Encode \a inlen bytes of \a in as unpadded base64url into \a out.
 * @return number of characters written (excluding NUL), or -1 if \a out is
 *   too small.
 */
static int
resume_b64url_encode(const unsigned char *in, size_t inlen,
                     char *out, size_t outlen)
{
  size_t i, o = 0;

  for (i = 0; i < inlen; i += 3) {
    size_t rem = inlen - i;
    unsigned int n = (unsigned int)in[i] << 16;
    int nchars = (rem >= 3) ? 4 : (rem == 2 ? 3 : 2);

    if (rem > 1)
      n |= (unsigned int)in[i + 1] << 8;
    if (rem > 2)
      n |= (unsigned int)in[i + 2];

    if (o + (size_t)nchars + 1 > outlen) /* +1 for the NUL */
      return -1;

    out[o++] = resume_b64url[(n >> 18) & 0x3f];
    out[o++] = resume_b64url[(n >> 12) & 0x3f];
    if (nchars > 2)
      out[o++] = resume_b64url[(n >> 6) & 0x3f];
    if (nchars > 3)
      out[o++] = resume_b64url[n & 0x3f];
  }

  out[o] = '\0';
  return (int)o;
}

/** Hash a session id to a table bucket (FNV-1a; ids are already random). */
static unsigned int
resume_hash(const unsigned char *id)
{
  unsigned int h = 2166136261u;
  int i;

  for (i = 0; i < RESUME_ID_BYTES; i++) {
    h ^= id[i];
    h *= 16777619u;
  }
  return h % RESUME_HASHSIZE;
}

/** Insert \a s into the lookup table. */
static void
resume_hash_add(struct ResumeSession *s)
{
  unsigned int b = resume_hash(s->id);

  s->hnext = resumeTable[b];
  resumeTable[b] = s;
  resume_count++;
}

/** Remove \a s from the lookup table if present. */
static void
resume_hash_remove(struct ResumeSession *s)
{
  unsigned int b = resume_hash(s->id);
  struct ResumeSession **pp = &resumeTable[b];

  while (*pp) {
    if (*pp == s) {
      *pp = s->hnext;
      s->hnext = NULL;
      if (resume_count)
        resume_count--;
      return;
    }
    pp = &(*pp)->hnext;
  }
}

struct ResumeSession *
resume_find(const unsigned char *id)
{
  struct ResumeSession *s;

  for (s = resumeTable[resume_hash(id)]; s; s = s->hnext)
    if (0 == memcmp(s->id, id, RESUME_ID_BYTES)) /* id is public, not a secret */
      return s;
  return NULL;
}

/** Fill \a s->id with a fresh random id not already in the table.
 * @return 0 on success, -1 if the CSPRNG failed repeatedly.
 */
static int
resume_gen_id(struct ResumeSession *s)
{
  int tries;

  for (tries = 0; tries < 8; tries++) {
    if (ircd_tls_random_bytes(s->id, RESUME_ID_BYTES) != 0)
      return -1;
    if (!resume_find(s->id))
      return 0;
  }
  return -1;
}

/** Encode the "<base64url-id>.<base64url-secret>" bearer token for \a s. */
static int
resume_token_encode(const struct ResumeSession *s, char *out, size_t outlen)
{
  char idpart[32];
  char secpart[64];

  if (resume_b64url_encode(s->id, RESUME_ID_BYTES, idpart, sizeof(idpart)) < 0)
    return -1;
  if (resume_b64url_encode(s->secret, RESUME_SECRET_BYTES,
                           secpart, sizeof(secpart)) < 0)
    return -1;
  if ((size_t)ircd_snprintf(0, out, outlen, "%s.%s", idpart, secpart) >= outlen)
    return -1;
  return 0;
}

/** Decode one base64url character to its 6-bit value, or -1 if invalid. */
static int
resume_b64url_val(char c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

/** Decode unpadded base64url \a in into \a out (at most \a outcap bytes).
 * @return 0 on success with *outlen set, -1 on any invalid input or overflow.
 */
static int
resume_b64url_decode(const char *in, size_t inlen, unsigned char *out,
                     size_t outcap, size_t *outlen)
{
  size_t i = 0, o = 0;

  while (i < inlen) {
    size_t rem = inlen - i;
    int v0, v1, v2, v3;

    if (rem < 2) /* a lone trailing character is never valid */
      return -1;
    if ((v0 = resume_b64url_val(in[i])) < 0
        || (v1 = resume_b64url_val(in[i + 1])) < 0)
      return -1;
    if (o >= outcap)
      return -1;
    out[o++] = (unsigned char)((v0 << 2) | (v1 >> 4));

    if (rem == 2)
      break;
    if ((v2 = resume_b64url_val(in[i + 2])) < 0)
      return -1;
    if (o >= outcap)
      return -1;
    out[o++] = (unsigned char)(((v1 & 0x0f) << 4) | (v2 >> 2));

    if (rem == 3)
      break;
    if ((v3 = resume_b64url_val(in[i + 3])) < 0)
      return -1;
    if (o >= outcap)
      return -1;
    out[o++] = (unsigned char)(((v2 & 0x03) << 6) | v3);
    i += 4;
  }

  *outlen = o;
  return 0;
}

/** Parse a bearer token "<id>.<secret>" into raw \a id and \a secret.
 * Rejects malformed or wrong-length input without allocating.
 * @return 0 on success, -1 on any error.
 */
static int
resume_token_parse(const char *token, unsigned char *id, unsigned char *secret)
{
  const char *dot;
  size_t tlen, idtext, sectext, idlen, seclen;

  if (BadPtr(token))
    return -1;
  tlen = strlen(token);
  if (tlen < 3 || tlen > RESUME_TOKEN_MAX)
    return -1;

  dot = strchr(token, '.');
  if (!dot || dot == token || dot[1] == '\0')
    return -1;

  idtext = (size_t)(dot - token);
  sectext = tlen - idtext - 1;

  if (resume_b64url_decode(token, idtext, id, RESUME_ID_BYTES, &idlen) != 0
      || idlen != RESUME_ID_BYTES)
    return -1;
  if (resume_b64url_decode(dot + 1, sectext, secret, RESUME_SECRET_BYTES,
                           &seclen) != 0
      || seclen != RESUME_SECRET_BYTES)
    return -1;
  return 0;
}

/** Constant-time comparison of \a n bytes.  Returns 0 iff equal. */
static int
resume_ct_memcmp(const void *a, const void *b, size_t n)
{
  const volatile unsigned char *pa = a;
  const volatile unsigned char *pb = b;
  unsigned char r = 0;
  size_t i;

  for (i = 0; i < n; i++)
    r |= (unsigned char)(pa[i] ^ pb[i]);
  return r;
}

/*
 * Public interface.
 */

int
resume_enabled(void)
{
  return feature_bool(FEAT_RESUME);
}

int
resume_conf_timeout(void)
{
  return resume_timeout_v;
}

int
resume_conf_max_detached(void)
{
  return resume_max_detached_v;
}

void
resume_feat_notify(void)
{
  int t = feature_int(FEAT_RESUME_TIMEOUT);

  if (t < RESUME_TIMEOUT_MIN)
    t = RESUME_TIMEOUT_MIN;
  else if (t > RESUME_TIMEOUT_MAX)
    t = RESUME_TIMEOUT_MAX;
  resume_timeout_v = t;

  resume_max_detached_v = feature_int(FEAT_RESUME_MAX_DETACHED);
  if (resume_max_detached_v < 0)
    resume_max_detached_v = 0;
}

int
resume_is_capable_transport(const struct Client *cptr)
{
  /* TLS is the real requirement: the bearer token must not be interceptable.
     By default we further restrict to secure WebSockets; clearing
     RESUME_REQUIRE_WEBSOCKET allows any TLS connection to resume. */
  if (!MyConnect(cptr) || !IsTLS(cptr))
    return 0;
  if (feature_bool(FEAT_RESUME_REQUIRE_WEBSOCKET) && !IsWebsocket(cptr))
    return 0;
  return 1;
}

void
resume_init(void)
{
  memset(resumeTable, 0, sizeof(resumeTable));
  resume_count = 0;
  resume_total_issued = 0;
  resume_feat_notify(); /* seed cached feature values from their defaults */
}

void
resume_token_issue(struct Client *cptr)
{
  struct ResumeSession *s;
  char token[RESUME_TOKEN_MAX];

  if (!resume_enabled() || !resume_is_capable_transport(cptr))
    return;

  s = cli_resume(cptr);
  if (!s) {
    s = (struct ResumeSession *)MyCalloc(1, sizeof(*s));
    s->state = RESUME_STATE_ATTACHED;
    s->client = cptr;
    if (resume_gen_id(s) != 0) {
      MyFree(s);
      return;
    }
    cli_resume(cptr) = s;
    resume_hash_add(s);
  }

  /* (Re)generate the bearer secret and bump the generation counter; the old
     secret -- and therefore any previously issued token -- stops verifying. */
  if (ircd_tls_random_bytes(s->secret, RESUME_SECRET_BYTES) != 0)
    return;
  s->generation++;

  if (resume_token_encode(s, token, sizeof(token)) != 0)
    return;

  resume_total_issued++;
  sendcmdto_one(&me, CMD_RESUME, cptr, "TOKEN :%s", token);
}

/** Make an authenticated secure client resumable without a token, so it can be
 * reattached by account after an unexpected transport loss even if it never
 * negotiated the capability.  No-op if it already has a session. */
void
resume_session_ensure(struct Client *cptr)
{
  struct ResumeSession *s;

  if (!resume_enabled() || !feature_bool(FEAT_RESUME_AUTO_ACCOUNT)
      || !resume_is_capable_transport(cptr) || !IsAccount(cptr)
      || cli_resume(cptr)
      || (cli_user(cptr)->acc_flags & RESUME_ACC_NO_AUTO))
    return;

  s = (struct ResumeSession *)MyCalloc(1, sizeof(*s));
  s->state = RESUME_STATE_ATTACHED;
  s->client = cptr;
  if (resume_gen_id(s) != 0) {
    MyFree(s);
    return;
  }
  cli_resume(cptr) = s;
  resume_hash_add(s);
}

/** Free a session's memory.  Callers must have already unlinked it from the
 * table and from its owning client. */
static void
resume_session_free(struct ResumeSession *s)
{
  volatile unsigned char *p = s->secret;
  size_t i;

  /* Wipe the bearer secret before returning the memory to the heap.  The
     volatile store defeats dead-store elimination (plain memset can be dropped
     since the object is freed immediately after). */
  for (i = 0; i < RESUME_SECRET_BYTES; i++)
    p[i] = 0;

  MyFree(s->saved_away);
  MyFree(s);
}

/** Human-readable detach reason for operator notices (never a token/secret). */
static const char *
resume_reason_name(enum ResumeDetachReason reason)
{
  switch (reason) {
  case RESUME_DETACH_EOF:         return "transport-eof";
  case RESUME_DETACH_RESET:       return "transport-reset";
  case RESUME_DETACH_TLS_ERROR:   return "tls-error";
  case RESUME_DETACH_WS_ABNORMAL: return "ws-abnormal";
  case RESUME_DETACH_PING_TIMEOUT: return "ping-timeout";
  case RESUME_DETACH_BRB:         return "brb";
  default:                        return "unknown";
  }
}

/** Detach-expiry timer callback.
 *
 * ET_EXPIRE performs the final exit but does NOT free the session: the event
 * engine still references the embedded timer and fires ET_DESTROY immediately
 * afterwards (see timer_run()).  ET_DESTROY -- reached here after expiry and
 * also synchronously from timer_del() on a non-expiry teardown -- is the single
 * place the session memory is released.
 */
static void
resume_expiry_cb(struct Event *ev)
{
  struct ResumeSession *s = (struct ResumeSession *)t_data(ev_timer(ev));
  struct Client *cptr;

  switch (ev_type(ev)) {
  case ET_EXPIRE:
    cptr = s->client;
    assert(cptr != NULL);

    /* Unlink first so the exit path's invalidate hook is a no-op; the session
       memory is released on the ET_DESTROY that timer_run() fires next. */
    resume_hash_remove(s);
    cli_resume(cptr) = NULL;
    s->client = NULL;
    s->state = RESUME_STATE_NONE;
    s->discarding = 1;

    if (resume_cur_detached)
      resume_cur_detached--;
    resume_total_expired++;

    if (feature_bool(FEAT_RESUME_SERVER_NOTICES)) {
      static time_t rate;
      sendto_opmask_butone_ratelimited(0, SNO_CONNEXIT, &rate,
                           "RESUME: expired %s, sending QUIT", cli_name(cptr));
    }

    exit_client(cptr, cptr, &me, "Resume timeout");
    break;

  case ET_DESTROY:
    /* Only free when the session is actually being torn down.  A successful
       resume disarms this timer with timer_del() (discarding == 0), which also
       fires ET_DESTROY but must leave the now-reattached session alive. */
    if (s->discarding)
      resume_session_free(s);
    break;

  default:
    break;
  }
}

void
resume_session_invalidate(struct Client *cptr)
{
  struct ResumeSession *s = cli_resume(cptr);

  if (!s)
    return;

  cli_resume(cptr) = NULL;
  resume_hash_remove(s);
  if (IsDetached(cptr) && resume_cur_detached)
    resume_cur_detached--;

  /* If a resume attempt was mid-flight, drop its dangling claim pointer. */
  if (s->state == RESUME_STATE_CLAIMING && s->claimant)
    cli_resume_claim(s->claimant) = NULL;

  s->discarding = 1;
  if (t_active(&s->expiry_timer))
    timer_del(&s->expiry_timer); /* fires ET_DESTROY -> resume_session_free */
  else
    resume_session_free(s);
}

void
resume_mark_history_lost(struct Client *cptr)
{
  struct ResumeSession *s = cli_resume(cptr);

  if (s)
    s->history_lost = 1;
}

/** Broadcast \a cptr's current away state to servers and away-notify peers. */
static void
resume_away_notify(struct Client *cptr)
{
  const char *away = cli_user(cptr)->away;

  sendcmdto_serv_butone(cptr, CMD_AWAY, cptr, away ? ":%s" : "", away);
  sendcmdto_capflag_common_channels_butone(cptr, CMD_AWAY, cptr,
                                           CAP_AWAYNOTIFY, 0,
                                           away ? ":%s" : "", away);
}

/** Set the temporary detach away, preserving any away the client already had.
 * Disabled when RESUME_DETACH_AWAY is empty. */
static void
resume_set_detach_away(struct Client *cptr, struct ResumeSession *s)
{
  if (!RESUME_DETACH_AWAY[0])
    return;
  MyFree(s->saved_away);                /* none expected while attached */
  s->saved_away = cli_user(cptr)->away; /* take ownership; may be NULL */
  DupString(cli_user(cptr)->away, RESUME_DETACH_AWAY);
  s->away_overridden = 1;
  resume_away_notify(cptr);
}

/** Restore the client's pre-detach away (or clear it) and notify peers.  Keyed
 * on whether we actually overrode the away, so a rehash of RESUME_DETACH_AWAY
 * between detach and resume cannot strand the detach message. */
static void
resume_restore_away(struct Client *cptr, struct ResumeSession *s)
{
  if (!s->away_overridden)              /* nothing was overridden on detach */
    return;
  MyFree(cli_user(cptr)->away);         /* the detach message */
  cli_user(cptr)->away = s->saved_away; /* prior away, or NULL */
  s->saved_away = NULL;
  s->away_overridden = 0;
  resume_away_notify(cptr);
}

void
resume_detach(struct Client *cptr, enum ResumeDetachReason reason)
{
  struct ResumeSession *s = cli_resume(cptr);
  int timeout = resume_conf_timeout();

  assert(s != NULL);
  assert(s->state == RESUME_STATE_ATTACHED);
  assert(!IsDetached(cptr));

  detach_connection(cptr); /* release transport, keep the Client visible */

  SetDetach(cptr);
  s->state = RESUME_STATE_DETACHED;
  s->detach_reason = reason;
  s->detached_at = CurrentTime;
  s->expires_at = CurrentTime + timeout;
  s->history_lost = 0;

  resume_set_detach_away(cptr, s);

  timer_add(timer_init(&s->expiry_timer), resume_expiry_cb, s,
            TT_RELATIVE, timeout);

  resume_cur_detached++;
  resume_total_detached++;
  if (resume_cur_detached > resume_peak_detached)
    resume_peak_detached = resume_cur_detached;

  if (feature_bool(FEAT_RESUME_SERVER_NOTICES)) {
    static time_t rate;
    sendto_opmask_butone_ratelimited(0, SNO_CONNEXIT, &rate,
                         "RESUME: detached %s, reason=%s, expires=%ds",
                         cli_name(cptr), resume_reason_name(reason), timeout);
  }
}

int
resume_try_detach(struct Client *cptr, enum ResumeDetachReason reason)
{
  if (!resume_enabled())
    return 0;

  /* Only an eligible, registered, secure-WebSocket local user with a live
     resume session may detach; everything else exits normally. */
  if (!IsUser(cptr) || !MyConnect(cptr) || IsDetached(cptr)
      || HasFlag(cptr, FLAG_KILLED))
    return 0;
  if (!resume_is_capable_transport(cptr))
    return 0;
  if (!cli_resume(cptr) || cli_resume(cptr)->state != RESUME_STATE_ATTACHED)
    return 0;

  /* Respect the global cap; when full, fall back to an ordinary disconnect. */
  if (resume_cur_detached >= (unsigned int)resume_conf_max_detached())
    return 0;

  /* The client is being kept alive, so it is not a dead socket. */
  ClrFlag(cptr, FLAG_DEADSOCKET);
  resume_detach(cptr, reason);
  return 1;
}

int
m_brb(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  if (!resume_enabled() || !feature_bool(FEAT_RESUME_ALLOW_BRB)
      || !IsUser(sptr) || !resume_is_capable_transport(sptr)
      || IsDetached(sptr) || !cli_resume(sptr)
      || cli_resume(sptr)->state != RESUME_STATE_ATTACHED
      || resume_cur_detached >= (unsigned int)resume_conf_max_detached()) {
    sendstdreply(sptr, MSG_FAIL, "BRB", "CANNOT_BRB",
                 "Cannot suspend this connection");
    return 0;
  }

  /* Tell the client how long its session will be held, flush it out before
     the transport is torn down, then detach on the user's behalf. */
  sendcmdto_one(&me, CMD_BRB, sptr, "%d", resume_conf_timeout());
  send_queued(sptr);
  resume_detach(sptr, RESUME_DETACH_BRB);
  return 0;
}

void
resume_send_whois(struct Client *sptr, struct Client *acptr, const char *name)
{
  struct ResumeSession *s;
  int remaining;

  if (!IsDetached(acptr) || RESUME_WHOIS_POLICY == RESUME_WHOIS_OFF)
    return;
  if (RESUME_WHOIS_POLICY == RESUME_WHOIS_OPERS
      && !(IsAnOper(sptr) || sptr == acptr))
    return;

  s = cli_resume(acptr);
  if (!s)
    return;

  remaining = (int)(s->expires_at - CurrentTime);
  if (remaining < 0)
    remaining = 0;

  send_reply(sptr, SND_EXPLICIT | RPL_WHOISWEBIRC,
             "%s :is temporarily detached (resume window: %d seconds)",
             name, remaining);
}

/** Swap the Connections of \a old_client (detached shell) and \a new_client
 * (live WSS/TLS), so the old client adopts the live transport and the new
 * client is left holding the dead shell to be freed alongside it.
 *
 * con_socket is embedded and its event generator references &con_socket, so we
 * keep both Connection objects intact and only re-point the ownership
 * back-pointers -- avoiding any socket/timer re-registration.
 */
static void
resume_adopt(struct Client *old_client, struct Client *new_client)
{
  struct Connection *newcon = cli_connect(new_client);
  struct Connection *oldshell = cli_connect(old_client);

  /* Oper privileges and snomask live on the Connection, so the swap below would
     drop them -- leaving a resumed oper with +o but no privs.  Carry them over. */
  *con_privs(newcon) = *con_privs(oldshell);
  con_snomask(newcon) = con_snomask(oldshell);

  /* Carry the session's resolved sendq/flood limits (the new connection has none). */
  con_max_sendq(newcon) = con_max_sendq(oldshell);
  con_max_flood(newcon) = con_max_flood(oldshell);

  /* Carry the accumulated nick-change penalty, so a BRB/reconnect can't reset it. */
  con_nextnick(newcon) = con_nextnick(oldshell);

  /* Keep the local-count bucket and byte stats balanced across the swap. */
  strcpy(con_sockhost(newcon), con_sockhost(oldshell));
  con_sendM(newcon) = con_sendM(oldshell);
  con_receiveM(newcon) = con_receiveM(oldshell);
  con_sendB(newcon) = con_sendB(oldshell);
  con_receiveB(newcon) = con_receiveB(oldshell);

  /* Move the session's conf attachments (incl. any Operator block) onto the live
     connection and hand the transient's own to the shell, so class link-counts
     stay balanced -- the transient's is freed when new_client exits. */
  {
    struct SLink *tmp = con_confs(newcon);
    con_confs(newcon) = con_confs(oldshell);
    con_confs(oldshell) = tmp;
  }

  cli_connect(old_client) = newcon;
  cli_connect(new_client) = oldshell;
  con_client(newcon) = old_client;
  con_client(oldshell) = new_client;
  con_resume_claim(newcon) = NULL;

  /* The live fd now belongs to the old client. */
  if (-1 < cli_fd(old_client))
    LocalClientArray[cli_fd(old_client)] = old_client;
}

/** Reconstruct a resumed client's own local view: the registration welcome
 * burst, its user modes and away state, and for each channel it belongs to a
 * self JOIN, topic, and NAMES.  Everything is sent only to \a cptr -- no
 * broadcast -- so peers see nothing.
 *
 * \a send_loggedin re-sends RPL_LOGGEDIN so a token-path resumer (which never
 * SASLs on the new connection) re-learns it is still logged in.
 */
static void
resume_replay(struct Client *cptr, int send_loggedin)
{
  struct Membership *member;

  /* The account numeric precedes the welcome, as at registration. */
  if (send_loggedin)
    send_reply(cptr, RPL_LOGGEDIN, cli_name(cptr), cli_user(cptr)->username,
               cli_user(cptr)->host, cli_user(cptr)->account,
               cli_user(cptr)->account);

  send_welcome(cptr);

  /* Echo the client's own user modes as a MODE message, like registration.
     "old" is empty, so every mode the client holds (including +r) is shown. */
  {
    struct Flags old;
    memset(&old, 0, sizeof(old));
    send_umode(cptr, cptr, &old, ALL_UMODES);
  }

  if (cli_user(cptr)->away)
    send_reply(cptr, RPL_NOWAWAY);

  for (member = cli_user(cptr)->channel; member;
       member = member->next_channel) {
    struct Channel *chptr = member->channel;
    char modebuf[MODEBUFLEN];
    char parabuf[MODEBUFLEN];

    sendjointo_one(cptr, chptr, cptr);

    *modebuf = *parabuf = '\0';
    channel_modes(cptr, modebuf, parabuf, sizeof(parabuf), chptr, member);
    send_reply(cptr, RPL_CHANNELMODEIS, chptr->chname, modebuf, parabuf);

    if (chptr->topic[0]) {
      send_reply(cptr, RPL_TOPIC, chptr->chname, chptr->topic);
      send_reply(cptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
                 chptr->topic_time);
    }
    do_names(cptr, chptr, NAMES_ALL | NAMES_EON);
  }
}

/** Finish a validated resume from check_auth_finished(): adopt the new
 * connection onto the detached client, dispose the temporary client, rotate
 * the token, and confirm success.
 * @return CPTR_KILLED -- the temporary client (auth->client) is gone.
 */
int
resume_complete(struct Client *new_client)
{
  struct ResumeSession *s = cli_resume_claim(new_client);
  struct Client *old_client;
  int send_loggedin;

  assert(s != NULL);
  assert(s->state == RESUME_STATE_CLAIMING);
  old_client = s->client;
  assert(old_client != NULL);

  /* A token-path resumer did not SASL here, so it never got RPL_LOGGEDIN;
     re-send it for an accounted session (matters when only the server-local
     token, not services, let it back in).  A SASL resumer already has it. */
  send_loggedin = IsAccount(old_client) && !HasFlag(new_client, FLAG_SASL);

  /* Release the temporary client's registration bookkeeping while its
     connection is still its own. */
  if (cli_auth(new_client))
    destroy_auth_request(cli_auth(new_client));

  /* Drop any in-flight SASL cookie/timer before the swap frees new_client. */
  sasl_stop_timeout(new_client);
  sasl_session_remove(cli_sasl(new_client));
  cli_sasl(new_client) = 0;

  cli_resume_claim(new_client) = NULL;
  s->claimant = NULL;

  resume_adopt(old_client, new_client);

  /* The adopted connection came from an unfinished registration; switch it to
     dispatching commands as the client's real type.  An oper must get
     OPER_HANDLER or the parser routes its commands to the non-oper handlers,
     leaving it with privileges it cannot use. */
  cli_handler(old_client) = IsAnOper(old_client) ? OPER_HANDLER : CLIENT_HANDLER;

  /* The old client is live again on the new transport. */
  ClearDetach(old_client);
  s->state = RESUME_STATE_ATTACHED;
  s->detach_reason = RESUME_DETACH_NONE;
  s->detached_at = 0;
  s->expires_at = 0;
  if (resume_cur_detached)
    resume_cur_detached--;

  /* Disarm the expiry timer WITHOUT freeing the now-reattached session
     (discarding == 0, so the timer's ET_DESTROY is a no-op). */
  if (t_active(&s->expiry_timer))
    timer_del(&s->expiry_timer);

  resume_total_resumed++;

  /* Lift the SendQ ceiling so the bounded replay burst does not disconnect a
     client in many/large channels.  The limit is enforced at queue time
     (send_buffer()), not at flush (send_queued()), so raising it only across
     the burst is safe. */
  {
    struct Connection *con = cli_connect(old_client);
    unsigned int saved_sendq = con_max_sendq(con);

    con_max_sendq(con) = UINT_MAX;

    sendcmdto_one(&me, CMD_RESUME, old_client, "SUCCESS :%s",
                  cli_name(old_client));
    resume_restore_away(old_client, s);
    resume_replay(old_client, send_loggedin);
    if (s->history_lost)
      sendstdreply(old_client, MSG_WARN, "RESUME", "HISTORY_LOST",
                   "Messages may have been missed while you were disconnected");
    s->history_lost = 0;
    /* Rotate the bearer token only for clients that negotiated the capability.
       An account-path resumer that never enabled draft/resume-0.5 must not be
       handed a token it did not opt into (mirrors the gating in m_cap.c). */
    if (CapHas(cli_active(old_client), CAP_RESUME))
      resume_token_issue(old_client);

    /* Flush before restoring the ceiling, so a large replay does not leave the
       SendQ above the class limit and trip "Max SendQ exceeded" on the next
       inbound message. */
    send_queued(old_client);
    con_max_sendq(con) = saved_sendq;
  }

  if (feature_bool(FEAT_RESUME_SERVER_NOTICES)) {
    static time_t rate;
    sendto_opmask_butone_ratelimited(0, SNO_CONNEXIT, &rate,
                         "RESUME: resumed %s", cli_name(old_client));
  }

  /* Dispose the temporary client (unregistered -> no QUIT); it now holds the
     dead shell, which is freed with it. */
  return exit_client(new_client, new_client, &me, "Resumed onto new session");
}

void
resume_release_claim(struct Client *cptr)
{
  struct ResumeSession *s = cli_resume_claim(cptr);

  if (!s)
    return;

  cli_resume_claim(cptr) = NULL;
  if (s->state == RESUME_STATE_CLAIMING && s->claimant == cptr) {
    /* The target stays detached with its expiry timer still armed. */
    s->state = RESUME_STATE_DETACHED;
    s->claimant = NULL;
  }
}

/** Whether an unregistered secure client's nick collision with \a acptr should
 * be deferred for a possible account-based reattach.  The account is not known
 * yet, so only the collision target's eligibility is checked here. */
int
resume_account_deferrable(const struct Client *sptr, const struct Client *acptr)
{
  struct ResumeSession *s;

  if (!resume_enabled() || !feature_bool(FEAT_RESUME_AUTO_ACCOUNT))
    return 0;
  if (IsRegistered(sptr) || !resume_is_capable_transport(sptr))
    return 0;
  if (!acptr || !IsDetached(acptr))
    return 0;

  s = cli_resume(acptr);
  return s && s->state == RESUME_STATE_DETACHED;
}

/** Claim \a target's detached session for \a new_client if the two share an
 * account (and IP, unless waived).  Mirrors the token path's authorization;
 * on success the caller drives resume_complete() from check_auth_finished().
 * @return 1 if claimed, 0 otherwise. */
int
resume_account_try_claim(struct Client *new_client, struct Client *target)
{
  struct ResumeSession *s;

  if (!resume_enabled() || !feature_bool(FEAT_RESUME_AUTO_ACCOUNT))
    return 0;
  if (!target || target == new_client || !IsDetached(target))
    return 0;

  s = cli_resume(target);
  if (!s || s->state != RESUME_STATE_DETACHED)
    return 0;
  if (!IsAccount(new_client) || !IsAccount(target)
      || ircd_strcmp(cli_account(new_client), cli_account(target)) != 0)
    return 0;
  if (cli_user(new_client)->acc_flags & RESUME_ACC_NO_AUTO)
    return 0; /* account opted out of auto-reattach */
  if (!feature_bool(FEAT_RESUME_ACCOUNT_ANY_IP)
      && irc_in_addr_cmp(&cli_ip(new_client), &cli_ip(target)))
    return 0;

  s->state = RESUME_STATE_CLAIMING;
  s->claimant = new_client;
  cli_resume_claim(new_client) = s;
  return 1;
}

int
m_resume(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  unsigned char id[RESUME_ID_BYTES];
  unsigned char secret[RESUME_SECRET_BYTES];
  struct ResumeSession *s;

  if (!resume_enabled())
    return 0; /* feature off: ignore silently */

  if (IsRegistered(sptr)) {
    sendstdreply(sptr, MSG_FAIL, "RESUME", "REGISTRATION_IS_COMPLETED",
                 "Cannot resume connection, connection registration has "
                 "completed");
    return 0;
  }

  if (!resume_is_capable_transport(sptr)) {
    sendstdreply(sptr, MSG_FAIL, "RESUME", "INSECURE_SESSION",
                 "Cannot resume connection, you are not connected with secure "
                 "WebSockets");
    return 0;
  }

  /* Bound resume attempts per connection. */
  if (cli_resume(sptr)) {
    if (cli_resume(sptr)->attempts >= RESUME_MAX_ATTEMPTS) {
      sendstdreply(sptr, MSG_FAIL, "RESUME", "CANNOT_RESUME",
                   "Cannot resume connection");
      return 0;
    }
    cli_resume(sptr)->attempts++;
  }

  if (parc < 2 || resume_token_parse(parv[1], id, secret) != 0) {
    sendstdreply(sptr, MSG_FAIL, "RESUME", "INVALID_TOKEN",
                 "Cannot resume connection, token is not valid");
    return 0;
  }

  /* One generic failure for unknown/expired/used/active/other-IP tokens so a
     caller cannot probe which sessions exist. */
  s = resume_find(id);
  if (!s || s->state != RESUME_STATE_DETACHED
      || resume_ct_memcmp(s->secret, secret, RESUME_SECRET_BYTES) != 0
      || (RESUME_REQUIRE_SAME_IP
          && irc_in_addr_cmp(&cli_ip(sptr), &cli_ip(s->client)))) {
    sendstdreply(sptr, MSG_FAIL, "RESUME", "INVALID_TOKEN",
                 "Cannot resume connection, token is not valid");
    return 0;
  }

  /* Claim the session, then drive registration to completion.  The adoption
     runs from check_auth_finished() only after all normal auth, ban, and
     policy checks have passed (see resume_complete()). */
  s->state = RESUME_STATE_CLAIMING;
  s->claimant = sptr;
  cli_resume_claim(sptr) = s;

  return auth_cap_done(cli_auth(sptr));
}
