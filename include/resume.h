#ifndef INCLUDED_resume_h
#define INCLUDED_resume_h
/*
 * IRC - Internet Relay Chat, include/resume.h
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
 * @brief Public interface for IRCv3 session resume (draft/resume-0.5).
 * @version $Id$
 */

#ifndef INCLUDED_ircd_events_h
#include "ircd_events.h"	/* struct Timer */
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>		/* size_t */
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_time_h
#include <time.h>		/* time_t */
#define INCLUDED_time_h
#endif

struct Client;

/*
 * Compile-time constants and policy.
 *
 * These fix struct layout, token entropy, and the token wire format, so they
 * are compiled in rather than made runtime features.  Operator-tunable policy
 * lives in the feature system (see FEAT_RESUME* in ircd_features.h).
 */
/** Bytes of public session id (128 bits). */
#define RESUME_ID_BYTES		16
/** Bytes of bearer secret (256 bits). */
#define RESUME_SECRET_BYTES	32
/** Maximum accepted token length; longer input is rejected before parsing. */
#define RESUME_TOKEN_MAX	256
/** Lower/upper clamp for the RESUME_TIMEOUT feature value, in seconds. */
#define RESUME_TIMEOUT_MIN	10
#define RESUME_TIMEOUT_MAX	300
/** Same-IP resume is required and attempts are capped for every server. */
#define RESUME_REQUIRE_SAME_IP	1
#define RESUME_MAX_ATTEMPTS	3

/** Account-flags bit (from the auth service) opting an account out of
 * account-based auto-reattach; the token path is unaffected. */
#define RESUME_ACC_NO_AUTO	0x080

/** Away set on a detached session (prior away restored on reattach); empty
 * disables it. */
#define RESUME_DETACH_AWAY	"Temporarily detached, messages will be missed."

/** Context appended after the ERR_CANNOTSENDTOUSER (531) prefix when a message
 * is sent to a detached client; empty disables the 531 reply. */
#define RESUME_CANNOTSEND	"recipient is temporarily detached"

/** Who may see that a client is temporarily detached in WHOIS. */
enum ResumeWhois {
  RESUME_WHOIS_OFF = 0, /**< never shown */
  RESUME_WHOIS_OPERS,   /**< opers (and the user themselves) only */
  RESUME_WHOIS_ALL      /**< any requester */
};
/** Fixed WHOIS disclosure policy. */
#define RESUME_WHOIS_POLICY	RESUME_WHOIS_OPERS

/** Authoritative lifecycle state of a resumable session. */
enum ResumeState {
  RESUME_STATE_NONE = 0,	/**< not resumable */
  RESUME_STATE_ATTACHED,	/**< live transport present */
  RESUME_STATE_DETACHED,	/**< transport lost, awaiting resume or expiry */
  RESUME_STATE_CLAIMING		/**< a resume attempt is adopting this session */
};

/** Why a session detached (kept typed, never parsed from display strings). */
enum ResumeDetachReason {
  RESUME_DETACH_NONE = 0,
  RESUME_DETACH_EOF,
  RESUME_DETACH_RESET,
  RESUME_DETACH_TLS_ERROR,
  RESUME_DETACH_WS_ABNORMAL,
  RESUME_DETACH_PING_TIMEOUT,
  RESUME_DETACH_BRB
};

/** Per-session resume metadata, associated with the network-visible Client. */
struct ResumeSession {
  enum ResumeState state;               /**< authoritative lifecycle state */

  struct Client *client;                /**< owning network-visible client */
  struct Client *claimant;              /**< new client adopting this (CLAIMING) */
  int discarding;                       /**< set when the session is being freed */

  unsigned char id[RESUME_ID_BYTES];    /**< public lookup key */
  unsigned char secret[RESUME_SECRET_BYTES]; /**< constant-time compared */

  time_t detached_at;                   /**< when detach happened (0 if attached) */
  time_t expires_at;                    /**< detach deadline (0 if attached) */

  unsigned int generation;              /**< bumped on every token rotation */
  unsigned int attempts;                /**< resume attempts seen (rate limiting) */
  int history_lost;                     /**< output was discarded while detached */
  char *saved_away;                     /**< away held before detach, restored on resume */
  int away_overridden;                  /**< a detach-away replaced the user's away */

  enum ResumeDetachReason detach_reason;/**< why the session detached */
  struct Timer expiry_timer;            /**< one-shot detach-expiry timer */

  struct ResumeSession *hnext;          /**< resumeTable[] bucket chain */
};

/*
 * Module lifecycle / configuration.
 */
extern void resume_init(void);
extern void resume_feat_notify(void);
extern int resume_enabled(void);
extern int resume_conf_timeout(void);
extern int resume_conf_max_detached(void);

/*
 * Eligibility.
 */
extern int resume_is_capable_transport(const struct Client *cptr);

/*
 * Token / session lifecycle.
 */
extern void resume_token_issue(struct Client *cptr);
extern void resume_session_ensure(struct Client *cptr);
extern void resume_session_invalidate(struct Client *cptr);
extern struct ResumeSession *resume_find(const unsigned char *id);

/*
 * Detach / expiry.
 */
extern void resume_detach(struct Client *cptr, enum ResumeDetachReason reason);
extern int resume_try_detach(struct Client *cptr, enum ResumeDetachReason reason);
extern void resume_mark_history_lost(struct Client *cptr);

/*
 * RESUME command and reattachment.
 */
extern int m_resume(struct Client *cptr, struct Client *sptr,
                    int parc, char *parv[]);
extern int m_brb(struct Client *cptr, struct Client *sptr,
                 int parc, char *parv[]);
extern int resume_complete(struct Client *new_client);
extern void resume_release_claim(struct Client *cptr);

/*
 * Account-based auto-reattach (same nick + account, no client support needed).
 */
extern int resume_account_deferrable(const struct Client *sptr,
                                     const struct Client *acptr);
extern int resume_account_try_claim(struct Client *new_client,
                                    struct Client *target);

/*
 * WHOIS.
 */
extern void resume_send_whois(struct Client *sptr, struct Client *acptr,
                              const char *name);

#endif /* INCLUDED_resume_h */
