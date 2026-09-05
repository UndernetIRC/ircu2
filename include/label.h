/*
 * IRC - Internet Relay Chat, include/label.h
 * Copyright (C) 2026 MrIron <mriron@undernet.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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
 * @brief IRCv3 labeled-response capture interface (see ircd/label.c).
 */
#ifndef INCLUDED_label_h
#define INCLUDED_label_h

struct Client;
struct LabelCapture;
struct MsgBuf;
struct MsgTagCtx;

/* IRCv3 labeled-response: a connection may have several outstanding
 * captures at once (struct LabelCapture, see client.h), each independently
 * identified by its ref. At most one is ever "active" (the current
 * recipient of anything cptr sends) at a time, for the duration of a
 * synchronous command dispatch or a single continuation tick; the rest
 * are parked, waiting for whatever will eventually finish them (a later
 * list_next_channels() tick, or -- once S2S support lands -- a matching
 * inbound batch=ref close from a remote server). */

/* Create a new capture for \a cptr, push it onto its outstanding list, and
 * mark it active. Returns the new capture (owned by \a cptr's list; valid
 * until finished/aborted/dropped by label_capture_client_gone()). */
extern struct LabelCapture *label_capture_start(struct Client *cptr,
                                                const char *label);
/* Convert the capture currently active for \a cptr into a streaming one
 * and emit its BATCH open line immediately, instead of deferring the
 * ACK/single-line/BATCH decision to finish() -- for a response that's
 * unconditionally multi-line and may span many event-loop ticks (LIST).
 * Must be called with a capture already active for cptr. Returns the ref
 * to remember (e.g. into ListingArgs.label_ref), or NULL if there was no
 * active capture (the command wasn't labeled). */
extern const char *label_capture_stream_active(struct Client *cptr);
/* Resume an existing parked capture (by ref) as the active one for a new
 * continuation tick. No-op if not found (e.g. it was already dropped by
 * label_capture_client_gone()) -- callers that are about to send
 * something meant specifically for that capture (not just "whatever's
 * currently active") must check the return value before doing so; a
 * silent no-op leaves the *previous* active window (if any) unchanged,
 * which is very likely the wrong destination. Returns 1 if reopened,
 * 0 if ref didn't resolve to anything. */
extern int label_capture_reopen(struct Client *cptr, const char *ref);
/* End the current dispatch/tick: nothing sent to a client is captured
 * again until label_capture_start()/reopen() is called anew. Always safe
 * to call (touches no Client), so it can run unconditionally even when
 * the handler that just ran may have freed cptr (CPTR_KILLED). */
extern void label_capture_close_window(void);
/* Snapshot/restore the active window around a temporary redirect (e.g.
 * reopening a *different* capture to fold one more line into it before
 * finishing it) -- unlike finish()/abort(), which only protect their own
 * internal replay sends, this covers sends the caller makes itself
 * before invoking finish()/abort(). See m_list.c's superseded-listing
 * handling for the motivating case. */
extern void label_capture_save_active(struct Client **client_out,
				      struct LabelCapture **node_out);
extern void label_capture_restore_active(struct Client *client,
					 struct LabelCapture *node);

/* Normal completion: decide ACK / single-tag / BATCH-wrap for the capture
 * \a ref on \a cptr based on how many lines were produced, release them
 * labeled, and free the capture. Only valid when the response is known to
 * be complete. Call label_capture_close_window() first. */
extern void label_capture_finish(struct Client *cptr, const char *ref);
/* The response for capture \a ref could not be honestly labeled as
 * complete (e.g. it yields more output on a later event-loop tick, as
 * LIST does, or the capture buffer overflowed) -- release whatever was
 * captured as plain, unlabeled output instead of misrepresenting it with
 * a closed batch, and free the capture. Call label_capture_close_window()
 * first. */
extern void label_capture_abort(struct Client *cptr, const char *ref);
/* cptr is about to be freed: drop every capture still outstanding for it
 * (no attempt to send anything -- cptr's socket is already gone). Call
 * from exit_one_client() while cptr is still valid memory, before
 * free_client() runs. */
extern void label_capture_client_gone(struct Client *cptr);

/* send_buffer() hook: if \a to -- the *intended recipient*, before
 * cli_from() resolution, so a remote user is distinguishable from the
 * link it sits behind -- is the owner of the active capture, take the
 * line into that capture and return 1; otherwise return 0 and let it go
 * to the wire. \a tctx is the effective tag context for the line (cache
 * ctx or explicit ctx). */
extern int label_capture_intercept(struct Client *to, struct Client *from,
                                   struct MsgBuf *buf, int prio,
                                   const struct MsgTagCtx *tctx);
/* The capture currently active for \a owner (the requesting client
 * itself, local or remote), or NULL if the active window belongs to
 * someone else or is closed. For callers that need to hand a capture off (see
 * sendcmdto_one_hunted() in send.c). */
extern struct LabelCapture *label_capture_active_for(struct Client *owner);

#endif /* INCLUDED_label_h */
