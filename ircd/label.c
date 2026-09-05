/*
 * IRC - Internet Relay Chat, ircd/label.c
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
 * @brief IRCv3 labeled-response capture.
 *
 * A labeled command's output to the requesting connection is intercepted
 * from send_buffer() (label_capture_intercept()) while its capture is the
 * active window, and released once the response is known to be complete
 * (label_capture_finish()) as a bare ACK, a single labeled line, or a
 * labeled BATCH, depending on how many lines it produced. LIST streams
 * instead (label_capture_stream_active()). Captures for a remote
 * requester answered on its behalf emit S2S-addressed BATCH/ACK relayed
 * back by m_batch.c/m_ack.c. See include/label.h for the contract.
 */
#include "config.h"

#include "label.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "msg_tag.h"
#include "msgq.h"
#include "send.h"

#include <stdarg.h>
#include <string.h>

/** IRCv3 labeled-response: output deferred for a client during one
 * capture's active window.  \a body is a heap copy of the pre-tag-prefix
 * wire line (not a reference-counted MsgBuf -- avoids entangling this with
 * msgq.c's buffer pool/refcount contract for what is normally 0-1 lines). */
struct LabelDeferred {
  char *body;
  unsigned int len;
  int prio;
  struct MsgTagCtx tagctx;    /**< copied by value: tags/tok/local_time/etc. */
  struct Client *from;
  struct LabelDeferred *next;
};

/** Safety valve against a labeled command whose reply fans out to an
 * unbounded number of lines (e.g. LIST/WHO on a large network): stop
 * deferring, flush what is buffered as a batch, and let the remainder
 * through unlabeled rather than growing this list without bound.
 *
 * Sized for a genuinely large network's LIST (thousands of channels,
 * not hundreds) to stay inside one clean batch rather than degrading to
 * unlabeled output for a perfectly ordinary-sized response. */
#define LABEL_CAPTURE_MAX_COUNT 5000
#define LABEL_CAPTURE_MAX_BYTES 1048576

/** The one capture (among possibly several outstanding on its owning
 * client) currently receiving anything sent to that client -- valid only
 * for the duration of a synchronous command dispatch or a single
 * continuation tick (see label_capture_start()/reopen()/close_window()).
 * A client's other, parked captures are untouched by send_buffer() until
 * something explicitly reopens them. */
static struct Client *label_capture_active_client;
static struct LabelCapture *label_capture_active_node;

/* --- IRCv3 labeled-response capture ---------------------------------- */

/** Free \a lc's deferred-line chain and the node itself.  Caller must
 * already have unlinked \a lc from its owning client's list. */
static void
label_capture_free_node(struct LabelCapture *lc)
{
  struct LabelDeferred *entry = lc->head;

  while (entry) {
    struct LabelDeferred *next = entry->next;
    MyFree(entry->body);
    MyFree(entry);
    entry = next;
  }
  MyFree(lc);
}

/** Find \a ref on \a cptr's outstanding-capture list and unlink it.
 * Returns the node (now on no list), or NULL if not found. */
static struct LabelCapture *
label_capture_unlink(struct Client *cptr, const char *ref)
{
  struct LabelCapture **prev = &cli_labelcap(cptr);
  struct LabelCapture *lc;

  for (lc = *prev; lc; prev = &lc->next, lc = lc->next) {
    if (!strcmp(lc->ref, ref)) {
      *prev = lc->next;
      return lc;
    }
  }
  return NULL;
}

static void
label_capture_append(struct Client *to, struct Client *from,
                     struct MsgBuf *buf, int prio,
                     const struct MsgTagCtx *tctx)
{
  struct LabelCapture *lc = label_capture_active_node;
  struct LabelDeferred *entry;

  if (lc->streaming) {
    /* Re-emit immediately, tagged batch=ref, instead of deferring --
     * the capture-overflow safety valve below does not apply here (there
     * is nothing buffered to overflow). Un-redirected: suspend the
     * window first so this send doesn't recurse back into
     * label_capture_append() for the same capture. Unlike the buffered
     * path (msgq_raw_alloc()'d and cleaned per replayed entry at
     * finish() time), this send_buffer() call goes through the *real*
     * cli_sendQ() -- streamed output is no longer exempt from
     * list_next_channels()'s own sendQ-based pause check the way
     * buffered captures were. */
    struct MsgTag batchtag;
    struct MsgTagCtx streamctx;
    struct MsgBuf *mb;

    if (tctx)
      streamctx = *tctx;
    else
      msgtagctx_init(&streamctx, NULL);

    batchtag.next = streamctx.tags;
    batchtag.key = "batch";
    batchtag.value = lc->ref;
    streamctx.tags = &batchtag;

    label_capture_active_client = NULL;
    label_capture_active_node = NULL;

    mb = msgq_raw_alloc(to, buf->length + 1);
    memcpy(mb->msg, buf->msg, buf->length);
    mb->msg[buf->length] = '\0';
    mb->length = buf->length;

    send_buffer(to, from, mb, prio, &streamctx, NULL);
    msgq_clean(mb);

    label_capture_active_client = to;
    label_capture_active_node = lc;
    return;
  }

  if (lc->count >= LABEL_CAPTURE_MAX_COUNT
      || lc->bytes + buf->length > LABEL_CAPTURE_MAX_BYTES) {
    /* Degrade gracefully: this response no longer fits in one labeled
     * reply. Release what's buffered so far unlabeled (closing a batch
     * here would falsely claim the response ended at the overflow point),
     * then let this and any further lines for this command go out
     * normally. */
    char ref[sizeof(lc->ref)];

    ircd_strncpy(ref, lc->ref, sizeof(ref) - 1);
    ref[sizeof(ref) - 1] = '\0';
    label_capture_close_window();
    label_capture_abort(to, ref);
    send_buffer(to, from, buf, prio, tctx, NULL);
    return;
  }

  entry = (struct LabelDeferred *)MyMalloc(sizeof(*entry));
  entry->body = (char *)MyMalloc(buf->length + 1);
  memcpy(entry->body, buf->msg, buf->length);
  entry->body[buf->length] = '\0';
  entry->len = buf->length;
  entry->prio = prio;
  entry->from = from;
  entry->next = NULL;
  if (tctx)
    entry->tagctx = *tctx;
  else
    msgtagctx_init(&entry->tagctx, NULL);

  *lc->tail = entry;
  lc->tail = &entry->next;
  ++lc->count;
  lc->bytes += buf->length;
}

/** Send one server-generated line to \a to with an explicit tag context,
 * bypassing capture (label_capture_close_window() must already have been
 * called if a capture was active for \a to) and bypassing parse_tags()
 * (unlike sendcmdto_one(), which always picks up the *current* input
 * line's tags -- these lines need their own, synthetic tag list instead).
 *
 * \a to may be a genuine local client (the common case) or a *remote*
 * one -- e.g. parse_server()'s labeled-response wrapper finishing a
 * capture kept for a remote requester whose command we answered on its
 * behalf (see hunt_server_cmd()). In the local case the wire form is the
 * plain, unaddressed client-facing one (":<from> BATCH +ref type", one
 * recipient implied by the connection itself). Addressed to a server,
 * BATCH/ACK need an explicit target -- unlike numerics, which always
 * carry one -- so an intermediate hop's ms_batch()/ms_ack() (m_batch.c)
 * knows who to relay it to next. */
static void
label_emit(struct Client *to, struct Client *from, int prio,
          struct MsgTagCtx *tagctx, const char *cmd, const char *tok,
          const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct Client *dest = cli_from(to);
  const char *word = (IsServer(dest) || IsMe(dest)) ? tok : cmd;

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  if (IsServer(dest))
    mb = msgq_make(dest, "%:#C %s %C %v", from, word, to, &vd);
  else
    mb = msgq_make(dest, "%:#C %s %v", from, word, &vd);
  va_end(vd.vd_args);

  send_buffer(to, from, mb, prio, tagctx, NULL);

  msgq_clean(mb);
}

struct LabelCapture *
label_capture_start(struct Client *cptr, const char *label)
{
  static unsigned int label_ref_seq;
  /* The owner is the requesting client itself -- a genuine local client,
   * or, for a hunted command answered on its behalf (parse_server()), a
   * *remote* user. Deliberately not cli_from(cptr): for a remote user
   * that is the shared S2S link, and keying the window on the link would
   * sweep every line headed down it during the dispatch (a WALLOPS the
   * handler broadcasts, an RPING it sends onward, another user's reply)
   * into this requester's response. send_buffer() therefore runs the
   * intercept on the intended recipient, before resolving the link. */
  struct Client *owner = cptr;
  struct LabelCapture *lc = (struct LabelCapture *)MyMalloc(sizeof(*lc));

  ircd_snprintf(0, lc->ref, sizeof(lc->ref), "%x", ++label_ref_seq);
  ircd_strncpy(lc->value, label, sizeof(lc->value) - 1);
  lc->value[sizeof(lc->value) - 1] = '\0';
  lc->head = NULL;
  lc->tail = &lc->head;
  lc->count = 0;
  lc->bytes = 0;
  lc->streaming = 0;

  lc->next = cli_labelcap(owner);
  cli_labelcap(owner) = lc;

  label_capture_active_client = owner;
  label_capture_active_node = lc;

  return lc;
}

/** Convert the capture currently active for \a cptr into a streaming one
 * and emit its BATCH open line immediately, for a response that's
 * unconditionally multi-line and may span many event-loop ticks (LIST)
 * -- where deferring the ACK/single-line/BATCH decision to the end (the
 * ordinary label_capture_start()/finish() contract) doesn't make sense:
 * there's nothing to decide, and buffering an unbounded number of lines
 * in memory until some eventual finish() is wasteful when they could
 * just go out as they're produced.
 *
 * Must be called with a capture already active for cptr (i.e. after
 * parse.c's normal label_capture_start() for this dispatch) -- LIST
 * doesn't start its own capture, it upgrades the one already there. Any
 * lines already buffered on it (e.g. RPL_LISTSTART, sent before m_list()
 * gets far enough to know it's starting a genuine paginated listing and
 * call this) are flushed in order, tagged batch=ref, right after the
 * open line -- they predate the decision to stream, but the client must
 * still see them inside the batch, not lost.
 *
 * Returns the ref to store (e.g. into ListingArgs.label_ref), or NULL if
 * there was no active capture (the command wasn't labeled). */
const char *
label_capture_stream_active(struct Client *cptr)
{
  struct Client *owner = cptr;
  struct LabelCapture *lc;
  struct MsgTag labeltag;
  struct MsgTagCtx opentagctx;
  struct LabelDeferred *entry;

  if (owner != label_capture_active_client || !label_capture_active_node)
    return NULL;

  lc = label_capture_active_node;
  lc->streaming = 1;

  /* Emit the opening line (and any pre-existing buffered entries) un-
   * redirected: suspend the window first so these sends aren't captured
   * by the very capture they belong to. */
  label_capture_active_client = NULL;
  label_capture_active_node = NULL;

  labeltag.next = NULL;
  labeltag.key = "label";
  labeltag.value = lc->value;

  memset(&opentagctx, 0, sizeof(opentagctx));
  opentagctx.tags = &labeltag;
  opentagctx.local_time = CurrentTime;
  opentagctx.tok = TOK_BATCH;

  label_emit(cptr, &me, 0, &opentagctx, CMD_BATCH, "+%s labeled-response", lc->ref);

  entry = lc->head;
  lc->head = NULL;
  lc->tail = &lc->head;
  lc->count = 0;
  lc->bytes = 0;
  while (entry) {
    struct LabelDeferred *next = entry->next;
    struct MsgTag batchtag;
    struct MsgBuf *mb;

    batchtag.next = entry->tagctx.tags;
    batchtag.key = "batch";
    batchtag.value = lc->ref;
    entry->tagctx.tags = &batchtag;

    mb = msgq_raw_alloc(cptr, entry->len + 1);
    memcpy(mb->msg, entry->body, entry->len);
    mb->msg[entry->len] = '\0';
    mb->length = entry->len;

    send_buffer(cptr, entry->from, mb, entry->prio, &entry->tagctx, NULL);
    msgq_clean(mb);

    MyFree(entry->body);
    MyFree(entry);
    entry = next;
  }

  label_capture_active_client = owner;
  label_capture_active_node = lc;

  return lc->ref;
}

int
label_capture_reopen(struct Client *cptr, const char *ref)
{
  struct Client *owner = cptr;
  struct LabelCapture *lc;

  if (!ref || !*ref)
    return 0;

  for (lc = cli_labelcap(owner); lc; lc = lc->next) {
    if (!strcmp(lc->ref, ref)) {
      label_capture_active_client = owner;
      label_capture_active_node = lc;
      return 1;
    }
  }
  return 0;
}

void
label_capture_close_window(void)
{
  label_capture_active_client = NULL;
  label_capture_active_node = NULL;
}

/** Snapshot the currently-active window so a caller can temporarily
 * redirect it (e.g. reopen a *different* capture to fold one more line
 * into it) and put the original back afterward with
 * label_capture_restore_active(). Unlike finish()/abort(), which only
 * protect their own internal replay sends, this covers sends a caller
 * makes *before* invoking finish()/abort() -- see m_list.c's superseded-
 * listing handling. */
void
label_capture_save_active(struct Client **client_out, struct LabelCapture **node_out)
{
  *client_out = label_capture_active_client;
  *node_out = label_capture_active_node;
}

/** Restore a window previously captured by label_capture_save_active(). */
void
label_capture_restore_active(struct Client *client, struct LabelCapture *node)
{
  label_capture_active_client = client;
  label_capture_active_node = node;
}

/** If \a ref (belonging to \a cptr) is the currently-active window, close
 * it first -- finish()/abort() must never let their own replay sends
 * re-enter capture for the node they are about to free. Callers are
 * expected to have already called label_capture_close_window()
 * themselves; this is a defensive backstop, not the primary mechanism. */
static void
label_capture_close_if_active(struct Client *cptr, const char *ref)
{
  struct Client *owner = cptr;

  if (label_capture_active_client == owner && label_capture_active_node
      && !strcmp(label_capture_active_node->ref, ref))
    label_capture_close_window();
}

void
label_capture_finish(struct Client *cptr, const char *ref)
{
  struct Client *saved_active_client;
  struct LabelCapture *saved_active_node;
  struct LabelCapture *lc;
  unsigned int count;

  label_capture_close_if_active(cptr, ref);

  lc = label_capture_unlink(cptr, ref);
  if (!lc)
    return; /* not outstanding for this client: defensive no-op */

  /* The sends below must never be captured by a *different* window that
   * happens to be active for the same client right now -- e.g. an
   * interrupting command aborting an older parked capture while its own
   * reply is being captured. Suspend whatever's active, restore it once
   * we're done. */
  saved_active_client = label_capture_active_client;
  saved_active_node = label_capture_active_node;
  label_capture_active_client = NULL;
  label_capture_active_node = NULL;

  if (lc->streaming) {
    /* The open line and every body line already went out as they were
     * produced (label_capture_append()); nothing was buffered, so there
     * is nothing to decide or replay -- just close the batch. */
    struct MsgTagCtx closetagctx;

    memset(&closetagctx, 0, sizeof(closetagctx));
    closetagctx.local_time = CurrentTime;
    closetagctx.tok = TOK_BATCH;

    label_emit(cptr, &me, 0, &closetagctx, CMD_BATCH, "-%s", lc->ref);

    label_capture_active_client = saved_active_client;
    label_capture_active_node = saved_active_node;

    label_capture_free_node(lc);
    return;
  }

  count = lc->count;

  if (count == 0) {
    struct MsgTag labeltag;
    struct MsgTagCtx tagctx;

    labeltag.next = NULL;
    labeltag.key = "label";
    labeltag.value = lc->value;

    memset(&tagctx, 0, sizeof(tagctx));
    tagctx.tags = &labeltag;
    tagctx.local_time = CurrentTime;
    tagctx.tok = TOK_ACK;

    label_emit(cptr, &me, 0, &tagctx, CMD_ACK, "");
  } else if (count == 1) {
    struct LabelDeferred *entry = lc->head;
    struct MsgTag labeltag;
    struct MsgBuf *mb;

    labeltag.next = entry->tagctx.tags;
    labeltag.key = "label";
    labeltag.value = lc->value;
    entry->tagctx.tags = &labeltag;

    mb = msgq_raw_alloc(cptr, entry->len + 1);
    memcpy(mb->msg, entry->body, entry->len);
    mb->msg[entry->len] = '\0';
    mb->length = entry->len;

    send_buffer(cptr, entry->from, mb, entry->prio, &entry->tagctx, NULL);
    msgq_clean(mb);
  } else {
    struct MsgTag labeltag;
    struct MsgTagCtx opentagctx, closetagctx;
    struct LabelDeferred *entry;

    labeltag.next = NULL;
    labeltag.key = "label";
    labeltag.value = lc->value;

    memset(&opentagctx, 0, sizeof(opentagctx));
    opentagctx.tags = &labeltag;
    opentagctx.local_time = CurrentTime;
    opentagctx.tok = TOK_BATCH;

    label_emit(cptr, &me, 0, &opentagctx, CMD_BATCH,
              "+%s labeled-response", lc->ref);

    for (entry = lc->head; entry; entry = entry->next) {
      struct MsgTag batchtag;
      struct MsgBuf *mb;

      batchtag.next = entry->tagctx.tags;
      batchtag.key = "batch";
      batchtag.value = lc->ref;
      entry->tagctx.tags = &batchtag;

      mb = msgq_raw_alloc(cptr, entry->len + 1);
      memcpy(mb->msg, entry->body, entry->len);
      mb->msg[entry->len] = '\0';
      mb->length = entry->len;

      send_buffer(cptr, entry->from, mb, entry->prio, &entry->tagctx, NULL);
      msgq_clean(mb);
    }

    memset(&closetagctx, 0, sizeof(closetagctx));
    closetagctx.local_time = CurrentTime;
    closetagctx.tok = TOK_BATCH;

    label_emit(cptr, &me, 0, &closetagctx, CMD_BATCH, "-%s", lc->ref);
  }

  label_capture_active_client = saved_active_client;
  label_capture_active_node = saved_active_node;

  label_capture_free_node(lc);
}

void
label_capture_abort(struct Client *cptr, const char *ref)
{
  struct Client *saved_active_client;
  struct LabelCapture *saved_active_node;
  struct LabelCapture *lc;
  struct LabelDeferred *entry;

  label_capture_close_if_active(cptr, ref);

  lc = label_capture_unlink(cptr, ref);
  if (!lc)
    return; /* not outstanding for this client: defensive no-op */

  /* See label_capture_finish(): suspend whatever window is active for
   * this client right now, so the replay below can't be swept into a
   * different, currently-in-progress capture. */
  saved_active_client = label_capture_active_client;
  saved_active_node = label_capture_active_node;
  label_capture_active_client = NULL;
  label_capture_active_node = NULL;

  if (lc->streaming) {
    /* Nothing was buffered (every line already went out live, tagged
     * batch=ref, as it was produced) -- an already-sent line can't be
     * un-sent, so there's nothing to replay unlabeled here the way the
     * buffered path below does. The honest close for a stream that
     * can't honestly continue is the same as a clean finish: just close
     * the batch. (Nothing currently calls abort() on a streaming
     * capture -- LIST always finish()es it, even when superseded, see
     * m_list.c -- this branch is defensive parity only.) */
    struct MsgTagCtx closetagctx;

    memset(&closetagctx, 0, sizeof(closetagctx));
    closetagctx.local_time = CurrentTime;
    closetagctx.tok = TOK_BATCH;

    label_emit(cptr, &me, 0, &closetagctx, CMD_BATCH, "-%s", lc->ref);

    label_capture_active_client = saved_active_client;
    label_capture_active_node = saved_active_node;

    label_capture_free_node(lc);
    return;
  }

  /* Replay exactly what was captured, with no label/batch tag added --
   * i.e. as if capture had never intercepted it. This is the outcome the
   * spec itself sanctions for responses a server cannot honestly finish
   * labeling (e.g. its own WHOIS-through-a-netsplit example): "servers
   * might not produce a labeled response... clients should handle these
   * cases as they would normally for a server without support for
   * labeled responses." */
  for (entry = lc->head; entry; entry = entry->next) {
    struct MsgBuf *mb;

    mb = msgq_raw_alloc(cptr, entry->len + 1);
    memcpy(mb->msg, entry->body, entry->len);
    mb->msg[entry->len] = '\0';
    mb->length = entry->len;

    send_buffer(cptr, entry->from, mb, entry->prio, &entry->tagctx, NULL);
    msgq_clean(mb);
  }

  label_capture_active_client = saved_active_client;
  label_capture_active_node = saved_active_node;

  label_capture_free_node(lc);
}

void
label_capture_client_gone(struct Client *cptr)
{
  struct LabelCapture *lc;

  if (label_capture_active_client == cptr)
    label_capture_close_window();

  while ((lc = cli_labelcap(cptr)) != NULL) {
    cli_labelcap(cptr) = lc->next;
    label_capture_free_node(lc);
  }
}

int
label_capture_intercept(struct Client *to, struct Client *from,
                        struct MsgBuf *buf, int prio,
                        const struct MsgTagCtx *tctx)
{
  if (to != label_capture_active_client)
    return 0;
  label_capture_append(to, from, buf, prio, tctx);
  return 1;
}

struct LabelCapture *
label_capture_active_for(struct Client *owner)
{
  return (owner == label_capture_active_client) ? label_capture_active_node : NULL;
}
