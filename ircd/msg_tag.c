/*
 * IRC - Internet Relay Chat, ircd/msg_tag.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */
/** @file
 * @brief IRCv3 message tag parsing and formatting
 */
#include "config.h"

#include "msg_tag.h"
#include "capab.h"
#include "client.h"
#include "ircd.h"
#include "ircd_defs.h"
#include "ircd_features.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"

#include <string.h>
#include <time.h>

/** Maximum tags per incoming line (generous; typical lines have few). */
#define MAX_PARSE_TAGS 64

/** Maximum CLIENTTAGDENY list entries. */
#define CLIENTTAGDENY_MAX 64

static struct MsgTag tag_storage[MAX_PARSE_TAGS];
static int tag_count;

static int clienttag_deny_all;
static char clienttag_names[CLIENTTAGDENY_MAX][256];
static int clienttag_name_count;

/** Unescape one IRCv3 tag value in place; returns new length.
 *  Mapping: \\s→SPACE, \\:→;, \\\\→\\, \\r→CR, \\n→LF.
 *  Invalid escapes drop the backslash (\\b→b); a trailing lone \\ is dropped.
 */
static unsigned int
msg_tag_unescape(char *value)
{
  char *r = value;
  char *w = value;

  while (*r) {
    if (*r == '\\') {
      if (!r[1]) {
        /* Trailing lone backslash: drop it. */
        break;
      }
      switch (r[1]) {
      case 's':  *w++ = ' ';  r += 2; break;
      case ':':  *w++ = ';';  r += 2; break;
      case '\\': *w++ = '\\'; r += 2; break;
      case 'r':  *w++ = '\r'; r += 2; break;
      case 'n':  *w++ = '\n'; r += 2; break;
      default:
        /* Invalid escape: drop the backslash, keep the next octet. */
        r++;
        *w++ = *r++;
        break;
      }
    } else {
      *w++ = *r++;
    }
  }
  *w = '\0';
  return (unsigned int)(w - value);
}

/** Escape a tag value into \a out; returns bytes written (excluding NUL).
 *  IRCv3: ;→\\:, SPACE→\\s, \\→\\\\, CR→\\r, LF→\\n.
 */
static unsigned int
msg_tag_escape(const char *value, char *out, size_t outlen)
{
  size_t used = 0;

  if (!value || !outlen)
    return 0;

  while (*value && used + 2 < outlen) {
    switch (*value) {
    case ' ':
      out[used++] = '\\';
      out[used++] = 's';
      break;
    case ';':
      out[used++] = '\\';
      out[used++] = ':';
      break;
    case '\\':
      out[used++] = '\\';
      out[used++] = '\\';
      break;
    case '\r':
      out[used++] = '\\';
      out[used++] = 'r';
      break;
    case '\n':
      out[used++] = '\\';
      out[used++] = 'n';
      break;
    default:
      out[used++] = *value;
      break;
    }
    value++;
  }
  out[used] = '\0';
  return (unsigned int)used;
}

/** Format \a t as ISO-8601 UTC with milliseconds into \a buf. */
static void
msg_tag_format_time(char *buf, size_t buflen, time_t t)
{
  struct tm tm;

  gmtime_r(&t, &tm);
  ircd_snprintf(0, buf, buflen, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, 0);
}

struct MsgTag *
msg_tag_parse(char *start, char *end)
{
  struct MsgTag *head = NULL;
  char *p = start;

  tag_count = 0;

  if (!start || start >= end)
    return NULL;

  *end = '\0';

  while (p < end && tag_count < MAX_PARSE_TAGS) {
    struct MsgTag *tag;
    char *semi = p;
    char *key;
    char *val;

    while (semi < end && *semi != ';')
      semi++;

    if (semi < end)
      *semi = '\0';

    key = p;
    val = strchr(key, '=');
    if (val) {
      *val++ = '\0';
      msg_tag_unescape(val);
    }

    if (*key) {
      tag = &tag_storage[tag_count++];
      tag->key = key;
      tag->value = val;
      tag->next = head;
      head = tag;
    }

    if (semi >= end)
      break;
    p = semi + 1;
  }

  return head;
}

struct MsgTag *
msg_tag_find(struct MsgTag *tags, const char *key)
{
  for (; tags; tags = tags->next) {
    if (!ircd_strcmp(tags->key, key))
      return tags;
  }
  return NULL;
}

/** Strip optional leading '+' from a client-only tag key for deny lookup. */
static const char *
clienttag_lookup_name(const char *key)
{
  if (key && key[0] == '+')
    return key + 1;
  return key;
}

void
msg_tag_clienttagdeny_rebuild(void)
{
  const char *cfg = feature_str(FEAT_CLIENTTAGDENY);
  char buf[512];
  char *p;
  char *entry;

  clienttag_deny_all = 0;
  clienttag_name_count = 0;

  if (!cfg || !*cfg)
    return;

  ircd_strncpy(buf, cfg, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';

  for (p = buf; (entry = strtok(p, ",")) != NULL; p = NULL) {
    while (*entry == ' ')
      entry++;

    if (!*entry)
      continue;

    if (clienttag_name_count >= CLIENTTAGDENY_MAX)
      break;

    if (!ircd_strcmp(entry, "*")) {
      clienttag_deny_all = 1;
      continue;
    }

    if (*entry == '-') {
      if (!clienttag_deny_all)
        continue;
      ircd_strncpy(clienttag_names[clienttag_name_count++],
                   clienttag_lookup_name(entry + 1),
                   sizeof(clienttag_names[0]) - 1);
      continue;
    }

    if (clienttag_deny_all)
      continue;

    ircd_strncpy(clienttag_names[clienttag_name_count++],
                 clienttag_lookup_name(entry),
                 sizeof(clienttag_names[0]) - 1);
  }
}

int
msg_tag_key_server(const char *key)
{
  if (!key)
    return 0;
  return !ircd_strcmp(key, "time") || !ircd_strcmp(key, "account")
    || !ircd_strcmp(key, "batch");
}

int
msg_tag_key_client_only(const char *key)
{
  return key && key[0] == '+';
}

int
msg_tag_client_allowed(const char *key)
{
  const char *name;
  int i;

  if (!msg_tag_key_client_only(key))
    return 0;

  name = clienttag_lookup_name(key);
  if (!name || !*name)
    return 0;

  if (clienttag_deny_all) {
    for (i = 0; i < clienttag_name_count; ++i) {
      if (!ircd_strcmp(name, clienttag_names[i]))
        return 1;
    }
    return 0;
  }

  for (i = 0; i < clienttag_name_count; ++i) {
    if (!ircd_strcmp(name, clienttag_names[i]))
      return 0;
  }
  return 1;
}

int
msg_tag_have_client_relay(struct MsgTag *tags)
{
  for (; tags; tags = tags->next) {
    if (msg_tag_key_client_only(tags->key)
        && msg_tag_client_allowed(tags->key))
      return 1;
  }
  return 0;
}

struct MsgTag *
msg_tag_filter_client(struct MsgTag *tags)
{
  struct MsgTag *head = NULL;
  struct MsgTag **tail = &head;

  for (; tags; tags = tags->next) {
    if (msg_tag_key_client_only(tags->key)
        && msg_tag_client_allowed(tags->key)) {
      *tail = tags;
      tail = &tags->next;
    }
  }
  *tail = NULL;
  return head;
}

static int
msg_tag_wants_time(struct Client *to)
{
  if (!to || IsServer(to))
    return 0;
  return CapHas(cli_active(to), CAP_SERVER_TIME)
    || CapHas(cli_active(to), CAP_MESSAGE_TAGS);
}

static int
msg_tag_wants_account(struct Client *to)
{
  if (!to || IsServer(to))
    return 0;
  return CapHas(cli_active(to), CAP_ACCOUNT_TAG)
    || CapHas(cli_active(to), CAP_MESSAGE_TAGS);
}

int
msg_tag_key_federated(const char *key)
{
  if (!key)
    return 0;
  return !ircd_strcmp(key, "time") || !ircd_strcmp(key, "batch");
}

int
msg_tag_s2s_needs_time(const char *tok)
{
  if (!tok)
    return 0;
  /* Omit @time= on link/state and net-admin protocol.  Everything else that
   * hits S2S is treated as (eventually) client-visible. */
  if (!ircd_strcmp(tok, TOK_BURST)
      || !ircd_strcmp(tok, TOK_END_OF_BURST)
      || !ircd_strcmp(tok, TOK_END_OF_BURST_ACK)
      || !ircd_strcmp(tok, TOK_SERVER)
      || !ircd_strcmp(tok, TOK_PING)
      || !ircd_strcmp(tok, TOK_PONG)
      || !ircd_strcmp(tok, TOK_SETTIME)
      || !ircd_strcmp(tok, TOK_ASLL)
      || !ircd_strcmp(tok, TOK_RPING)
      || !ircd_strcmp(tok, TOK_RPONG)
      || !ircd_strcmp(tok, TOK_UPING)
      || !ircd_strcmp(tok, TOK_PASS)
      || !ircd_strcmp(tok, TOK_ERROR)
      || !ircd_strcmp(tok, TOK_PROTO)
      || !ircd_strcmp(tok, TOK_SQUIT)
      || !ircd_strcmp(tok, TOK_CONFIG)
      || !ircd_strcmp(tok, TOK_JUPE)
      || !ircd_strcmp(tok, TOK_GLINE)
      || !ircd_strcmp(tok, TOK_SLINE)
      || !ircd_strcmp(tok, TOK_DESTRUCT))
    return 0;
  return 1;
}

/** Append one tag to a wire prefix; \a *wrote tracks whether '@' was emitted. */
static char *
msg_tag_append(char *pos, char *end, int *wrote, const char *key,
               const char *value)
{
  if (!key || pos + 1 >= end)
    return NULL;

  if (*wrote)
    *pos++ = ';';
  else {
    *pos++ = '@';
    *wrote = 1;
  }

  /* ircd_snprintf() returns the untruncated (would-be) length, so pos can
   * land past end when the key does not fit.  Bail before the next write:
   * (end - pos) would go negative and wrap to a huge size_t. */
  pos += ircd_snprintf(0, pos, end - pos, "%s", key);
  if (pos >= end)
    return NULL;
  if (value) {
    *pos++ = '=';
    /* Escape straight into the output buffer (bounded by end): no fixed
     * scratch buffer, so long tag values are not truncated. */
    pos += msg_tag_escape(value, pos, end - pos);
  }

  return (pos < end) ? pos : NULL;
}

unsigned int
msg_tag_format_s2s(char *buf, size_t buflen, struct MsgTag *tags,
                   time_t local_time, int invent_time)
{
  char *pos = buf;
  char *end = buf + buflen;
  int wrote = 0;
  struct MsgTag *tag;
  const struct MsgTag *time_tag = msg_tag_find(tags, "time");

  if (buflen < 3)
    return 0;

  /* Only stamp/forward time on client-event commands, and only when
   * NETWORK_TIME is enabled. */
  if (invent_time && feature_bool(FEAT_NETWORK_TIME)) {
    char tbuf[32];

    if (time_tag && time_tag->value)
      ircd_strncpy(tbuf, time_tag->value, sizeof(tbuf) - 1);
    else
      msg_tag_format_time(tbuf, sizeof(tbuf), local_time);
    tbuf[sizeof(tbuf) - 1] = '\0';

    pos = msg_tag_append(pos, end, &wrote, "time", tbuf);
    if (!pos)
      return 0;
  }

  for (tag = tags; tag; tag = tag->next) {
    if (!ircd_strcmp(tag->key, "time") || !ircd_strcmp(tag->key, "account"))
      continue;
    if (msg_tag_key_client_only(tag->key))
      continue;
    if (!msg_tag_key_federated(tag->key))
      continue;
    pos = msg_tag_append(pos, end, &wrote, tag->key, tag->value);
    if (!pos)
      return 0;
  }

  if (!wrote)
    return 0;

  if (pos + 1 >= end)
    return 0;
  *pos++ = ' ';
  *pos = '\0';
  return (unsigned int)(pos - buf);
}

unsigned int
msg_tag_profile(struct Client *to)
{
  unsigned int profile = TAGP_NONE;

  if (!to || IsServer(to))
    return TAGP_NONE;

  if (msg_tag_wants_time(to))
    profile |= TAGP_TIME;
  if (msg_tag_wants_account(to))
    profile |= TAGP_ACCOUNT;

  return profile;
}

unsigned int
msg_tag_format(char *buf, size_t buflen, struct Client *to,
               struct Client *from, struct MsgTag *tags, time_t local_time)
{
  char *pos = buf;
  char *end = buf + buflen;
  int wrote = 0;
  struct MsgTag *tag;
  const struct MsgTag *time_tag;

  if (!to || IsServer(to) || buflen < 3)
    return 0;

  time_tag = msg_tag_find(tags, "time");

  /* server-time (before client tags, per IRCv3 ordering).
   * With NETWORK_TIME, prefer an upstream stamp; otherwise always use
   * the local queue/delivery time. */
  if (msg_tag_wants_time(to)) {
    char tbuf[32];

    if (feature_bool(FEAT_NETWORK_TIME) && time_tag && time_tag->value)
      ircd_strncpy(tbuf, time_tag->value, sizeof(tbuf) - 1);
    else
      msg_tag_format_time(tbuf, sizeof(tbuf), local_time);
    tbuf[sizeof(tbuf) - 1] = '\0';

    pos = msg_tag_append(pos, end, &wrote, "time", tbuf);
    if (!pos)
      return 0;
  }

  /* account-tag (local edge only) */
  if (msg_tag_wants_account(to)
      && from && IsUser(from) && cli_user(from) && IsAccount(from)) {
    char esc[ACCOUNTLEN * 2 + 16];

    msg_tag_escape(cli_user(from)->account, esc, sizeof(esc));
    pos = msg_tag_append(pos, end, &wrote, "account", esc);
    if (!pos)
      return 0;
  }

  /* client-only tags */
  if (CapHas(cli_active(to), CAP_MESSAGE_TAGS)) {
    for (tag = tags; tag; tag = tag->next) {
      if (!msg_tag_key_client_only(tag->key))
        continue;
      if (!msg_tag_client_allowed(tag->key))
        continue;
      pos = msg_tag_append(pos, end, &wrote, tag->key, tag->value);
      if (!pos)
        return 0;
    }
  }

  if (!wrote)
    return 0;

  if (pos + 1 >= end)
    return 0;
  *pos++ = ' ';
  *pos = '\0';
  return (unsigned int)(pos - buf);
}

unsigned int
msg_tag_assemble(char *out, size_t outlen,
                 const char *prefix, unsigned int prefix_len,
                 const char *body, unsigned int body_len)
{
  if (prefix_len + body_len >= outlen)
    return 0;
  if (prefix_len)
    memcpy(out, prefix, prefix_len);
  memcpy(out + prefix_len, body, body_len);
  out[prefix_len + body_len] = '\0';
  return prefix_len + body_len;
}
