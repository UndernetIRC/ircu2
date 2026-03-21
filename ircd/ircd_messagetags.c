/*
 * IRC - Internet Relay Chat, ircd/ircd_messagetags.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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
 *
 * $Id$
 */

/** @file
 * @brief Shared helpers for IRCv3 message-tags handling.
 * @version $Id$
 */

#include "config.h"

#include "ircd_messagetags.h"

#include "client.h"
#include "ircd_features.h"
#include "ircd_string.h"

#include <string.h>

#define IRCV3_TAGS_CLIENT_DATA_MAX 4094
#define IRCV3_TAGS_COMBINED_MAX    8190

static int has_later_same_key(const char* current_start, const char* current_end)
{
  const char* current_key_end;
  size_t current_key_len;
  const char* p = current_end;
  const char* tag_start;
  const char* tag_key_end;
  size_t tag_key_len;

  current_key_end = memchr(current_start, '=', (size_t)(current_end - current_start));
  if (!current_key_end)
    current_key_end = current_end;
  current_key_len = (size_t)(current_key_end - current_start);

  if (*p == ';')
    ++p;

  while (*p) {
    tag_start = p;

    while (*p && *p != ';')
      ++p;

    tag_key_end = memchr(tag_start, '=', (size_t)(p - tag_start));
    if (!tag_key_end)
      tag_key_end = p;
    tag_key_len = (size_t)(tag_key_end - tag_start);

    if (current_key_len == tag_key_len &&
        0 == memcmp(current_start, tag_start, current_key_len))
      return 1;

    if (*p == ';')
      ++p;
  }

  return 0;
}

static int client_tag_allowed_by_isupport(const char* key_start, const char* key_end)
{
  const char* deny = feature_str(FEAT_CLIENTTAGDENY);
  const char* p;
  int allowed = 1;
  const char* tok_start;
  const char* tok_end;
  int negate;

  if (EmptyString(deny))
    return 1;

  p = deny;
  while (*p) {
    tok_start = p;
    negate = 0;

    while (*p && *p != ',')
      ++p;
    tok_end = p;

    if (*tok_start == '-') {
      negate = 1;
      ++tok_start;
    }

    if (tok_start < tok_end) {
      if (tok_start + 1 == tok_end && *tok_start == '*') {
        if (!negate)
          allowed = 0;
      }
      else if ((size_t)(tok_end - tok_start) == (size_t)(key_end - key_start) &&
               0 == memcmp(tok_start, key_start, (size_t)(key_end - key_start))) {
        if (negate)
          allowed = 1;
        else
          allowed = 0;
      }
    }

    if (*p == ',')
      ++p;
  }

  return allowed;
}

static int ircd_validate_message_tags(char* tags)
{
  char *p;
  int have_key_char;

  if (!tags || *tags != '@')
    return 0;

  if (strlen(tags) > IRCV3_TAGS_COMBINED_MAX)
    return -1;

  p = tags + 1;
  if (*p == '\0')
    return -1;

  while (*p) {
    have_key_char = 0;

    while (*p && *p != '=' && *p != ';') {
      if (*p == ' ' || *p == '\r' || *p == '\n')
        return -1;
      have_key_char = 1;
      ++p;
    }

    if (!have_key_char)
      return -1;

    if (*p == '=') {
      ++p;

      while (*p && *p != ';') {
        if (*p == ' ' || *p == '\r' || *p == '\n')
          return -1;
        ++p;
      }

      if (*p == ';') {
        if (*(p + 1) == '\0')
          return -1;
        ++p;
      }
    }
    else if (*p == ';') {
      if (*(p + 1) == '\0')
        return -1;
      ++p;
    }
    else
      break;
  }

  return 0;
}

static int ircd_client_message_tags_too_long(const char* tags)
{
  if (!tags || *tags != '@')
    return 0;

  return (strlen(tags) - 1) > IRCV3_TAGS_CLIENT_DATA_MAX;
}

static char* ircd_filter_relayable_client_tags(char* tags)
{
  char* src;
  char* out;
  int wrote = 0;
  const char* tag_start;
  const char* tag_end;
  const char* key_end;
  int keep;
  size_t len;

  if (!tags || *tags != '@')
    return 0;

  src = tags + 1;
  out = tags + 1;

  while (*src) {
    tag_start = src;

    while (*src && *src != ';')
      ++src;
    tag_end = src;

    key_end = memchr(tag_start, '=', (size_t)(tag_end - tag_start));
    if (!key_end)
      key_end = tag_end;

    keep = (*tag_start == '+') &&
           client_tag_allowed_by_isupport(tag_start + 1, key_end) &&
           !has_later_same_key(tag_start, tag_end);

    if (keep) {
      len = (size_t)(tag_end - tag_start);

      if (wrote)
        *out++ = ';';

      memmove(out, tag_start, len);
      out += len;
      wrote = 1;
    }

    if (*src == ';')
      ++src;
  }

  if (!wrote)
    return 0;

  *out = '\0';
  return tags;
}

int ircd_parse_message_tags(struct Client* sptr, int parc, char* parv[],
                            char** tags, char** target, int* target_index,
                            int require_tags, int filter_local_sender)
{
  int idx = 1;

  *tags = 0;
  if (target)
    *target = 0;

  if (parc > 1 && parv[1][0] == '@') {
    idx = 2;
    *tags = parv[1];
  }

  if (target_index)
    *target_index = idx;

  if (filter_local_sender && *tags &&
      (!feature_bool(FEAT_CAP_MESSAGETAGS) || !CapActive(sptr, CAP_MESSAGETAGS)))
    *tags = 0;

  if (require_tags && EmptyString(*tags))
    return 0;

  if (parc < idx + 1 || EmptyString(parv[idx]))
    return 0;

  if (target)
    *target = parv[idx];

  return 1;
}

int ircd_sanitize_message_tags(char** tags,
                               int enforce_client_data_limit,
                               int filter_relayable_client_tags,
                               int drop_on_invalid,
                               int* too_long)
{
  if (too_long)
    *too_long = 0;

  if (!tags || !*tags)
    return 1;

  if (enforce_client_data_limit && ircd_client_message_tags_too_long(*tags)) {
    if (too_long)
      *too_long = 1;
    return 0;
  }

  if (ircd_validate_message_tags(*tags) != 0) {
    if (drop_on_invalid)
      return 0;
    *tags = 0;
    return 1;
  }

  if (filter_relayable_client_tags)
    *tags = ircd_filter_relayable_client_tags(*tags);

  if (drop_on_invalid && !*tags)
    return 0;

  return 1;
}