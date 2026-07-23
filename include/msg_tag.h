#ifndef INCLUDED_msg_tag_h
#define INCLUDED_msg_tag_h
/*
 * IRC - Internet Relay Chat, include/msg_tag.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */
/** @file
 * @brief IRCv3 message tag support
 */
#ifndef INCLUDED_client_h
#include "client.h"
#endif
#ifndef INCLUDED_time_h
#include <time.h>
#endif

struct Client;

/** A single message tag (key-value pair). */
struct MsgTag {
  struct MsgTag *next;  /**< Next tag in the list. */
  char *key;            /**< Tag key (points into parse buffer). */
  char *value;          /**< Tag value, or NULL if tag has no '=' value. */
};

/** Bitmask of outbound tag profiles for recipient bucketing. */
enum MsgTagProfile {
  TAGP_NONE    = 0,
  TAGP_TIME    = 0x01,
  TAGP_ACCOUNT = 0x02,
};

/** Parse IRCv3 tags from a wire section (without leading '@').
 * Mutates the buffer in place; returned list pointers alias \a start..\a end.
 * @param[in,out] start First character after '@'.
 * @param[in] end Character after the last tag byte (the separating space).
 * @return Head of tag list, or NULL if no tags.
 */
struct MsgTag *msg_tag_parse(char *start, char *end);

/** Find a tag by key in a list. */
struct MsgTag *msg_tag_find(struct MsgTag *tags, const char *key);

/** Rebuild CLIENTTAGDENY state from configured feature value. */
void msg_tag_clienttagdeny_rebuild(void);

/** Return non-zero if \a key is a server-managed tag (not relayed from clients). */
int msg_tag_key_server(const char *key);

/** Return non-zero if \a key is a client-only tag (\a key begins with '+'). */
int msg_tag_key_client_only(const char *key);

/** Return non-zero if client-only tag \a key may be relayed (CLIENTTAGDENY). */
int msg_tag_client_allowed(const char *key);

/** Return non-zero if \a tags contains relayable client-only tags. */
int msg_tag_have_client_relay(struct MsgTag *tags);

/** Keep only allowed client-only tags (strip all others). */
struct MsgTag *msg_tag_filter_client(struct MsgTag *tags);

/** Classify which server tags a recipient should receive. */
unsigned int msg_tag_profile(struct Client *to);

/** Return non-zero if \a key is federated on server-server links. */
int msg_tag_key_federated(const char *key);

/** Format federated tags for a server-server wire line.
 * Always includes \a time (from \a tags or \a local_time).  Also forwards
 * other federated keys present in \a tags (e.g. \a batch in the future).
 * Never includes \a account or client-only tags.
 * @return Length of prefix beginning with '@' and ending with a space, or 0.
 */
unsigned int msg_tag_format_s2s(char *buf, size_t buflen, struct MsgTag *tags,
                                time_t local_time);

/** Format tags for a client into \a buf.
 * @param[out] buf Output buffer.
 * @param[in] buflen Size of \a buf.
 * @param[in] to Recipient (for capability checks).
 * @param[in] from Message source (for account-tag; may be NULL).
 * @param[in] tags Upstream tag list from parse (may be NULL).
 * @param[in] local_time Time to use when no upstream \a time tag is present.
 * @return Length of formatted prefix excluding trailing space, or 0 if no tags.
 *         On success \a buf begins with '@' and ends with a separating space.
 */
unsigned int msg_tag_format(char *buf, size_t buflen, struct Client *to,
                            struct Client *from, struct MsgTag *tags,
                            time_t local_time);

/** Append \a prefix then \a body into \a out (NUL-terminated, no extra CRLF).
 * @return Total length written, or 0 on overflow.
 */
unsigned int msg_tag_assemble(char *out, size_t outlen,
                              const char *prefix, unsigned int prefix_len,
                              const char *body, unsigned int body_len);

#endif /* INCLUDED_msg_tag_h */
