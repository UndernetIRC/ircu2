/*
 * IRC - Internet Relay Chat, include/ircd_sha1.h
 * Copyright (C) 2026 MrIron <mriron@undernet.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
/** @file
 * @brief SHA-1 implementation for ircu.
 *
 * SHA-1 core by Steve Reid / OpenBSD, public domain.
 */
#ifndef INCLUDED_ircd_sha1_h
#define INCLUDED_ircd_sha1_h

#include <stddef.h>

#define SHA1_DIGEST_LENGTH 20

/** SHA-1 context structure. */
struct SHA1Context {
  unsigned int state[5];        /**< Current digest state. */
  unsigned int count[2];        /**< Number of bits hashed so far. */
  unsigned char buffer[64];     /**< Residual input buffer. */
};

typedef struct SHA1Context SHA1_CTX;

void SHA1Init(SHA1_CTX *context);
void SHA1Update(SHA1_CTX *context, const unsigned char *data, size_t len);
void SHA1Final(unsigned char digest[SHA1_DIGEST_LENGTH], SHA1_CTX *context);

/** Compute RFC 4648 base64(SHA1(\a data)) into \a out.
 * \returns 0 on success, -1 on failure.
 */
int ircd_sha1_base64(const void *data, size_t len, char *out, size_t outlen);

#endif /* INCLUDED_ircd_sha1_h */
