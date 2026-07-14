/*
 * IRC - Internet Relay Chat, ircd/ircd_sha1.c
 * Copyright (C) 2026 MrIron <mriron@undernet.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * SHA-1 implementation by Steve Reid / OpenBSD, public domain.
 */
/** @file
 * @brief SHA-1 implementation for ircu.
 */
#include "ircd_sha1.h"
#include <stdint.h>
#include <string.h>

typedef union {
  unsigned char c[64];
  uint32_t l[16];
} CHAR64LONG16;

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define blk0(i) (block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00) \
                  | (rol(block->l[i], 8) & 0x00FF00FF))
#else
# define blk0(i) block->l[i]
#endif

#define blk(i) (block->l[i & 15] = rol(block->l[(i + 13) & 15] ^ block->l[(i + 8) & 15] \
                  ^ block->l[(i + 2) & 15] ^ block->l[i & 15], 1))

#define R0(v,w,x,y,z,i) z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5); w = rol(w, 30);
#define R1(v,w,x,y,z,i) z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5); w = rol(w, 30);
#define R2(v,w,x,y,z,i) z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5); w = rol(w, 30);
#define R3(v,w,x,y,z,i) z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5); w = rol(w, 30);
#define R4(v,w,x,y,z,i) z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5); w = rol(w, 30);

static void SHA1Transform(unsigned int state[5], const unsigned char buffer[64])
{
  uint32_t a, b, c, d, e;
  CHAR64LONG16 workspace;
  CHAR64LONG16 *block = &workspace;

  memcpy(block, buffer, 64);

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];

  R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
  R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
  R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
  R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
  R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
  R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
  R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
  R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
  R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
  R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
  R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
  R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
  R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
  R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
  R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
  R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
  R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
  R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
  R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
  R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
}

void SHA1Init(SHA1_CTX *context)
{
  context->state[0] = 0x67452301;
  context->state[1] = 0xEFCDAB89;
  context->state[2] = 0x98BADCFE;
  context->state[3] = 0x10325476;
  context->state[4] = 0xC3D2E1F0;
  context->count[0] = context->count[1] = 0;
}

void SHA1Update(SHA1_CTX *context, const unsigned char *data, size_t len)
{
  size_t i;
  unsigned int j;

  j = context->count[0];
  if ((context->count[0] += (unsigned int)(len << 3)) < j)
    context->count[1] += (unsigned int)((len >> 29) + 1);
  j = (j >> 3) & 63;
  if ((j + len) > 63) {
    memcpy(&context->buffer[j], data, i = 64 - j);
    SHA1Transform(context->state, context->buffer);
    for (; i + 63 < len; i += 64)
      SHA1Transform(context->state, &data[i]);
    j = 0;
  } else {
    i = 0;
  }
  memcpy(&context->buffer[j], &data[i], len - i);
}

void SHA1Final(unsigned char digest[SHA1_DIGEST_LENGTH], SHA1_CTX *context)
{
  unsigned char finalcount[8];
  int i;

  for (i = 0; i < 8; ++i)
    finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)]
                                   >> ((3 - (i & 3)) * 8)) & 255);

  SHA1Update(context, (const unsigned char *)"\200", 1);
  while ((context->count[0] & 504) != 448)
    SHA1Update(context, (const unsigned char *)"\0", 1);
  SHA1Update(context, finalcount, 8);

  for (i = 0; i < SHA1_DIGEST_LENGTH; ++i)
    digest[i] = (unsigned char)((context->state[i >> 2]
                                 >> ((3 - (i & 3)) * 8)) & 255);
}

static size_t base64_encode(const unsigned char *in, size_t inlen,
                            char *out, size_t outlen)
{
  static const char table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t i = 0;
  size_t o = 0;

  while (i + 2 < inlen) {
    if (o + 4 >= outlen)
      return 0;
    out[o++] = table[(in[i] >> 2) & 0x3f];
    out[o++] = table[((in[i] & 0x3) << 4) | ((in[i + 1] >> 4) & 0xf)];
    out[o++] = table[((in[i + 1] & 0xf) << 2) | ((in[i + 2] >> 6) & 0x3)];
    out[o++] = table[in[i + 2] & 0x3f];
    i += 3;
  }

  if (i < inlen) {
    if (o + 4 >= outlen)
      return 0;
    out[o++] = table[(in[i] >> 2) & 0x3f];
    if (i + 1 < inlen) {
      out[o++] = table[((in[i] & 0x3) << 4) | ((in[i + 1] >> 4) & 0xf)];
      out[o++] = table[((in[i + 1] & 0xf) << 2)];
      out[o++] = '=';
    } else {
      out[o++] = table[((in[i] & 0x3) << 4)];
      out[o++] = '=';
      out[o++] = '=';
    }
  }

  if (o >= outlen)
    return 0;
  out[o] = '\0';
  return o;
}

int ircd_sha1_base64(const void *data, size_t len, char *out, size_t outlen)
{
  SHA1_CTX ctx;
  unsigned char digest[SHA1_DIGEST_LENGTH];

  if (!data || !out || len == 0 || outlen == 0)
    return -1;

  SHA1Init(&ctx);
  SHA1Update(&ctx, data, len);
  SHA1Final(digest, &ctx);

  if (base64_encode(digest, sizeof(digest), out, outlen) == 0)
    return -1;

  return 0;
}
