/*
 * IRC - Internet Relay Chat, ircd/random.c
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
#include "config.h"

#include "random.h"
#include "client.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "send.h"

#include <string.h>
#include <sys/time.h>


char localkey[9] = "12345678";

/* This devious-looking construct rolls a character to the left by r bits */
#define char_roll(c, r)	(((c) << (r)) | ((c) >> (8 - (r))))

/* this routine is intended to be called by the feature subsystem; it takes
 * a key as found in the .conf and mashes it up for the seed for the random
 * number generator.
 */
int
random_seed_set(struct Client* from, const char* const* fields, int count)
{
  const char *p = 0;
  int len, i, roll = 0;

  if (count < 1) {
    if (from) /* send an error */
      return need_more_params(from, "SET");
    else {
      log_write(LS_CONFIG, L_ERROR, 0, "Not enough fields in F line");
      return 0;
    }
  }

  len = strlen(fields[0]);

  /* logic is: go through loop at least 8 times, but use all bits of seed */
  for (i = 0; i < (len < 8 ? 8 : len); i++, p++) {
    if (!(i % len)) { /* if we've exceeded the string length, reset */
      p = fields[0];
      roll++; /* so latter part of string looks different from former */
    }

    /* set the appropriate location of localkey according to the following
     * rules: first, roll current value by an amount depending on how many
     * times we've touched this character.  Then take seed value and roll
     * it by an amount depending upon how many times we've touched that
     * character.  Finally, xor the values together.
     */
    localkey[i % 8] = char_roll(localkey[i % 8], (i / 8) % 8) ^
      char_roll(*p, roll % 8);
  }

  return 1;
}

/* this is like memcpy except it xors the areas in memory. */
static void
memxor(void *dest, void *src, int n)
{
  unsigned char *d = (unsigned char *)dest;
  unsigned char *s = (unsigned char *)src;

  while (n--)
    d[n] ^= s[n];
}

/*
 * MD5 transform algorithm, taken from code written by Colin Plumb,
 * and put into the public domain
 *
 * Kev: Taken from Ted T'so's /dev/random random.c code and modified to
 * be slightly simpler.  That code is released under a BSD-style copyright
 * OR under the terms of the GNU Public License, which should be included
 * at the top of this source file.
 *
 * record: Cleaned up to work with ircd.  RANDOM_TOKEN is defined in
 * setup.h by the make script; if people start to "guess" your cookies,
 * consider recompiling your server with a different random token.
 *
 * Kev: Now the seed comes from the feature subsystem and is fed into a
 * mash routine (random_set_seed) that depends on previous values of the
 * localkey array; also, part of the output of the RNG is fed back into
 * the localkey array.  Finally, the time values are xor'd with the local
 * key to enhance non-determinability of the data fed into the MD5 core.
 */

/* The four core functions - F1 is optimized somewhat */

#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
        ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 *
 * original comment left in; this used to be called MD5Transform and took
 * two arguments; I've internalized those arguments, creating the character
 * array "localkey," which should contain 8 bytes of data.  The function also
 * originally returned nothing; now it returns an unsigned long that is the
 * random number.  It appears to be reallyrandom, so... -Kev
 *
 * I don't really know what this does.  I tried to figure it out and got
 * a headache.  If you know what's good for you, you'll leave this stuff
 * for the smart people and do something else.          -record
 */
unsigned int ircrandom(void)
{
  unsigned int a, b, c, d;
  unsigned char in[16];
  struct timeval tv;

  gettimeofday(&tv, 0);

  memcpy((void *)in, (void *)localkey, 8);
  memcpy((void *)(in + 8), (void *)localkey, 8);
  memxor((void *)(in + 8), (void *)&tv.tv_sec, 4);
  memxor((void *)(in + 12), (void *)&tv.tv_usec, 4);

  a = 0x67452301;
  b = 0xefcdab89;
  c = 0x98badcfe;
  d = 0x10325476;

  MD5STEP(F1, a, b, c, d, (int)in[0] + 0xd76aa478, 7);
  MD5STEP(F1, d, a, b, c, (int)in[1] + 0xe8c7b756, 12);
  MD5STEP(F1, c, d, a, b, (int)in[2] + 0x242070db, 17);
  MD5STEP(F1, b, c, d, a, (int)in[3] + 0xc1bdceee, 22);
  MD5STEP(F1, a, b, c, d, (int)in[4] + 0xf57c0faf, 7);
  MD5STEP(F1, d, a, b, c, (int)in[5] + 0x4787c62a, 12);
  MD5STEP(F1, c, d, a, b, (int)in[6] + 0xa8304613, 17);
  MD5STEP(F1, b, c, d, a, (int)in[7] + 0xfd469501, 22);
  MD5STEP(F1, a, b, c, d, (int)in[8] + 0x698098d8, 7);
  MD5STEP(F1, d, a, b, c, (int)in[9] + 0x8b44f7af, 12);
  MD5STEP(F1, c, d, a, b, (int)in[10] + 0xffff5bb1, 17);
  MD5STEP(F1, b, c, d, a, (int)in[11] + 0x895cd7be, 22);
  MD5STEP(F1, a, b, c, d, (int)in[12] + 0x6b901122, 7);
  MD5STEP(F1, d, a, b, c, (int)in[13] + 0xfd987193, 12);
  MD5STEP(F1, c, d, a, b, (int)in[14] + 0xa679438e, 17);
  MD5STEP(F1, b, c, d, a, (int)in[15] + 0x49b40821, 22);

  MD5STEP(F2, a, b, c, d, (int)in[1] + 0xf61e2562, 5);
  MD5STEP(F2, d, a, b, c, (int)in[6] + 0xc040b340, 9);
  MD5STEP(F2, c, d, a, b, (int)in[11] + 0x265e5a51, 14);
  MD5STEP(F2, b, c, d, a, (int)in[0] + 0xe9b6c7aa, 20);
  MD5STEP(F2, a, b, c, d, (int)in[5] + 0xd62f105d, 5);
  MD5STEP(F2, d, a, b, c, (int)in[10] + 0x02441453, 9);
  MD5STEP(F2, c, d, a, b, (int)in[15] + 0xd8a1e681, 14);
  MD5STEP(F2, b, c, d, a, (int)in[4] + 0xe7d3fbc8, 20);
  MD5STEP(F2, a, b, c, d, (int)in[9] + 0x21e1cde6, 5);
  MD5STEP(F2, d, a, b, c, (int)in[14] + 0xc33707d6, 9);
  MD5STEP(F2, c, d, a, b, (int)in[3] + 0xf4d50d87, 14);
  MD5STEP(F2, b, c, d, a, (int)in[8] + 0x455a14ed, 20);
  MD5STEP(F2, a, b, c, d, (int)in[13] + 0xa9e3e905, 5);
  MD5STEP(F2, d, a, b, c, (int)in[2] + 0xfcefa3f8, 9);
  MD5STEP(F2, c, d, a, b, (int)in[7] + 0x676f02d9, 14);
  MD5STEP(F2, b, c, d, a, (int)in[12] + 0x8d2a4c8a, 20);

  MD5STEP(F3, a, b, c, d, (int)in[5] + 0xfffa3942, 4);
  MD5STEP(F3, d, a, b, c, (int)in[8] + 0x8771f681, 11);
  MD5STEP(F3, c, d, a, b, (int)in[11] + 0x6d9d6122, 16);
  MD5STEP(F3, b, c, d, a, (int)in[14] + 0xfde5380c, 23);
  MD5STEP(F3, a, b, c, d, (int)in[1] + 0xa4beea44, 4);
  MD5STEP(F3, d, a, b, c, (int)in[4] + 0x4bdecfa9, 11);
  MD5STEP(F3, c, d, a, b, (int)in[7] + 0xf6bb4b60, 16);
  MD5STEP(F3, b, c, d, a, (int)in[10] + 0xbebfbc70, 23);
  MD5STEP(F3, a, b, c, d, (int)in[13] + 0x289b7ec6, 4);
  MD5STEP(F3, d, a, b, c, (int)in[0] + 0xeaa127fa, 11);
  MD5STEP(F3, c, d, a, b, (int)in[3] + 0xd4ef3085, 16);
  MD5STEP(F3, b, c, d, a, (int)in[6] + 0x04881d05, 23);
  MD5STEP(F3, a, b, c, d, (int)in[9] + 0xd9d4d039, 4);
  MD5STEP(F3, d, a, b, c, (int)in[12] + 0xe6db99e5, 11);
  MD5STEP(F3, c, d, a, b, (int)in[15] + 0x1fa27cf8, 16);
  MD5STEP(F3, b, c, d, a, (int)in[2] + 0xc4ac5665, 23);

  MD5STEP(F4, a, b, c, d, (int)in[0] + 0xf4292244, 6);
  MD5STEP(F4, d, a, b, c, (int)in[7] + 0x432aff97, 10);
  MD5STEP(F4, c, d, a, b, (int)in[14] + 0xab9423a7, 15);
  MD5STEP(F4, b, c, d, a, (int)in[5] + 0xfc93a039, 21);
  MD5STEP(F4, a, b, c, d, (int)in[12] + 0x655b59c3, 6);
  MD5STEP(F4, d, a, b, c, (int)in[3] + 0x8f0ccc92, 10);
  MD5STEP(F4, c, d, a, b, (int)in[10] + 0xffeff47d, 15);
  MD5STEP(F4, b, c, d, a, (int)in[1] + 0x85845dd1, 21);
  MD5STEP(F4, a, b, c, d, (int)in[8] + 0x6fa87e4f, 6);
  MD5STEP(F4, d, a, b, c, (int)in[15] + 0xfe2ce6e0, 10);
  MD5STEP(F4, c, d, a, b, (int)in[6] + 0xa3014314, 15);
  MD5STEP(F4, b, c, d, a, (int)in[13] + 0x4e0811a1, 21);
  MD5STEP(F4, a, b, c, d, (int)in[4] + 0xf7537e82, 6);
  MD5STEP(F4, d, a, b, c, (int)in[11] + 0xbd3af235, 10);
  MD5STEP(F4, c, d, a, b, (int)in[2] + 0x2ad7d2bb, 15);
  MD5STEP(F4, b, c, d, a, (int)in[9] + 0xeb86d391, 21);

  /* This feeds part of the output of the random number generator into the
   * seed to further obscure any patterns
   */
  memxor((void *)localkey, (void *)&a, 4);
  memxor((void *)(localkey + 4), (void *)&b, 4);

  /*
   * We have 4 unsigned longs generated by the above sequence; this scrambles
   * them together so that if there is any pattern, it will be obscured.
   *
   * a and b are now part of the state of the random number generator;
   * returning them is a security hazard.
   */
  return (c ^ d);
}
