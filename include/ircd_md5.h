/*
 * IRC - Internet Relay Chat, include/ircd_md5.h
 *
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * ircuified 2002 by hikari
 *
 * $Id$
*/
#ifndef ircd_md5_h
#define ircd_md5_h

#define MD5Name(x) Good##x

typedef unsigned int uint32;

struct MD5Context {
	uint32 buf[4];
	uint32 bits[2];
	unsigned char in[64];
};

void GoodMD5Init(struct MD5Context *);
void GoodMD5Update(struct MD5Context *, unsigned const char *, unsigned);
void GoodMD5Final(unsigned char digest[16], struct MD5Context *);
void GoodMD5Transform(uint32 buf[4], uint32 const in[16]);
void BrokenMD5Init(struct MD5Context *);
void BrokenMD5Update(struct MD5Context *, unsigned const char *, unsigned);
void BrokenMD5Final(unsigned char digest[16], struct MD5Context *);
void BrokenMD5Transform(uint32 buf[4], uint32 const in[16]);

char *Goodcrypt_md5(const char *pw, const char *salt);
char *Brokencrypt_md5(const char *pw, const char *salt);

/*
 * This is needed to make RSAREF happy on some MS-DOS compilers.
 */

typedef struct MD5Context MD5_CTX;

#endif /* ircd_md5_h */
