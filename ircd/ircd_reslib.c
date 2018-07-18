/*
 * Copyright (c) 1985, 1993
 *    The Regents of the University of California.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * 	This product includes software developed by the University of
 * 	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Portions Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/* Original copyright ISC as above. 
 * Code modified specifically for ircd use from the following original files
 * in bind ...
 *
 * res_comp.c
 * ns_name.c
 * ns_netint.c
 * res_init.c
 * 
 * - Dianora
 */

#include "ircd.h"
#include "res.h"
#include "ircd_reslib.h"
#include "ircd_defs.h"
#include "fileio.h"
#include "ircd_string.h"

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define NS_TYPE_ELT             0x40 /**< EDNS0 extended label type */
#define DNS_LABELTYPE_BITSTRING 0x41 /**< Bitstring label */
#define MAXLINE 128 /**< Maximum line length for resolv.conf */

/** @file
 * @brief DNS resolver library functions.
 * @version $Id$
 */

/** Array of nameserver addresses. */
struct irc_sockaddr irc_nsaddr_list[IRCD_MAXNS];
/** Number of nameservers in #irc_nsaddr_list. */
int irc_nscount;
/** Local domain to use as a search suffix. */
char irc_domain[HOSTLEN + 1];

/** Maps hex digits to their values, or -1 for other characters. */
static const char digitvalue[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*16*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*32*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*48*/
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, /*64*/
  -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*80*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*96*/
  -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*112*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*128*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*256*/
};

static int parse_resvconf(void);

/** Array of decimal digits, indexed by value. */
static const char digits[] = "0123456789";
static int labellen(const unsigned char *lp);
static int special(int ch);
static int printable(int ch);
static int irc_decode_bitstring(const char **cpp, char *dn, const char *eom);
static int irc_ns_name_compress(const char *src, unsigned char *dst, size_t dstsiz,
    const unsigned char **dnptrs, const unsigned char **lastdnptr);
static int irc_dn_find(const unsigned char *, const unsigned char *, const unsigned char * const *,
                       const unsigned char * const *);
static int irc_encode_bitstring(const char **, const char *, unsigned char **, unsigned char **,
                               const char *);
static int mklower(int ch);

/** Initialize the resolver library.
 * @return Zero on success, non-zero on failure.
 */
int
irc_res_init(void)
{
  return (irc_nscount == 0) ? parse_resvconf() : 0;
}

/** Read resolver configuration file for domain and nameserver lines.
 * The "domain" line is used to overwrite #irc_domain.
 * Addresses in "nameserver" lines are appended to #irc_nsaddr_list.
 * @return Zero on success, non-zero on failure.
 */
static int
parse_resvconf(void)
{
  char *p;
  char *opt;
  char *arg;
  char input[MAXLINE];
  FBFILE *file;

  /* XXX "/etc/resolv.conf" should be from a define in setup.h perhaps
   * for cygwin support etc. this hardcodes it to unix for now -db
   */
  if ((file = fbopen("/etc/resolv.conf", "r")) == NULL)
    return(-1);

  while (fbgets(input, MAXLINE, file) != NULL)
  {
    /* blow away any newline */
    if ((p = strpbrk(input, "\r\n")) != NULL)
      *p = '\0';

    /* Ignore comment lines immediately */
    if (*input == '#')
      continue;

    p = input;
    /* skip until something that's not a space is seen */
    while (IsSpace(*p))
      p++;
    /* if at this point, have a '\0' then continue */
    if (*p == '\0')
      continue;

    /* skip until a space is found */
    opt = input;
    while (!IsSpace(*p))
      if (*p++ == '\0')
        continue;  /* no arguments?.. ignore this line */
    /* blow away the space character */
    *p++ = '\0';

    /* skip these spaces that are before the argument */
    while (IsSpace(*p))
      p++;
    /* Now arg should be right where p is pointing */
    arg = p;
    if ((p = strpbrk(arg, " \t")) != NULL)
      *p = '\0';  /* take the first word */

    if (strcasecmp(opt, "domain") == 0)
      ircd_strncpy(irc_domain, arg, HOSTLEN);
    else if (strcasecmp(opt, "nameserver") == 0)
      add_nameserver(arg);
  }

  fbclose(file);
  return(0);
}

/** Add a resolver to #irc_nsaddr_list.
 * @param[in] arg Dotted quad or IPv6 text form of nameserver address.
 */
void
add_nameserver(const char *arg)
{
  struct irc_sockaddr res;

  /* Done max number of nameservers? */
  if (irc_nscount >= IRCD_MAXNS)
    return;

  /* Failure converting from numeric string? */
  if (!ircd_aton(&res.addr, arg))
      return;
  res.port = 53;
  memcpy(&irc_nsaddr_list[irc_nscount], &res, sizeof(irc_nsaddr_list[irc_nscount]));
  irc_nscount++;
}

/**
 * Expand compressed domain name to full domain name.
 * Like irc_ns_name_uncompress(), but checks for a well-formed result.
 * @param[in] msg Pointer to the beginning of the message.
 * @param[in] eom First location after the message.
 * @param[in] src Pointer to where to starting decoding.
 * @param[out] dst Output buffer.
 * @param[in] dstsiz Number of bytes that can be written to \a dst.
 * @return Number of bytes written to \a dst.
 */
int
irc_dn_expand(const unsigned char *msg, const unsigned char *eom,
              const unsigned char *src, char *dst, int dstsiz)
{
  int n = irc_ns_name_uncompress(msg, eom, src, dst, (size_t)dstsiz);

  if (n > 0 && dst[0] == '.')
    dst[0] = '\0';
  return(n);
}

/**
 * Expand compressed domain name to full domain name.
 * @param[in] msg Pointer to the beginning of the message.
 * @param[in] eom First location after the message.
 * @param[in] src Pointer to where to starting decoding.
 * @param[out] dst Output buffer.
 * @param[in] dstsiz Number of bytes that can be written to \a dst.
 * @return Number of bytes written to \a dst.
 */
int
irc_ns_name_uncompress(const unsigned char *msg, const unsigned char *eom,
                       const unsigned char *src, char *dst, size_t dstsiz)
{
  unsigned char tmp[NS_MAXCDNAME];
  int n;

  if ((n = irc_ns_name_unpack(msg, eom, src, tmp, sizeof tmp)) == -1)
    return(-1);
  if (irc_ns_name_ntop((char*)tmp, (char*)dst, dstsiz) == -1)
    return(-1);
  return(n);
}

/**
 * Unpack compressed domain name to uncompressed form.
 * @param[in] msg Pointer to the beginning of the message.
 * @param[in] eom First location after the message.
 * @param[in] src Pointer to where to starting decoding.
 * @param[out] dst Output buffer.
 * @param[in] dstsiz Number of bytes that can be written to \a dst.
 * @return Number of bytes written to \a dst.
 */
int
irc_ns_name_unpack(const unsigned char *msg, const unsigned char *eom,
                   const unsigned char *src, unsigned char *dst,
                   size_t dstsiz)
{
	const unsigned char *srcp, *dstlim;
	unsigned char *dstp;
	int n, len, checked, l;

	len = -1;
	checked = 0;
	dstp = dst;
	srcp = src;
	dstlim = dst + dstsiz;
	if (srcp < msg || srcp >= eom) {
		errno = EMSGSIZE;
		return (-1);
	}
	/* Fetch next label in domain name. */
	while ((n = *srcp++) != 0) {
		/* Check for indirection. */
		switch (n & NS_CMPRSFLGS) {
		case 0:
		case NS_TYPE_ELT:
			/* Limit checks. */
			if ((l = labellen(srcp - 1)) < 0) {
				errno = EMSGSIZE;
				return(-1);
			}
			if (dstp + l + 1 >= dstlim || srcp + l >= eom) {
				errno = EMSGSIZE;
				return (-1);
			}
			checked += l + 1;
			*dstp++ = n;
			memcpy(dstp, srcp, l);
			dstp += l;
			srcp += l;
			break;

		case NS_CMPRSFLGS:
			if (srcp >= eom) {
				errno = EMSGSIZE;
				return (-1);
			}
			if (len < 0)
				len = srcp - src + 1;
			srcp = msg + (((n & 0x3f) << 8) | (*srcp & 0xff));
			if (srcp < msg || srcp >= eom) {  /* Out of range. */
				errno = EMSGSIZE;
				return (-1);
			}
			checked += 2;
			/*
			 * Check for loops in the compressed name;
			 * if we've looked at the whole message,
			 * there must be a loop.
			 */
			if (checked >= eom - msg) {
				errno = EMSGSIZE;
				return (-1);
			}
			break;

		default:
			errno = EMSGSIZE;
			return (-1);			/* flag error */
		}
	}
	*dstp = '\0';
	if (len < 0)
		len = srcp - src;
	return (len);
}

/**
 * Convert RFC1035 length-prefixed tag sequence to printable ASCII.
 * @param[in] src Input tag sequence (effectively NUL terminated).
 * @param[out] dst Buffer for uncompressed output.
 * @param[in] dstsiz Number of bytes that can be written to \a dst.
 * @return Number of bytes written to \a dst.
 */
int
irc_ns_name_ntop(const char *src, char *dst, size_t dstsiz)
{
	const char *cp;
	char *dn, *eom;
	unsigned char c;
	unsigned int n;
	int l;

	cp = src;
	dn = dst;
	eom = dst + dstsiz;

	while ((n = *cp++) != 0) {
		if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			/* Some kind of compression pointer. */
			errno = EMSGSIZE;
			return (-1);
		}
		if (dn != dst) {
			if (dn >= eom) {
				errno = EMSGSIZE;
				return (-1);
			}
			*dn++ = '.';
		}
		if ((l = labellen((const unsigned char*)(cp - 1))) < 0) {
			errno = EMSGSIZE; /* XXX */
			return(-1);
		}
		if (dn + l >= eom) {
			errno = EMSGSIZE;
			return (-1);
		}
		if ((n & NS_CMPRSFLGS) == NS_TYPE_ELT) {
			int m;

			if (n != DNS_LABELTYPE_BITSTRING) {
				/* XXX: labellen should reject this case */
				errno = EINVAL;
				return(-1);
			}
			if ((m = irc_decode_bitstring(&cp, dn, eom)) < 0)
			{
				errno = EMSGSIZE;
				return(-1);
			}
			dn += m; 
			continue;
		}
		for ((void)NULL; l > 0; l--) {
			c = *cp++;
			if (special(c)) {
				if (dn + 1 >= eom) {
					errno = EMSGSIZE;
					return (-1);
				}
				*dn++ = '\\';
				*dn++ = (char)c;
			} else if (!printable(c)) {
				if (dn + 3 >= eom) {
					errno = EMSGSIZE;
					return (-1);
				}
				*dn++ = '\\';
				*dn++ = digits[c / 100];
				*dn++ = digits[(c % 100) / 10];
				*dn++ = digits[c % 10];
			} else {
				if (dn >= eom) {
					errno = EMSGSIZE;
					return (-1);
				}
				*dn++ = (char)c;
			}
		}
	}
	if (dn == dst) {
		if (dn >= eom) {
			errno = EMSGSIZE;
			return (-1);
		}
		*dn++ = '.';
	}
	if (dn >= eom) {
		errno = EMSGSIZE;
		return (-1);
	}
	*dn++ = '\0';
	return (dn - dst);
}

/** Pack domain name from presentation form into compressed format.
 * @param[in] src Presentation form of name.
 * @param[out] dst Output buffer.
 * @param[in] dstsiz Number of bytes that can be written to \a dst.
 * @param[in,out] dnptrs Array of previously seen labels.
 * @param[in] lastdnptr End of \a dnptrs array.
 * @return Number of bytes written to \a dst.
 */
int
irc_dn_comp(const char *src, unsigned char *dst, int dstsiz,
            unsigned char **dnptrs, unsigned char **lastdnptr)
{
  return(irc_ns_name_compress(src, dst, (size_t)dstsiz,
                              (const unsigned char **)dnptrs,
                              (const unsigned char **)lastdnptr));
}

/** Skip over a compressed domain name.
 * @param[in] ptr Start of compressed name.
 * @param[in] eom End of message.
 * @return Length of the compressed name, or -1 on error.
 */
int
irc_dn_skipname(const unsigned char *ptr, const unsigned char *eom) {
  const unsigned char *saveptr = ptr;

  if (irc_ns_name_skip(&ptr, eom) == -1)
    return(-1);
  return(ptr - saveptr);
}

/** Advance \a ptrptr to skip over the compressed name it points at.
 * @param[in,out] ptrptr Pointer to the compressed name.
 * @param[in] eom End of message.
 * @return Zero on success; non-zero (with errno set) on failure.
 */
int
irc_ns_name_skip(const unsigned char **ptrptr, const unsigned char *eom)
{
  const unsigned char *cp;
  unsigned int n;
  int l;

  cp = *ptrptr;

  while (cp < eom && (n = *cp++) != 0)
  {
    /* Check for indirection. */
    switch (n & NS_CMPRSFLGS)
    {
      case 0: /* normal case, n == len */
        cp += n;
        continue;
      case NS_TYPE_ELT: /* EDNS0 extended label */
        if ((l = labellen(cp - 1)) < 0)
        {
          errno = EMSGSIZE; /* XXX */
          return(-1);
        }

        cp += l;
        continue;
      case NS_CMPRSFLGS: /* indirection */
        cp++;
        break;
      default: /* illegal type */
        errno = EMSGSIZE;
        return(-1);
    }

    break;
  }

  if (cp > eom)
  {
    errno = EMSGSIZE;
    return (-1);
  }

  *ptrptr = cp;
  return(0);
}

/** Read a 16-bit network-endian value from \a src.
 * @param[in] src Input data buffer.
 * @return Value retrieved from buffer.
 */
unsigned int
irc_ns_get16(const unsigned char *src)
{
  unsigned int dst;

  IRC_NS_GET16(dst, src);
  return(dst);
}

/** Read a 32-bit network-endian value from \a src.
 * @param[in] src Input data buffer.
 * @return Value retrieved from buffer.
 */
unsigned long
irc_ns_get32(const unsigned char *src)
{
  unsigned long dst;

  IRC_NS_GET32(dst, src);
  return(dst);
}

/** Write a 16-bit network-endian value to \a dst.
 * @param[in] src Value to write.
 * @param[out] dst Output buffer.
 */
void
irc_ns_put16(unsigned int src, unsigned char *dst)
{
  IRC_NS_PUT16(src, dst);
}

/** Write a 32-bit network-endian value to \a dst.
 * @param[in] src Value to write.
 * @param[out] dst Output buffer.
 */
void
irc_ns_put32(unsigned long src, unsigned char *dst)
{
  IRC_NS_PUT32(src, dst);
}

/* From ns_name.c */

/** Indicate whether a character needs quoting.
 * (What RFC does this come from?)
 * @param[in] ch Character to check for specialness.
 * @return Non-zero if the character should be quoted.
 */
static int
special(int ch)
{
  switch (ch)
  {
    case 0x22: /* '"'  */
    case 0x2E: /* '.'  */
    case 0x3B: /* ';'  */
    case 0x5C: /* '\\' */
    case 0x28: /* '('  */
    case 0x29: /* ')'  */
    /* Special modifiers in zone files. */
    case 0x40: /* '@'  */
    case 0x24: /* '$'  */
      return(1);
    default:
      return(0);
  }
}

/** Calculate the length of a particular DNS label.
 * @param[in] lp Start of label.
 * @return Length of label, or -1 on error.
 */
static int
labellen(const unsigned char *lp)
{
  int bitlen;
  unsigned char l = *lp;

  if ((l & NS_CMPRSFLGS) == NS_CMPRSFLGS)
  {
    /* should be avoided by the caller */
    return(-1);
  }

  if ((l & NS_CMPRSFLGS) == NS_TYPE_ELT)
  {
    if (l == DNS_LABELTYPE_BITSTRING)
    {
      if ((bitlen = *(lp + 1)) == 0)
        bitlen = 256;
      return((bitlen + 7 ) / 8 + 1);
    }

    return(-1); /* unknown ELT */
  }

  return(l);
}


/** Indicate whether a character is printable.
 * @param[in] ch Character to check for printability.
 * @return Non-zero if the character is printable; zero if it is not.
 */
static int
printable(int ch)
{
  return(ch > 0x20 && ch < 0x7f);
}

/** Decode a bitstring label from DNS.
 * @param[in,out] cpp Pointer to start of label.
 * @param[in,out] dn Output buffer.
 * @param[in] eom End of message.
 */
static int
irc_decode_bitstring(const char **cpp, char *dn, const char *eom)
{
        const char *cp = *cpp;
        char *beg = dn, tc;
        int b, blen, plen;

        if ((blen = (*cp & 0xff)) == 0)
                blen = 256;
        plen = (blen + 3) / 4;
        plen += sizeof("\\[x/]") + (blen > 99 ? 3 : (blen > 9) ? 2 : 1);
        if (dn + plen >= eom)
                return(-1);

        cp++;
        dn += sprintf(dn, "\\[x");
        for (b = blen; b > 7; b -= 8, cp++)
                dn += sprintf(dn, "%02x", *cp & 0xff);
        if (b > 4) {
                tc = *cp++;
                dn += sprintf(dn, "%02x", tc & (0xff << (8 - b)));
        } else if (b > 0) {
                tc = *cp++;
               dn += sprintf(dn, "%1x",
                               ((tc >> 4) & 0x0f) & (0x0f << (4 - b)));
        }
        dn += sprintf(dn, "/%d]", blen);

        *cpp = cp;
        return(dn - beg);
}

/** Convert an ASCII name string into an encoded domain name.
 * This function enforces per-label and total name lengths.
 * @param[in] src ASCII name string.
 * @param[out] dst Destination buffer.
 * @param[in] dstsiz Number of bytes that can be written to \a dst.
 * @return -1 on failure, 0 if \a src was not fully qualified, 1 if \a
 * src was fully qualified.
 */
int
irc_ns_name_pton(const char *src, unsigned char *dst, size_t dstsiz)
{
  unsigned char *label, *bp, *eom;
  char *cp;
  int c, n, escaped, e = 0;

  escaped = 0;
  bp = dst;
  eom = dst + dstsiz;
  label = bp++;


  while ((c = *src++) != 0) {
    if (escaped) {
      if (c == '[') { /* start a bit string label */
        if ((cp = strchr(src, ']')) == NULL) {
          errno = EINVAL; /* ??? */
          return(-1);
        }
        if ((e = irc_encode_bitstring(&src,
               cp + 2,
               &label,
               &bp,
               (const char *)eom))
            != 0) {
          errno = e;
          return(-1);
        }
        escaped = 0;
        label = bp++;
        if ((c = *src++) == 0)
          goto done;
        else if (c != '.') {
          errno = EINVAL;
          return(-1);
        }
        continue;
      }
      else if ((cp = strchr(digits, c)) != NULL) {
        n = (cp - digits) * 100;
        if ((c = *src++) == 0 ||
            (cp = strchr(digits, c)) == NULL) {
          errno = EMSGSIZE;
          return (-1);
        }
        n += (cp - digits) * 10;
        if ((c = *src++) == 0 ||
            (cp = strchr(digits, c)) == NULL) {
          errno = EMSGSIZE;
          return (-1);
        }
        n += (cp - digits);
        if (n > 255) {
          errno = EMSGSIZE;
          return (-1);
        }
        c = n;
      }
      escaped = 0;
    } else if (c == '\\') {
      escaped = 1;
      continue;
    } else if (c == '.') {
      c = (bp - label - 1);
      if ((c & NS_CMPRSFLGS) != 0) {  /* Label too big. */
        errno = EMSGSIZE;
        return (-1);
      }
      if (label >= eom) {
        errno = EMSGSIZE;
        return (-1);
      }
      *label = c;
      /* Fully qualified ? */
      if (*src == '\0') {
        if (c != 0) {
          if (bp >= eom) {
            errno = EMSGSIZE;
            return (-1);
          }
          *bp++ = '\0';
        }
        if ((bp - dst) > NS_MAXCDNAME) {
          errno = EMSGSIZE;
          return (-1);
        }
        return (1);
      }
      if (c == 0 || *src == '.') {
        errno = EMSGSIZE;
        return (-1);
      }
      label = bp++;
      continue;
    }
    if (bp >= eom) {
      errno = EMSGSIZE;
      return (-1);
    }
    *bp++ = (unsigned char)c;
  }
  c = (bp - label - 1);
  if ((c & NS_CMPRSFLGS) != 0) {    /* Label too big. */
    errno = EMSGSIZE;
    return (-1);
  }
  done:
  if (label >= eom) {
    errno = EMSGSIZE;
    return (-1);
  }
  *label = c;
  if (c != 0) {
    if (bp >= eom) {
      errno = EMSGSIZE;
      return (-1);
    }
    *bp++ = 0;
  }

  if ((bp - dst) > NS_MAXCDNAME)
  { /* src too big */
    errno = EMSGSIZE;
    return (-1);
  }

  return (0);
}

/** Compress a domain name.
 * @param[in] src List of length-prefixed labels.
 * @param[out] dst Output buffer.
 * @param[in] dstsiz Number of bytes that can be written to \a dst.
 * @param[in,out] dnptrs Array of pointers to previously compressed names.
 * @param[in] lastdnptr End of \a dnptrs array.
 * @return Number of bytes written to \a dst.
 */
int
irc_ns_name_pack(const unsigned char *src, unsigned char *dst, int dstsiz,
                 const unsigned char **dnptrs, const unsigned char **lastdnptr)
{
  unsigned char *dstp;
  const unsigned char **cpp, **lpp, *eob, *msg;
  const unsigned char *srcp;
  int n, l, first = 1;

  srcp = src;
  dstp = dst;
  eob = dstp + dstsiz;
  lpp = cpp = NULL;
  if (dnptrs != NULL) {
    if ((msg = *dnptrs++) != NULL) {
      for (cpp = dnptrs; *cpp != NULL; cpp++)
        (void)NULL;
      lpp = cpp;  /* end of list to search */
    }
  } else
    msg = NULL;

  /* make sure the domain we are about to add is legal */
  l = 0;
  do {
    int l0;

    n = *srcp;
    if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
      errno = EMSGSIZE;
      return (-1);
    }
    if ((l0 = labellen(srcp)) < 0) {
      errno = EINVAL;
      return(-1);
    }
    l += l0 + 1;
    if (l > NS_MAXCDNAME) {
      errno = EMSGSIZE;
      return (-1);
    }
    srcp += l0 + 1;
  } while (n != 0);

  /* from here on we need to reset compression pointer array on error */
  srcp = src;
  do {
    /* Look to see if we can use pointers. */
    n = *srcp;
    if (n != 0 && msg != NULL) {
      l = irc_dn_find(srcp, msg, (const unsigned char * const *)dnptrs,
            (const unsigned char * const *)lpp);
      if (l >= 0) {
        if (dstp + 1 >= eob) {
          goto cleanup;
        }
        *dstp++ = (l >> 8) | NS_CMPRSFLGS;
        *dstp++ = l % 256;
        return (dstp - dst);
      }
      /* Not found, save it. */
      if (lastdnptr != NULL && cpp < lastdnptr - 1 &&
          (dstp - msg) < 0x4000 && first) {
        *cpp++ = dstp;
        *cpp = NULL;
        first = 0;
      }
    }
    /* copy label to buffer */
    if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
      /* Should not happen. */
      goto cleanup;
    }
    n = labellen(srcp);
    if (dstp + 1 + n >= eob) {
      goto cleanup;
    }
    memcpy(dstp, srcp, n + 1);
    srcp += n + 1;
    dstp += n + 1;
  } while (n != 0);

  if (dstp > eob) {
cleanup:
    if (msg != NULL)
      *lpp = NULL;
    errno = EMSGSIZE;
    return (-1);
  }
  return(dstp - dst);
}

/** Encode and compress an ASCII domain name.
 * @param[in] src ASCII domain name.
 * @param[out] dst Output buffer.
 * @param[in] dstsiz Number of bytes that can be written to \a dst.
 * @param[in] dnptrs Array of previously compressed names.
 * @param[in] lastdnptr End of \a dnptrs array.
 */
static int
irc_ns_name_compress(const char *src, unsigned char *dst, size_t dstsiz,
                     const unsigned char **dnptrs, const unsigned char **lastdnptr)
{
  unsigned char tmp[NS_MAXCDNAME];

  if (irc_ns_name_pton(src, tmp, sizeof tmp) == -1)
    return(-1);
  return(irc_ns_name_pack(tmp, dst, dstsiz, dnptrs, lastdnptr));
}

/** Encode a bitstring label.
 * @param[in,out] bp Input buffer pointer.
 * @param[in] end End of input buffer.
 * @param[out] labelp Pointer to output label.
 * @param[out] dst Output buffer.
 * @param[out] eom End of output buffer.
 */
static int
irc_encode_bitstring(const char **bp, const char *end, unsigned char **labelp,
                    unsigned char **dst, const char *eom)
{
  int afterslash = 0;
  const char *cp = *bp;
  char *tp, c;
  const char *beg_blen = NULL;
  char *end_blen = NULL;
  int value = 0, count = 0, tbcount = 0, blen = 0;

  /* a bitstring must contain at least 2 characters */
  if (end - cp < 2)
    return(EINVAL);

  /* XXX: currently, only hex strings are supported */
  if (*cp++ != 'x')
    return(EINVAL);
  if (!isxdigit((*cp) & 0xff)) /* reject '\[x/BLEN]' */
    return(EINVAL);

  for (tp = (char*)(*dst + 1); cp < end && tp < eom; cp++) {
    switch((c = *cp)) {
    case ']': /* end of the bitstring */
      if (afterslash) {
        if (beg_blen == NULL)
          return(EINVAL);
        blen = (int)strtol(beg_blen, &end_blen, 10);
        if (*end_blen != ']')
          return(EINVAL);
      }
      if (count)
        *tp++ = ((value << 4) & 0xff);
      cp++; /* skip ']' */
      goto done;
    case '/':
      afterslash = 1;
      break;
    default:
      if (afterslash) {
        if (!isdigit(c&0xff))
          return(EINVAL);
        if (beg_blen == NULL) {

          if (c == '0') {
            /* blen never begins with 0 */
            return(EINVAL);
          }
          beg_blen = cp;
        }
      } else {
        if (!isxdigit(c&0xff))
          return(EINVAL);
        value <<= 4;
        value += digitvalue[(int)c];
        count += 4;
        tbcount += 4;
        if (tbcount > 256)
          return(EINVAL);
        if (count == 8) {
          *tp++ = value;
          count = 0;
        }
      }
      break;
    }
  }
  done:
  if (cp >= end || tp >= eom)
    return(EMSGSIZE);

  /*
   * bit length validation:
   * If a <length> is present, the number of digits in the <bit-data>
   * MUST be just sufficient to contain the number of bits specified
   * by the <length>. If there are insignificant bits in a final
   * hexadecimal or octal digit, they MUST be zero.
   * RFC 2673, Section 3.2.
   */
  if (blen > 0) {
    int traillen;

    if (((blen + 3) & ~3) != tbcount)
      return(EINVAL);
    traillen = tbcount - blen; /* between 0 and 3 */
    if (((value << (8 - traillen)) & 0xff) != 0)
      return(EINVAL);
  }
  else
    blen = tbcount;
  if (blen == 256)
    blen = 0;

  /* encode the type and the significant bit fields */
  **labelp = DNS_LABELTYPE_BITSTRING;
  **dst = blen;

  *bp = cp;
  *dst = (unsigned char*)tp;

  return(0);
}

/** Find a name in an array of compressed name.
 * @param[in] domain Name to search for.
 * @param[in] msg Start of DNS message.
 * @param[in] dnptrs Start of compressed name array.
 * @param[in] lastdnptr End of compressed name array.
 * @return Non-negative offset from \a msg, or -1 if not found.
 */
static int
irc_dn_find(const unsigned char *domain, const unsigned char *msg,
            const unsigned char * const *dnptrs,
            const unsigned char * const *lastdnptr)
{
  const unsigned char *dn, *cp, *sp;
  const unsigned char * const *cpp;
  unsigned int n;

  for (cpp = dnptrs; cpp < lastdnptr; cpp++)
  {
    sp = *cpp;
    /*
     * terminate search on:
     * root label
     * compression pointer
     * unusable offset
     */
    while (*sp != 0 && (*sp & NS_CMPRSFLGS) == 0 &&
           (sp - msg) < 0x4000) {
      dn = domain;
      cp = sp;
      while ((n = *cp++) != 0) {
        /*
         * check for indirection
         */
        switch (n & NS_CMPRSFLGS) {
        case 0:   /* normal case, n == len */
          n = labellen(cp - 1); /* XXX */

          if (n != *dn++)
            goto next;

          for ((void)NULL; n > 0; n--)
            if (mklower(*dn++) !=
                mklower(*cp++))
              goto next;
          /* Is next root for both ? */
          if (*dn == '\0' && *cp == '\0')
            return (sp - msg);
          if (*dn)
            continue;
          goto next;
        case NS_CMPRSFLGS:  /* indirection */
          cp = msg + (((n & 0x3f) << 8) | *cp);
          break;

        default:  /* illegal type */
          errno = EMSGSIZE;
          return (-1);
        }
      }
 next: ;
      sp += *sp + 1;
    }
  }
  errno = ENOENT;
  return (-1);
}

/** Convert a character to lowercase, assuming ASCII encoded English.
 * @param[in] ch Character to convert.
 * @return Lower-case version of \a ch.
 */
static int
mklower(int ch)
{
  if (ch >= 0x41 && ch <= 0x5A)
    return(ch + 0x20);

  return(ch);
}

/* From resolv/mkquery.c */

/** Form a query for \a dname in \a buf.
 * @param[in] dname Domain name to look up.
 * @param[in] class Query class to set in header.
 * @param[in] type Query type to set in header.
 * @param[out] buf Output buffer for query.
 * @param[in] buflen Number of bytes that can be written to \a buf.
 * @return Length of message written to \a buf, or -1 on error.
 */
int
irc_res_mkquery(
	     const char *dname,		/* domain name */
	     int class, int type,	/* class and type of query */
	     unsigned char *buf,		/* buffer to put query */
	     int buflen)		/* size of buffer */
{
	HEADER *hp;
	unsigned char *cp;
	int n;
	unsigned char *dnptrs[20], **dpp, **lastdnptr;

	/*
	 * Initialize header fields.
	 */
	if ((buf == NULL) || (buflen < HFIXEDSZ))
		return (-1);
	memset(buf, 0, HFIXEDSZ);
	hp = (HEADER *) buf;

	hp->id = 0;
	hp->opcode = QUERY;
	hp->rd = 1;		/* recurse */
	hp->rcode = NO_ERRORS;
	cp = buf + HFIXEDSZ;
	buflen -= HFIXEDSZ;
	dpp = dnptrs;
	*dpp++ = buf;
	*dpp++ = NULL;
	lastdnptr = dnptrs + sizeof dnptrs / sizeof dnptrs[0];

	if ((buflen -= QFIXEDSZ) < 0)
	  return (-1);
	if ((n = irc_dn_comp(dname, cp, buflen, dnptrs, lastdnptr)) < 0)
	  return (-1);

	cp += n;
	buflen -= n;
	IRC_NS_PUT16(type, cp);
	IRC_NS_PUT16(class, cp);
	hp->qdcount = htons(1);

	return (cp - buf);
}
