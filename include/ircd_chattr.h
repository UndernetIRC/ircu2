/*
 * IRC - Internet Relay Chat, include/ircd_chattr.h
 * Copyright (C) 1998 Andrea Cocito
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
 * @brief Character attribute definitions and arrays.
 * @version $Id$
 *
 * This character set code is adapted from Nemesi's Tools Library,
 * which gives us the prefix NTL_ on these macros.
 */

#ifndef INCLUDED_ircd_chattr_h
#define INCLUDED_ircd_chattr_h
#ifndef INCLUDED_limits_h
#include <limits.h>
#define INCLUDED_limits_h
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

/*
 * Character attribute macros
 */
#define NTL_ALNUM   0x0001  /**< (NTL_ALPHA | NTL_DIGIT)             */
#define NTL_ALPHA   0x0002  /**< (NTL_LOWER | NTL_UPPER)             */
#define NTL_CNTRL   0x0004  /**< \\000 - \\037 == 0x00 - 0x1F        */
#define NTL_DIGIT   0x0008  /**< 0123456789                          */
#define NTL_GRAPH   0x0010  /**< (NTL_ALNUM | NTL_PUNCT)             */
#define NTL_LOWER   0x0020  /**< abcdefghijklmnopqrstuvwxyz{|}~      */
#define NTL_PRINT   0x0040  /**< (NTL_GRAPH | ' ')                   */
#define NTL_PUNCT   0x0080  /**< !"#$%&'()*+,-./:;<=>?\@_`           */
#define NTL_SPACE   0x0100  /**< \\011\\012\\013\\014\\015\\040      */
#define NTL_UPPER   0x0200  /**< ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^     */
#define NTL_IRCCH   0x0400  /**< Channel's names charset             */
#define NTL_IRCCL   0x0800  /**< Force toLower() in ch-name          */
#define NTL_IRCNK   0x1000  /**< Nick names charset, aka isvalid()   */
#define NTL_IRCUI   0x2000  /**< UserIDs charset, IRCHN plus tilde   */
#define NTL_IRCHN   0x4000  /**< Hostnames charset (weak, RFC 1033)  */
#define NTL_IRCIP   0x8000  /**< Numeric IPs charset (DIGIT and .)   */
#define NTL_EOL    0x10000  /**< \\r\\n                              */
#define NTL_KTIME  0x20000  /**< Valid character for a k:line time   */
#define NTL_CHPFX  0x40000  /**< channel prefix char # & +           */
#define NTL_IRCIP6 0x80000  /**< Numeric IPv6 character (hex or colon) */

/*
 * Tables used for translation and classification macros
 */
/** Array mapping characters to RFC 1459 lower-case versions.
 * Yes, the variable name lies about the encoding.
 */
extern const char ToLowerTab_8859_1[];
/** Array mapping characters to RFC 1459 upper-case versions.
 * Yes, the variable name lies about the encoding.
 */
extern const char ToUpperTab_8859_1[];
/** Array mapping characters to attribute bitmasks. */
extern const unsigned int  IRCD_CharAttrTab[];

/*
 * Translation macros for channel name case translation
 * NOTE: Channel names are supposed to be lower case insensitive for
 * ISO 8859-1 character sets.
 */
/** Convert a character to its lower-case equivalent. */
#define ToLower(c)        (ToLowerTab_8859_1[(c) - CHAR_MIN])
/** Convert a character to its upper-case equivalent. */
#define ToUpper(c)        (ToUpperTab_8859_1[(c) - CHAR_MIN])

/*
 * Character classification macros
 * NOTE: The IsUpper and IsLower macros do not apply to the complete
 * ISO 8859-1 character set, unlike the ToUpper and ToLower macros above.
 * IsUpper and IsLower only apply for comparisons of the US ASCII subset.
 */
/** Test whether a character is alphanumeric. */
#define IsAlnum(c)         (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_ALNUM)
/** Test whether a character is alphabetic. */
#define IsAlpha(c)         (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_ALPHA)
/** Test whether a character is a digit. */
#define IsDigit(c)         (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_DIGIT)
/** Test whether a character is lower case. */
#define IsLower(c)         (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_LOWER)
/** Test whether a character is whitespace. */
#define IsSpace(c)         (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_SPACE)
/** Test whether a character is upper case. */
#define IsUpper(c)         (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_UPPER)
/** Test whether a character is a control character. */
#define IsCntrl(c)         (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_CNTRL)

/** Test whether a character is valid in a channel name. */
#define IsChannelChar(c)   (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_IRCCH)
/** Test whether a character is a lower-case channel name character. */
#define IsChannelLower(c)  (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_IRCCL)
/** Test whether a character is a channel prefix. */
#define IsChannelPrefix(c) (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_CHPFX)
/** Test whether a character is valid in a nickname. */
#define IsNickChar(c)      (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_IRCNK)
/** Test whether a character is valid in a userid. */
#define IsUserChar(c)      (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_IRCUI)
/** Test whether a character is valid in a hostname. */
#define IsHostChar(c)      (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_IRCHN)
/** Test whether a character is valid in an IPv4 address. */
#define IsIPChar(c)        (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_IRCIP)
/** Test whether a character is valid in an IPv6 address. */
#define IsIP6Char(c)       (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_IRCIP6)
/** Test whether a character is an end-of-line character. */
#define IsEol(c)           (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_EOL)
/** Test whether a character is valid in a K: line expiration string. */
#define IsKTimeChar(c)     (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_KTIME)


#endif /* INCLUDED_ircd_chattr_h */
