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
 *
 * $Id$
 *
 */
/*
 * All the code in common.h/common.c is taken from the NTL
 * (Nemesi's Tools Library), adapted for ircu's character set
 * and thereafter released under GNU GPL, from there comes the
 * NTL_ prefix of all macro and object names.
 * Removed isXdigit() to leave space to other char sets in the
 * bitmap, should give the same results as isxdigit() on any
 * implementation and isn't used in IRC anyway.
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
#define NTL_ALNUM   0x0001  /* (NTL_ALPHA | NTL_DIGIT)             */
#define NTL_ALPHA   0x0002  /* (NTL_LOWER | NTL_UPPER)             */
#define NTL_CNTRL   0x0004  /* \000 - \037 == 0x00 - 0x1F          */
#define NTL_DIGIT   0x0008  /* 0123456789                          */
#define NTL_GRAPH   0x0010  /* (NTL_ALNUM | NTL_PUNCT)             */
#define NTL_LOWER   0x0020  /* abcdefghijklmnopqrstuvwxyz{|}~      */
#define NTL_PRINT   0x0040  /* (NTL_GRAPH | ' ')                   */
#define NTL_PUNCT   0x0080  /* !"#$%&'()*+,-./:;<=>?@_`            */
#define NTL_SPACE   0x0100  /* \011\012\013\014\015\040            */
#define NTL_UPPER   0x0200  /* ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^      */
#define NTL_IRCCH   0x0400  /* Channel's names charset             */
#define NTL_IRCCL   0x0800  /* Force toLower() in ch-name          */
#define NTL_IRCNK   0x1000  /* Nick names charset, aka isvalid()   */
#define NTL_IRCUI   0x2000  /* UserIDs charset, IRCHN plus tilde   */
#define NTL_IRCHN   0x4000  /* Hostnames charset (weak, RFC 1033)  */
#define NTL_IRCIP   0x8000  /* Numeric IPs charset (DIGIT and .)   */
#define NTL_EOL    0x10000  /* \r\n                                */
#define NTL_KTIME  0x20000  /* Valid character for a k:line time   */
#define NTL_CHPFX  0x40000  /* channel prefix char # & +           */

/*
 * Tables used for translation and classification macros
 */
extern const char ToLowerTab_8859_1[];
extern const char ToUpperTab_8859_1[];
extern const unsigned int  IRCD_CharAttrTab[];

/*
 * Translation macros for channel name case translation
 * NOTE: Channel names are supposed to be lower case insensitive for
 * ISO 8859-1 character sets.
 */
#define ToLower(c)        (ToLowerTab_8859_1[(c) - CHAR_MIN])
#define ToUpper(c)        (ToUpperTab_8859_1[(c) - CHAR_MIN])

/*
 * Character classification macros
 * NOTE: The IsUpper and IsLower macros do not apply to the complete
 * ISO 8859-1 character set, unlike the ToUpper and ToLower macros above.
 * IsUpper and IsLower only apply for comparisons of the US ASCII subset.
 */
#define IsAlnum(c)         (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_ALNUM)
#define IsAlpha(c)         (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_ALPHA)
#define IsDigit(c)         (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_DIGIT)
#define IsLower(c)         (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_LOWER)
#define IsSpace(c)         (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_SPACE)
#define IsUpper(c)         (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_UPPER)
#define IsCntrl(c)         (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_CNTRL)

#define IsChannelChar(c)   (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_IRCCH)
#define IsChannelLower(c)  (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_IRCCL)
#define IsChannelPrefix(c) (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_CHPFX)
#define IsNickChar(c)      (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_IRCNK)
#define IsUserChar(c)      (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_IRCUI)
#define IsHostChar(c)      (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_IRCHN)
#define IsIPChar(c)        (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_IRCIP)
#define IsEol(c)           (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_EOL)
#define IsKTimeChar(c)     (IRCD_CharAttrTab[(c) - CHAR_MIN] & NTL_KTIME)


#endif /* INCLUDED_ircd_chattr_h */
