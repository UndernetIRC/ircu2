/*
 * IRC - Internet Relay Chat, include/common.h
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

 /*
    All the code in common.h/common.c is taken from the NTL
    (Nemesi's Tools Library), adapted for ircu's character set 
    and thereafter released under GNU GPL, from there comes the
    NTL_ prefix of all macro and object names.
    Removed isXdigit() to leave space to other char sets in the
    bitmap, should give the same results as isxdigit() on any
    implementation and isn't used in IRC anyway.
  */

#ifndef COMMON_H
#define COMMON_H

/*=============================================================================
 * System's headers needed in this header file
 */

#include "sys.h"
#include <limits.h>

/*=============================================================================
 * Macros and constants for internal use, 
 * WARNING: match.c depends on these macros, don't change them
 *          without looking at that part of the code too !
 */

#define NTL_ALNUM 0x0001	/*    (NTL_ALPHA|NTL_DIGIT)               */
#define NTL_ALPHA 0x0002	/*    (NTL_LOWER|NTL_UPPER)               */
#define NTL_CNTRL 0x0004	/*    \000 - \037 == 0x00 - 0x1F          */
#define NTL_DIGIT 0x0008	/*    0123456789                          */
#define NTL_GRAPH 0x0010	/*    (NTL_ALNUM|NTL_PUNCT)               */
#define NTL_LOWER 0x0020	/*    abcdefghijklmnopqrstuvwxyz{|}~      */
#define NTL_PRINT 0x0040	/*    (NTL_GRAPH|' ')                     */
#define NTL_PUNCT 0x0080	/*    !"#$%&'()*+,-./:;<=>?@_`            */
#define NTL_SPACE 0x0100	/*    \011\012\013\014\015\040            */
#define NTL_UPPER 0x0200	/*    ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^      */
#define NTL_IRCCH 0x0400	/*    Channel's names charset             */
#define NTL_IRCCL 0x0800	/*    Force toLower() in ch-name          */
#define NTL_IRCNK 0x1000	/*    Nick names charset, aka isvalid()   */
#define NTL_IRCUI 0x2000	/*    UserIDs charset, IRCHN plus tilde   */
#define NTL_IRCHN 0x4000	/*    Hostnames charset (weak, RFC 1033)  */
#define NTL_IRCIP 0x8000	/*    Numeric IPs charset (DIGIT and .)   */
#define NTL_EOL  0x10000	/*    \r\n                                */

/*=============================================================================
 * Structures
 */

/*=============================================================================
 * Externally visible function-like macros
 */

#define DupString(x, y)   (strcpy((x = (char *)RunMalloc(strlen(y) + 1)), y))

#define toLower(c)        (NTL_tolower_tab[(c)-CHAR_MIN])
#define toUpper(c)        (NTL_toupper_tab[(c)-CHAR_MIN])

/* Char classification pseudo-functions, when others are needed add them */
#define isAlnum(c)        (NTL_char_attrib[(c)-CHAR_MIN] & NTL_ALNUM)
#define isAlpha(c)        (NTL_char_attrib[(c)-CHAR_MIN] & NTL_ALPHA)
#define isDigit(c)        (NTL_char_attrib[(c)-CHAR_MIN] & NTL_DIGIT)
#define isLower(c)        (NTL_char_attrib[(c)-CHAR_MIN] & NTL_LOWER)
#define isSpace(c)        (NTL_char_attrib[(c)-CHAR_MIN] & NTL_SPACE)
#define isUpper(c)        (NTL_char_attrib[(c)-CHAR_MIN] & NTL_UPPER)
#define isCntrl(c)        (NTL_char_attrib[(c)-CHAR_MIN] & NTL_CNTRL)

#define isIrcCh(c)        (NTL_char_attrib[(c)-CHAR_MIN] & NTL_IRCCH)
#define isIrcCl(c)        (NTL_char_attrib[(c)-CHAR_MIN] & NTL_IRCCL)
#define isIrcNk(c)        (NTL_char_attrib[(c)-CHAR_MIN] & NTL_IRCNK)
#define isIrcUi(c)        (NTL_char_attrib[(c)-CHAR_MIN] & NTL_IRCUI)
#define isIrcHn(c)        (NTL_char_attrib[(c)-CHAR_MIN] & NTL_IRCHN)
#define isIrcIp(c)        (NTL_char_attrib[(c)-CHAR_MIN] & NTL_IRCIP)
#define isEol(c)          (NTL_char_attrib[(c)-CHAR_MIN] & NTL_EOL)

/* String classification pseudo-functions, when others are needed add them,
   strIsXxxxx(s) is true when IsXxxxx(c) is true for every char in s */

#define strIsAlnum(s)     (strChattr(s) & NTL_ALNUM)
#define strIsAlpha(s)     (strChattr(s) & NTL_ALPHA)
#define strIsDigit(s)     (strChattr(s) & NTL_DIGIT)
#define strIsLower(s)     (strChattr(s) & NTL_LOWER)
#define strIsSpace(s)     (strChattr(s) & NTL_SPACE)
#define strIsUpper(s)     (strChattr(s) & NTL_UPPER)

#define strIsIrcCh(s)     (strChattr(s) & NTL_IRCCH)
#define strIsIrcCl(s)     (strChattr(s) & NTL_IRCCL)
#define strIsIrcNk(s)     (strChattr(s) & NTL_IRCNK)
#define strIsIrcUi(s)     (strChattr(s) & NTL_IRCUI)
#define strIsIrcHn(s)     (strChattr(s) & NTL_IRCHN)
#define strIsIrcIp(s)     (strChattr(s) & NTL_IRCIP)

/*=============================================================================
 * Externally visible static memory stuff
 */
#ifdef MAKETABLES
extern char NTL_tolower_tab[];	/* 256 bytes */
extern char NTL_toupper_tab[];	/* 256 bytes */
extern unsigned int NTL_char_attrib[];	/* 256 ints = 0.5 to 2 kilobytes */
#else
extern const char NTL_tolower_tab[];	/* 256 bytes */
extern const char NTL_toupper_tab[];	/* 256 bytes */
extern const unsigned int NTL_char_attrib[];	/* 256 ints = 0.5 to 2 kilobytes */
#endif

/*=============================================================================
 * Critical small functions to inline even in separate compilation
 * when FORCEINLINE is defined (provided you have a compiler that supports
 * `inline').
 */

#define NTL_HDR_strChattr   int strChattr(const char *s)

#define NTL_SRC_strChattr   register const char *rs = s; \
                            register int x = ~0; \
                            while(*rs) \
                              x &= NTL_char_attrib[*rs++ - CHAR_MIN]; \
                            return x;

#define NTL_HDR_strCasediff int strCasediff(const char *a, const char *b)

#define NTL_SRC_strCasediff register const char *ra = a; \
                            register const char *rb = b; \
                            while(toLower(*ra) == toLower(*rb++)) \
                              if(!*ra++) \
                                return 0; \
                            return 1;

#ifndef FORCEINLINE
extern NTL_HDR_strChattr;
extern NTL_HDR_strCasediff;
#else /* FORCEINLINE */
/* *INDENT-OFF* */
#ifdef __cplusplus
inline NTL_HDR_strChattr { NTL_SRC_strChattr }
inline NTL_HDR_strCasediff { NTL_SRC_strCasediff }
#else
static __inline__ NTL_HDR_strChattr { NTL_SRC_strChattr }
static __inline__ NTL_HDR_strCasediff { NTL_SRC_strCasediff }
#endif
/* *INDENT-ON* */
#endif /* FORCEINLINE */

/*=============================================================================
 * Proto types of other externally visible functions
 */

extern int strnChattr(const char *s, const size_t n);
extern int strCasecmp(const char *a, const char *b);
extern int strnCasecmp(const char *a, const char *b, const size_t n);

#endif /* COMMON_H */
