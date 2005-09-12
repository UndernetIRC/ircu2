/** @file ircd_string.h
 * @brief Public declarations and APIs for string operations.
 * @version $Id$
 */
#ifndef INCLUDED_ircd_string_h
#define INCLUDED_ircd_string_h

#include <string.h> /* for DupString()'s strcpy, strlen */

#ifndef INCLUDED_ircd_chattr_h
#include "ircd_chattr.h"
#endif

struct irc_in_addr;

/*
 * Macros
 */
/** Check whether \a x is a NULL or empty string. */
#define EmptyString(x) (!(x) || !(*x))

extern int string_has_wildcards(const char* str);

extern char*       ircd_strncpy(char* dest, const char* src, size_t len);
extern int         ircd_strcmp(const char *a, const char *b);
extern int         ircd_strncmp(const char *a, const char *b, size_t n);
extern int         unique_name_vector(char* names, char token,
                                      char** vector, int size);
extern int         token_vector(char* names, char token,
                                char** vector, int size);
extern const char* ircd_ntoa(const struct irc_in_addr* addr);
extern const char* ircd_ntoa_r(char* buf, const struct irc_in_addr* addr);
#define ircd_aton(ADDR, STR) ipmask_parse((STR), (ADDR), NULL)
extern int ipmask_parse(const char *in, struct irc_in_addr *mask, unsigned char *bits_ptr);
extern char*       host_from_uh(char* buf, const char* userhost, size_t len);
extern char*       ircd_strtok(char** save, char* str, char* fs);

extern char*       canonize(char* buf);

/** Make \a y a duplicate \a x, a la strdup(). */
#define DupString(x, y)  (strcpy((x = (char*) MyMalloc(strlen(y) + 1)), y))


/* String classification pseudo-functions, when others are needed add them,
   strIsXxxxx(s) is true when IsXxxxx(c) is true for every char in s */

/** Test whether all characters in \a s are alphanumeric. */
#define strIsAlnum(s)     (strChattr(s) & NTL_ALNUM)
/** Test whether all characters in \a s are alphabetic. */
#define strIsAlpha(s)     (strChattr(s) & NTL_ALPHA)
/** Test whether all characters in \a s are digits. */
#define strIsDigit(s)     (strChattr(s) & NTL_DIGIT)
/** Test whether all characters in \a s are lower case. */
#define strIsLower(s)     (strChattr(s) & NTL_LOWER)
/** Test whether all characters in \a s are whitespace. */
#define strIsSpace(s)     (strChattr(s) & NTL_SPACE)
/** Test whether all characters in \a s are upper case. */
#define strIsUpper(s)     (strChattr(s) & NTL_UPPER)

/** Test whether all characters in \a s are channel name characters. */
#define strIsIrcCh(s)     (strChattr(s) & NTL_IRCCH)
/** Test whether all characters in \a s are forced to lower-case in channel names. */
#define strIsIrcCl(s)     (strChattr(s) & NTL_IRCCL)
/** Test whether all characters in \a s are valid in nicknames. */
#define strIsIrcNk(s)     (strChattr(s) & NTL_IRCNK)
/** Test whether all characters in \a s are valid in a user field. */
#define strIsIrcUi(s)     (strChattr(s) & NTL_IRCUI)
/** Test whether all characters in \a s are valid in host names. */
#define strIsIrcHn(s)     (strChattr(s) & NTL_IRCHN)
/** Test whether all characters in \a s are valid in IP addresses. */
#define strIsIrcIp(s)     (strChattr(s) & NTL_IRCIP)

/*
 * Critical small functions to inline even in separate compilation
 * when FORCEINLINE is defined (provided you have a compiler that supports
 * `inline').
 */

/** Declaration for strChattr(). */
#define NTL_HDR_strChattr   unsigned int strChattr(const char *s)

/** Body for strChattr(). */
#define NTL_SRC_strChattr   const char *rs = s; \
                            unsigned int x = ~0; \
                            while(*rs) \
                              x &= IRCD_CharAttrTab[*rs++ - CHAR_MIN]; \
                            return x;

/*
 * XXX - bleah should return 1 if different 0 if the same
 */
/** Declaration for strCasediff(). */
#define NTL_HDR_strCasediff int strCasediff(const char *a, const char *b)

/** Body for strCasediff(). */
#define NTL_SRC_strCasediff const char *ra = a; \
                            const char *rb = b; \
                            while(ToLower(*ra) == ToLower(*rb++)) \
                              if(!*ra++) \
                                return 0; \
                            return 1;

#ifndef FORCEINLINE
extern NTL_HDR_strChattr;
extern NTL_HDR_strCasediff;

#else /* FORCEINLINE */
#ifdef __cplusplus
inline NTL_HDR_strChattr { NTL_SRC_strChattr }
inline NTL_HDR_strCasediff { NTL_SRC_strCasediff }
#else
static __inline__ NTL_HDR_strChattr { NTL_SRC_strChattr }
static __inline__ NTL_HDR_strCasediff { NTL_SRC_strCasediff }
#endif
#endif /* FORCEINLINE */

#endif /* INCLUDED_ircd_string_h */

