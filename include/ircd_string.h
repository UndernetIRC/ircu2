/*
 * ircd_string.h
 *
 * $Id$
 */
#ifndef INCLUDED_ircd_string_h
#define INCLUDED_ircd_string_h
#ifndef INCLUDED_ircd_chattr_h
#include "ircd_chattr.h"
#endif

/*
 * Macros
 */
#define EmptyString(x) (!(x) || !(*x))

/*
 * initialize recognizers
 */
extern int init_string(void);

extern int string_is_hostname(const char* str);
extern int string_is_address(const char* str);
extern int string_has_wildcards(const char* str);

extern char*       ircd_strncpy(char* dest, const char* src, size_t len);
extern int         ircd_strcmp(const char *a, const char *b);
extern int         ircd_strncmp(const char *a, const char *b, size_t n);
extern int         unique_name_vector(char* names, char token, char** vector, int size);
extern int         token_vector(char* names, char token, char** vector, int size);
extern const char* ircd_ntoa(const char* addr);
extern const char* ircd_ntoa_r(char* buf, const char* addr);
extern char*       host_from_uh(char* buf, const char* userhost, size_t len);
extern char*       ircd_strtok(char** save, char* str, char* fs);

extern char*       canonize(char* buf);

#define DupString(x, y)  (strcpy((x = (char*) MyMalloc(strlen(y) + 1)), y))


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

/*
 * Critical small functions to inline even in separate compilation
 * when FORCEINLINE is defined (provided you have a compiler that supports
 * `inline').
 */

#define NTL_HDR_strChattr   unsigned int strChattr(const char *s)

#define NTL_SRC_strChattr   const char *rs = s; \
                            unsigned int x = ~0; \
                            while(*rs) \
                              x &= IRCD_CharAttrTab[*rs++ - CHAR_MIN]; \
                            return x;

/*
 * XXX - bleah should return 1 if different 0 if the same
 */
#define NTL_HDR_strCasediff int strCasediff(const char *a, const char *b)

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

/*
 * Proto types of other externally visible functions
 */
extern int strnChattr(const char *s, const size_t n);

#endif /* INCLUDED_ircd_string_h */

