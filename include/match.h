/*
 * match.h
 *
 * $Id$
 */
#ifndef INCLUDED_match_h
#define INCLUDED_match_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>         /* XXX - broken BSD system headers */
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_netinet_in_h
#include <netinet/in.h>        /* struct in_addr */
#define INCLUDED_netinet_in_h
#endif

/*
 * Structures
 */
struct in_mask {
  struct in_addr bits;
  struct in_addr mask;
  int fall;
};

/*
 * Prototypes
 */

/*
 * XXX - match returns 0 if a match is found. Smelly interface
 * needs to be fixed. --Bleep
 */
extern int mmatch(const char *old_mask, const char *new_mask);
extern int match(const char *ma, const char *na);
extern char *collapse(char *pattern);

extern int matchcomp(char *cmask, int *minlen, int *charset, const char *mask);
extern int matchexec(const char *string, const char *cmask, int minlen);
extern int matchdecomp(char *mask, const char *cmask);
extern int mmexec(const char *wcm, int wminlen, const char *rcm, int rminlen);
extern int matchcompIP(struct in_mask *imask, const char *mask);

#endif /* INCLUDED_match_h */
