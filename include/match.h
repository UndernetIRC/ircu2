/** @file match.h
 * @brief Interface for matching strings to IRC masks.
 */
#ifndef INCLUDED_match_h
#define INCLUDED_match_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>         /* XXX - broken BSD system headers */
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_res_h
#include "res.h"
#endif

/*
 * Prototypes
 */

/*
 * XXX - match returns 0 if a match is found. Smelly interface
 * needs to be fixed. --Bleep
 */
extern int match(const char *ma, const char *na);
extern char *collapse(char *pattern);
int mmatch(const char *old_mask, const char *new_mask);

extern int matchcomp(char *cmask, int *minlen, int *charset, const char *mask);
extern int matchexec(const char *string, const char *cmask, int minlen);

extern int ipmask_check(const struct irc_in_addr *addr, const struct irc_in_addr *mask, unsigned char bits);

#endif /* INCLUDED_match_h */
