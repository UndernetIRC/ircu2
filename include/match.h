#ifndef MATCH_H
#define MATCH_H

/*=============================================================================
 * System headers used by this header file
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*=============================================================================
 * Structures
 */

struct in_mask {
  struct in_addr bits;
  struct in_addr mask;
  int fall;
};

/*=============================================================================
 * Proto types
 */

extern int mmatch(const char *old_mask, const char *new_mask);
extern int match(const char *ma, const char *na);
extern char *collapse(char *pattern);

extern int matchcomp(char *cmask, int *minlen, int *charset, const char *mask);
extern int matchexec(const char *string, const char *cmask, int minlen);
extern int matchdecomp(char *mask, const char *cmask);
extern int mmexec(const char *wcm, int wminlen, const char *rcm, int rminlen);
extern int matchcompIP(struct in_mask *imask, const char *mask);

#endif /* MATCH_H */
