#ifndef BSD_H
#define BSD_H

/*=============================================================================
 * Proto types
 */

extern RETSIGTYPE dummy(HANDLER_ARG(int sig));
extern int deliver_it(aClient *cptr, const char *str, int len);

extern int writecalls;
extern int writeb[10];

#endif
