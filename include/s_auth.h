#ifndef S_AUTH_H
#define S_AUTH_H

/*=============================================================================
 * Proto types
 */

extern void start_auth(aClient *cptr);
extern void send_authports(aClient *cptr);
extern void read_authports(aClient *cptr);

#endif /* S_AUTH_H */
