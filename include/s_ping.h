#ifndef S_PING_H
#define S_PING_H

/*=============================================================================
 * Proto types
 */

extern int start_ping(aClient *cptr);
extern void send_ping(aClient *cptr);
extern void read_ping(aClient *cptr);
extern int ping_server(aClient *cptr);
extern int m_uping(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern void end_ping(aClient *cptr);
extern void cancel_ping(aClient *sptr, aClient *acptr);

#endif /* S_PING_H */
