#ifndef WHOCMDS_H
#define WHOCMDS_H

/*=============================================================================
 * Macro's
 */

/*=============================================================================
 * Proto types
 */

extern int m_who(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_whois(aClient *cptr, aClient *sptr, int parc, char *parv[]);

#endif /* WHOCMDS_H */
