#ifndef S_SERV_H
#define S_SERV_H

#include "struct.h"

/*=============================================================================
 * General defines
 */

/*-----------------------------------------------------------------------------
 * Macro's
 */

#define STAT_PING		0
#define STAT_LOG		1	/* logfile for -x */
#define STAT_MASTER		2	/* Local ircd master before identification */
#define STAT_CONNECTING		3
#define STAT_HANDSHAKE		4
#define STAT_ME			5
#define STAT_UNKNOWN		6
#define STAT_UNKNOWN_USER	7	/* Connect to client port */
#define STAT_UNKNOWN_SERVER	8	/* Connect to server port */
#define STAT_SERVER		9
#define STAT_USER		10

/* 
 * for when you wanna create a bitmask of status values
 */
#define StatusMask(T) (1<<(T))
#define IsStatMask(x, s) (StatusMask((x)->status) & (s))

/*
 * status macros.
 */
#define IsRegistered(x)		(IsStatMask(x, \
					StatusMask(STAT_SERVER)|\
					StatusMask(STAT_USER)))
#define IsConnecting(x)		((x)->status == STAT_CONNECTING)
#define IsHandshake(x)		((x)->status == STAT_HANDSHAKE)
#define IsMe(x)			((x)->status == STAT_ME)
#define IsUnknown(x)		(IsStatMask(x, \
					StatusMask(STAT_UNKNOWN)|\
					StatusMask(STAT_UNKNOWN_USER)|\
					StatusMask(STAT_UNKNOWN_SERVER)|\
					StatusMask(STAT_MASTER)))
#define IsServerPort(x)		((x)->status == STAT_UNKNOWN_SERVER )
#define IsUserPort(x)		((x)->status == STAT_UNKNOWN_USER )
#define IsMaster(x)		((x)->status == STAT_MASTER)
#define IsClient(x)		(IsStatMask(x, \
					StatusMask(STAT_MASTER)|\
					StatusMask(STAT_HANDSHAKE)|\
					StatusMask(STAT_ME)|\
					StatusMask(STAT_UNKNOWN)|\
					StatusMask(STAT_UNKNOWN_USER)|\
					StatusMask(STAT_UNKNOWN_SERVER)|\
					StatusMask(STAT_SERVER)|\
					StatusMask(STAT_USER)))
#define IsTrusted(x)		(IsStatMask(x, \
					StatusMask(STAT_PING)|\
					StatusMask(STAT_LOG)|\
					StatusMask(STAT_CONNECTING)|\
					StatusMask(STAT_HANDSHAKE)|\
					StatusMask(STAT_ME)|\
					StatusMask(STAT_SERVER)))
#ifdef DEBUGMODE		/* Coredump if we miss something... */
#define IsServer(x)		( ((x)->status == STAT_SERVER) && \
                                  (((x)->serv) ? 1 : (*((char *) NULL) = 0)) )
#define IsUser(x)		( ((x)->status == STAT_USER) && \
                                  (((x)->user) ? 1 : (*((char *) NULL) = 0)) )
#else
#define IsServer(x)		((x)->status == STAT_SERVER)
#define IsUser(x)		((x)->status == STAT_USER)
#endif
#define IsLog(x)		((x)->status == STAT_LOG)
#define IsPing(x)		((x)->status == STAT_PING)

#define SetMaster(x)		((x)->status = STAT_MASTER)
#define SetConnecting(x)	((x)->status = STAT_CONNECTING)
#define SetHandshake(x)		((x)->status = STAT_HANDSHAKE)
#define SetServer(x)		((x)->status = STAT_SERVER)
#define SetMe(x)		((x)->status = STAT_ME)
#define SetUser(x)		((x)->status = STAT_USER)

/*=============================================================================
 * Proto types
 */

extern int m_server(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_server_estab(aClient *cptr, aConfItem *aconf, aConfItem *bconf);
extern int m_error(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_end_of_burst(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_end_of_burst_ack(aClient *cptr, aClient *sptr,
    int parc, char *parv[]);
extern int m_desynch(aClient *cptr, aClient *sptr, int parc, char *parv[]);

extern unsigned int max_connection_count, max_client_count;

#endif /* S_SERV_H */
