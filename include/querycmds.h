#ifndef QUERYCMDS_H
#define QUERYCMDS_H

/*=============================================================================
 * Structs
 */

struct lusers_st {
  /* Local connections: */
  unsigned int unknowns;	/* IsUnknown() || IsConnecting() || IsHandshake() */
  unsigned int local_servers;	/* IsServer() && MyConnect() */
  unsigned int local_clients;	/* IsUser() && MyConnect() */
  /* Global counts: */
  unsigned int servers;		/* IsServer() || IsMe() */
  unsigned int clients;		/* IsUser() */
  /* Global user mode changes: */
  unsigned int inv_clients;	/* IsUser() && IsInvisible() */
  unsigned int opers;		/* IsUser() && IsOper() */
  /* Misc: */
  unsigned int channels;
};

/*=============================================================================
 * Macros
 */

/* Macros for remote connections: */
#define Count_newremoteclient(nrof)		(++nrof.clients)
#define Count_newremoteserver(nrof)		(++nrof.servers)
#define Count_remoteclientquits(nrof)		(--nrof.clients)
#define Count_remoteserverquits(nrof)		(--nrof.servers)

/* Macros for local connections: */
#define Count_newunknown(nrof)			(++nrof.unknowns)
#define Count_unknownbecomesclient(cptr, nrof) \
  do { \
    --nrof.unknowns; ++nrof.local_clients; ++nrof.clients; \
    if (match("*" DOMAINNAME, cptr->sockhost) == 0) \
      ++current_load.local_count; \
    if (nrof.local_clients > max_client_count) \
      max_client_count = nrof.local_clients; \
    if (nrof.local_clients + nrof.local_servers > max_connection_count) \
    { \
      max_connection_count = nrof.local_clients + nrof.local_servers; \
      if (max_connection_count % 10 == 0) \
        sendto_ops("Maximum connections: %d (%d clients)", \
	    max_connection_count, max_client_count); \
    } \
  } while(0)
#define Count_unknownbecomesserver(nrof)	do { --nrof.unknowns; ++nrof.local_servers; ++nrof.servers; } while(0)
#define Count_clientdisconnects(cptr, nrof) \
  do \
  { \
    --nrof.local_clients; --nrof.clients; \
    if (match("*" DOMAINNAME, cptr->sockhost) == 0) \
      --current_load.local_count; \
  } while(0)
#define Count_serverdisconnects(nrof)		do { --nrof.local_servers; --nrof.servers; } while(0)
#define Count_unknowndisconnects(nrof)		(--nrof.unknowns)

/*=============================================================================
 * Proto types
 */

extern int m_version(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_info(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_links(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_help(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_lusers(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_admin(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_motd(aClient *cptr, aClient *sptr, int parc, char *parv[]);

extern struct lusers_st nrof;

#endif /* QUERYCMDS_H */
