/*
 * querycmds.h
 *
 * $Id$
 */
#ifndef INCLUDED_querycmds_h
#define INCLUDED_querycmds_h

struct Client;

/*
 * Structs
 */

struct UserStatistics {
  /* Local connections: */
  unsigned int unknowns;  /* IsUnknown() || IsConnecting() || IsHandshake() */
  unsigned int local_servers;   /* IsServer() && MyConnect() */
  unsigned int local_clients;   /* IsUser() && MyConnect() */

  /* Global counts: */
  unsigned int servers;         /* IsServer() || IsMe() */
  unsigned int clients;         /* IsUser() */

  /* Global user mode changes: */
  unsigned int inv_clients;     /* IsUser() && IsInvisible() */
  unsigned int opers;           /* IsUser() && IsOper() */

  /* Misc: */
  unsigned int channels;
};

extern struct UserStatistics UserStats;

/*
 * Macros
 */

/* Macros for remote connections: */
#define Count_newremoteclient(UserStats, cptr)  (++UserStats.clients, ++cptr->serv->clients)
#define Count_newremoteserver(UserStats)  (++UserStats.servers)
#if 0
#define Count_remoteclientquits(UserStats)      (--UserStats.clients)
#endif

#define Count_remoteclientquits(UserStats,cptr)                \
  do { \
    --UserStats.clients; \
    if (!IsServer(cptr)) \
      --cptr->user->server->serv->clients; \
  } while (0)

#define Count_remoteserverquits(UserStats)      (--UserStats.servers)

/* Macros for local connections: */
#define Count_newunknown(UserStats)                     (++UserStats.unknowns)
#define Count_unknownbecomesclient(cptr, UserStats) \
  do { \
    --UserStats.unknowns; ++UserStats.local_clients; ++UserStats.clients; \
    if (match("*" DOMAINNAME, cptr->sockhost) == 0) \
      ++current_load.local_count; \
    if (UserStats.local_clients > max_client_count) \
      max_client_count = UserStats.local_clients; \
    if (UserStats.local_clients + UserStats.local_servers > max_connection_count) \
    { \
      max_connection_count = UserStats.local_clients + UserStats.local_servers; \
      if (max_connection_count % 10 == 0) \
        sendto_ops("Maximum connections: %d (%d clients)", \
            max_connection_count, max_client_count); \
    } \
  } while(0)
#define Count_unknownbecomesserver(UserStats)   do { --UserStats.unknowns; ++UserStats.local_servers; ++UserStats.servers; } while(0)
#define Count_clientdisconnects(cptr, UserStats) \
  do \
  { \
    --UserStats.local_clients; --UserStats.clients; \
    if (match("*" DOMAINNAME, cptr->sockhost) == 0) \
      --current_load.local_count; \
  } while(0)
#define Count_serverdisconnects(UserStats)              do { --UserStats.local_servers; --UserStats.servers; } while(0)
#define Count_unknowndisconnects(UserStats)             (--UserStats.unknowns)

/*
 * Prototypes
 */


#endif /* INCLUDED_querycmds_h */
