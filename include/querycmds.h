/** @file
 * @brief Interface and declarations for client counting functions.
 * @version $Id$
 */
#ifndef INCLUDED_querycmds_h
#define INCLUDED_querycmds_h

#ifndef INCLUDED_ircd_features_h
#include "ircd_features.h"	/* feature_str() */
#endif

struct Client;

/*
 * Structs
 */

/** Counts types of clients, servers, etc.\ on the network. */
struct UserStatistics {
  /* Local connections: */
  unsigned int unknowns;  /**< Clients of types: unknown, connecting, handshake */
  unsigned int local_servers;   /**< Directly connected servers. */
  unsigned int local_clients;   /**< Directly connected clients. */

  /* Global counts: */
  unsigned int servers;         /**< Known servers, including #me. */
  unsigned int clients;         /**< Registered users. */

  /* Global user mode changes: */
  unsigned int inv_clients;     /**< Registered invisible users. */
  unsigned int opers;           /**< Registered IRC operators. */

  /* Misc: */
  unsigned int channels;        /**< Existing channels. */
};

extern struct UserStatistics UserStats;

/*
 * Macros
 */

/* Macros for remote connections: */
/** Count \a cptr as a new remote client. */
#define Count_newremoteclient(UserStats, cptr)  (++UserStats.clients, ++(cli_serv(cptr)->clients))
/** Count a new remote server. */
#define Count_newremoteserver(UserStats)  (++UserStats.servers)

/** Count a remote user quit. */
#define Count_remoteclientquits(UserStats,cptr)                \
  do { \
    --UserStats.clients; \
    if (!IsServer(cptr)) \
      --(cli_serv(cli_user(cptr)->server)->clients); \
  } while (0)

/** Count a remote server quit. */
#define Count_remoteserverquits(UserStats)      (--UserStats.servers)

/* Macros for local connections: */
/** Count a new local unknown connection. */
#define Count_newunknown(UserStats)                     (++UserStats.unknowns)
/** Update counters when \a cptr goes from unknown to registered. */
#define Count_unknownbecomesclient(cptr, UserStats) \
  do { \
    --UserStats.unknowns; ++UserStats.local_clients; ++UserStats.clients; \
    if (match(feature_str(FEAT_DOMAINNAME), cli_sockhost(cptr)) == 0) \
      ++current_load.local_count; \
    if (UserStats.local_clients > max_client_count) \
      max_client_count = UserStats.local_clients; \
    if (UserStats.local_clients + UserStats.local_servers > max_connection_count) \
    { \
      max_connection_count = UserStats.local_clients + UserStats.local_servers; \
      if (max_connection_count % 10 == 0) \
        sendto_opmask_butone(0, SNO_OLDSNO, "Maximum connections: %d (%d clients)", \
            max_connection_count, max_client_count); \
    } \
  } while(0)
/** Update counters when \a cptr goes from unknown to server. */
#define Count_unknownbecomesserver(UserStats)   do { --UserStats.unknowns; ++UserStats.local_servers; ++UserStats.servers; } while(0)
/** Update counters when \a cptr (a local user) disconnects. */
#define Count_clientdisconnects(cptr, UserStats) \
  do \
  { \
    --UserStats.local_clients; --UserStats.clients; \
    if (match(feature_str(FEAT_DOMAINNAME), cli_sockhost(cptr)) == 0) \
      --current_load.local_count; \
  } while(0)
/** Update counters when a local server disconnects. */
#define Count_serverdisconnects(UserStats)              do { --UserStats.local_servers; --UserStats.servers; } while(0)
/** Update counters when an unknown client disconnects. */
#define Count_unknowndisconnects(UserStats)             (--UserStats.unknowns)

/*
 * Prototypes
 */


#endif /* INCLUDED_querycmds_h */
