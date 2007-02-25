/** @file s_bsd.h
 * @brief Wrapper functions to avoid direct use of BSD APIs.
 * @version $Id$
 */
#ifndef INCLUDED_s_bsd_h
#define INCLUDED_s_bsd_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>         /* size_t, time_t */
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_netinet_in_h
#include <netinet/in.h>
#define INCLUDED_netinet_in_h
#endif

struct Client;
struct ConfItem;
struct Listener;
struct MsgQ;
struct irc_in_addr;

/*
 * TCP window sizes
 * Set server window to a large value for fat pipes,
 * set client to a smaller size to allow TCP flow control
 * to reduce flooding
 */
/** Default TCP window size for server connections. */
#define SERVER_TCP_WINDOW 61440
/** Default TCP window size for client connections. */
#define CLIENT_TCP_WINDOW 2048

extern void report_error(const char* text, const char* who, int err);
/*
 * text for report_error
 */
extern const char* const BIND_ERROR_MSG;
extern const char* const LISTEN_ERROR_MSG;
extern const char* const NONB_ERROR_MSG;
extern const char* const REUSEADDR_ERROR_MSG;
extern const char* const SOCKET_ERROR_MSG;
extern const char* const CONNLIMIT_ERROR_MSG;
extern const char* const ACCEPT_ERROR_MSG;
extern const char* const PEERNAME_ERROR_MSG;
extern const char* const POLL_ERROR_MSG;
extern const char* const SELECT_ERROR_MSG;
extern const char* const CONNECT_ERROR_MSG;
extern const char* const SETBUFS_ERROR_MSG;
extern const char* const TOS_ERROR_MSG;
extern const char* const REGISTER_ERROR_MSG;

extern int            HighestFd;
extern struct Client* LocalClientArray[MAXCONNECTIONS];
extern struct irc_sockaddr VirtualHost_v4;
extern struct irc_sockaddr VirtualHost_v6;
extern struct irc_sockaddr VirtualHost_dns_v4;
extern struct irc_sockaddr VirtualHost_dns_v6;

/*
 * Proto types
 */
extern unsigned int deliver_it(struct Client *cptr, struct MsgQ *buf);
extern int connect_server(struct ConfItem* aconf, struct Client* by);
extern int  net_close_unregistered_connections(struct Client* source);
extern void close_connection(struct Client *cptr);
extern void add_connection(struct Listener* listener, int fd);
extern int  read_message(time_t delay);
extern void init_server_identity(void);
extern void close_connections(int close_stderr);
extern int  init_connection_limits(void);
extern void update_write(struct Client* cptr);

#endif /* INCLUDED_s_bsd_h */
