/*
 * s_bsd.h
 *
 * $Id$
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
struct DNSReply;
struct MsgQ;

/*
 * TCP window sizes
 * Set server window to a large value for fat pipes,
 * set client to a smaller size to allow TCP flow control
 * to reduce flooding
 */
#define SERVER_TCP_WINDOW 61440
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
extern int            OpenFileDescriptorCount;

extern struct sockaddr_in VirtualHost;

enum PollType {
  PT_NONE,
  PT_READ,
  PT_WRITE
};

struct Pollable;

typedef int (*PollReadyFn)(struct Pollable*);

struct Pollable {
  struct Pollable* next;
  struct Pollable* prev;
  int              fd;
  int              index;
  int              state;
  PollReadyFn      r_handler;
  PollReadyFn      w_handler;
};
  
/*
 * Proto types
 */
extern unsigned int deliver_it(struct Client *cptr, struct MsgQ *buf);
extern int connect_server(struct ConfItem* aconf, struct Client* by,
                          struct DNSReply* reply);
extern void release_dns_reply(struct Client* cptr);
extern int  net_close_unregistered_connections(struct Client* source);
extern void close_connection(struct Client *cptr);
extern void add_connection(struct Listener* listener, int fd);
extern int  read_message(time_t delay);
extern void init_server_identity(void);
extern void close_connections(int close_stderr);
extern int  init_connection_limits(void);
extern void set_virtual_host(struct in_addr addr);
extern void update_write(struct Client* cptr);

#endif /* INCLUDED_s_bsd_h */
