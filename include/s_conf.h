/*
 * s_conf.h
 *
 * $Id$ 
 */
#ifndef INCLUDED_s_conf_h
#define INCLUDED_s_conf_h
#ifndef INCLUDED_time_h
#include <time.h>              /* struct tm */
#define INCLUDED_time_h
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_netinet_in_h
#include <netinet/in.h>        /* struct in_addr */
#define INCLUDED_netinet_in_h
#endif

struct Client;
struct SLink;
struct TRecord;
struct hostent;


/*
 * General defines
 */

/*-----------------------------------------------------------------------------
 * Macros
 */

#define CONF_ILLEGAL            0x80000000
#define CONF_MATCH              0x40000000
#define CONF_CLIENT             0x0002
#define CONF_SERVER             0x0004
#define CONF_LOCOP              0x0010
#define CONF_OPERATOR           0x0020
#define CONF_ME                 0x0040
#define CONF_KILL               0x0080
#define CONF_ADMIN              0x0100
#define CONF_CLASS              0x0400
#define CONF_LEAF               0x1000
#define CONF_LISTEN_PORT        0x2000
#define CONF_HUB                0x4000
#define CONF_UWORLD             0x8000
#define CONF_CRULEALL           0x00200000
#define CONF_CRULEAUTO          0x00400000
#define CONF_TLINES             0x00800000
#define CONF_IPKILL             0x00010000

#define CONF_OPS                (CONF_OPERATOR | CONF_LOCOP)
#define CONF_CLIENT_MASK        (CONF_CLIENT | CONF_OPS | CONF_SERVER)
#define CONF_CRULE              (CONF_CRULEALL | CONF_CRULEAUTO)
#define CONF_KLINE              (CONF_KILL | CONF_IPKILL)

#define IsIllegal(x)    ((x)->status & CONF_ILLEGAL)

/*
 * Structures
 */

struct ConfItem {
  unsigned int       status;    /* If CONF_ILLEGAL, delete when no clients */
  unsigned int       clients;   /* Number of *LOCAL* clients using this */
  struct in_addr     ipnum;     /* ip number of host field */
  char 		     bits;      /* Number of bits for ipkills */
  char*              host;
  char*              passwd;
  char*              name;
  unsigned short int port;
  time_t             hold;      /* Hold until this time (calendar time) */
  int                dns_pending; /* a dns request is pending */
  struct ConfClass*  confClass; /* Class of connection */
  struct ConfItem*   next;
};

/*
 * A line: A:<line 1>:<line 2>:<line 3>
 */
struct LocalConf {
  char* server_alias;
  char* vhost_address;
  char* description;
  char* numeric_id;
  char* admin_line1;
  char* admin_line2;
  char* admin_line3;
};

struct MotdItem {
  char line[82];
  struct MotdItem *next;
};

struct TRecord {
  char *hostmask;
  struct MotdItem *tmotd;
  struct tm tmotd_tm;
  struct TRecord *next;
};

enum AuthorizationCheckResult {
  ACR_OK,
  ACR_NO_AUTHORIZATION,
  ACR_TOO_MANY_IN_CLASS,
  ACR_TOO_MANY_FROM_IP,
  ACR_ALREADY_AUTHORIZED,
  ACR_BAD_SOCKET
};

/*
 * GLOBALS
 */
extern struct ConfItem* GlobalConfList;
extern int              GlobalConfCount;
extern struct tm        motd_tm;
extern struct MotdItem* motd;
extern struct MotdItem* rmotd;
extern struct TRecord*  tdata;

/*
 * Proto types
 */
extern struct ConfItem* attach_confs_byhost(struct Client* cptr, 
                                            const char* host, int statmask);
extern struct ConfItem* find_conf_byhost(struct SLink* lp, const char* host,
                                         int statmask);
extern struct ConfItem* find_conf_byname(struct SLink* lp, const char *name,
                                         int statmask);
extern struct ConfItem* conf_find_server(const char* name);
const char* conf_eval_crule(struct ConfItem* conf);

extern void det_confs_butmask(struct Client *cptr, int mask);
extern int detach_conf(struct Client *cptr, struct ConfItem *aconf);
extern enum AuthorizationCheckResult attach_conf(struct Client *cptr, struct ConfItem *aconf);
extern struct ConfItem* find_admin(void);
extern struct ConfItem* find_me(void);
extern struct ConfItem* find_conf_exact(const char* name, 
                                        const char* user,
                                        const char* host, int statmask);
extern enum AuthorizationCheckResult conf_check_client(struct Client *cptr);
extern int  conf_check_server(struct Client *cptr);
extern struct ConfItem* find_conf_name(const char* name, int statmask);
extern int rehash(struct Client *cptr, int sig);
extern int conf_init(void);
extern void read_tlines(void);
extern int find_kill(struct Client *cptr);
extern int find_restrict(struct Client *cptr);
extern int m_killcomment(struct Client *sptr, char *parv, char *filename);
extern struct MotdItem* read_motd(const char* motdfile);

#endif /* INCLUDED_s_conf_h */
