#ifndef S_CONF_H
#define S_CONF_H

#include "list.h"
#include <netinet/in.h>
#include <netdb.h>

/*=============================================================================
 * General defines
 */

/*-----------------------------------------------------------------------------
 * Macro's
 */

#define CONF_ILLEGAL		0x80000000
#define CONF_MATCH		0x40000000
#define CONF_CLIENT		0x0002
#define CONF_CONNECT_SERVER	0x0004
#define CONF_NOCONNECT_SERVER	0x0008
#define CONF_LOCOP		0x0010
#define CONF_OPERATOR		0x0020
#define CONF_ME			0x0040
#define CONF_KILL		0x0080
#define CONF_ADMIN		0x0100
#ifdef	R_LINES
#define CONF_RESTRICT		0x0200
#endif
#define CONF_CLASS		0x0400
#define CONF_LEAF		0x1000
#define CONF_LISTEN_PORT	0x2000
#define CONF_HUB		0x4000
#define CONF_UWORLD		0x8000
#define CONF_CRULEALL		0x00200000
#define CONF_CRULEAUTO		0x00400000
#define CONF_TLINES		0x00800000
#define CONF_IPKILL		0x00010000

#define CONF_OPS		(CONF_OPERATOR | CONF_LOCOP)
#define CONF_SERVER_MASK	(CONF_CONNECT_SERVER | CONF_NOCONNECT_SERVER)
#define CONF_CLIENT_MASK	(CONF_CLIENT | CONF_OPS | CONF_SERVER_MASK)
#define CONF_CRULE		(CONF_CRULEALL | CONF_CRULEAUTO)
#define CONF_KLINE		(CONF_KILL | CONF_IPKILL)

#define IsIllegal(x)	((x)->status & CONF_ILLEGAL)

/*=============================================================================
 * Structures
 */

struct ConfItem {
  unsigned int status;		/* If CONF_ILLEGAL, delete when no clients */
  unsigned int clients;		/* Number of *LOCAL* clients using this */
  struct in_addr ipnum;		/* ip number of host field */
  char *host;
  char *passwd;
  char *name;
  unsigned short int port;
  time_t hold;			/* Hold action until this time
				   (calendar time) */
#ifndef VMSP
  struct ConfClass *confClass;	/* Class of connection */
#endif
  struct ConfItem *next;
};

struct MotdItem {
  char line[82];
  struct MotdItem *next;
};

struct trecord {
  char *hostmask;
  struct MotdItem *tmotd;
  struct tm tmotd_tm;
  struct trecord *next;
};

enum AuthorizationCheckResult {
  ACR_OK,
  ACR_NO_AUTHORIZATION,
  ACR_TOO_MANY_IN_CLASS,
  ACR_TOO_MANY_FROM_IP,
  ACR_ALREADY_AUTHORIZED,
  ACR_BAD_SOCKET
};

/*=============================================================================
 * Proto types
 */

extern aConfItem *find_conf_host(Link *lp, char *host, int statmask);
extern void det_confs_butmask(aClient *cptr, int mask);
extern enum AuthorizationCheckResult attach_Iline(aClient *cptr,
    struct hostent *hp, char *sockhost);
extern aConfItem *count_cnlines(Link *lp);
extern int detach_conf(aClient *cptr, aConfItem *aconf);
extern enum AuthorizationCheckResult attach_conf(aClient *cptr,
    aConfItem *aconf);
extern aConfItem *find_admin(void);
extern aConfItem *find_me(void);
extern aConfItem *attach_confs(aClient *cptr, const char *name, int statmask);
extern aConfItem *attach_confs_host(aClient *cptr, char *host, int statmask);
extern aConfItem *find_conf_exact(char *name, char *user, char *host,
    int statmask);
extern aConfItem *find_conf_name(char *name, int statmask);
extern aConfItem *find_conf(Link *lp, const char *name, int statmask);
extern aConfItem *find_conf_ip(Link *lp, char *ip, char *user, int statmask);
extern int rehash(aClient *cptr, int sig);
extern int initconf(int opt);
extern void read_tlines(void);
extern int find_kill(aClient *cptr);
extern int find_restrict(aClient *cptr);
extern int m_killcomment(aClient *sptr, char *parv, char *filename);
extern aMotdItem *read_motd(char *motdfile);

extern aConfItem *conf;
extern aGline *gline;
extern struct tm motd_tm;
extern aMotdItem *motd;
extern aMotdItem *rmotd;
extern atrecord *tdata;

#endif /* S_CONF_H */
