/*
 * s_misc.h
 *
 * $Id$
 */
#ifndef INCLUDED_s_misc_h
#define INCLUDED_s_misc_h
#ifndef INCLUDED_stdarg_h
#include <stdarg.h>           /* va_list */
#define INCLUDED_stdarg_h
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>        /* time_t */
#define INCLUDED_sys_types_h
#endif


struct Client;
struct StatDesc;
struct ConfItem;

/*-----------------------------------------------------------------------------
 * Macros
 */

#define CPTR_KILLED     -2

/*
 * Structures
 */

struct ServerStatistics {
  unsigned int is_cl;           /* number of client connections */
  unsigned int is_sv;           /* number of server connections */
  unsigned int is_ni;           /* connection but no idea who it was */
  unsigned short int is_cbs;    /* bytes sent to clients */
  unsigned short int is_cbr;    /* bytes received to clients */
  unsigned short int is_sbs;    /* bytes sent to servers */
  unsigned short int is_sbr;    /* bytes received to servers */
  unsigned int is_cks;          /* k-bytes sent to clients */
  unsigned int is_ckr;          /* k-bytes received to clients */
  unsigned int is_sks;          /* k-bytes sent to servers */
  unsigned int is_skr;          /* k-bytes received to servers */
  time_t is_cti;                /* time spent connected by clients */
  time_t is_sti;                /* time spent connected by servers */
  unsigned int is_ac;           /* connections accepted */
  unsigned int is_ref;          /* accepts refused */
  unsigned int is_unco;         /* unknown commands */
  unsigned int is_wrdi;         /* command going in wrong direction */
  unsigned int is_unpf;         /* unknown prefix */
  unsigned int is_empt;         /* empty message */
  unsigned int is_num;          /* numeric message */
  unsigned int is_kill;         /* number of kills generated on collisions */
  unsigned int is_fake;         /* MODE 'fakes' */
  unsigned int is_asuc;         /* successful auth requests */
  unsigned int is_abad;         /* bad auth requests */
  unsigned int is_loc;          /* local connections made */
  unsigned int uping_recv;      /* UDP Pings received */
};

/*
 * Prototypes
 */

extern int check_registered(struct Client *sptr);
extern int check_registered_user(struct Client *sptr);
extern int exit_client(struct Client *cptr, struct Client *bcptr,
    struct Client *sptr, const char *comment);
extern char *myctime(time_t value);
extern int exit_client_msg(struct Client *cptr, struct Client *bcptr,
                           struct Client *sptr, const char *pattern, ...);
extern void initstats(void);
extern char *date(time_t clock);
extern const char* get_client_host(const struct Client *cptr);
extern void get_sockhost(struct Client *cptr, char *host);
extern int vexit_client_msg(struct Client *cptr, struct Client *bcptr,
    struct Client *sptr, const char *pattern, va_list vl);
extern void tstats(struct Client *cptr, struct StatDesc *sd, int stat,
		   char *param);

extern struct ServerStatistics* ServerStats;

#endif /* INCLUDED_s_misc_h */

