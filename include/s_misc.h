#ifndef S_MISC_H
#define S_MISC_H

/*=============================================================================
 * General defines
 */

/*-----------------------------------------------------------------------------
 * Macro's
 */

#define CPTR_KILLED	-2

/*=============================================================================
 * Structures
 */

struct stats {
  unsigned int is_cl;		/* number of client connections */
  unsigned int is_sv;		/* number of server connections */
  unsigned int is_ni;		/* connection but no idea who it was */
  unsigned short int is_cbs;	/* bytes sent to clients */
  unsigned short int is_cbr;	/* bytes received to clients */
  unsigned short int is_sbs;	/* bytes sent to servers */
  unsigned short int is_sbr;	/* bytes received to servers */
  unsigned int is_cks;		/* k-bytes sent to clients */
  unsigned int is_ckr;		/* k-bytes received to clients */
  unsigned int is_sks;		/* k-bytes sent to servers */
  unsigned int is_skr;		/* k-bytes received to servers */
  time_t is_cti;		/* time spent connected by clients */
  time_t is_sti;		/* time spent connected by servers */
  unsigned int is_ac;		/* connections accepted */
  unsigned int is_ref;		/* accepts refused */
  unsigned int is_unco;		/* unknown commands */
  unsigned int is_wrdi;		/* command going in wrong direction */
  unsigned int is_unpf;		/* unknown prefix */
  unsigned int is_empt;		/* empty message */
  unsigned int is_num;		/* numeric message */
  unsigned int is_kill;		/* number of kills generated on collisions */
  unsigned int is_fake;		/* MODE 'fakes' */
  unsigned int is_asuc;		/* successful auth requests */
  unsigned int is_abad;		/* bad auth requests */
  unsigned int is_udp;		/* packets recv'd on udp port */
  unsigned int is_loc;		/* local connections made */
};

/*=============================================================================
 * Proto types
 */

extern int check_registered(aClient *sptr);
extern int check_registered_user(aClient *sptr);
extern int exit_client(aClient *cptr, aClient *bcptr,
    aClient *sptr, char *comment);
extern char *myctime(time_t value);
extern char *get_client_name(aClient *sptr, int showip);
extern int exit_client_msg(aClient *cptr, aClient *bcptr,
    aClient *sptr, char *pattern, ...) __attribute__ ((format(printf, 4, 5)));
extern void initstats(void);
extern char *date(time_t clock);
extern char *get_client_host(aClient *cptr);
extern void get_sockhost(aClient *cptr, char *host);
extern char *my_name_for_link(char *name, aConfItem *aconf);
extern int vexit_client_msg(aClient *cptr, aClient *bcptr,
    aClient *sptr, char *pattern, va_list vl);
extern void checklist(void);
extern void tstats(aClient *cptr, char *name);

extern struct stats *ircstp;

#endif /* S_MISC_H */
