#ifndef OPERCMDS_H
#define OPERCMDS_H

/*=============================================================================
 * General defines
 */

/*-----------------------------------------------------------------------------
 * Macro's
 */

#define GLINE_ACTIVE	1
#define GLINE_IPMASK	2
#define GLINE_LOCAL	4

/*
 * G-line macros.
 */

#define GlineIsActive(g)	((g)->gflags & GLINE_ACTIVE)
#define GlineIsIpMask(g)	((g)->gflags & GLINE_IPMASK)
#define GlineIsLocal(g)		((g)->gflags & GLINE_LOCAL)

#define SetActive(g)		((g)->gflags |= GLINE_ACTIVE)
#define ClearActive(g)		((g)->gflags &= ~GLINE_ACTIVE)
#define SetGlineIsIpMask(g)	((g)->gflags |= GLINE_IPMASK)
#define SetGlineIsLocal(g)	((g)->gflags |= GLINE_LOCAL)

/*=============================================================================
 * Structures
 */

struct Gline {
  struct Gline *next;
  char *host;
  char *reason;
  char *name;
  time_t expire;
  unsigned int gflags;
};

/*=============================================================================
 * Proto types
 */

#if defined(OPER_REHASH) || defined(LOCOP_REHASH)
extern int m_rehash(aClient *cptr, aClient *sptr, int parc, char *parv[]);
#endif
#if defined(OPER_RESTART) || defined(LOCOP_RESTART)
extern int m_restart(aClient *cptr, aClient *sptr, int parc, char *parv[]);
#endif
#if defined(OPER_DIE) || defined(LOCOP_DIE)
extern int m_die(aClient *cptr, aClient *sptr, int parc, char *parv[]);
#endif
extern int m_squit(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_stats(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_connect(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_wallops(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_time(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_settime(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_rping(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_rpong(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_trace(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_close(aClient *cptr, aClient *sptr, int parc, char *parv[]);
extern int m_gline(aClient *cptr, aClient *sptr, int parc, char *parv[]);

#endif /* OPERCMDS_H */
