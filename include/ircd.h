/*
 * ircd.h
 *
 * $Id$
 */
#ifndef INCLUDED_ircd_h
#define INCLUDED_ircd_h
#ifndef INCLUDED_struct_h
#include "struct.h"           /* struct Client */
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>        /* size_t, time_t */
#endif

struct Daemon
{
  int          argc;
  char**       argv;
  pid_t        pid;
  uid_t        uid;
  uid_t        euid;
  unsigned int bootopt;
  int          running;
  int          pid_fd;
  const char*  server_bin;
  const char*  server_root;
  const char*  server_log;
};

/*
 * Macros
 */
#define TStime() (CurrentTime + TSoffset)
#define OLDEST_TS 780000000	/* Any TS older than this is bogus */
#define BadPtr(x) (!(x) || (*(x) == '\0'))

/* Miscellaneous defines */

#define UDP_PORT        "7007"
#define MINOR_PROTOCOL  "09"
#define MAJOR_PROTOCOL  "10"
#define BASE_VERSION    "u2.10"

/*
 * Proto types
 */
extern void server_die(const char* message);
extern void server_panic(const char* message);
extern void server_restart(const char* message);

extern struct Client  me;
extern time_t         CurrentTime;
extern struct Client* GlobalClientList;
extern time_t         TSoffset;
extern time_t         nextdnscheck;
extern time_t         nextconnect;
extern int            GlobalRehashFlag;      /* 1 if SIGHUP is received */
extern int            GlobalRestartFlag;     /* 1 if SIGINT is received */
extern time_t         nextping;
extern char*          configfile;
extern int            debuglevel;
extern char*          debugmode;
extern int	      running;

#endif /* INCLUDED_ircd_h */

