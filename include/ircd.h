/** @file ircd.h
 * @brief Global data for the daemon.
 */
#ifndef INCLUDED_ircd_h
#define INCLUDED_ircd_h
#ifndef INCLUDED_struct_h
#include "struct.h"           /* struct Client */
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>        /* size_t, time_t */
#endif

/** Describes status for a daemon. */
struct Daemon
{
  int          argc;        /**< Number of command-line arguments. */
  char**       argv;        /**< Array of command-line arguments. */
  pid_t        pid;         /**< %Daemon's process id. */
  uid_t        uid;         /**< %Daemon's user id. */
  uid_t        euid;        /**< %Daemon's effective user id. */
  unsigned int bootopt;     /**< Boot option flags. */
  int          pid_fd;      /**< File descriptor for process id file. */
};

/** Describes pending exit. */
struct PendingExit
{
  int          restart;     /**< Pending exit is for a restart. */
  char*        who;         /**< Who initiated the exit. */
  char*        message;     /**< Message to emit. */
  time_t       time;        /**< Absolute time at which to exit. */
};

/*
 * Macros
 */
#define TStime() (CurrentTime + TSoffset) /**< Current network time*/
#define OLDEST_TS 780000000	/**< Any TS older than this is bogus */
#define BadPtr(x) (!(x) || (*(x) == '\0')) /**< Is \a x a bad string? */
#define IRCD_MAX(a, b)  ((a) > (b) ? (a) : (b)) /**< Find maximum of \a a and \a b. */
#define IRCD_MIN(a, b)  ((a) < (b) ? (a) : (b)) /**< Find minimum of \a a and \a b. */

/* Miscellaneous defines */

#define UDP_PORT        "7007"  /**< Default port for server-to-server pings. */
#define MINOR_PROTOCOL  "10"    /**< Minimum protocol version supported. */
#define MAJOR_PROTOCOL  "10"    /**< Current protocol version. */
#define BASE_VERSION    "u2.10" /**< Base name of IRC daemon version. */

#define PEND_INT_LONG   300     /**< Length of long message interval. */
#define PEND_INT_MEDIUM  60     /**< Length of medium message interval. */
#define PEND_INT_SHORT   30     /**< Length of short message interval. */
#define PEND_INT_END     10     /**< Length of the end message interval. */
#define PEND_INT_LAST     1     /**< Length of last message interval. */

/*
 * Proto types
 */
extern void server_panic(const char* message);

extern void exit_cancel(struct Client *who);
extern void exit_schedule(int restart, time_t when, struct Client *who,
			  const char *message);

extern struct Client  me;
extern time_t         CurrentTime;
extern struct Client* GlobalClientList;
extern time_t         TSoffset;
extern char*          configfile;
extern int            debuglevel;
extern char*          debugmode;
extern int            running;
extern int            maxconnections;
extern int            maxclients;
extern int            refuse;

#endif /* INCLUDED_ircd_h */

