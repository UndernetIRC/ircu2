#ifndef IRCD_H
#define IRCD_H

/*=============================================================================
 * Macro's
 */

#define TStime() (now + TSoffset)
#define BadPtr(x) (!(x) || (*(x) == '\0'))

/* Miscellaneous defines */

#define UDP_PORT	"7007"
#define MINOR_PROTOCOL	"09"
#define MAJOR_PROTOCOL	"10"
#define BASE_VERSION	"u2.10"

/* Flags for bootup options (command line flags) */

#define BOOT_CONSOLE	1
#define BOOT_QUICK	2
#define BOOT_DEBUG	4
#define BOOT_INETD	8
#define BOOT_TTY	16
#define BOOT_AUTODIE	32

/*=============================================================================
 * Proto types
 */

#ifdef PROFIL
extern RETSIGTYPE s_monitor(HANDLER_ARG(int sig));
#endif
extern RETSIGTYPE s_die(HANDLER_ARG(int sig));
extern RETSIGTYPE s_restart(HANDLER_ARG(int sig));

extern void restart(char *mesg);
extern void server_reboot(void);

extern aClient me;
extern time_t now;
extern aClient *client;
extern time_t TSoffset;
extern unsigned int bootopt;
extern int have_server_port;
extern time_t nextdnscheck;
extern time_t nextconnect;
extern int dorehash;
extern time_t nextping;
extern unsigned short int portnum;
extern char *configfile;
extern int debuglevel;
extern char *debugmode;

#endif /* IRCD_H */
