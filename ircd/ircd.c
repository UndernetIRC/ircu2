/*
 * IRC - Internet Relay Chat, ircd/ircd.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "sys.h"
#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#include <sys/stat.h>
#include <pwd.h>
#include <signal.h>
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HPUX
#define _KERNEL
#endif
#include <sys/resource.h>
#ifdef HPUX
#undef _KERNEL
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#ifdef USE_SYSLOG
#include <syslog.h>
#endif
#ifdef	CHROOTDIR
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#endif
#include <sys/socket.h>		/* Needed for AF_INET on some OS */
#include "h.h"
#include "res.h"
#include "struct.h"
#include "s_serv.h"
#include "send.h"
#include "ircd.h"
#include "s_conf.h"
#include "class.h"
#include "s_misc.h"
#include "parse.h"
#include "match.h"
#include "s_bsd.h"
#include "crule.h"
#include "userload.h"
#include "numeric.h"
#include "hash.h"
#include "bsd.h"
#include "version.h"
#include "whowas.h"
#include "numnicks.h"

RCSTAG_CC("$Id$");

extern void init_counters(void);

aClient me;			/* That's me */
aClient *client = &me;		/* Pointer to beginning of Client list */
time_t TSoffset = 0;		/* Global variable; Offset of timestamps to
				   system clock */

char **myargv;
unsigned short int portnum = 0;	/* Server port number, listening this */
char *configfile = CPATH;	/* Server configuration file */
int debuglevel = -1;		/* Server debug level */
unsigned int bootopt = 0;	/* Server boot option flags */
char *debugmode = "";		/*  -"-    -"-   -"-  */
int dorehash = 0;
int restartFlag = 0;
static char *dpath = DPATH;

time_t nextconnect = 1;		/* time for next try_connections call */
time_t nextping = 1;		/* same as above for check_pings() */
time_t nextdnscheck = 0;	/* next time to poll dns to force timeouts */
time_t nextexpire = 1;		/* next expire run on the dns cache */

time_t now;			/* Updated every time we leave select(),
				   and used everywhere else */

#ifdef PROFIL
extern etext(void);

RETSIGTYPE s_monitor(HANDLER_ARG(int UNUSED(sig)))
{
  static int mon = 0;
#ifdef POSIX_SIGNALS
  struct sigaction act;
#endif

  moncontrol(mon);
  mon = 1 - mon;
#ifdef POSIX_SIGNALS
  act.sa_handler = s_rehash;
  act.sa_flags = 0;
  sigemptyset(&act.sa_mask);
  sigaddset(&act.sa_mask, SIGUSR1);
  sigaction(SIGUSR1, &act, NULL);
#else
  signal(SIGUSR1, s_monitor);
#endif
}

#endif

RETSIGTYPE s_die(HANDLER_ARG(int UNUSED(sig)))
{
#ifdef	USE_SYSLOG
  syslog(LOG_CRIT, "Server Killed By SIGTERM");
#endif
  flush_connections(me.fd);
  exit(-1);
}

static RETSIGTYPE s_rehash(HANDLER_ARG(int UNUSED(sig)))
{
#ifdef	POSIX_SIGNALS
  struct sigaction act;
#endif
  dorehash = 1;
#ifdef	POSIX_SIGNALS
  act.sa_handler = s_rehash;
  act.sa_flags = 0;
  sigemptyset(&act.sa_mask);
  sigaddset(&act.sa_mask, SIGHUP);
  sigaction(SIGHUP, &act, NULL);
#else
  signal(SIGHUP, s_rehash);	/* sysV -argv */
#endif
}

#ifdef	USE_SYSLOG
void restart(char *mesg)
#else
void restart(char *UNUSED(mesg))
#endif
{
#ifdef	USE_SYSLOG
  syslog(LOG_WARNING, "Restarting Server because: %s", mesg);
#endif
  server_reboot();
}

RETSIGTYPE s_restart(HANDLER_ARG(int UNUSED(sig)))
{
  restartFlag = 1;
}

void server_reboot(void)
{
  Reg1 int i;

  sendto_ops("Aieeeee!!!  Restarting server...");
  Debug((DEBUG_NOTICE, "Restarting server..."));
  flush_connections(me.fd);
  /*
   * fd 0 must be 'preserved' if either the -d or -i options have
   * been passed to us before restarting.
   */
#ifdef USE_SYSLOG
  closelog();
#endif
  for (i = 3; i < MAXCONNECTIONS; i++)
    close(i);
  if (!(bootopt & (BOOT_TTY | BOOT_DEBUG)))
    close(2);
  close(1);
  if ((bootopt & BOOT_CONSOLE) || isatty(0))
    close(0);
  if (!(bootopt & BOOT_INETD))
    execv(SPATH, myargv);
#ifdef USE_SYSLOG
  /* Have to reopen since it has been closed above */

  openlog(myargv[0], LOG_PID | LOG_NDELAY, LOG_FACILITY);
  syslog(LOG_CRIT, "execv(%s,%s) failed: %m\n", SPATH, myargv[0]);
  closelog();
#endif
  Debug((DEBUG_FATAL, "Couldn't restart server \"%s\": %s",
      SPATH, strerror(errno)));
  exit(-1);
}

/*
 * try_connections
 *
 * Scan through configuration and try new connections.
 *
 * Returns the calendar time when the next call to this
 * function should be made latest. (No harm done if this
 * is called earlier or later...)
 */
static time_t try_connections(void)
{
  Reg1 aConfItem *aconf;
  Reg2 aClient *cptr;
  aConfItem **pconf;
  int connecting, confrq;
  time_t next = 0;
  aConfClass *cltmp;
  aConfItem *cconf, *con_conf = NULL;
  unsigned int con_class = 0;

  connecting = FALSE;
  Debug((DEBUG_NOTICE, "Connection check at   : %s", myctime(now)));
  for (aconf = conf; aconf; aconf = aconf->next)
  {
    /* Also when already connecting! (update holdtimes) --SRB */
    if (!(aconf->status & CONF_CONNECT_SERVER) || aconf->port == 0)
      continue;
    cltmp = aconf->confClass;
    /*
     * Skip this entry if the use of it is still on hold until
     * future. Otherwise handle this entry (and set it on hold
     * until next time). Will reset only hold times, if already
     * made one successfull connection... [this algorithm is
     * a bit fuzzy... -- msa >;) ]
     */

    if ((aconf->hold > now))
    {
      if ((next > aconf->hold) || (next == 0))
	next = aconf->hold;
      continue;
    }

    confrq = get_con_freq(cltmp);
    aconf->hold = now + confrq;
    /*
     * Found a CONNECT config with port specified, scan clients
     * and see if this server is already connected?
     */
    cptr = FindServer(aconf->name);

    if (!cptr && (Links(cltmp) < MaxLinks(cltmp)) &&
	(!connecting || (ConClass(cltmp) > con_class)))
    {
      /* Check connect rules to see if we're allowed to try */
      for (cconf = conf; cconf; cconf = cconf->next)
	if ((cconf->status & CONF_CRULE) &&
	    (match(cconf->host, aconf->name) == 0))
	  if (crule_eval(cconf->passwd))
	    break;
      if (!cconf)
      {
	con_class = ConClass(cltmp);
	con_conf = aconf;
	/* We connect only one at time... */
	connecting = TRUE;
      }
    }
    if ((next > aconf->hold) || (next == 0))
      next = aconf->hold;
  }
  if (connecting)
  {
    if (con_conf->next)		/* are we already last? */
    {
      /* Put the current one at the end and make sure we try all connections */
      for (pconf = &conf; (aconf = *pconf); pconf = &(aconf->next))
	if (aconf == con_conf)
	  *pconf = aconf->next;
      (*pconf = con_conf)->next = 0;
    }
    if (connect_server(con_conf, (aClient *)NULL, (struct hostent *)NULL) == 0)
      sendto_ops("Connection to %s[%s] activated.",
	  con_conf->name, con_conf->host);
  }
  Debug((DEBUG_NOTICE, "Next connection check : %s", myctime(next)));
  return (next);
}

static time_t check_pings(void)
{
  Reg1 aClient *cptr;
  int ping = 0, i, rflag = 0;
  time_t oldest = 0, timeout;

  for (i = 0; i <= highest_fd; i++)
  {
    if (!(cptr = loc_clients[i]) || IsMe(cptr) || IsLog(cptr) || IsPing(cptr))
      continue;

    /*
     * Note: No need to notify opers here.
     * It's already done when "FLAGS_DEADSOCKET" is set.
     */
    if (IsDead(cptr))
    {
      exit_client(cptr, cptr, &me, LastDeadComment(cptr));
      continue;
    }

#if defined(R_LINES) && defined(R_LINES_OFTEN)
    rflag = IsUser(cptr) ? find_restrict(cptr) : 0;
#endif
    ping = IsRegistered(cptr) ? get_client_ping(cptr) : CONNECTTIMEOUT;
    Debug((DEBUG_DEBUG, "c(%s)=%d p %d r %d a %d",
	cptr->name, cptr->status, ping, rflag, (int)(now - cptr->lasttime)));
    /*
     * Ok, so goto's are ugly and can be avoided here but this code
     * is already indented enough so I think its justified. -avalon
     */
    if (!rflag && IsRegistered(cptr) && (ping >= now - cptr->lasttime))
      goto ping_timeout;
    /*
     * If the server hasnt talked to us in 2*ping seconds
     * and it has a ping time, then close its connection.
     * If the client is a user and a KILL line was found
     * to be active, close this connection too.
     */
    if (rflag ||
	((now - cptr->lasttime) >= (2 * ping) &&
	(cptr->flags & FLAGS_PINGSENT)) ||
	(!IsRegistered(cptr) && !IsHandshake(cptr) &&
	(now - cptr->firsttime) >= ping))
    {
      if (!IsRegistered(cptr) && (DoingDNS(cptr) || DoingAuth(cptr)))
      {
	Debug((DEBUG_NOTICE, "%s/%s timeout %s", DoingDNS(cptr) ? "DNS" : "",
	    DoingAuth(cptr) ? "AUTH" : "", get_client_name(cptr, TRUE)));
	if (cptr->authfd >= 0)
	{
	  close(cptr->authfd);
	  cptr->authfd = -1;
	  cptr->count = 0;
	  *cptr->buffer = '\0';
	}
	del_queries((char *)cptr);
	ClearAuth(cptr);
	ClearDNS(cptr);
	SetAccess(cptr);
	cptr->firsttime = now;
	cptr->lasttime = now;
	continue;
      }
      if (IsServer(cptr) || IsConnecting(cptr) || IsHandshake(cptr))
      {
	sendto_ops("No response from %s, closing link",
	    get_client_name(cptr, FALSE));
	exit_client(cptr, cptr, &me, "Ping timeout");
	continue;
      }
      /*
       * This is used for KILL lines with time restrictions
       * on them - send a messgae to the user being killed first.
       */
#if defined(R_LINES) && defined(R_LINES_OFTEN)
      else if (IsUser(cptr) && rflag)
      {
	sendto_ops("Restricting %s, closing link.",
	    get_client_name(cptr, FALSE));
	exit_client(cptr, cptr, &me, "R-lined");
      }
#endif
      else
      {
	if (!IsRegistered(cptr) && *cptr->name && *cptr->user->username)
	{
	  sendto_one(cptr,
	      ":%s %d %s :Your client may not be compatible with this server.",
	      me.name, ERR_BADPING, cptr->name);
	  sendto_one(cptr,
	      ":%s %d %s :Compatible clients are available at "
	      "ftp://ftp.undernet.org/pub/irc/clients",
	      me.name, ERR_BADPING, cptr->name);
	}
	exit_client_msg(cptr, cptr, &me, "Ping timeout for %s",
	    get_client_name(cptr, FALSE));
      }
      continue;
    }
    else if (IsRegistered(cptr) && (cptr->flags & FLAGS_PINGSENT) == 0)
    {
      /*
       * If we havent PINGed the connection and we havent
       * heard from it in a while, PING it to make sure
       * it is still alive.
       */
      cptr->flags |= FLAGS_PINGSENT;
      /* not nice but does the job */
      cptr->lasttime = now - ping;
      if (IsUser(cptr))
	sendto_one(cptr, "PING :%s", me.name);
      else
	sendto_one(cptr, ":%s PING :%s", me.name, me.name);
    }
  ping_timeout:
    timeout = cptr->lasttime + ping;
    while (timeout <= now)
      timeout += ping;
    if (timeout < oldest || !oldest)
      oldest = timeout;
  }
  if (!oldest || oldest < now)
    oldest = now + PINGFREQUENCY;
  Debug((DEBUG_NOTICE,
      "Next check_ping() call at: %s, %d " TIME_T_FMT " " TIME_T_FMT,
      myctime(oldest), ping, oldest, now));

  return (oldest);
}

/*
 * bad_command
 *
 * This is called when the commandline is not acceptable.
 * Give error message and exit without starting anything.
 */
static int bad_command(void)
{
  printf("Usage: ircd %s[-h servername] [-p portnumber] [-x loglevel] [-t]\n",
#ifdef CMDLINE_CONFIG
      "[-f config] "
#else
      ""
#endif
      );
  printf("Server not started\n\n");
  return (-1);
}

static void setup_signals(void)
{
#ifdef	POSIX_SIGNALS
  struct sigaction act;

  act.sa_handler = SIG_IGN;
  act.sa_flags = 0;
  sigemptyset(&act.sa_mask);
  sigaddset(&act.sa_mask, SIGPIPE);
  sigaddset(&act.sa_mask, SIGALRM);
#ifdef	SIGWINCH
  sigaddset(&act.sa_mask, SIGWINCH);
  sigaction(SIGWINCH, &act, NULL);
#endif
  sigaction(SIGPIPE, &act, NULL);
  act.sa_handler = dummy;
  sigaction(SIGALRM, &act, NULL);
  act.sa_handler = s_rehash;
  sigemptyset(&act.sa_mask);
  sigaddset(&act.sa_mask, SIGHUP);
  sigaction(SIGHUP, &act, NULL);
  act.sa_handler = s_restart;
  sigaddset(&act.sa_mask, SIGINT);
  sigaction(SIGINT, &act, NULL);
  act.sa_handler = s_die;
  sigaddset(&act.sa_mask, SIGTERM);
  sigaction(SIGTERM, &act, NULL);

#else
#ifndef HAVE_RELIABLE_SIGNALS
  signal(SIGPIPE, dummy);
#ifdef	SIGWINCH
  signal(SIGWINCH, dummy);
#endif
#else
#ifdef	SIGWINCH
  signal(SIGWINCH, SIG_IGN);
#endif
  signal(SIGPIPE, SIG_IGN);
#endif
  signal(SIGALRM, dummy);
  signal(SIGHUP, s_rehash);
  signal(SIGTERM, s_die);
  signal(SIGINT, s_restart);
#endif

#ifdef HAVE_RESTARTABLE_SYSCALLS
  /*
   * At least on Apollo sr10.1 it seems continuing system calls
   * after signal is the default. The following 'siginterrupt'
   * should change that default to interrupting calls.
   */
  siginterrupt(SIGALRM, 1);
#endif
}

/*
 * open_debugfile
 *
 * If the -t option is not given on the command line when the server is
 * started, all debugging output is sent to the file set by LPATH in config.h
 * Here we just open that file and make sure it is opened to fd 2 so that
 * any fprintf's to stderr also goto the logfile.  If the debuglevel is not
 * set from the command line by -x, use /dev/null as the dummy logfile as long
 * as DEBUGMODE has been defined, else dont waste the fd.
 */
static void open_debugfile(void)
{
#ifdef	DEBUGMODE
  int fd;
  aClient *cptr;

  if (debuglevel >= 0)
  {
    cptr = make_client(NULL, STAT_LOG);
    cptr->fd = 2;
    cptr->port = debuglevel;
    cptr->flags = 0;
    cptr->acpt = cptr;
    loc_clients[2] = cptr;
    strcpy(cptr->sockhost, me.sockhost);

    printf("isatty = %d ttyname = %#x\n", isatty(2), (unsigned int)ttyname(2));
    if (!(bootopt & BOOT_TTY))	/* leave debugging output on fd 2 */
    {
      if ((fd = creat(LOGFILE, 0600)) < 0)
	if ((fd = open("/dev/null", O_WRONLY)) < 0)
	  exit(-1);
      if (fd != 2)
      {
	dup2(fd, 2);
	close(fd);
      }
      strncpy(cptr->name, LOGFILE, sizeof(cptr->name));
      cptr->name[sizeof(cptr->name) - 1] = 0;
    }
    else if (isatty(2) && ttyname(2))
    {
      strncpy(cptr->name, ttyname(2), sizeof(cptr->name));
      cptr->name[sizeof(cptr->name) - 1] = 0;
    }
    else
      strcpy(cptr->name, "FD2-Pipe");
    Debug((DEBUG_FATAL, "Debug: File <%s> Level: %u at %s",
	cptr->name, cptr->port, myctime(now)));
  }
  else
    loc_clients[2] = NULL;
#endif
  return;
}

int have_server_port;

int main(int argc, char *argv[])
{
  unsigned short int portarg = 0;
  uid_t uid;
  uid_t euid;
  time_t delay = 0;
#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
  struct rlimit corelim;
#endif

  uid = getuid();
  euid = geteuid();
  now = time(NULL);
#ifdef PROFIL
  monstartup(0, etext);
  moncontrol(1);
  signal(SIGUSR1, s_monitor);
#endif

#ifdef CHROOTDIR
  if (chdir(DPATH))
  {
    fprintf(stderr, "Fail: Cannot chdir(%s): %s\n", DPATH, strerror(errno));
    exit(-1);
  }
  res_init();
  if (chroot(DPATH))
  {
    fprintf(stderr, "Fail: Cannot chroot(%s): %s\n", DPATH, strerror(errno));
    exit(5);
  }
  dpath = "/";
#endif /*CHROOTDIR */

  myargv = argv;
  umask(077);			/* better safe than sorry --SRB */
  memset(&me, 0, sizeof(me));
  memset(&vserv, 0, sizeof(vserv));
  vserv.sin_family = AF_INET;
  vserv.sin_addr.s_addr = htonl(INADDR_ANY);
  memset(&cserv, 0, sizeof(cserv));
  cserv.sin_addr.s_addr = htonl(INADDR_ANY);
  cserv.sin_family = AF_INET;

  setup_signals();
  initload();

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
  if (getrlimit(RLIMIT_CORE, &corelim))
  {
    fprintf(stderr, "Read of rlimit core size failed: %s\n", strerror(errno));
    corelim.rlim_max = RLIM_INFINITY;	/* Try to recover */
  }
  corelim.rlim_cur = corelim.rlim_max;
  if (setrlimit(RLIMIT_CORE, &corelim))
    fprintf(stderr, "Setting rlimit core size failed: %s\n", strerror(errno));
#endif

  /*
   * All command line parameters have the syntax "-fstring"
   * or "-f string" (e.g. the space is optional). String may
   * be empty. Flag characters cannot be concatenated (like
   * "-fxyz"), it would conflict with the form "-fstring".
   */
  while (--argc > 0 && (*++argv)[0] == '-')
  {
    char *p = argv[0] + 1;
    int flag = *p++;

    if (flag == '\0' || *p == '\0')
    {
      if (argc > 1 && argv[1][0] != '-')
      {
	p = *++argv;
	argc -= 1;
      }
      else
	p = "";
    }

    switch (flag)
    {
      case 'a':
	bootopt |= BOOT_AUTODIE;
	break;
      case 'c':
	bootopt |= BOOT_CONSOLE;
	break;
      case 'q':
	bootopt |= BOOT_QUICK;
	break;
      case 'd':
	if (euid != uid)
	  setuid((uid_t) uid);
	dpath = p;
	break;
#ifdef CMDLINE_CONFIG
      case 'f':
	if (euid != uid)
	  setuid((uid_t) uid);
	configfile = p;
	break;
#endif
      case 'h':
	strncpy(me.name, p, sizeof(me.name));
	me.name[sizeof(me.name) - 1] = 0;
	break;
      case 'i':
	bootopt |= BOOT_INETD | BOOT_AUTODIE;
	break;
      case 'p':
	if ((portarg = atoi(p)) > 0)
	  portnum = portarg;
	break;
      case 't':
	if (euid != uid)
	  setuid((uid_t) uid);
	bootopt |= BOOT_TTY;
	break;
      case 'v':
	printf("ircd %s\n", version);
	exit(0);
      case 'w':
      {
	struct hostent *hep;
	if (!(hep = gethostbyname(p)))
	{
	  fprintf(stderr, "%s: Error resolving \"%s\" (h_errno == %d).\n",
	      argv[-1], p, h_errno);
	  return -1;
	}
	if (hep->h_addrtype == AF_INET && hep->h_addr_list[0] &&
	    !hep->h_addr_list[1])
	{
	  int fd;
	  memcpy(&vserv.sin_addr, hep->h_addr_list[0], sizeof(struct in_addr));
	  memcpy(&cserv.sin_addr, hep->h_addr_list[0], sizeof(struct in_addr));
	  /* Test if we can bind to this address */
   	  fd = socket(AF_INET, SOCK_STREAM, 0);
          if (bind(fd, (struct sockaddr *)&vserv, sizeof(vserv)) == 0)
	  {
	    close(fd);
	    break;
	  }
	}
	fprintf(stderr, "%s:\tError binding to interface \"%s\".\n"
	    "   \tUse `ifconfig -a' to check your interfaces.\n", argv[-1], p);
	return -1;
      }
      case 'x':
#ifdef	DEBUGMODE
	if (euid != uid)
	  setuid((uid_t) uid);
	debuglevel = atoi(p);
	debugmode = *p ? p : "0";
	bootopt |= BOOT_DEBUG;
	break;
#else
	fprintf(stderr, "%s: DEBUGMODE must be defined for -x y\n", myargv[0]);
	exit(0);
#endif
      default:
	bad_command();
	break;
    }
  }

  if (chdir(dpath))
  {
    fprintf(stderr, "Fail: Cannot chdir(%s): %s\n", dpath, strerror(errno));
    exit(-1);
  }

#ifndef IRC_UID
  if ((uid != euid) && !euid)
  {
    fprintf(stderr,
	"ERROR: do not run ircd setuid root. Make it setuid a normal user.\n");
    exit(-1);
  }
#endif

#if !defined(CHROOTDIR) || (defined(IRC_UID) && defined(IRC_GID))
#ifndef _AIX
  if (euid != uid)
  {
    setuid((uid_t) uid);
    setuid((uid_t) euid);
  }
#endif

  if ((int)getuid() == 0)
  {
#if defined(IRC_UID) && defined(IRC_GID)

    /* run as a specified user */
    fprintf(stderr, "WARNING: running ircd with uid = %d\n", IRC_UID);
    fprintf(stderr, "	      changing to gid %d.\n", IRC_GID);
    setuid(IRC_UID);
    setgid(IRC_GID);
#else
    /* check for setuid root as usual */
    fprintf(stderr,
	"ERROR: do not run ircd setuid root. Make it setuid a normal user.\n");
    exit(-1);
#endif
  }
#endif /*CHROOTDIR/UID/GID */

  if (argc > 0)
    return bad_command();	/* This should exit out */

#if HAVE_UNISTD_H
  /* Sanity checks */
  {
    char c;
    char *path;

    c = 'S';
    path = SPATH;
    if (access(path, X_OK) == 0)
    {
      c = 'C';
      path = CPATH;
      if (access(path, R_OK) == 0)
      {
	c = 'M';
	path = MPATH;
	if (access(path, R_OK) == 0)
	{
	  c = 'R';
	  path = RPATH;
	  if (access(path, R_OK) == 0)
	  {
#ifndef DEBUG
            c = 0;
#else
            c = 'L';
            path = LPATH;
            if (access(path, W_OK) == 0)
              c = 0;
#endif
	  }
	}
      }
    }
    if (c)
    {
      fprintf(stderr, "Check on %cPATH (%s) failed: %s\n",
	  c, path, strerror(errno));
      fprintf(stderr,
	  "Please create file and/or rerun `make config' and recompile to correct this.\n");
#ifdef CHROOTDIR
      fprintf(stderr,
	  "Keep in mind that all paths are relative to CHROOTDIR.\n");
#endif
      exit(-1);
    }
  }
#endif

  hash_init();
#ifdef DEBUGMODE
  initlists();
#endif
  initclass();
  initwhowas();
  initmsgtree();
  initstats();
  open_debugfile();
  init_sys();
  me.flags = FLAGS_LISTEN;
  if ((bootopt & BOOT_INETD))
  {
    me.fd = 0;
    loc_clients[0] = &me;
    me.flags = FLAGS_LISTEN;
  }
  else
    me.fd = -1;

#ifdef USE_SYSLOG
  openlog(myargv[0], LOG_PID | LOG_NDELAY, LOG_FACILITY);
#endif
  if (initconf(bootopt) == -1)
  {
    Debug((DEBUG_FATAL, "Failed in reading configuration file %s", configfile));
    printf("Couldn't open configuration file %s\n", configfile);
    exit(-1);
  }
  if (!(bootopt & BOOT_INETD))
  {
    Debug((DEBUG_ERROR, "Port = %u", portnum));
    if (!have_server_port && inetport(&me, "*", "", portnum))
      exit(1);
  }
  else if (inetport(&me, "*", "*", 0))
    exit(1);

  read_tlines();
  rmotd = read_motd(RPATH);
  motd = read_motd(MPATH);
  setup_ping();
  get_my_name(&me, me.sockhost, sizeof(me.sockhost) - 1);
  now = time(NULL);
  me.hopcount = 0;
  me.authfd = -1;
  me.confs = NULL;
  me.next = NULL;
  me.user = NULL;
  me.from = &me;
  SetMe(&me);
  make_server(&me);
  /* Abuse own link timestamp as start timestamp: */
  me.serv->timestamp = TStime();
  me.serv->prot = atoi(MAJOR_PROTOCOL);
  me.serv->up = &me;
  me.serv->down = NULL;

  SetYXXCapacity(&me, MAXCLIENTS);

  me.lasttime = me.since = me.firsttime = now;
  hAddClient(&me);

  check_class();
  write_pidfile();

  init_counters();

  Debug((DEBUG_NOTICE, "Server ready..."));
#ifdef USE_SYSLOG
  syslog(LOG_NOTICE, "Server Ready");
#endif

  for (;;)
  {
    /*
     * We only want to connect if a connection is due,
     * not every time through.   Note, if there are no
     * active C lines, this call to Tryconnections is
     * made once only; it will return 0. - avalon
     */
    if (nextconnect && now >= nextconnect)
      nextconnect = try_connections();
    /*
     * DNS checks. One to timeout queries, one for cache expiries.
     */
    if (now >= nextdnscheck)
      nextdnscheck = timeout_query_list();
    if (now >= nextexpire)
      nextexpire = expire_cache();
    /*
     * Take the smaller of the two 'timed' event times as
     * the time of next event (stops us being late :) - avalon
     * WARNING - nextconnect can return 0!
     */
    if (nextconnect)
      delay = MIN(nextping, nextconnect);
    else
      delay = nextping;
    delay = MIN(nextdnscheck, delay);
    delay = MIN(nextexpire, delay);
    delay -= now;
    /*
     * Adjust delay to something reasonable [ad hoc values]
     * (one might think something more clever here... --msa)
     * We don't really need to check that often and as long
     * as we don't delay too long, everything should be ok.
     * waiting too long can cause things to timeout...
     * i.e. PINGS -> a disconnection :(
     * - avalon
     */
    if (delay < 1)
      delay = 1;
    else
      delay = MIN(delay, TIMESEC);
    read_message(delay);

    Debug((DEBUG_DEBUG, "Got message(s)"));

    /*
     * ...perhaps should not do these loops every time,
     * but only if there is some chance of something
     * happening (but, note that conf->hold times may
     * be changed elsewhere--so precomputed next event
     * time might be too far away... (similarly with
     * ping times) --msa
     */
    if (now >= nextping)
      nextping = check_pings();

    if (dorehash)
    {
      rehash(&me, 1);
      dorehash = 0;
    }
    if (restartFlag)
      server_reboot();
  }
}
