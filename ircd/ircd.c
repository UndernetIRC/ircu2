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
 *
 * $Id$
 */
#include "ircd.h"
#include "IPcheck.h"
#include "class.h"
#include "client.h"
#include "crule.h"
#include "hash.h"
#include "ircd_alloc.h" /* set_nomem_handler */
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_signal.h"
#include "ircd_string.h"
#include "jupe.h"
#include "list.h"
#include "listener.h"
#include "match.h"
#include "numeric.h"
#include "numnicks.h"
#include "parse.h"
#include "res.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "sys.h"
#include "uping.h"
#include "userload.h"
#include "version.h"
#include "whowas.h"
#include "msg.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>

extern void init_counters(void);

enum {
  BOOT_DEBUG = 1,
  BOOT_TTY   = 2
};

struct Client  me;                      /* That's me */
struct Client* GlobalClientList = &me;  /* Pointer to beginning of Client list */
time_t         TSoffset = 0;      /* Offset of timestamps to system clock */
int            GlobalRehashFlag = 0;    /* do a rehash if set */
int            GlobalRestartFlag = 0;   /* do a restart if set */
time_t         CurrentTime;       /* Updated every time we leave select() */

static struct Daemon thisServer = { 0 };     /* server process info */

char *configfile = CPATH;       /* Server configuration file */
int debuglevel = -1;            /* Server debug level */
char *debugmode = "";           /*  -"-    -"-   -"-  */
static char *dpath = DPATH;

time_t nextconnect = 1;         /* time for next try_connections call */
time_t nextping = 1;            /* same as above for check_pings() */
time_t nextdnscheck = 0;        /* next time to poll dns to force timeouts */
time_t nextexpire = 1;          /* next expire run on the dns cache */

#ifdef PROFIL
extern etext(void);
#endif

static void server_reboot(const char* message)
{
  sendto_opmask_butone(0, SNO_OLDSNO, "Restarting server: %s", message);
  Debug((DEBUG_NOTICE, "Restarting server..."));
  flush_connections(0);

  close_log();
  close_connections(!(thisServer.bootopt & (BOOT_TTY | BOOT_DEBUG)));

  execv(SPATH, thisServer.argv);

  /*
   * Have to reopen since it has been closed above
   */
  open_log(*thisServer.argv);
  ircd_log(L_CRIT, "execv(%s,%s) failed: %m\n", SPATH, *thisServer.argv);

  Debug((DEBUG_FATAL, "Couldn't restart server \"%s\": %s",
         SPATH, (strerror(errno)) ? strerror(errno) : ""));
  exit(2);
}

void server_die(const char* message)
{
  ircd_log(L_CRIT, "Server terminating: %s", message);
  sendto_opmask_butone(0, SNO_OLDSNO, "Server terminating: %s", message);
  flush_connections(0);
  close_connections(1);
  thisServer.running = 0;
}

void server_restart(const char* message)
{
  static int restarting = 0;

  ircd_log(L_WARNING, "Restarting Server: %s", message);
  if (restarting == 0) {
    restarting = 1;
    server_reboot(message);
  }
}

static void outofmemory(void)
{
  Debug((DEBUG_FATAL, "Out of memory: restarting server..."));
  server_restart("Out of Memory");
} 

static void write_pidfile(void)
{
#ifdef PPATH
  int fd;
  char buff[20];
  if ((fd = open(PPATH, O_CREAT | O_WRONLY, 0600)) == -1) {
    Debug((DEBUG_NOTICE, "Error opening pid file \"%s\": %s",
           PPATH, strerror(errno)));
    return;
  }
  memset(buff, 0, sizeof(buff));
  sprintf(buff, "%5d\n", getpid());
  if (write(fd, buff, strlen(buff)) == -1)
    Debug((DEBUG_NOTICE, "Error writing to pid file %s", PPATH));
  close(fd);
#endif
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
  struct ConfItem*  aconf;
  struct Client*    cptr;
  struct ConfItem** pconf;
  int               connecting;
  int               confrq;
  time_t            next = 0;
  struct ConfClass* cltmp;
  struct ConfItem*  cconf;
  struct ConfItem*  con_conf = NULL;
  struct Jupe*      ajupe;
  unsigned int      con_class = 0;

  connecting = FALSE;
  Debug((DEBUG_NOTICE, "Connection check at   : %s", myctime(CurrentTime)));
  for (aconf = GlobalConfList; aconf; aconf = aconf->next)
  {
    /* Also when already connecting! (update holdtimes) --SRB */
    if (!(aconf->status & CONF_SERVER) || aconf->port == 0)
      continue;

    /* Also skip juped servers */
    if ((ajupe = jupe_find(aconf->name)) && JupeIsActive(ajupe))
      continue;

    cltmp = aconf->confClass;
    /*
     * Skip this entry if the use of it is still on hold until
     * future. Otherwise handle this entry (and set it on hold
     * until next time). Will reset only hold times, if already
     * made one successfull connection... [this algorithm is
     * a bit fuzzy... -- msa >;) ]
     */

    if ((aconf->hold > CurrentTime))
    {
      if ((next > aconf->hold) || (next == 0))
        next = aconf->hold;
      continue;
    }

    confrq = get_con_freq(cltmp);
    aconf->hold = CurrentTime + confrq;
    /*
     * Found a CONNECT config with port specified, scan clients
     * and see if this server is already connected?
     */
    cptr = FindServer(aconf->name);

    if (!cptr && (Links(cltmp) < MaxLinks(cltmp)) &&
        (!connecting || (ConClass(cltmp) > con_class)))
    {
      /* Check connect rules to see if we're allowed to try */
      for (cconf = GlobalConfList; cconf; cconf = cconf->next)
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
    if (con_conf->next)         /* are we already last? */
    {
      /* Put the current one at the end and make sure we try all connections */
      for (pconf = &GlobalConfList; (aconf = *pconf); pconf = &(aconf->next))
        if (aconf == con_conf)
          *pconf = aconf->next;
      (*pconf = con_conf)->next = 0;
    }
    if (connect_server(con_conf, 0, 0))
      sendto_opmask_butone(0, SNO_OLDSNO, "Connection to %s activated.",
			   con_conf->name);
  }
  Debug((DEBUG_NOTICE, "Next connection check : %s", myctime(next)));
  return (next);
}

static time_t check_pings(void)
{
 int expire=0; 
             /* Temp to figure out what time this connection will next need
              * to be checked.
              */
 int next_check = CurrentTime + PINGFREQUENCY;
 	    /*
 	     * The current lowest expire time - ie: the time that check_pings
 	     * needs to be called next.
 	     */
 int max_ping = 0;
            /* 
             * The time you've got before a ping is sent/your connection is
             * terminated.
             */
             
 int i=0; /* loop counter */
  
 /* Scan through the client table */
 for (i=0; i <= HighestFd; i++) {
   struct Client *cptr;
   
   cptr = LocalClientArray[i];
   
   /* Skip empty entries */
   if (!cptr)
     continue;
     
   assert(&me != cptr); /* I should never be in the local client array,
   			 * so if I am, dying is a good thing(tm).
   			 */
   
   /* Remove dead clients.
    * We will have sent opers a message when we set the dead flag,
    * so don't bother to send one now.
    */
   if (IsDead(cptr)) {
     exit_client(cptr, cptr, &me, cptr->info);
     continue;
   }

   /* Should we concider adding a class 0 for 'unregistered clients',
    * where we can specify their 'ping timeout' etc?
    */
   max_ping = IsRegistered(cptr) ? get_client_ping(cptr) : CONNECTTIMEOUT;
   
   Debug((DEBUG_DEBUG, "check_pings(%s)=status:%s limit: %d current: %d",
          cptr->name, (cptr->flags & FLAGS_PINGSENT) ? "[Ping Sent]" : "[]", 
          max_ping, (int)(CurrentTime - cptr->lasttime)));
          
   /* Ok, the thing that will happen most frequently, is that someone will
    * have sent something recently.  Cover this first for speed.
    */
   if (CurrentTime-cptr->lasttime < max_ping) {
   	expire=cptr->lasttime + max_ping;
   	if (expire<next_check) 
   	  next_check=expire;
   	continue;
   }

   /* Quit the client after max_ping*2 - they should have answered by now */
   if (CurrentTime-cptr->lasttime >= (max_ping*2) ) {
      
      /* If it was a server, then tell ops about it. */
      if (IsServer(cptr) || IsConnecting(cptr) || IsHandshake(cptr))
	sendto_opmask_butone(0, SNO_OLDSNO,
			     "No response from %s, closing link", cptr->name);

      exit_client_msg(cptr, cptr, &me, "Ping timeout");
      continue;
    } /* of testing to see if ping has been sent */
    
    /* Unregistered clients pingout after max_ping seconds, they don't
     * get given a second chance - if they were then people could not quite
     * finish registration and hold resources without being subject to k/g
     * lines
     */
    if (!IsRegistered(cptr)) {
      /* Display message if they have sent a NICK and a USER but no
       * nospoof PONG.
       */
      if (*cptr->name && cptr->user && *cptr->user->username) {
	send_reply(cptr, SND_EXPLICIT | ERR_BADPING,
		   ":Your client may not be compatible with this server.");
	send_reply(cptr, SND_EXPLICIT | ERR_BADPING,
		   ":Compatible clients are available at "
		   "ftp://ftp.undernet.org/pub/irc/clients");
      }    
      exit_client_msg(cptr,cptr,&me, "Ping Timeout");
      continue;
    } /* of not registered */
    
    if (0 == (cptr->flags & FLAGS_PINGSENT)) {
      /*
       * If we havent PINGed the connection and we havent heard from it in a
       * while, PING it to make sure it is still alive.
       */
      cptr->flags |= FLAGS_PINGSENT;

      /*
       * If we're late in noticing don't hold it against them :)
       */
      cptr->lasttime = CurrentTime - max_ping;
      
      if (IsUser(cptr))
	sendrawto_one(cptr, MSG_PING " :%s", me.name);
      else
	sendcmdto_one(&me, CMD_PING, cptr, ":%s", me.name);
    } /* of if not ping sent... */
    
    expire=cptr->lasttime+max_ping*2;
    
    if (expire<next_check)
    	next_check=expire;

  }  /* end of loop over clients */
  
  assert(next_check>=CurrentTime);
  
  Debug((DEBUG_DEBUG, "[%i] check_pings() again in %is",CurrentTime,next_check-CurrentTime));
  
  return next_check;
}

#if 0
static time_t check_pings(void)
{
  struct Client *cptr;
  int max_ping = 0;
  int i;
  time_t oldest = CurrentTime + PINGFREQUENCY;
  time_t timeout;

  /* For each client... */
  for (i = 0; i <= HighestFd; i++) {
    if (!(cptr = LocalClientArray[i])) /* oops! not a client... */
      continue;
    /*
     * me is never in the local client array
     */
    assert(cptr != &me);
    /*
     * Note: No need to notify opers here.
     * It's already done when "FLAGS_DEADSOCKET" is set.
     */
    if (IsDead(cptr)) {
      exit_client(cptr, cptr, &me, cptr->info);
      continue;
    }

    max_ping = IsRegistered(cptr) ? get_client_ping(cptr) : CONNECTTIMEOUT;
    
    Debug((DEBUG_DEBUG, "check_pings(%s)=status:%d ping: %d current: %d",
          cptr->name, cptr->status, max_ping, 
          (int)(CurrentTime - cptr->lasttime)));
          
    /*
     * Ok, so goto's are ugly and can be avoided here but this code
     * is already indented enough so I think its justified. -avalon
     */
    /*
     * If this is a registered client that we've heard of in a reasonable
     * time, then skip them.
     */
    if (IsRegistered(cptr) && (max_ping >= CurrentTime - cptr->lasttime))
      goto ping_timeout;
    /*
     * If the server hasnt talked to us in 2 * ping seconds
     * and it has a ping time, then close its connection.
     * If the client is a user and a KILL line was found
     * to be active, close this connection too.
     */
    if (((CurrentTime - cptr->lasttime) >= (2 * ping) && (cptr->flags & FLAGS_PINGSENT)) ||
        (!IsRegistered(cptr) && !IsHandshake(cptr) && (CurrentTime - cptr->firsttime) >= ping))
    {
      if (IsServer(cptr) || IsConnecting(cptr) || IsHandshake(cptr))
      {
        sendto_ops("No response from %s, closing link", cptr->name); /* XXX DEAD */
        exit_client(cptr, cptr, &me, "Ping timeout");
        continue;
      }
      else {
        if (!IsRegistered(cptr) && *cptr->name && *cptr->user->username) {
          sendto_one(cptr, /* XXX DEAD */
              ":%s %d %s :Your client may not be compatible with this server.",
              me.name, ERR_BADPING, cptr->name);
          sendto_one(cptr, /* XXX DEAD */
              ":%s %d %s :Compatible clients are available at "
              "ftp://ftp.undernet.org/pub/irc/clients",
              me.name, ERR_BADPING, cptr->name);
        }
        exit_client_msg(cptr, cptr, &me, "Ping timeout");
      }
      continue;
    }
    else if (IsRegistered(cptr) && 0 == (cptr->flags & FLAGS_PINGSENT)) {
      /*
       * If we havent PINGed the connection and we havent
       * heard from it in a while, PING it to make sure
       * it is still alive.
       */
      cptr->flags |= FLAGS_PINGSENT;
      /*
       * not nice but does the job
       */
      cptr->lasttime = CurrentTime - ping;
      if (IsUser(cptr))
        sendto_one(cptr, "PING :%s", me.name); /* XXX DEAD */
      else
        sendto_one(cptr, "%s " TOK_PING " :%s", NumServ(&me), me.name); /* XXX DEAD */
    }
ping_timeout:
    timeout = cptr->lasttime + max_ping;
    while (timeout <= CurrentTime)
      timeout += max_ping;
    if (timeout < oldest)
      oldest = timeout;
  }
  if (oldest < CurrentTime)
    oldest = CurrentTime + PINGFREQUENCY;
  Debug((DEBUG_NOTICE,
        "Next check_ping() call at: %s, %d " TIME_T_FMT " " TIME_T_FMT,
        myctime(oldest), ping, oldest, CurrentTime));

  return (oldest);
}
#endif

/*
 * bad_command
 *
 * This is called when the commandline is not acceptable.
 * Give error message and exit without starting anything.
 */
static void print_usage(void)
{
  printf("Usage: ircd [-f config] [-h servername] [-x loglevel] [-ntv]\n");
  printf("\n -n -t\t Don't detach\n -v\t display version\n\n");
  printf("Server not started\n");
}


/*
 * for getopt
 * ZZZ this is going to need confirmation on other OS's
 *
 * #include <getopt.h>
 * Solaris has getopt.h, you should too... hopefully
 * BSD declares them in stdlib.h
 * extern char *optarg;
 *
 * for FreeBSD the following are defined:
 *
 * extern char *optarg;
 * extern int optind;
 * extern in optopt;
 * extern int opterr;
 * extern in optreset;
 *
 *
 * All command line parameters have the syntax "-f string" or "-fstring"
 * OPTIONS:
 * -d filename - specify d:line file
 * -f filename - specify config file
 * -h hostname - specify server name
 * -k filename - specify k:line file (hybrid)
 * -l filename - specify log file
 * -n          - do not fork, run in foreground
 * -t          - do not fork send debugging info to tty
 * -v          - print version and exit
 * -x          - set debug level, if compiled for debug logging
 */
static void parse_command_line(int argc, char** argv)
{
  const char* options = "d:f:h:ntvx:";
  int opt;

  if (thisServer.euid != thisServer.uid)
    setuid(thisServer.uid);

  while ((opt = getopt(argc, argv, options)) != EOF) {
    switch (opt) {
    case 'd':
      if (optarg)
        dpath = optarg;
      break;
    case 'f':
      if (optarg)
        configfile = optarg;
      break;
    case 'h':
      if (optarg)
        ircd_strncpy(me.name, optarg, HOSTLEN);
      break;
    case 'n':
    case 't':
      thisServer.bootopt |= BOOT_TTY;
      break;
    case 'v':
      printf("ircd %s\n", version);
      exit(0);
    case 'x':
      if (optarg) {
        debuglevel = atoi(optarg);
        if (debuglevel < 0)
          debuglevel = 0;
        debugmode = optarg;
        thisServer.bootopt |= BOOT_DEBUG;
      }
      break;
    default:
      print_usage();
      exit(1);
    }
  }
}

/*
 * daemon_init
 */
static void daemon_init(int no_fork)
{
  if (!init_connection_limits())
    exit(2);

  close_connections(!(thisServer.bootopt & (BOOT_DEBUG | BOOT_TTY)));
  if (no_fork)
    return;

  if (fork())
    exit(0);
#ifdef TIOCNOTTY
  {
    int fd;
    if ((fd = open("/dev/tty", O_RDWR)) > -1) {
      ioctl(fd, TIOCNOTTY, 0);
      close(fd);
    }
  }
#endif
  setsid();
}


static void event_loop(void)
{
  time_t delay = 0;

  while (thisServer.running) {
    /*
     * We only want to connect if a connection is due,
     * not every time through.   Note, if there are no
     * active C lines, this call to Tryconnections is
     * made once only; it will return 0. - avalon
     */
    if (nextconnect && CurrentTime >= nextconnect)
      nextconnect = try_connections();
    /*
     * DNS checks. One to timeout queries, one for cache expiries.
     */
    nextdnscheck = timeout_resolver(CurrentTime);
    /*
     * Take the smaller of the two 'timed' event times as
     * the time of next event (stops us being late :) - avalon
     * WARNING - nextconnect can return 0!
     */
    if (nextconnect)
      delay = IRCD_MIN(nextping, nextconnect);
    else
      delay = nextping;
    delay = IRCD_MIN(nextdnscheck, delay);
    delay -= CurrentTime;
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
      delay = IRCD_MIN(delay, TIMESEC);
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
    if (CurrentTime >= nextping)
      nextping = check_pings();
    
    /*
     * timeout pending queries that haven't been responded to
     */
    timeout_auth_queries(CurrentTime);

    IPcheck_expire();
    if (GlobalRehashFlag) {
      rehash(&me, 1);
      GlobalRehashFlag = 0;
    }
    if (GlobalRestartFlag)
      server_restart("caught signal: SIGINT");
  }
}

int main(int argc, char *argv[])
{
#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
  struct rlimit corelim;
#endif

  CurrentTime = time(NULL);
  /*
   * sanity check
   */
  if (MAXCONNECTIONS < 64 || MAXCONNECTIONS > 256000) {
    fprintf(stderr, "%s: MAXCONNECTIONS insane: %d\n", *argv, MAXCONNECTIONS);
    return 2;
  }
  thisServer.argc = argc;
  thisServer.argv = argv;
  thisServer.uid  = getuid();
  thisServer.euid = geteuid();
#ifdef PROFIL
  monstartup(0, etext);
  moncontrol(1);
  signal(SIGUSR1, s_monitor);
#endif

#ifdef CHROOTDIR
  if (chdir(DPATH)) {
    fprintf(stderr, "Fail: Cannot chdir(%s): %s\n", DPATH, strerror(errno));
    exit(2);
  }
  if (chroot(DPATH)) {
    fprintf(stderr, "Fail: Cannot chroot(%s): %s\n", DPATH, strerror(errno));
    exit(5);
  }
  dpath = "/";
#endif /*CHROOTDIR */

  umask(077);                   /* better safe than sorry --SRB */
  memset(&me, 0, sizeof(me));
  me.fd = -1;

  setup_signals();
  initload();

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
  if (getrlimit(RLIMIT_CORE, &corelim))
  {
    fprintf(stderr, "Read of rlimit core size failed: %s\n", strerror(errno));
    corelim.rlim_max = RLIM_INFINITY;   /* Try to recover */
  }
  corelim.rlim_cur = corelim.rlim_max;
  if (setrlimit(RLIMIT_CORE, &corelim))
    fprintf(stderr, "Setting rlimit core size failed: %s\n", strerror(errno));
#endif
  parse_command_line(argc, argv);

  if (chdir(dpath)) {
    fprintf(stderr, "Fail: Cannot chdir(%s): %s\n", dpath, strerror(errno));
    exit(2);
  }

#ifndef IRC_UID
  if ((thisServer.uid != thisServer.euid) && !thisServer.euid) {
    fprintf(stderr,
        "ERROR: do not run ircd setuid root. Make it setuid a normal user.\n");
    exit(2);
  }
#endif

#if !defined(CHROOTDIR) || (defined(IRC_UID) && defined(IRC_GID))
  if (thisServer.euid != thisServer.uid) {
    setuid(thisServer.uid);
    setuid(thisServer.euid);
  }

  if (0 == getuid()) {
#if defined(IRC_UID) && defined(IRC_GID)

    /* run as a specified user */
    fprintf(stderr, "WARNING: running ircd with uid = %d\n", IRC_UID);
    fprintf(stderr, "         changing to gid %d.\n", IRC_GID);
    setuid(IRC_UID);
    setgid(IRC_GID);
#else
    /* check for setuid root as usual */
    fprintf(stderr,
        "ERROR: do not run ircd setuid root. Make it setuid a normal user.\n");
    exit(2);
#endif
  }
#endif /*CHROOTDIR/UID/GID */

  /* Sanity checks */
  {
    char c;
    char *path;

    c = 'S';
    path = SPATH;
    if (access(path, X_OK) == 0) {
      c = 'C';
      path = CPATH;
      if (access(path, R_OK) == 0) {
        c = 'M';
        path = MPATH;
        if (access(path, R_OK) == 0) {
          c = 'R';
          path = RPATH;
          if (access(path, R_OK) == 0) {
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
    if (c) {
      fprintf(stderr, "Check on %cPATH (%s) failed: %s\n", c, path, strerror(errno));
      fprintf(stderr,
          "Please create file and/or rerun `make config' and recompile to correct this.\n");
#ifdef CHROOTDIR
      fprintf(stderr, "Keep in mind that all paths are relative to CHROOTDIR.\n");
#endif
      exit(2);
    }
  }

  init_list();
  hash_init();
  initclass();
  initwhowas();
  initmsgtree();
  initstats();

  debug_init(thisServer.bootopt & BOOT_TTY);
  daemon_init(thisServer.bootopt & BOOT_TTY);

  set_nomem_handler(outofmemory);
  init_resolver();

  open_log(*argv);

  if (!conf_init()) {
    Debug((DEBUG_FATAL, "Failed in reading configuration file %s", configfile));
    printf("Couldn't open configuration file %s\n", configfile);
    exit(2);
  }
  if (!init_server_identity()) {
    Debug((DEBUG_FATAL, "Failed to initialize server identity"));
    exit(2);
  }
  uping_init();
  read_tlines();
  rmotd = read_motd(RPATH);
  motd = read_motd(MPATH);
  CurrentTime = time(NULL);
  me.from = &me;
  SetMe(&me);
  make_server(&me);
  /*
   * Abuse own link timestamp as start timestamp:
   */
  me.serv->timestamp = TStime();
  me.serv->prot = atoi(MAJOR_PROTOCOL);
  me.serv->up = &me;
  me.serv->down = NULL;
  me.handler = SERVER_HANDLER;

  SetYXXCapacity(&me, MAXCLIENTS);

  me.lasttime = me.since = me.firsttime = CurrentTime;
  hAddClient(&me);

  check_class();
  write_pidfile();

  init_counters();

  Debug((DEBUG_NOTICE, "Server ready..."));
  ircd_log(L_NOTICE, "Server Ready");
  thisServer.running = 1;

  event_loop();
  return 0;
}


