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
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_signal.h"
#include "ircd_string.h"
#include "jupe.h"
#include "list.h"
#include "match.h"
#include "motd.h"
#include "msg.h"
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
#include "sys.h"
#include "uping.h"
#include "userload.h"
#include "version.h"
#include "whowas.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>



/*----------------------------------------------------------------------------
 * External stuff
 *--------------------------------------------------------------------------*/
extern void init_counters(void);

/*----------------------------------------------------------------------------
 * Constants / Enums
 *--------------------------------------------------------------------------*/
enum {
  BOOT_DEBUG = 1,
  BOOT_TTY   = 2
};


/*----------------------------------------------------------------------------
 * Global data (YUCK!)
 *--------------------------------------------------------------------------*/
struct Client  me;                      // That's me
struct Client *GlobalClientList  = &me; // Pointer to beginning of Client list
time_t         TSoffset          = 0;   // Offset of timestamps to system clock
int            GlobalRehashFlag  = 0;   // do a rehash if set
int            GlobalRestartFlag = 0;   // do a restart if set
time_t         CurrentTime;             // Updated every time we leave select()

char          *configfile        = CPATH; // Server configuration file
int            debuglevel        = -1;    // Server debug level 
char          *debugmode         = "";    // Server debug level
static char   *dpath             = DPATH;

time_t         nextconnect       = 1; // time for next try_connections call
time_t         nextping          = 1; // same as above for check_pings()

static struct Daemon thisServer  = { 0 };     // server process info 



/*----------------------------------------------------------------------------
 * API: server_die
 *--------------------------------------------------------------------------*/
void server_die(const char* message) {
  ircd_log(L_CRIT, "Server terminating: %s", message);
  sendto_opmask_butone(0, SNO_OLDSNO, "Server terminating: %s", message);
  flush_connections(0);
  close_connections(1);
  thisServer.running = 0;
}


/*----------------------------------------------------------------------------
 * API: server_restart
 *--------------------------------------------------------------------------*/
void server_restart(const char* message) {
  static int restarting = 0;

  ircd_log(L_WARNING, "Restarting Server: %s", message);
  if (restarting)
    return;

  sendto_opmask_butone(0, SNO_OLDSNO, "Restarting server: %s", message);
  Debug((DEBUG_NOTICE, "Restarting server..."));
  flush_connections(0);

  close_log();
  close_connections(!(thisServer.bootopt & (BOOT_TTY | BOOT_DEBUG)));

  execv(SPATH, thisServer.argv);

  /* Have to reopen since it has been closed above */
  open_log(*thisServer.argv);
  ircd_log(L_CRIT, "execv(%s,%s) failed: %m\n", SPATH, *thisServer.argv);

  Debug((DEBUG_FATAL, "Couldn't restart server \"%s\": %s",
         SPATH, (strerror(errno)) ? strerror(errno) : ""));
  exit(8);
}


/*----------------------------------------------------------------------------
 * outofmemory:  Handler for out of memory conditions...
 *--------------------------------------------------------------------------*/
static void outofmemory(void) {
  Debug((DEBUG_FATAL, "Out of memory: restarting server..."));
  server_restart("Out of Memory");
} 


/*----------------------------------------------------------------------------
 * write_pidfile
 *--------------------------------------------------------------------------*/
static void write_pidfile(void) {
  FILE *pidf;

  if (!(pidf = fopen(PPATH, "w+"))) {
    Debug((DEBUG_NOTICE, 
	   "Error opening pid file \"%s\": %s", PPATH, strerror(errno)));
    return;
  }
    
  if (fprintf(pidf, "%5d\n", getpid()) < 5)
    Debug((DEBUG_NOTICE, "Error writing to pid file %s", PPATH));

  fclose(pidf);
}


/*----------------------------------------------------------------------------
 * try_connections
 *
 * Scan through configuration and try new connections.
 *
 * Returns the calendar time when the next call to this
 * function should be made latest. (No harm done if this
 * is called earlier or later...)
 *--------------------------------------------------------------------------*/
static time_t try_connections(void) {
  struct ConfItem*  aconf;
  struct Client*    cptr;
  struct ConfItem** pconf;
  int               connecting;
  int               confrq;
  time_t            next        = 0;
  struct ConnectionClass* cltmp;
  struct ConfItem*  con_conf    = 0;
  struct Jupe*      ajupe;
  unsigned int      con_class   = 0;

  connecting = FALSE;
  Debug((DEBUG_NOTICE, "Connection check at   : %s", myctime(CurrentTime)));
  for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
    /* Also when already connecting! (update holdtimes) --SRB */
    if (!(aconf->status & CONF_SERVER) || aconf->port == 0)
      continue;

    /* Also skip juped servers */
    if ((ajupe = jupe_find(aconf->name)) && JupeIsActive(ajupe))
      continue;

    /* Skip this entry if the use of it is still on hold until
     * future. Otherwise handle this entry (and set it on hold until next
     * time). Will reset only hold times, if already made one successfull
     * connection... [this algorithm is a bit fuzzy... -- msa >;) ]
     */
    if (aconf->hold > CurrentTime && (next > aconf->hold || next == 0)) {
      next = aconf->hold;
      continue;
    }

    cltmp = aconf->conn_class;
    confrq = get_con_freq(cltmp);
    aconf->hold = CurrentTime + confrq;

    /* Found a CONNECT config with port specified, scan clients and see if
     * this server is already connected?
     */
    cptr = FindServer(aconf->name);

    if (!cptr && (Links(cltmp) < MaxLinks(cltmp)) &&
        (!connecting || (ConClass(cltmp) > con_class))) {
      /*
       * Check connect rules to see if we're allowed to try
       */
      if (0 == conf_eval_crule(aconf->name, CRULE_MASK)) {
        con_class = ConClass(cltmp);
        con_conf = aconf;
        /* We connect only one at time... */
        connecting = TRUE;
      }
    }
    if ((next > aconf->hold) || (next == 0))
      next = aconf->hold;
  }
  if (connecting) {
    if (con_conf->next) { /* are we already last? */
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
  return(next);
}


/*----------------------------------------------------------------------------
 * check_pings
 *
 * TODO: This should be moved out of ircd.c.  It's protocol-specific when you
 *       get right down to it.  Can't really be done until the server is more
 *       modular, however...
 *--------------------------------------------------------------------------*/
static time_t check_pings(void) {
  int expire     = 0; 
  int next_check = CurrentTime + PINGFREQUENCY;
  int max_ping   = 0;
  int i;
  
  /* Scan through the client table */
  for (i=0; i <= HighestFd; i++) {
    struct Client *cptr = LocalClientArray[i];
   
    if (!cptr)
      continue;
     
    assert(&me != cptr);  /* I should never be in the local client array! */
   

    /* Remove dead clients. */
    if (IsDead(cptr)) {
      exit_client(cptr, cptr, &me, cptr->info);
      continue;
    }

    max_ping = IsRegistered(cptr) ? client_get_ping(cptr) : CONNECTTIMEOUT;
   
    Debug((DEBUG_DEBUG, "check_pings(%s)=status:%s limit: %d current: %d",
	   cptr->name, (cptr->flags & FLAGS_PINGSENT) ? "[Ping Sent]" : "[]", 
	   max_ping, (int)(CurrentTime - cptr->lasttime)));
          

    /* Ok, the thing that will happen most frequently, is that someone will
     * have sent something recently.  Cover this first for speed.
     */
    if (CurrentTime-cptr->lasttime < max_ping) {
      expire = cptr->lasttime + max_ping;
      if (expire < next_check) 
	next_check = expire;
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
    }
    
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
    }
    
    if (!(cptr->flags & FLAGS_PINGSENT)) {
      /* If we havent PINGed the connection and we havent heard from it in a
       * while, PING it to make sure it is still alive.
       */
      cptr->flags |= FLAGS_PINGSENT;

      /* If we're late in noticing don't hold it against them :) */
      cptr->lasttime = CurrentTime - max_ping;
      
      if (IsUser(cptr))
	sendrawto_one(cptr, MSG_PING " :%s", me.name);
      else
	sendcmdto_one(&me, CMD_PING, cptr, ":%s", me.name);
    }
    
    expire = cptr->lasttime + max_ping * 2;
    if (expire < next_check)
      next_check=expire;
  }
  
  assert(next_check >= CurrentTime);
  
  Debug((DEBUG_DEBUG, "[%i] check_pings() again in %is",
	 CurrentTime, next_check-CurrentTime));
  
  return next_check;
}


/*----------------------------------------------------------------------------
 * parse_command_line
 * Side Effects: changes GLOBALS me, thisServer, dpath, configfile, debuglevel
 * debugmode
 *--------------------------------------------------------------------------*/
static void parse_command_line(int argc, char** argv) {
  const char *options = "d:f:h:ntvx:";
  int opt;

  if (thisServer.euid != thisServer.uid)
    setuid(thisServer.uid);

  /* Do we really need to santiy check the non-NULLness of optarg?  That's
   * getopt()'s job...  Removing those... -zs
   */
  while ((opt = getopt(argc, argv, options)) != EOF)
    switch (opt) {
    case 'n':
    case 't':  thisServer.bootopt |= BOOT_TTY;         break;
    case 'd':  dpath      = optarg;                    break;
    case 'f':  configfile = optarg;                    break;
    case 'h':  ircd_strncpy(me.name, optarg, HOSTLEN); break;
    case 'v':  printf("ircd %s\n", version);           exit(0);
      
    case 'x':
      debuglevel = atoi(optarg);
      if (debuglevel < 0)
	debuglevel = 0;
      debugmode = optarg;
      thisServer.bootopt |= BOOT_DEBUG;
      break;
      
    default:
      printf("Usage: ircd [-f config] [-h servername] [-x loglevel] [-ntv]\n");
      printf("\n -n -t\t Don't detach\n -v\t display version\n\n");
      printf("Server not started.\n");
      exit(1);
    }
}


/*----------------------------------------------------------------------------
 * daemon_init
 *--------------------------------------------------------------------------*/
static void daemon_init(int no_fork) {
  if (!init_connection_limits())
    exit(9);

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


/*----------------------------------------------------------------------------
 * event_loop
 *--------------------------------------------------------------------------*/
static void event_loop(void) {
  time_t nextdnscheck = 0;
  time_t delay        = 0;

  thisServer.running = 1;
  while (thisServer.running) {
    /* We only want to connect if a connection is due, not every time through.
     * Note, if there are no active C lines, this call to Tryconnections is
     * made once only; it will return 0. - avalon
     */
    if (nextconnect && CurrentTime >= nextconnect)
      nextconnect = try_connections();

    /* DNS checks. One to timeout queries, one for cache expiries. */
    nextdnscheck = timeout_resolver(CurrentTime);

    /* Take the smaller of the two 'timed' event times as the time of next
     * event (stops us being late :) - avalon
     * WARNING - nextconnect can return 0!
     */
    if (nextconnect)
      delay = IRCD_MIN(nextping, nextconnect);
    else
      delay = nextping;

    delay = IRCD_MIN(nextdnscheck, delay) - CurrentTime;

    /* Adjust delay to something reasonable [ad hoc values] (one might think
     * something more clever here... --msa) We don't really need to check that
     * often and as long as we don't delay too long, everything should be ok.
     * waiting too long can cause things to timeout...  i.e. PINGS -> a
     * disconnection :( - avalon
     */
    if (delay < 1)
      read_message(1);
    else
      read_message(IRCD_MIN(delay, TIMESEC));

    /* ...perhaps should not do these loops every time, but only if there is
     * some chance of something happening (but, note that conf->hold times may
     * be changed elsewhere--so precomputed next event time might be too far
     * away... (similarly with ping times) --msa
     */
    if (CurrentTime >= nextping)
      nextping = check_pings();
    
    /* timeout pending queries that haven't been responded to */
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

/*----------------------------------------------------------------------------
 * check_file_access:  random helper function to make sure that a file is
 *                     accessible in a certain way, and complain if not.
 *--------------------------------------------------------------------------*/
static char check_file_access(const char *path, char which, int mode) {
  if (!access(path, mode))
    return 1;

  fprintf(stderr, 
	  "Check on %cPATH (%s) failed: %s\n"
	  "Please create file and/or rerun `make config' and "
	  "recompile to correct this.\n",
	  which, path, strerror(errno));

#ifdef CHROOTDIR
  fprintf(stderr, "Keep in mind that paths are relative to CHROOTDIR.\n");
#endif

  return 0;
}


/*----------------------------------------------------------------------------
 * set_core_limit
 *--------------------------------------------------------------------------*/
#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
static void set_core_limit(void) {
  struct rlimit corelim;

  if (getrlimit(RLIMIT_CORE, &corelim)) {
    fprintf(stderr, "Read of rlimit core size failed: %s\n", strerror(errno));
    corelim.rlim_max = RLIM_INFINITY;   /* Try to recover */
  }

  corelim.rlim_cur = corelim.rlim_max;
  if (setrlimit(RLIMIT_CORE, &corelim))
    fprintf(stderr, "Setting rlimit core size failed: %s\n", strerror(errno));
}
#endif



/*----------------------------------------------------------------------------
 * set_chroot_environment
 *--------------------------------------------------------------------------*/
#ifdef CHROOTDIR
static char set_chroot_environment(void) {
  /* Must be root to chroot! Silly if you ask me... */
  if (geteuid())
    seteuid(0);

  if (chdir(dpath)) {
    fprintf(stderr, "Fail: Cannot chdir(%s): %s\n", dpath, strerror(errno));
    return 0;
  }
  if (chroot(dpath)) {
    fprintf(stderr, "Fail: Cannot chroot(%s): %s\n", dpath, strerror(errno));
    return 0;
  }
  dpath = "/";
  return 1;
}
#endif


/*----------------------------------------------------------------------------
 * set_userid_if_needed()
 *--------------------------------------------------------------------------*/
static int set_userid_if_needed(void) {
  /* TODO: Drop privs correctly! */
#if defined(IRC_GID) && defined(IRC_UID)
  setgid (IRC_GID);
  setegid(IRC_GID);
  setuid (IRC_UID);
  seteuid(IRC_UID);
#endif

  if (getuid() == 0 || geteuid() == 0 ||
      getgid() == 0 || getegid() == 0) {
    fprintf(stderr, "ERROR:  This server will not run as superuser.\n");
    return 0;
  }

  return 1;
}


/*----------------------------------------------------------------------------
 * main - entrypoint
 *
 * TODO:  This should set the basic environment up and start the main loop.
 *        we're doing waaaaaaaaay too much server initialization here.  I hate
 *        long and ugly control paths...  -smd
 *--------------------------------------------------------------------------*/
int main(int argc, char **argv) {
  CurrentTime = time(NULL);

  thisServer.argc = argc;
  thisServer.argv = argv;
  thisServer.uid  = getuid();
  thisServer.euid = geteuid();

#ifdef CHROOTDIR
  if (!set_chroot_environment())
    return 1;
#endif

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
  set_core_limit();
#endif

  umask(077);                   /* better safe than sorry --SRB */
  memset(&me, 0, sizeof(me));
  me.fd = -1;

  parse_command_line(argc, argv);

  if (chdir(dpath)) {
    fprintf(stderr, "Fail: Cannot chdir(%s): %s, check DPATH\n", dpath, strerror(errno));
    return 2;
  }

  if (!set_userid_if_needed())
    return 3;

  /* Check paths for accessibility */
  if (!check_file_access(SPATH, 'S', X_OK) ||
      !check_file_access(configfile, 'C', R_OK) ||
      !check_file_access(MPATH, 'M', R_OK) ||
      !check_file_access(RPATH, 'R', R_OK))
    return 4;
      
#ifdef DEBUG
  if (!check_file_access(LPATH, 'L', W_OK))
    return 5;
#endif

  debug_init(thisServer.bootopt & BOOT_TTY);
  daemon_init(thisServer.bootopt & BOOT_TTY);

  setup_signals();
  open_log(*argv);

  set_nomem_handler(outofmemory);
  
  if (!init_string()) {
    ircd_log(L_CRIT, "Failed to initialize string module");
    return 6;
  }

  initload();
  init_list();
  init_hash();
  init_class();
  initwhowas();
  initmsgtree();
  initstats();

  init_resolver();

  motd_init();

  if (!init_conf()) {
    ircd_log(L_CRIT, "Failed to read configuration file %s", configfile);
    return 7;
  }

  init_server_identity();

  uping_init();

  CurrentTime = time(NULL);

  SetMe(&me);
  me.from = &me;
  make_server(&me);

  me.serv->timestamp = TStime();  /* Abuse own link timestamp as start TS */
  me.serv->prot      = atoi(MAJOR_PROTOCOL);
  me.serv->up        = &me;
  me.serv->down      = NULL;
  me.handler         = SERVER_HANDLER;

  SetYXXCapacity(&me, MAXCLIENTS);

  me.lasttime = me.since = me.firsttime = CurrentTime;

  hAddClient(&me);

  write_pidfile();
  init_counters();

  Debug((DEBUG_NOTICE, "Server ready..."));
  ircd_log(L_NOTICE, "Server Ready");

  event_loop();

  return 0;
}


