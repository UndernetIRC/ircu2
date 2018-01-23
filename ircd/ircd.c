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
/** @file
 * @brief Entry point and other initialization functions for the daemon.
 * @version $Id$
 */
#include "config.h"

#include "ircd.h"
#include "IPcheck.h"
#include "class.h"
#include "client.h"
#include "crule.h"
#include "destruct_event.h"
#include "hash.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_signal.h"
#include "ircd_string.h"
#include "ircd_crypt.h"
#include "jupe.h"
#include "list.h"
#include "match.h"
#include "motd.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "parse.h"
#include "res.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_stats.h"
#include "send.h"
#include "sys.h"
#include "uping.h"
#include "userload.h"
#include "version.h"
#include "whowas.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>



/*----------------------------------------------------------------------------
 * External stuff
 *--------------------------------------------------------------------------*/
extern void init_counters(void);
extern void mem_dbg_initialise(void);

/*----------------------------------------------------------------------------
 * Constants / Enums
 *--------------------------------------------------------------------------*/
enum {
  BOOT_DEBUG = 1,  /**< Enable debug output. */
  BOOT_TTY   = 2,  /**< Stay connected to TTY. */
  BOOT_CHKCONF = 4 /**< Exit after reading configuration file. */
};


/*----------------------------------------------------------------------------
 * Global data (YUCK!)
 *--------------------------------------------------------------------------*/
struct Client  me;                      /**< That's me */
struct Connection me_con;		/**< That's me too */
struct Client *GlobalClientList  = &me; /**< Pointer to beginning of
					   Client list */
time_t         TSoffset          = 0;   /**< Offset of timestamps to system clock */
time_t         CurrentTime;             /**< Updated every time we leave select() */

char          *configfile        = CPATH; /**< Server configuration file */
int            debuglevel        = -1;    /**< Server debug level  */
char          *debugmode         = "";    /**< Server debug level */
static char   *dpath             = DPATH; /**< Working directory for daemon */
static char   *dbg_client;                /**< Client specifier for chkconf */

static struct Timer connect_timer; /**< timer structure for try_connections() */
static struct Timer ping_timer; /**< timer structure for check_pings() */
static struct Timer destruct_event_timer; /**< timer structure for exec_expired_destruct_events() */

/** Daemon information. */
static struct Daemon thisServer  = { 0, 0, 0, 0, 0, 0, -1 };

/** Non-zero until we want to exit. */
int running = 1;


/*----------------------------------------------------------------------------
 * API: server_die
 *--------------------------------------------------------------------------*/
/** Terminate the server with a message.
 * @param[in] message Message to log and send to operators.
 */
void server_die(const char *message)
{
  /* log_write will send out message to both log file and as server notice */
  log_write(LS_SYSTEM, L_CRIT, 0, "Server terminating: %s", message);
  flush_connections(0);
  close_connections(1);
  running = 0;
}

/*----------------------------------------------------------------------------
 * API: server_panic
 *--------------------------------------------------------------------------*/
/** Immediately terminate the server with a message.
 * @param[in] message Message to log, but not send to operators.
 */
void server_panic(const char *message)
{
  /* inhibit sending server notice--we may be panicking due to low memory */
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSNOTICE, "Server panic: %s", message);
  flush_connections(0);
  log_close();
  close_connections(1);
  exit(1);
}

/*----------------------------------------------------------------------------
 * API: server_restart
 *--------------------------------------------------------------------------*/
/** Restart the server with a message.
 * @param[in] message Message to log and send to operators.
 */
void server_restart(const char *message)
{
  static int restarting = 0;

  /* inhibit sending any server notices; we may be in a loop */
  log_write(LS_SYSTEM, L_WARNING, LOG_NOSNOTICE, "Restarting Server: %s",
	    message);
  if (restarting++) /* increment restarting to prevent looping */
    return;

  sendto_opmask_butone(0, SNO_OLDSNO, "Restarting server: %s", message);
  Debug((DEBUG_NOTICE, "Restarting server..."));
  flush_connections(0);

  log_close();

  close_connections(!(thisServer.bootopt & (BOOT_TTY | BOOT_DEBUG | BOOT_CHKCONF)));

  reap_children();

  execv(SPATH, thisServer.argv);

  /* Have to reopen since it has been closed above */
  log_reopen();

  log_write(LS_SYSTEM, L_CRIT, 0, "execv(%s,%s) failed: %m", SPATH,
	    *thisServer.argv);

  Debug((DEBUG_FATAL, "Couldn't restart server \"%s\": %s",
         SPATH, (strerror(errno)) ? strerror(errno) : ""));
  exit(8);
}


/*----------------------------------------------------------------------------
 * outofmemory:  Handler for out of memory conditions...
 *--------------------------------------------------------------------------*/
/** Handle out-of-memory condition. */
static void outofmemory(void) {
  Debug((DEBUG_FATAL, "Out of memory: restarting server..."));
  server_restart("Out of Memory");
}


/*----------------------------------------------------------------------------
 * write_pidfile
 *--------------------------------------------------------------------------*/
/** Write process ID to PID file. */
static void write_pidfile(void) {
  char buff[20];

  if (thisServer.pid_fd >= 0) {
    memset(buff, 0, sizeof(buff));
    sprintf(buff, "%5d\n", (int)getpid());
    if (write(thisServer.pid_fd, buff, strlen(buff)) == -1)
      Debug((DEBUG_NOTICE, "Error writing to pid file %s: %m",
	     feature_str(FEAT_PPATH)));
    return;
  }
  Debug((DEBUG_NOTICE, "Error opening pid file %s: %m",
	 feature_str(FEAT_PPATH)));
}

/** Try to create the PID file.
 * @return Zero on success; non-zero on any error.
 */
static int check_pid(void)
{
  struct flock lock;

  lock.l_type = F_WRLCK;
  lock.l_start = 0;
  lock.l_whence = SEEK_SET;
  lock.l_len = 0;

  if ((thisServer.pid_fd = open(feature_str(FEAT_PPATH), O_CREAT | O_RDWR,
				0600)) >= 0)
    return fcntl(thisServer.pid_fd, F_SETLK, &lock) == -1;

  return 1;
}


/** Look for any connections that we should try to initiate.
 * Reschedules itself to run again at the appropriate time.
 * @param[in] ev Timer event (ignored).
 */
static void try_connections(struct Event* ev) {
  struct ConfItem*  aconf;
  struct ConfItem** pconf;
  time_t            next;
  struct Jupe*      ajupe;
  int               hold;
  int               done;

  assert(ET_EXPIRE == ev_type(ev));
  assert(0 != ev_timer(ev));

  Debug((DEBUG_NOTICE, "Connection check at   : %s", myctime(CurrentTime)));
  next = CurrentTime + feature_int(FEAT_CONNECTFREQUENCY);
  done = 0;

  for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
    /* Only consider server items with non-zero port and non-zero
     * connect times that are not actively juped.
     */
    if (!(aconf->status & CONF_SERVER)
        || aconf->address.port == 0
        || !(aconf->flags & CONF_AUTOCONNECT)
        || ((ajupe = jupe_find(aconf->name)) && JupeIsActive(ajupe)))
      continue;

    /* Do we need to postpone this connection further? */
    hold = aconf->hold > CurrentTime;

    /* Update next possible connection check time. */
    if (hold && next > aconf->hold)
        next = aconf->hold;

    /* Do not try to connect if its use is still on hold until future,
     * we have already initiated a connection this try_connections(),
     * too many links in its connection class, it is already linked,
     * or if connect rules forbid a link now.
     */
    if (hold || done
        || (ConfLinks(aconf) > ConfMaxLinks(aconf))
        || FindServer(aconf->name)
        || conf_eval_crule(aconf->name, CRULE_MASK))
      continue;

    /* Ensure it is at the end of the list for future checks. */
    if (aconf->next) {
      /* Find aconf's location in the list and splice it out. */
      for (pconf = &GlobalConfList; *pconf; pconf = &(*pconf)->next)
        if (*pconf == aconf)
          *pconf = aconf->next;
      /* Reinsert it at the end of the list (where pconf is now). */
      *pconf = aconf;
      aconf->next = 0;
    }

    /* Activate the connection itself. */
    if (connect_server(aconf, 0))
      sendto_opmask_butone(0, SNO_OLDSNO, "Connection to %s activated.",
			   aconf->name);

    /* And stop looking for further candidates. */
    done = 1;
  }

  Debug((DEBUG_NOTICE, "Next connection check : %s", myctime(next)));
  timer_add(&connect_timer, try_connections, 0, TT_ABSOLUTE, next);
}


/** Check for clients that have not sent a ping response recently.
 * Reschedules itself to run again at the appropriate time.
 * @param[in] ev Timer event (ignored).
 */
static void check_pings(struct Event* ev) {
  int expire     = 0;
  int next_check = CurrentTime;
  int max_ping   = 0;
  int i;

  assert(ET_EXPIRE == ev_type(ev));
  assert(0 != ev_timer(ev));

  next_check += feature_int(FEAT_PINGFREQUENCY);
  
  /* Scan through the client table */
  for (i=0; i <= HighestFd; i++) {
    struct Client *cptr = LocalClientArray[i];
   
    if (!cptr)
      continue;
     
    assert(&me != cptr);  /* I should never be in the local client array! */
   

    /* Remove dead clients. */
    if (IsDead(cptr)) {
      exit_client(cptr, cptr, &me, cli_info(cptr));
      continue;
    }

    Debug((DEBUG_DEBUG, "check_pings(%s)=status:%s current: %d",
	   cli_name(cptr),
	   IsPingSent(cptr) ? "[Ping Sent]" : "[]", 
	   (int)(CurrentTime - cli_lasttime(cptr))));

    /* Unregistered clients pingout after max_ping seconds, they don't
     * get given a second chance - if they were then people could not quite
     * finish registration and hold resources without being subject to k/g
     * lines
     */
    if (!IsRegistered(cptr)) {
      assert(!IsServer(cptr));
      max_ping = feature_int(FEAT_CONNECTTIMEOUT);
      /* If client authorization time has expired, ask auth whether they
       * should be checked again later. */
      if ((CurrentTime-cli_firsttime(cptr) >= max_ping)
          && auth_ping_timeout(cptr))
        continue;
      if (!IsRegistered(cptr)) {
	/* OK, they still have enough time left, so we'll just skip to the
	 * next client.  Set the next check to be when their time is up, if
	 * that's before the currently scheduled next check -- hikari */
	expire = cli_firsttime(cptr) + max_ping;
	if (expire < next_check)
	  next_check = expire;
	continue;
      }
    }

    max_ping = client_get_ping(cptr);

    /* If it's a server and we have not sent an AsLL lately, do so. */
    if (IsServer(cptr)) {
      if (CurrentTime - cli_serv(cptr)->asll_last >= max_ping) {
        char *asll_ts;

        SetPingSent(cptr);
        cli_serv(cptr)->asll_last = CurrentTime;
        expire = cli_serv(cptr)->asll_last + max_ping;
        asll_ts = militime_float(NULL);
        sendcmdto_prio_one(&me, CMD_PING, cptr, "!%s %s %s", asll_ts,
                           cli_name(cptr), asll_ts);
      }

      expire = cli_serv(cptr)->asll_last + max_ping;
      if (expire < next_check)
        next_check = expire;
    }

    /* Ok, the thing that will happen most frequently, is that someone will
     * have sent something recently.  Cover this first for speed.
     * -- 
     * If it's an unregistered client and hasn't managed to register within
     * max_ping then it's obviously having problems (broken client) or it's
     * just up to no good, so we won't skip it, even if its been sending
     * data to us. 
     * -- hikari
     */
    if ((CurrentTime-cli_lasttime(cptr) < max_ping) && IsRegistered(cptr)) {
      expire = cli_lasttime(cptr) + max_ping;
      if (expire < next_check) 
	next_check = expire;
      continue;
    }

    /* Quit the client after max_ping*2 - they should have answered by now */
    if (CurrentTime-cli_lasttime(cptr) >= (max_ping*2) )
    {
      /* If it was a server, then tell ops about it. */
      if (IsServer(cptr) || IsConnecting(cptr) || IsHandshake(cptr))
        sendto_opmask_butone(0, SNO_OLDSNO,
                             "No response from %s, closing link",
                             cli_name(cptr));
      exit_client_msg(cptr, cptr, &me, "Ping timeout");
      continue;
    }
    
    if (!IsPingSent(cptr))
    {
      /* If we haven't PINGed the connection and we haven't heard from it in a
       * while, PING it to make sure it is still alive.
       */
      SetPingSent(cptr);

      /* If we're late in noticing don't hold it against them :) */
      cli_lasttime(cptr) = CurrentTime - max_ping;
      
      if (IsUser(cptr))
        sendrawto_one(cptr, MSG_PING " :%s", cli_name(&me));
      else
        sendcmdto_prio_one(&me, CMD_PING, cptr, ":%s", cli_name(&me));
    }
    
    expire = cli_lasttime(cptr) + max_ping * 2;
    if (expire < next_check)
      next_check=expire;
  }
  
  assert(next_check >= CurrentTime);
  
  Debug((DEBUG_DEBUG, "[%i] check_pings() again in %is",
	 CurrentTime, next_check-CurrentTime));
  
  timer_add(&ping_timer, check_pings, 0, TT_ABSOLUTE, next_check);
}


/** Parse command line arguments.
 * Global variables are updated to reflect the arguments.
 * As a side effect, makes sure the process's effective user id is the
 * same as the real user id.
 * @param[in] argc Number of arguments on command line.
 * @param[in,out] argv Command-lne arguments.
 */
static void parse_command_line(int argc, char** argv) {
  const char *options = "d:f:h:nktvx:c:";
  int opt;

  if (thisServer.euid != thisServer.uid)
    setuid(thisServer.uid);

  /* Do we really need to sanity check the non-NULLness of optarg?  That's
   * getopt()'s job...  Removing those... -zs
   */
  while ((opt = getopt(argc, argv, options)) != EOF)
    switch (opt) {
    case 'k':  thisServer.bootopt |= BOOT_CHKCONF | BOOT_TTY; break;
    case 'c':  dbg_client = optarg;                    break;
    case 'n':
    case 't':  thisServer.bootopt |= BOOT_TTY;         break;
    case 'd':  dpath      = optarg;                    break;
    case 'f':  configfile = optarg;                    break;
    case 'h':  ircd_strncpy(cli_name(&me), optarg, HOSTLEN); break;
    case 'v':
      printf("ircd %s\n", version);
      printf("Event engines: ");
#ifdef USE_KQUEUE
      printf("kqueue() ");
#endif
#ifdef USE_DEVPOLL
      printf("/dev/poll ");
#endif
#ifdef USE_EPOLL
      printf("epoll_*() ");
#endif
#ifdef USE_POLL
      printf("poll()");
#else
      printf("select()");
#endif
      printf("\nCompiled for a maximum of %d connections.\n", MAXCONNECTIONS);


      exit(0);
      break;

    case 'x':
      debuglevel = atoi(optarg);
      if (debuglevel < 0)
	debuglevel = 0;
      debugmode = optarg;
      thisServer.bootopt |= BOOT_DEBUG;
#ifndef DEBUGMODE
      printf("WARNING: DEBUGMODE disabled; -x has no effect.\n");
#endif
      break;

    default:
      printf("Usage: ircd [-f config] [-h servername] [-x loglevel] [-ntv] [-k [-c clispec]]\n"
             "\n -f config\t specify explicit configuration file"
             "\n -x loglevel\t set debug logging verbosity"
             "\n -n or -t\t don't detach"
             "\n -v\t\t display version"
             "\n -k\t\t exit after checking config"
             "\n -c clispec\t search for client/kill blocks matching client"
             "\n\t\t clispec is comma-separated list of user@host,"
             "\n\t\t user@ip, $Rrealname, and port number"
             "\n\nServer not started.\n");
      exit(1);
    }
}


/** Become a daemon.
 * @param[in] no_fork If non-zero, do not fork into the background.
 */
static void daemon_init(int no_fork) {
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

/** Check that we have access to a particular file.
 * If we do not have access to the file, complain on stderr.
 * @param[in] path File name to check for access.
 * @param[in] which Configuration character associated with file.
 * @param[in] mode Bitwise combination of R_OK, W_OK, X_OK and/or F_OK.
 * @return Non-zero if we have the necessary access, zero if not.
 */
static char check_file_access(const char *path, char which, int mode) {
  if (!access(path, mode))
    return 1;

  fprintf(stderr, 
	  "Check on %cPATH (%s) failed: %s\n"
	  "Please create this file and/or rerun `configure' "
	  "using --with-%cpath and recompile to correct this.\n",
	  toupper(which), path, strerror(errno), which);

  return 0;
}


/*----------------------------------------------------------------------------
 * set_core_limit
 *--------------------------------------------------------------------------*/
#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
/** Set the core size soft limit to the same as the hard limit. */
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



/** Complain to stderr if any user or group ID belongs to the superuser.
 * @return Non-zero if all IDs are okay, zero if some are 0.
 */
static int set_userid_if_needed(void) {
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
/** Run the daemon.
 * @param[in] argc Number of arguments in \a argv.
 * @param[in] argv Arguments to program execution.
 */
int main(int argc, char **argv) {
  CurrentTime = time(NULL);

  thisServer.argc = argc;
  thisServer.argv = argv;
  thisServer.uid  = getuid();
  thisServer.euid = geteuid();

#ifdef MDEBUG
  mem_dbg_initialise();
#endif

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
  set_core_limit();
#endif

  umask(077);                   /* better safe than sorry --SRB */
  memset(&me, 0, sizeof(me));
  memset(&me_con, 0, sizeof(me_con));
  cli_connect(&me) = &me_con;
  cli_fd(&me) = -1;

  parse_command_line(argc, argv);

  if (chdir(dpath)) {
    fprintf(stderr, "Fail: Cannot chdir(%s): %s, check DPATH\n", dpath, strerror(errno));
    return 2;
  }

  if (!set_userid_if_needed())
    return 3;

  /* Check paths for accessibility */
  if (!check_file_access(SPATH, 'S', X_OK) ||
      !check_file_access(configfile, 'c', R_OK))
    return 4;

  if (!init_connection_limits())
    return 9;

  close_connections(!(thisServer.bootopt & (BOOT_DEBUG | BOOT_TTY | BOOT_CHKCONF)));

  /* daemon_init() must be before event_init() because kqueue() FDs
   * are, perversely, not inherited across fork().
   */
  daemon_init(thisServer.bootopt & BOOT_TTY);

#ifdef DEBUGMODE
  /* Must reserve fd 2... */
  if (debuglevel >= 0 && !(thisServer.bootopt & BOOT_TTY)) {
    int fd;
    if ((fd = open("/dev/null", O_WRONLY)) < 0) {
      fprintf(stderr, "Unable to open /dev/null (to reserve fd 2): %s\n",
	      strerror(errno));
      return 8;
    }
    if (fd != 2 && dup2(fd, 2) < 0) {
      fprintf(stderr, "Unable to reserve fd 2; dup2 said: %s\n",
	      strerror(errno));
      return 8;
    }
  }
#endif

  event_init(MAXCONNECTIONS);

  setup_signals();
  feature_init(); /* initialize features... */
  log_init(*argv);
  set_nomem_handler(outofmemory);

  initload();
  init_list();
  init_hash();
  init_class();
  initwhowas();
  initmsgtree();
  initstats();

  /* we need this for now, when we're modular this 
     should be removed -- hikari */
  ircd_crypt_init();

  motd_init();

  if (!init_conf()) {
    log_write(LS_SYSTEM, L_CRIT, 0, "Failed to read configuration file %s",
	      configfile);
    return 7;
  }

  if (thisServer.bootopt & BOOT_CHKCONF) {
    if (dbg_client)
      conf_debug_iline(dbg_client);
    fprintf(stderr, "Configuration file %s checked okay.\n", configfile);
    return 0;
  }

  debug_init(thisServer.bootopt & BOOT_TTY);
  if (check_pid()) {
    Debug((DEBUG_FATAL, "Failed to acquire PID file lock after fork"));
    exit(2);
  }

  init_server_identity();

  uping_init();

  stats_init();

  IPcheck_init();
  timer_add(timer_init(&connect_timer), try_connections, 0, TT_RELATIVE, 1);
  timer_add(timer_init(&ping_timer), check_pings, 0, TT_RELATIVE, 1);
  timer_add(timer_init(&destruct_event_timer), exec_expired_destruct_events, 0, TT_PERIODIC, 60);

  CurrentTime = time(NULL);

  SetMe(&me);
  cli_magic(&me) = CLIENT_MAGIC;
  cli_from(&me) = &me;
  make_server(&me);

  cli_serv(&me)->timestamp = TStime();  /* Abuse own link timestamp as start TS */
  cli_serv(&me)->prot      = atoi(MAJOR_PROTOCOL);
  cli_serv(&me)->up        = &me;
  cli_serv(&me)->down      = NULL;
  cli_handler(&me)         = SERVER_HANDLER;

  SetYXXCapacity(&me, MAXCLIENTS);

  cli_lasttime(&me) = cli_since(&me) = cli_firsttime(&me) = CurrentTime;

  hAddClient(&me);
  SetIPv6(&me);

  write_pidfile();
  init_counters();

  Debug((DEBUG_NOTICE, "Server ready..."));
  log_write(LS_SYSTEM, L_NOTICE, 0, "Server Ready");

  event_loop();

  return 0;
}


