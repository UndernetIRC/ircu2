/*
 * IRC - Internet Relay Chat, ircd/s_bsd.c
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
#include <stdlib.h>
#include <sys/socket.h>
#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef SOL2
#include <sys/filio.h>
#endif
#ifdef UNIXPORT
#include <sys/un.h>
#endif
#include <stdio.h>
#ifdef USE_POLL
#ifndef HAVE_POLL_H
#undef USE_POLL
#else /* HAVE_POLL_H */
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif
#include <poll.h>
#endif /* HAVE_POLL_H */
#endif /* USE_POLL */
#include <signal.h>
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <utmp.h>
#include <sys/resource.h>
#ifdef USE_SYSLOG
#include <syslog.h>
#endif
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "h.h"
#include "res.h"
#include "struct.h"
#include "s_bsd.h"
#include "s_serv.h"
#include "numeric.h"
#include "send.h"
#include "s_conf.h"
#include "s_misc.h"
#include "s_bsd.h"
#include "hash.h"
#include "s_err.h"
#include "ircd.h"
#include "support.h"
#include "s_auth.h"
#include "class.h"
#include "packet.h"
#include "s_ping.h"
#include "channel.h"
#include "version.h"
#include "parse.h"
#include "common.h"
#include "bsd.h"
#include "numnicks.h"
#include "s_user.h"
#include "sprintf_irc.h"
#include "querycmds.h"
#include "IPcheck.h"

RCSTAG_CC("$Id$");

#ifndef IN_LOOPBACKNET
#define IN_LOOPBACKNET	0x7f
#endif

aClient *loc_clients[MAXCONNECTIONS];
int highest_fd = 0, udpfd = -1, resfd = -1;
unsigned int readcalls = 0;
static struct sockaddr_in mysk;
static void polludp();

static struct sockaddr *connect_inet(aConfItem *, aClient *, int *);
static int completed_connection(aClient *);
static int check_init(aClient *, char *);
static void do_dns_async(), set_sock_opts(int, aClient *);
#ifdef	UNIXPORT
static struct sockaddr *connect_unix(aConfItem *, aClient *, int *);
static void add_unixconnection(aClient *, int);
static char unixpath[256];
#endif
static char readbuf[8192];
#ifdef USE_POLL
static struct pollfd poll_fds[MAXCONNECTIONS + 1];
static aClient *poll_cptr[MAXCONNECTIONS + 1];
#endif /* USE_POLL */
struct sockaddr_in vserv;	/* Default address/interface to bind listen sockets to.
                                   This is set with the -w commandline option OR whatever
				   the name in the M: line resolves to OR INADDR_ANY. */
struct sockaddr_in cserv;	/* Default address/interface to bind connecting sockets to.
				   This is set with the -w commandline option OR whatever
				   the name in the M: line resolves to OR the first
				   interface specified in the ircd.conf file for the
				   server port. */
static int running_in_background;

#ifdef GODMODE
#ifndef NOFLOODCONTROL
#define NOFLOODCONTROL
#endif
#endif

/*
 * Try and find the correct name to use with getrlimit() for setting the max.
 * number of files allowed to be open by this process.
 */
#ifdef RLIMIT_FDMAX
#define RLIMIT_FD_MAX	RLIMIT_FDMAX
#else
#ifdef RLIMIT_NOFILE
#define RLIMIT_FD_MAX RLIMIT_NOFILE
#else
#ifdef RLIMIT_OPEN_MAX
#define RLIMIT_FD_MAX RLIMIT_OPEN_MAX
#else
#undef RLIMIT_FD_MAX
#endif
#endif
#endif

#if !defined(USE_POLL)
#if FD_SETSIZE < (MAXCONNECTIONS + 4)
/*
 * Sanity check
 *
 * All operating systems work when MAXCONNECTIONS <= 252.
 * Most operating systems work when MAXCONNECTIONS <= 1020 and FD_SETSIZE is
 *   updated correctly in the system headers (on BSD systems our sys.h has
 *   defined FD_SETSIZE to MAXCONNECTIONS+4 before including the system's headers 
 *   but sys/types.h might have abruptly redefined it so the check is still 
 *   done), you might already need to recompile your kernel.
 * For larger FD_SETSIZE your milage may vary (kernel patches may be needed).
 * The check is _NOT_ done if we will not use FD_SETS at all (USE_POLL)
 */
#error "FD_SETSIZE is too small or MAXCONNECTIONS too large."
#endif
#endif

/*
 * Cannot use perror() within daemon. stderr is closed in
 * ircd and cannot be used. And, worse yet, it might have
 * been reassigned to a normal connection...
 */

/*
 * report_error
 *
 * This a replacement for perror(). Record error to log and
 * also send a copy to all *LOCAL* opers online.
 *
 * text    is a *format* string for outputting error. It must
 *         contain only two '%s', the first will be replaced
 *         by the sockhost from the cptr, and the latter will
 *         be taken from sys_errlist[errno].
 *
 * cptr    if not NULL, is the *LOCAL* client associated with
 *         the error.
 */
void report_error(char *text, aClient *cptr)
{
  Reg1 int errtmp = errno;	/* debug may change 'errno' */
  Reg2 char *host;
#if defined(SO_ERROR) && !defined(SOL2)
  int err;
  size_t len = sizeof(err);
#endif

  host = (cptr) ? get_client_name(cptr, FALSE) : "";

  Debug((DEBUG_ERROR, text, host, strerror(errtmp)));

  /*
   * Get the *real* error from the socket (well try to anyway..).
   * This may only work when SO_DEBUG is enabled but its worth the
   * gamble anyway.
   */
#if defined(SO_ERROR) && !defined(SOL2)
  if (cptr && !IsMe(cptr) && cptr->fd >= 0)
    if (!getsockopt(cptr->fd, SOL_SOCKET, SO_ERROR, (OPT_TYPE *)&err, &len))
      if (err)
	errtmp = err;
#endif
  sendto_ops(text, host, strerror(errtmp));
#ifdef USE_SYSLOG
  syslog(LOG_WARNING, text, host, strerror(errtmp));
#endif
  if (!running_in_background)
  {
    fprintf(stderr, text, host, strerror(errtmp));
    fprintf(stderr, "\n");
    fflush(stderr);
  }
  return;
}

/*
 * inetport
 *
 * Create a socket in the AF_INET domain, bind it to the port given in
 * 'port' and listen to it.  Connections are accepted to this socket
 * depending on the IP# mask given by 'name'.  Returns the fd of the
 * socket created or -1 on error.
 */
int inetport(aClient *cptr, char *name, char *bind_addr, unsigned short int port)
{
  unsigned short int sin_port;
  int ad[4], opt;
  char ipname[20];

#ifdef TESTNET
    sin_port = htons(port + 10000);
#else
    sin_port = htons(port);
#endif

  ad[0] = ad[1] = ad[2] = ad[3] = 0;

  /*
   * do it this way because building ip# from separate values for each
   * byte requires endian knowledge or some nasty messing. Also means
   * easy conversion of "*" to 0.0.0.0 or 134.* to 134.0.0.0 :-)
   */
  sscanf(name, "%d.%d.%d.%d", &ad[0], &ad[1], &ad[2], &ad[3]);
  sprintf_irc(ipname, "%d.%d.%d.%d", ad[0], ad[1], ad[2], ad[3]);

  if (cptr != &me)
  {
    sprintf(cptr->sockhost, "%-.42s.%u", name, port);
    strcpy(cptr->name, me.name);
  }
  /*
   * At first, open a new socket
   */
  if (cptr->fd == -1)
  {
    alarm(2);
    cptr->fd = socket(AF_INET, SOCK_STREAM, 0);
    alarm(0);
    if (cptr->fd < 0 && errno == EAGAIN)
    {
      sendto_ops("opening stream socket %s: No more sockets",
	  get_client_name(cptr, TRUE));
      return -1;
    }
  }
  if (cptr->fd < 0)
  {
    report_error("opening stream socket %s: %s", cptr);
    return -1;
  }
  else if (cptr->fd >= MAXCLIENTS)
  {
    sendto_ops("No more connections allowed (%s)", cptr->name);
    close(cptr->fd);
    return -1;
  }

  opt = 1;
  setsockopt(cptr->fd, SOL_SOCKET, SO_REUSEADDR, (OPT_TYPE *)&opt, sizeof(opt));

  /*
   * Bind a port to listen for new connections if port is non-null,
   * else assume it is already open and try get something from it.
   */
  if (port)
  {
    struct sockaddr_in bindaddr;
    memset(&bindaddr, 0, sizeof(struct sockaddr_in));
    if (*bind_addr == '*' && bind_addr[1] == 0)
      bindaddr.sin_addr.s_addr = htonl(INADDR_ANY);	/* Bind to all interfaces */
    else if (*bind_addr)
    {
      bindaddr.sin_addr.s_addr = inet_addr(bind_addr);	/* Use name from P: line */
      /* If server port and bind_addr isn't localhost: */
      if (port == portnum && strcmp("127.0.0.1", bind_addr))
        cserv.sin_addr.s_addr = bindaddr.sin_addr.s_addr;	/* Initialize /connect port */
    }
    else
      bindaddr.sin_addr = vserv.sin_addr;		/* Default */
    bindaddr.sin_family = AF_INET;
    bindaddr.sin_port = sin_port;
    if (bind(cptr->fd, (struct sockaddr *)&bindaddr, sizeof(bindaddr)) == -1)
    {
      report_error("binding stream socket %s: %s", cptr);
      close(cptr->fd);
      return -1;
    }
  }

  if (cptr == &me)		/* KLUDGE to get it work... */
  {
    char buf[1024];
    sprintf_irc(buf, rpl_str(RPL_MYPORTIS), me.name, "*", port);
    write(1, buf, strlen(buf));
  }
  if (cptr->fd > highest_fd)
    highest_fd = cptr->fd;
  cptr->ip.s_addr = inet_addr(ipname);
  cptr->port = port;
  listen(cptr->fd, 128);	/* Use listen port backlog of 128 */
  loc_clients[cptr->fd] = cptr;

  return 0;
}

#ifdef	UNIXPORT
/*
 * unixport
 *
 * Create a socket and bind it to a filename which is comprised of the path
 * (directory where file is placed) and port (actual filename created).
 * Set directory permissions as rwxr-xr-x so other users can connect to the
 * file which is 'forced' to rwxrwxrwx (different OS's have different need of
 * modes so users can connect to the socket).
 */
int unixport(aClient *cptr, char *path, unsigned short int port)
{
  struct sockaddr_un un;

  alarm(2);
  cptr->fd = socket(AF_UNIX, SOCK_STREAM, 0);
  alarm(0);
  if (cptr->fd == -1 && errno == EAGAIN)
  {
    sendto_ops("error opening unix domain socket %s: No more sockets",
	get_client_name(cptr, TRUE));
    return -1;
  }
  if (cptr->fd == -1)
  {
    report_error("error opening unix domain socket %s: %s", cptr);
    return -1;
  }
  else if (cptr->fd >= MAXCLIENTS)
  {
    sendto_ops("No more connections allowed (%s)", cptr->name);
    close(cptr->fd);
    cptr->fd = -1;
    return -1;
  }

  un.sun_family = AF_UNIX;
#if HAVE_MKDIR
  mkdir(path, 0755);
#else
  if (chmod(path, 0755) == -1)
  {
    sendto_ops("error 'chmod 0755 %s': %s", path, strerror(errno));
#ifdef USE_SYSLOG
    syslog(LOG_WARNING, "error 'chmod 0755 %s': %s", path, strerror(errno));
#endif
    close(cptr->fd);
    cptr->fd = -1;
    return -1;
  }
#endif
  sprintf_irc(unixpath, "%s/%u", path, port);
  unlink(unixpath);
  strncpy(un.sun_path, unixpath, sizeof(un.sun_path) - 1);
  un.sun_path[sizeof(un.sun_path) - 1] = 0;
  strcpy(cptr->name, me.name);
  errno = 0;
  get_sockhost(cptr, unixpath);

  if (bind(cptr->fd, (struct sockaddr *)&un, strlen(unixpath) + 2) == -1)
  {
    report_error("error binding unix socket %s: %s", cptr);
    close(cptr->fd);
    return -1;
  }
  if (cptr->fd > highest_fd)
    highest_fd = cptr->fd;
  listen(cptr->fd, 5);
  chmod(unixpath, 0777);
  cptr->flags |= FLAGS_UNIX;
  cptr->port = 0;
  loc_clients[cptr->fd] = cptr;

  return 0;
}
#endif

/*
 * add_listener
 *
 * Create a new client which is essentially the stub like 'me' to be used
 * for a socket that is passive (listen'ing for connections to be accepted).
 */
int add_listener(aConfItem *aconf)
{
  aClient *cptr;

  cptr = make_client(NULL, STAT_ME);
  cptr->flags = FLAGS_LISTEN;
  cptr->acpt = cptr;
  cptr->from = cptr;
  strncpy(cptr->name, aconf->host, sizeof(cptr->name) - 1);
  cptr->name[sizeof(cptr->name) - 1] = 0;
#ifdef	UNIXPORT
  if (*aconf->host == '/')
  {
    if (unixport(cptr, aconf->host, aconf->port))
      cptr->fd = -2;
  }
  else
#endif
  if (inetport(cptr, aconf->host, aconf->passwd, aconf->port))
    cptr->fd = -2;

  if (cptr->fd >= 0)
  {
    cptr->confs = make_link();
    cptr->confs->next = NULL;
    cptr->confs->value.aconf = aconf;
    set_non_blocking(cptr->fd, cptr);
    if (aconf->port == portnum)
      have_server_port = 1;
  }
  else
    free_client(cptr);
  return 0;
}

/*
 * close_listeners
 *
 * Close and free all clients which are marked as having their socket open
 * and in a state where they can accept connections.  Unix sockets have
 * the path to the socket unlinked for cleanliness.
 */
void close_listeners(void)
{
  Reg1 aClient *cptr;
  Reg2 int i;
  Reg3 aConfItem *aconf;

  /*
   * close all 'extra' listening ports we have and unlink the file
   * name if it was a unix socket.
   */
  for (i = highest_fd; i >= 0; i--)
  {
    if (!(cptr = loc_clients[i]))
      continue;
    if (!IsMe(cptr) || cptr == &me || !IsListening(cptr))
      continue;
    aconf = cptr->confs->value.aconf;

    if (IsIllegal(aconf) && aconf->clients == 0)
    {
#ifdef	UNIXPORT
      if (IsUnixSocket(cptr))
      {
	sprintf_irc(unixpath, "%s/%u", aconf->host, aconf->port);
	unlink(unixpath);
      }
#endif
      close_connection(cptr);
    }
  }
}

/*
 * init_sys
 */
void init_sys(void)
{
  Reg1 int fd;
#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_FD_MAX)
  struct rlimit limit;

  if (!getrlimit(RLIMIT_FD_MAX, &limit))
  {
#ifdef	pyr
    if (limit.rlim_cur < MAXCONNECTIONS)
#else
    if (limit.rlim_max < MAXCONNECTIONS)
#endif
    {
      fprintf(stderr, "ircd fd table too big\n");
      fprintf(stderr, "Hard Limit: " LIMIT_FMT " IRC max: %d\n",
#ifdef pyr
	  limit.rlim_cur,
#else
	  limit.rlim_max,
#endif
	  (int)MAXCONNECTIONS);
      fprintf(stderr, "Fix MAXCONNECTIONS\n");
      exit(-1);
    }
#ifndef pyr
    limit.rlim_cur = limit.rlim_max;	/* make soft limit the max */
    if (setrlimit(RLIMIT_FD_MAX, &limit) == -1)
    {
      fprintf(stderr, "error setting max fd's to " LIMIT_FMT "\n",
	  limit.rlim_cur);
      exit(-1);
    }
#endif
  }
#endif /* defined(HAVE_SETRLIMIT) && defined(RLIMIT_FD_MAX) */
#ifdef DEBUGMODE
  if (1)
  {
    static char logbuf[BUFSIZ];
#if SETVBUF_REVERSED
    setvbuf(stderr, _IOLBF, logbuf, sizeof(logbuf));
#else
    setvbuf(stderr, logbuf, _IOLBF, sizeof(logbuf));
#endif
  }
#endif

  for (fd = 3; fd < MAXCONNECTIONS; fd++)
  {
    close(fd);
    loc_clients[fd] = NULL;
  }
  loc_clients[1] = NULL;
  close(1);

  if (bootopt & BOOT_TTY)	/* debugging is going to a tty */
    goto init_dgram;
  if (!(bootopt & BOOT_DEBUG))
    close(2);

  if (((bootopt & BOOT_CONSOLE) || isatty(0)) &&
      !(bootopt & BOOT_INETD))
  {
    if (fork())
      exit(0);
    running_in_background = 1;
#ifdef TIOCNOTTY
    if ((fd = open("/dev/tty", O_RDWR)) >= 0)
    {
      ioctl(fd, TIOCNOTTY, (char *)NULL);
      close(fd);
    }
#endif
#if defined(HPUX) || defined(SOL2) || defined(_SEQUENT_) || \
    defined(_POSIX_SOURCE) || defined(SVR4)
    setsid();
#else
    setpgid(0, 0);
#endif
    close(0);			/* fd 0 opened by inetd */
    loc_clients[0] = NULL;
  }
init_dgram:
  resfd = init_resolver();

  return;
}

void write_pidfile(void)
{
#ifdef PPATH
  int fd;
  char buff[20];
  if ((fd = open(PPATH, O_CREAT | O_WRONLY, 0600)) >= 0)
  {
    memset(buff, 0, sizeof(buff));
    sprintf(buff, "%5d\n", (int)getpid());
    if (write(fd, buff, strlen(buff)) == -1)
      Debug((DEBUG_NOTICE, "Error writing to pid file %s", PPATH));
    close(fd);
    return;
  }
#ifdef	DEBUGMODE
  else
    Debug((DEBUG_NOTICE, "Error opening pid file \"%s\": %s",
	PPATH, strerror(errno)));
#endif
#endif
}

/*
 * Initialize the various name strings used to store hostnames. This is set
 * from either the server's sockhost (if client fd is a tty or localhost)
 * or from the ip# converted into a string. 0 = success, -1 = fail.
 */
static int check_init(aClient *cptr, char *sockn)
{
  struct sockaddr_in sk;
  size_t len = sizeof(struct sockaddr_in);
  sockn[HOSTLEN] = 0;

#ifdef	UNIXPORT
  if (IsUnixSocket(cptr))
  {
    strncpy(sockn, cptr->acpt->sockhost, HOSTLEN);
    get_sockhost(cptr, sockn);
    return 0;
  }
#endif

  /* If descriptor is a tty, special checking... */
  if (isatty(cptr->fd))
  {
    strncpy(sockn, me.sockhost, HOSTLEN);
    memset(&sk, 0, sizeof(struct sockaddr_in));
  }
  else if (getpeername(cptr->fd, (struct sockaddr *)&sk, &len) == -1)
  {
    report_error("connect failure: %s %s", cptr);
    return -1;
  }
  strcpy(sockn, inetntoa(sk.sin_addr));
  if (inet_netof(sk.sin_addr) == IN_LOOPBACKNET)
  {
    cptr->hostp = NULL;
    strncpy(sockn, me.sockhost, HOSTLEN);
  }
  memcpy(&cptr->ip, &sk.sin_addr, sizeof(struct in_addr));
#ifdef TESTNET
  cptr->port = ntohs(sk.sin_port) - 10000;
#else
  cptr->port = ntohs(sk.sin_port);
#endif

  return 0;
}

/*
 * Ordinary client access check. Look for conf lines which have the same
 * status as the flags passed.
 */
enum AuthorizationCheckResult check_client(aClient *cptr)
{
  static char sockname[HOSTLEN + 1];
  Reg2 struct hostent *hp = NULL;
  Reg3 int i;
  enum AuthorizationCheckResult acr;

  ClearAccess(cptr);
  Debug((DEBUG_DNS, "ch_cl: check access for %s[%s]",
      cptr->name, inetntoa(cptr->ip)));

  if (check_init(cptr, sockname))
    return ACR_BAD_SOCKET;

  if (!IsUnixSocket(cptr))
    hp = cptr->hostp;
  /*
   * Verify that the host to ip mapping is correct both ways and that
   * the ip#(s) for the socket is listed for the host.
   */
  if (hp)
  {
    for (i = 0; hp->h_addr_list[i]; i++)
      if (!memcmp(hp->h_addr_list[i], &cptr->ip, sizeof(struct in_addr)))
	break;
    if (!hp->h_addr_list[i])
    {
      sendto_op_mask(SNO_IPMISMATCH, "IP# Mismatch: %s != %s[%08x]",
	  inetntoa(cptr->ip), hp->h_name, *((unsigned int *)hp->h_addr));
      hp = NULL;
    }
  }

  if ((acr = attach_Iline(cptr, hp, sockname)))
  {
    Debug((DEBUG_DNS, "ch_cl: access denied: %s[%s]", cptr->name, sockname));
    return acr;
  }

  Debug((DEBUG_DNS, "ch_cl: access ok: %s[%s]", cptr->name, sockname));

  if (inet_netof(cptr->ip) == IN_LOOPBACKNET || IsUnixSocket(cptr) ||
      inet_netof(cptr->ip) == inet_netof(mysk.sin_addr))
  {
    ircstp->is_loc++;
    cptr->flags |= FLAGS_LOCAL;
  }
  return ACR_OK;
}

#define CFLAG	CONF_CONNECT_SERVER
#define NFLAG	CONF_NOCONNECT_SERVER

/*
 * check_server()
 *
 * Check access for a server given its name (passed in cptr struct).
 * Must check for all C/N lines which have a name which matches the
 * name given and a host which matches. A host alias which is the
 * same as the server name is also acceptable in the host field of a
 * C/N line.
 *
 * Returns
 *  0 = Success
 * -1 = Access denied
 * -2 = Bad socket.
 */
int check_server(aClient *cptr)
{
  Reg1 const char *name;
  Reg2 aConfItem *c_conf = NULL, *n_conf = NULL;
  struct hostent *hp = NULL;
  Link *lp;
  char abuff[HOSTLEN + USERLEN + 2];
  char sockname[HOSTLEN + 1], fullname[HOSTLEN + 1];
  int i;

  name = cptr->name;
  Debug((DEBUG_DNS, "sv_cl: check access for %s[%s]", name, cptr->sockhost));

  if (IsUnknown(cptr) && !attach_confs(cptr, name, CFLAG | NFLAG))
  {
    Debug((DEBUG_DNS, "No C/N lines for %s", name));
    return -1;
  }
  lp = cptr->confs;
  /*
   * We initiated this connection so the client should have a C and N
   * line already attached after passing through the connec_server()
   * function earlier.
   */
  if (IsConnecting(cptr) || IsHandshake(cptr))
  {
    c_conf = find_conf(lp, name, CFLAG);
    n_conf = find_conf(lp, name, NFLAG);
    if (!c_conf || !n_conf)
    {
      sendto_ops("Connecting Error: %s[%s]", name, cptr->sockhost);
      det_confs_butmask(cptr, 0);
      return -1;
    }
  }
#ifdef	UNIXPORT
  if (IsUnixSocket(cptr))
  {
    if (!c_conf)
      c_conf = find_conf(lp, name, CFLAG);
    if (!n_conf)
      n_conf = find_conf(lp, name, NFLAG);
  }
#endif

  /*
   * If the servername is a hostname, either an alias (CNAME) or
   * real name, then check with it as the host. Use gethostbyname()
   * to check for servername as hostname.
   */
  if (!IsUnixSocket(cptr) && !cptr->hostp)
  {
    Reg1 aConfItem *aconf;

    aconf = count_cnlines(lp);
    if (aconf)
    {
      Reg1 char *s;
      Link lin;

      /*
       * Do a lookup for the CONF line *only* and not
       * the server connection else we get stuck in a
       * nasty state since it takes a SERVER message to
       * get us here and we cant interrupt that very well.
       */
      ClearAccess(cptr);
      lin.value.aconf = aconf;
      lin.flags = ASYNC_CONF;
      nextdnscheck = 1;
      if ((s = strchr(aconf->host, '@')))
	s++;
      else
	s = aconf->host;
      Debug((DEBUG_DNS, "sv_ci:cache lookup (%s)", s));
      hp = gethost_byname(s, &lin);
    }
  }

  lp = cptr->confs;

  ClearAccess(cptr);
  if (check_init(cptr, sockname))
    return -2;

check_serverback:
  if (hp)
  {
    for (i = 0; hp->h_addr_list[i]; i++)
      if (!memcmp(hp->h_addr_list[i], &cptr->ip, sizeof(struct in_addr)))
	break;
    if (!hp->h_addr_list[i])
    {
      sendto_op_mask(SNO_IPMISMATCH, "IP# Mismatch: %s != %s[%08x]",
	  inetntoa(cptr->ip), hp->h_name, *((unsigned int *)hp->h_addr));
      hp = NULL;
    }
  }
  else if (cptr->hostp)
  {
    hp = cptr->hostp;
    goto check_serverback;
  }

  if (hp)
    /*
     * If we are missing a C or N line from above, search for
     * it under all known hostnames we have for this ip#.
     */
    for (i = 0, name = hp->h_name; name; name = hp->h_aliases[i++])
    {
      strncpy(fullname, name, sizeof(fullname) - 1);
      fullname[sizeof(fullname) - 1] = 0;
      add_local_domain(fullname, HOSTLEN - strlen(fullname));
      Debug((DEBUG_DNS, "sv_cl: gethostbyaddr: %s->%s", sockname, fullname));
      sprintf_irc(abuff, "%s@%s", cptr->username, fullname);
      if (!c_conf)
	c_conf = find_conf_host(lp, abuff, CFLAG);
      if (!n_conf)
	n_conf = find_conf_host(lp, abuff, NFLAG);
      if (c_conf && n_conf)
      {
	get_sockhost(cptr, fullname);
	break;
      }
    }
  name = cptr->name;

  /*
   * Check for C and N lines with the hostname portion the ip number
   * of the host the server runs on. This also checks the case where
   * there is a server connecting from 'localhost'.
   */
  if (IsUnknown(cptr) && (!c_conf || !n_conf))
  {
    sprintf_irc(abuff, "%s@%s", cptr->username, sockname);
    if (!c_conf)
      c_conf = find_conf_host(lp, abuff, CFLAG);
    if (!n_conf)
      n_conf = find_conf_host(lp, abuff, NFLAG);
  }
  /*
   * Attach by IP# only if all other checks have failed.
   * It is quite possible to get here with the strange things that can
   * happen when using DNS in the way the irc server does. -avalon
   */
  if (!hp)
  {
    if (!c_conf)
      c_conf = find_conf_ip(lp, (char *)&cptr->ip, cptr->username, CFLAG);
    if (!n_conf)
      n_conf = find_conf_ip(lp, (char *)&cptr->ip, cptr->username, NFLAG);
  }
  else
    for (i = 0; hp->h_addr_list[i]; i++)
    {
      if (!c_conf)
	c_conf = find_conf_ip(lp, hp->h_addr_list[i], cptr->username, CFLAG);
      if (!n_conf)
	n_conf = find_conf_ip(lp, hp->h_addr_list[i], cptr->username, NFLAG);
    }
  /*
   * detach all conf lines that got attached by attach_confs()
   */
  det_confs_butmask(cptr, 0);
  /*
   * if no C or no N lines, then deny access
   */
  if (!c_conf || !n_conf)
  {
    get_sockhost(cptr, sockname);
    Debug((DEBUG_DNS, "sv_cl: access denied: %s[%s@%s] c %p n %p",
	name, cptr->username, cptr->sockhost, c_conf, n_conf));
    return -1;
  }
  /*
   * attach the C and N lines to the client structure for later use.
   */
  attach_conf(cptr, n_conf);
  attach_conf(cptr, c_conf);
  attach_confs(cptr, name, CONF_HUB | CONF_LEAF | CONF_UWORLD);

  if ((c_conf->ipnum.s_addr == INADDR_NONE) && !IsUnixSocket(cptr))
    memcpy(&c_conf->ipnum, &cptr->ip, sizeof(struct in_addr));
  if (!IsUnixSocket(cptr))
    get_sockhost(cptr, c_conf->host);

  Debug((DEBUG_DNS, "sv_cl: access ok: %s[%s]", name, cptr->sockhost));
  return 0;
}
#undef	CFLAG
#undef	NFLAG

/*
 * completed_connection
 *
 * Complete non-blocking connect()-sequence. Check access and
 * terminate connection, if trouble detected.
 *
 * Return  TRUE, if successfully completed
 *        FALSE, if failed and ClientExit
 */
static int completed_connection(aClient *cptr)
{
  aConfItem *aconf;
  time_t newts;
  aClient *acptr;
  int i;

  aconf = find_conf(cptr->confs, cptr->name, CONF_CONNECT_SERVER);
  if (!aconf)
  {
    sendto_ops("Lost C-Line for %s", get_client_name(cptr, FALSE));
    return -1;
  }
  if (!BadPtr(aconf->passwd))
    sendto_one(cptr, "PASS :%s", aconf->passwd);

  aconf = find_conf(cptr->confs, cptr->name, CONF_NOCONNECT_SERVER);
  if (!aconf)
  {
    sendto_ops("Lost N-Line for %s", get_client_name(cptr, FALSE));
    return -1;
  }
  make_server(cptr);
  /* Create a unique timestamp */
  newts = TStime();
  for (i = highest_fd; i >= 0; i--)
  {
    if (!(acptr = loc_clients[i]) || (!IsServer(acptr) && !IsHandshake(acptr)))
      continue;
    if (acptr->serv->timestamp >= newts)
      newts = acptr->serv->timestamp + 1;
  }
  cptr->serv->timestamp = newts;
  SetHandshake(cptr);
  /* Make us timeout after twice the timeout for DNS look ups */
  cptr->lasttime = now;
  cptr->flags |= FLAGS_PINGSENT;
  sendto_one(cptr, "SERVER %s 1 " TIME_T_FMT " " TIME_T_FMT " J%s %s%s :%s",
      my_name_for_link(me.name, aconf), me.serv->timestamp,
      newts, MAJOR_PROTOCOL, NumServCap(&me), me.info);
  if (!IsDead(cptr))
    start_auth(cptr);

  return (IsDead(cptr)) ? -1 : 0;
}

/*
 * close_connection
 *
 * Close the physical connection. This function must make
 * MyConnect(cptr) == FALSE, and set cptr->from == NULL.
 */
void close_connection(aClient *cptr)
{
  Reg1 aConfItem *aconf;
  Reg2 int i, j;
  int empty = cptr->fd;

  if (IsServer(cptr))
  {
    ircstp->is_sv++;
    ircstp->is_sbs += cptr->sendB;
    ircstp->is_sbr += cptr->receiveB;
    ircstp->is_sks += cptr->sendK;
    ircstp->is_skr += cptr->receiveK;
    ircstp->is_sti += now - cptr->firsttime;
    if (ircstp->is_sbs > 1023)
    {
      ircstp->is_sks += (ircstp->is_sbs >> 10);
      ircstp->is_sbs &= 0x3ff;
    }
    if (ircstp->is_sbr > 1023)
    {
      ircstp->is_skr += (ircstp->is_sbr >> 10);
      ircstp->is_sbr &= 0x3ff;
    }
  }
  else if (IsUser(cptr))
  {
    ircstp->is_cl++;
    ircstp->is_cbs += cptr->sendB;
    ircstp->is_cbr += cptr->receiveB;
    ircstp->is_cks += cptr->sendK;
    ircstp->is_ckr += cptr->receiveK;
    ircstp->is_cti += now - cptr->firsttime;
    if (ircstp->is_cbs > 1023)
    {
      ircstp->is_cks += (ircstp->is_cbs >> 10);
      ircstp->is_cbs &= 0x3ff;
    }
    if (ircstp->is_cbr > 1023)
    {
      ircstp->is_ckr += (ircstp->is_cbr >> 10);
      ircstp->is_cbr &= 0x3ff;
    }
  }
  else
    ircstp->is_ni++;

  /*
   * Remove outstanding DNS queries.
   */
  del_queries((char *)cptr);
  /*
   * If the connection has been up for a long amount of time, schedule
   * a 'quick' reconnect, else reset the next-connect cycle.
   */

  if ((aconf = find_conf_exact(cptr->name, cptr->username,
      cptr->sockhost, CONF_CONNECT_SERVER)))
  {
    /*
     * Reschedule a faster reconnect, if this was a automaticly
     * connected configuration entry. (Note that if we have had
     * a rehash in between, the status has been changed to
     * CONF_ILLEGAL). But only do this if it was a "good" link.
     */
    aconf->hold = now;
    aconf->hold += (aconf->hold - cptr->since > HANGONGOODLINK) ?
	HANGONRETRYDELAY : ConfConFreq(aconf);
    if (nextconnect > aconf->hold)
      nextconnect = aconf->hold;
  }

  if (cptr->authfd >= 0)
    close(cptr->authfd);

  if (cptr->fd >= 0)
  {
    flush_connections(cptr->fd);
    loc_clients[cptr->fd] = NULL;
    close(cptr->fd);
    cptr->fd = -2;
  }

  DBufClear(&cptr->sendQ);
  DBufClear(&cptr->recvQ);
  memset(cptr->passwd, 0, sizeof(cptr->passwd));
  set_snomask(cptr, 0, SNO_SET);
  /*
   * Clean up extra sockets from P-lines which have been discarded.
   */
  if (cptr->acpt != &me && cptr->acpt != cptr)
  {
    aconf = cptr->acpt->confs->value.aconf;
    if (aconf->clients > 0)
      aconf->clients--;
    if (!aconf->clients && IsIllegal(aconf))
      close_connection(cptr->acpt);
  }

  for (; highest_fd > 0; highest_fd--)
    if (loc_clients[highest_fd])
      break;

  det_confs_butmask(cptr, 0);

  /*
   * fd remap to keep loc_clients[i] filled at the bottom.
   */
  if (empty > 0)
    if ((j = highest_fd) > (i = empty) && !IsLog(loc_clients[j]))
    {
      if (IsListening(loc_clients[j]))
	return;
      if (dup2(j, i) == -1)
	return;
      loc_clients[i] = loc_clients[j];
      loc_clients[i]->fd = i;
      loc_clients[j] = NULL;
      close(j);
      while (!loc_clients[highest_fd])
	highest_fd--;
    }

  return;
}

/*
 *  set_sock_opts
 */
static void set_sock_opts(int fd, aClient *cptr)
{
  size_t opt;
#ifdef SO_REUSEADDR
  opt = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
      (OPT_TYPE *)&opt, sizeof(opt)) < 0)
    report_error("setsockopt(SO_REUSEADDR) %s: %s", cptr);
#endif
#ifdef	SO_USELOOPBACK
  opt = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_USELOOPBACK,
      (OPT_TYPE *)&opt, sizeof(opt)) < 0)
    report_error("setsockopt(SO_USELOOPBACK) %s: %s", cptr);
#endif
#ifdef	SO_RCVBUF
  opt = 8192;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (OPT_TYPE *)&opt, sizeof(opt)) < 0)
    report_error("setsockopt(SO_RCVBUF) %s: %s", cptr);
#endif
#ifdef SO_SNDBUF
#ifdef _SEQUENT_
/*
 * Seems that Sequent freezes up if the receving buffer is a different size
 * to the sending buffer (maybe a tcp window problem too).
 */
  opt = 8192;
#else
  opt = 8192;
#endif
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (OPT_TYPE *)&opt, sizeof(opt)) < 0)
    report_error("setsockopt(SO_SNDBUF) %s: %s", cptr);
#endif
#if defined(IP_OPTIONS) && defined(IPPROTO_IP)
  {
    char *s = readbuf, *t = readbuf + sizeof(readbuf) / 2;

    opt = sizeof(readbuf) / 8;
    if (getsockopt(fd, IPPROTO_IP, IP_OPTIONS, (OPT_TYPE *)t, &opt) < 0)
      report_error("getsockopt(IP_OPTIONS) %s: %s", cptr);
    else if (opt > 0 && opt != sizeof(readbuf) / 8)
    {
      for (*readbuf = '\0'; opt > 0; opt--, s += 3)
	sprintf(s, "%02x:", *t++);
      *s = '\0';
      sendto_ops("Connection %s using IP opts: (%s)",
	  get_client_name(cptr, TRUE), readbuf);
    }
    if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, (OPT_TYPE *)NULL, 0) < 0)
      report_error("setsockopt(IP_OPTIONS) %s: %s", cptr);
  }
#endif
}

int get_sockerr(aClient *cptr)
{
  int errtmp = errno;
#if defined(SO_ERROR) && !defined(SOL2)
  int err = 0;
  size_t len = sizeof(err);
  if (cptr->fd >= 0)
    if (!getsockopt(cptr->fd, SOL_SOCKET, SO_ERROR, (OPT_TYPE *)&err, &len))
      if (err)
	errtmp = err;
#endif
  return errtmp;
}

/*
 * set_non_blocking
 *
 * Set the client connection into non-blocking mode. If your
 * system doesn't support this, you can make this a dummy
 * function (and get all the old problems that plagued the
 * blocking version of IRC--not a problem if you are a
 * lightly loaded node...)
 */
void set_non_blocking(int fd, aClient *cptr)
{
  int res;
#ifndef NBLOCK_SYSV
  int nonb = 0;
#endif

  /*
   * NOTE: consult ALL your relevant manual pages *BEFORE* changing
   * these ioctl's. There are quite a few variations on them,
   * as can be seen by the PCS one. They are *NOT* all the same.
   * Heed this well. - Avalon.
   */
#ifdef	NBLOCK_POSIX
  nonb |= O_NONBLOCK;
#endif
#ifdef	NBLOCK_BSD
  nonb |= O_NDELAY;
#endif
#ifdef	NBLOCK_SYSV
  /* This portion of code might also apply to NeXT. -LynX */
  res = 1;

  if (ioctl(fd, FIONBIO, &res) < 0)
    report_error("ioctl(fd,FIONBIO) failed for %s: %s", cptr);
#else
  if ((res = fcntl(fd, F_GETFL, 0)) == -1)
    report_error("fcntl(fd, F_GETFL) failed for %s: %s", cptr);
  else if (fcntl(fd, F_SETFL, res | nonb) == -1)
    report_error("fcntl(fd, F_SETL, nonb) failed for %s: %s", cptr);
#endif
  return;
}

/*
 * Creates a client which has just connected to us on the given fd.
 * The sockhost field is initialized with the ip# of the host.
 * The client is added to the linked list of clients but isnt added to any
 * hash tables yet since it doesn't have a name.
 */
aClient *add_connection(aClient *cptr, int fd, int type)
{
  Link lin;
  aClient *acptr;
  aConfItem *aconf = NULL;
  acptr =
      make_client(NULL,
      (cptr->port == portnum) ? STAT_UNKNOWN_SERVER : STAT_UNKNOWN_USER);

  if (cptr != &me)
    aconf = cptr->confs->value.aconf;
  /*
   * Removed preliminary access check. Full check is performed in
   * m_server and m_user instead. Also connection time out help to
   * get rid of unwanted connections.
   */
  if (type == ADCON_TTY)	/* If descriptor is a tty,
				   special checking... */
    get_sockhost(acptr, cptr->sockhost);
  else
  {
    Reg1 char *s, *t;
    struct sockaddr_in addr;
    size_t len = sizeof(struct sockaddr_in);

    if (getpeername(fd, (struct sockaddr *)&addr, &len) == -1)
    {
      report_error("Failed in connecting to %s: %s", cptr);
    add_con_refuse:
      ircstp->is_ref++;
      acptr->fd = -2;
      free_client(acptr);
      close(fd);
      return NULL;
    }
    /* Don't want to add "Failed in connecting to" here.. */
    if (aconf && IsIllegal(aconf))
      goto add_con_refuse;
    /*
     * Copy ascii address to 'sockhost' just in case. Then we
     * have something valid to put into error messages...
     */
    get_sockhost(acptr, inetntoa(addr.sin_addr));
    memcpy(&acptr->ip, &addr.sin_addr, sizeof(struct in_addr));
#ifdef TESTNET
    acptr->port = ntohs(addr.sin_port) - 10000;
#else
    acptr->port = ntohs(addr.sin_port);
#endif

    /*
     * Check that this socket (client) is allowed to accept
     * connections from this IP#.
     */
    for (s = (char *)&cptr->ip, t = (char *)&acptr->ip, len = 4;
	len > 0; len--, s++, t++)
    {
      if (!*s)
	continue;
      if (*s != *t)
	break;
    }

    if (len)
      goto add_con_refuse;

    lin.flags = ASYNC_CLIENT;
    lin.value.cptr = acptr;
    Debug((DEBUG_DNS, "lookup %s", inetntoa(addr.sin_addr)));
    acptr->hostp = gethost_byaddr(&acptr->ip, &lin);
    if (!acptr->hostp)
      SetDNS(acptr);
    nextdnscheck = 1;
  }

  if (aconf)
    aconf->clients++;
  acptr->fd = fd;
  if (fd > highest_fd)
    highest_fd = fd;
  loc_clients[fd] = acptr;
  acptr->acpt = cptr;
  Count_newunknown(nrof);
  add_client_to_list(acptr);
  set_non_blocking(acptr->fd, acptr);
  set_sock_opts(acptr->fd, acptr);

  /*
   * Add this local client to the IPcheck registry.
   * If it is a connection to a user port and if the site has been throttled,
   * reject the user.
   */
  if (IPcheck_local_connect(acptr) == -1 && IsUserPort(acptr))
  {
    ircstp->is_ref++;
    exit_client(cptr, acptr, &me,
	"Your host is trying to (re)connect too fast -- throttled");
    return NULL;
  }

  start_auth(acptr);
  return acptr;
}

#ifdef	UNIXPORT
static void add_unixconnection(aClient *cptr, int fd)
{
  aClient *acptr;
  aConfItem *aconf = NULL;

  acptr = make_client(NULL, STAT_UNKNOWN);

  /*
   * Copy ascii address to 'sockhost' just in case. Then we
   * have something valid to put into error messages...
   */
  get_sockhost(acptr, me.sockhost);
  if (cptr != &me)
    aconf = cptr->confs->value.aconf;
  if (aconf)
  {
    if (IsIllegal(aconf))
    {
      ircstp->is_ref++;
      acptr->fd = -2;
      free_client(acptr);
      close(fd);
      return;
    }
    else
      aconf->clients++;
  }
  acptr->fd = fd;
  if (fd > highest_fd)
    highest_fd = fd;
  loc_clients[fd] = acptr;
  acptr->acpt = cptr;
  SetUnixSock(acptr);
  memcpy(&acptr->ip, &me.ip, sizeof(struct in_addr));

  Count_newunknown(nrof);
  add_client_to_list(acptr);
  set_non_blocking(acptr->fd, acptr);
  set_sock_opts(acptr->fd, acptr);
  SetAccess(acptr);
  return;
}
#endif

/*
 * select/poll convert macro's by Run.
 *
 * The names are chosen to reflect what they means when NOT using poll().
 */
#ifndef USE_POLL
typedef fd_set *fd_setp_t;
#define RFD_ISSET(fd, rfd, index) FD_ISSET((fd), (rfd))
#define WFD_ISSET(fd, wfd, index) FD_ISSET((fd), (wfd))
#define RFD_SET(fd, rfd, index, cptr) FD_SET((fd), (rfd))
#define WFD_SET(fd, wfd, index, cptr) FD_SET((fd), (wfd))
#define RWFD_SET(fd, wfd, index) FD_SET((fd), (wfd))
#define RFD_CLR_OUT(fd, rfd, index) FD_CLR((fd), (rfd))
#define WFD_CLR_OUT(fd, wfd, index) FD_CLR((fd), (wfd))
#define LOC_FD(index) (index)
#define LOC_CLIENTS(index) loc_clients[index]
#define HIGHEST_INDEX highest_fd
#else /* USE_POLL */
typedef unsigned int fd_setp_t;	/* Actually, an index to poll_fds[] */
#ifdef _AIX
#define POLLREADFLAGS (POLLIN|POLLMSG)
#else
#  if defined(POLLMSG) && defined(POLLIN) && defined(POLLRDNORM)
#    define POLLREADFLAGS (POLLMSG|POLLIN|POLLRDNORM)
#  else
#    if defined(POLLIN) && defined(POLLRDNORM)
#      define POLLREADFLAGS (POLLIN|POLLRDNORM)
#    else
#      if defined(POLLIN)
#        define POLLREADFLAGS POLLIN
#      else
#        if defined(POLLRDNORM)
#          define POLLREADFLAGS POLLRDNORM
#        endif
#      endif
#    endif
#  endif
#endif
#if defined(POLLOUT) && defined(POLLWRNORM)
#define POLLWRITEFLAGS (POLLOUT|POLLWRNORM)
#else
#  if defined(POLLOUT)
#    define POLLWRITEFLAGS POLLOUT
#  else
#    if defined(POLLWRNORM)
#      define POLLWRITEFLAGS POLLWRNORM
#    endif
#  endif
#endif
#ifdef POLLHUP
#define POLLERRORS (POLLHUP|POLLERR)
#else
#define POLLERRORS POLLERR
#endif
#define RFD_ISSET(fd, rfd, index) \
  ((poll_fds[index].revents & POLLREADFLAGS) || \
  ((poll_fds[index].events & POLLREADFLAGS) && \
    (poll_fds[index].revents & POLLERRORS)))
#define WFD_ISSET(fd, wfd, index) \
  ((poll_fds[index].revents & POLLWRITEFLAGS) || \
  ((poll_fds[index].events & POLLWRITEFLAGS) && \
    (poll_fds[index].revents & POLLERRORS)))
#define RFD_SET(fdes, rfd, index, cptr) \
  do { \
    poll_fds[index].fd = fdes; \
    poll_cptr[index] = cptr; \
    poll_fds[index].events = POLLREADFLAGS; \
    added = TRUE; \
  } while(0)
#define WFD_SET(fdes, wfd, index, cptr) \
  do { \
    poll_fds[index].fd = fdes; \
    poll_cptr[index] = cptr; \
    if (added) \
      poll_fds[index].events |= POLLWRITEFLAGS; \
    else \
    { \
      poll_fds[index].events = POLLWRITEFLAGS; \
      added = TRUE; \
    } \
  } while(0)
/* This identical to WFD_SET() when used after a call to RFD_SET(): */
#define RWFD_SET(fd, wfd, index) poll_fds[index].events |= POLLWRITEFLAGS
/* [RW]FD_CLR_OUT() clears revents, not events */
#define RFD_CLR_OUT(fd, rfd, index) poll_fds[index].revents &= ~POLLREADFLAGS
#define WFD_CLR_OUT(fd, wfd, index) poll_fds[index].revents &= ~POLLWRITEFLAGS
#define LOC_FD(index) (poll_fds[index].fd)
#define LOC_CLIENTS(index) (poll_cptr[index])
#define HIGHEST_INDEX (currfd_index - 1)
#endif /* USE_POLL */

/*
 * read_packet
 *
 * Read a 'packet' of data from a connection and process it.  Read in 8k
 * chunks to give a better performance rating (for server connections).
 * Do some tricky stuff for client connections to make sure they don't do
 * any flooding >:-) -avalon
 */
static int read_packet(aClient *cptr, fd_setp_t rfd)
{
  size_t dolen = 0;
  int length = 0;
  int done;

  if (RFD_ISSET(cptr->fd, rfd, rfd) &&
      !(IsUser(cptr) && DBufLength(&cptr->recvQ) > 6090))
  {
    errno = 0;
    length = recv(cptr->fd, readbuf, sizeof(readbuf), 0);

    cptr->lasttime = now;
    if (cptr->lasttime > cptr->since)
      cptr->since = cptr->lasttime;
    cptr->flags &= ~(FLAGS_PINGSENT | FLAGS_NONL);
    /*
     * If not ready, fake it so it isnt closed
     */
    if (length == -1 && ((errno == EWOULDBLOCK) || (errno == EAGAIN)))
      return 1;
    if (length <= 0)
      return length;
  }

  /*
   * For server connections, we process as many as we can without
   * worrying about the time of day or anything :)
   */
  if (IsServer(cptr) || IsConnecting(cptr) || IsHandshake(cptr))
  {
    if (length > 0)
      if ((done = dopacket(cptr, readbuf, length)))
	return done;
  }
  else
  {
    /*
     * Before we even think of parsing what we just read, stick
     * it on the end of the receive queue and do it when its
     * turn comes around.
     */
    if (!dbuf_put(&cptr->recvQ, readbuf, length))
      return exit_client(cptr, cptr, &me, "dbuf_put fail");

#ifndef NOFLOODCONTROL
    if (IsUser(cptr) && DBufLength(&cptr->recvQ) > CLIENT_FLOOD)
      return exit_client(cptr, cptr, &me, "Excess Flood");
#endif

    while (DBufLength(&cptr->recvQ) && !NoNewLine(cptr)
#ifndef NOFLOODCONTROL
	&& (IsTrusted(cptr) || cptr->since - now < 10)
#endif
	)
    {
      /*
       * If it has become registered as a Server
       * then skip the per-message parsing below.
       */
      if (IsServer(cptr))
      {
	/*
	 * XXX - this blindly deletes data if no cr/lf is received at
	 * the end of a lot of messages and the data stored in the 
	 * dbuf is greater than sizeof(readbuf)
	 */
	dolen = dbuf_get(&cptr->recvQ, readbuf, sizeof(readbuf));
	if (0 == dolen)
	  break;
	if ((done = dopacket(cptr, readbuf, dolen)))
	  return done;
	break;
      }
      dolen = dbuf_getmsg(&cptr->recvQ, cptr->buffer, BUFSIZE);
      /*
       * Devious looking...whats it do ? well..if a client
       * sends a *long* message without any CR or LF, then
       * dbuf_getmsg fails and we pull it out using this
       * loop which just gets the next 512 bytes and then
       * deletes the rest of the buffer contents.
       * -avalon
       */
      if (0 == dolen)
      {
	if (DBufLength(&cptr->recvQ) < 510)
	{
	  cptr->flags |= FLAGS_NONL;
	  break;
	}
	DBufClear(&cptr->recvQ);
	break;
      }
      else if (CPTR_KILLED == client_dopacket(cptr, dolen))
	return CPTR_KILLED;
    }
  }
  return 1;
}

/*
 * Check all connections for new connections and input data that is to be
 * processed. Also check for connections with data queued and whether we can
 * write it out.
 *
 * Don't ever use ZERO for `delay', unless you mean to poll and then
 * you have to have sleep/wait somewhere else in the code.--msa
 */
int read_message(time_t delay)
{
  Reg1 aClient *cptr;
  Reg2 int nfds;
  struct timeval wait;
#ifdef	pyr
  struct timeval nowt;
  unsigned long us;
#endif
  time_t delay2 = delay;
  unsigned long usec = 0;
  int res, length, fd, i;
  int auth = 0, ping = 0;
#ifndef USE_POLL
  fd_set read_set, write_set;
#else /* USE_POLL */
  unsigned int currfd_index = 0;
  unsigned int udpfdindex = 0;
  unsigned int resfdindex = 0;
  unsigned long timeout;
  int added;
#endif /* USE_POLL */

#ifdef	pyr
  gettimeofday(&nowt, NULL);
  now = nowt.tv_sec;
#endif

  for (res = 0;;)
  {
#ifndef USE_POLL
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
#endif /* not USE_POLL */
    for (i = highest_fd; i >= 0; i--)
    {
#ifdef USE_POLL
      added = FALSE;
#endif /* USE_POLL */
      if (!(cptr = loc_clients[i]))
	continue;
      if (IsLog(cptr))
	continue;
      if (DoingAuth(cptr))
      {
	auth++;
	Debug((DEBUG_NOTICE, "auth on %p %d", cptr, i));
	RFD_SET(cptr->authfd, &read_set, currfd_index, cptr);
	if (cptr->flags & FLAGS_WRAUTH)
	  RWFD_SET(cptr->authfd, &write_set, currfd_index);
      }
      if (IsPing(cptr))
      {
	ping++;
	Debug((DEBUG_NOTICE, "open ping on %p %d", cptr, i));
	if (!cptr->firsttime || now <= cptr->firsttime)
	{
	  RFD_SET(i, &read_set, currfd_index, cptr);
	  delay2 = 1;
	  if (DoPing(cptr) && now > cptr->lasttime)
	    RWFD_SET(i, &write_set, currfd_index);
	}
	else
	{
	  del_queries((char *)cptr);
	  end_ping(cptr);
	}
#ifdef USE_POLL
	if (added)
	  currfd_index++;
#endif /* USE_POLL */
	continue;
      }
      if (DoingDNS(cptr) || DoingAuth(cptr))
      {
#ifdef USE_POLL
	if (added)
	  currfd_index++;
#endif /* USE_POLL */
	continue;
      }
      if (IsMe(cptr) && IsListening(cptr))
	RFD_SET(i, &read_set, currfd_index, cptr);
      else if (!IsMe(cptr))
      {
	if (DBufLength(&cptr->recvQ) && delay2 > 2)
	  delay2 = 1;
	if (DBufLength(&cptr->recvQ) < 4088)
	  RFD_SET(i, &read_set, currfd_index, cptr);
	if (DBufLength(&cptr->sendQ) || IsConnecting(cptr) ||
	    (cptr->listing && DBufLength(&cptr->sendQ) < 2048))
#ifndef pyr
	  WFD_SET(i, &write_set, currfd_index, cptr);
#else /* pyr */
	{
	  if (!(cptr->flags & FLAGS_BLOCKED))
	    WFD_SET(i, &write_set, currfd_index, cptr);
	  else
	    delay2 = 0, usec = 500000;
	}
	if (now - cptr->lw.tv_sec && nowt.tv_usec - cptr->lw.tv_usec < 0)
	  us = 1000000;
	else
	  us = 0;
	us += nowt.tv_usec;
	if (us - cptr->lw.tv_usec > 500000)
	  cptr->flags &= ~FLAGS_BLOCKED;
#endif /* pyr */
      }
#ifdef USE_POLL
      if (added)
	currfd_index++;
#endif /* USE_POLL */
    }

    if (udpfd >= 0)
    {
      RFD_SET(udpfd, &read_set, currfd_index, NULL);
#ifdef USE_POLL
      udpfdindex = currfd_index;
      currfd_index++;
#endif /* USE_POLL */
    }
    if (resfd >= 0)
    {
      RFD_SET(resfd, &read_set, currfd_index, NULL);
#ifdef USE_POLL
      resfdindex = currfd_index;
      currfd_index++;
#endif /* USE_POLL */
    }

    wait.tv_sec = MIN(delay2, delay);
    wait.tv_usec = usec;
#ifndef USE_POLL
#ifdef	HPUX
    nfds = select(FD_SETSIZE, (int *)&read_set, (int *)&write_set, 0, &wait);
#else
    nfds = select(FD_SETSIZE, &read_set, &write_set, 0, &wait);
#endif
#else /* USE_POLL */
    timeout = (wait.tv_sec * 1000) + (wait.tv_usec / 1000);
    nfds = poll(poll_fds, currfd_index, timeout);
#endif /* USE_POLL */
    now = time(NULL);
    if (nfds == -1 && errno == EINTR)
      return -1;
    else if (nfds >= 0)
      break;
    report_error("select %s: %s", &me);
    res++;
    if (res > 5)
      restart("too many select errors");
    sleep(10);
    now += 10;
  }

  if (udpfd >= 0 && RFD_ISSET(udpfd, &read_set, udpfdindex))
  {
    polludp();
    nfds--;
    RFD_CLR_OUT(udpfd, &read_set, udpfdindex);
  }
  /*
   * Check fd sets for the ping fd's (if set and valid!) first
   * because these can not be processed using the normal loops below.
   * And we want them to be as fast as possible.
   * -Run
   */
  for (i = HIGHEST_INDEX; (ping > 0) && (i >= 0); i--)
  {
    if (!(cptr = LOC_CLIENTS(i)))
      continue;
    if (!IsPing(cptr))
      continue;
    ping--;
    if ((nfds > 0) && RFD_ISSET(cptr->fd, &read_set, i))
    {
      nfds--;
      RFD_CLR_OUT(cptr->fd, &read_set, i);
      read_ping(cptr);		/* This can RunFree(cptr) ! */
    }
    else if ((nfds > 0) && WFD_ISSET(cptr->fd, &write_set, i))
    {
      nfds--;
      cptr->lasttime = now;
      WFD_CLR_OUT(cptr->fd, &write_set, i);
      send_ping(cptr);		/* This can RunFree(cptr) ! */
    }
  }
  if (resfd >= 0 && RFD_ISSET(resfd, &read_set, resfdindex))
  {
    do_dns_async();
    nfds--;
    RFD_CLR_OUT(resfd, &read_set, resfdindex);
  }
  /*
   * Check fd sets for the auth fd's (if set and valid!) first
   * because these can not be processed using the normal loops below.
   * -avalon
   */
  for (i = HIGHEST_INDEX; (auth > 0) && (i >= 0); i--)
  {
    if (!(cptr = LOC_CLIENTS(i)))
      continue;
    if (cptr->authfd < 0)
      continue;
    auth--;
    if ((nfds > 0) && WFD_ISSET(cptr->authfd, &write_set, i))
    {
      nfds--;
      send_authports(cptr);
    }
    else if ((nfds > 0) && RFD_ISSET(cptr->authfd, &read_set, i))
    {
      nfds--;
      read_authports(cptr);
    }
  }
  for (i = HIGHEST_INDEX; i >= 0; i--)
    if ((cptr = LOC_CLIENTS(i)) && RFD_ISSET(i, &read_set, i) &&
	IsListening(cptr))
    {
      RFD_CLR_OUT(i, &read_set, i);
      nfds--;
      cptr->lasttime = now;
      /*
       * There may be many reasons for error return, but
       * in otherwise correctly working environment the
       * probable cause is running out of file descriptors
       * (EMFILE, ENFILE or others?). The man pages for
       * accept don't seem to list these as possible,
       * although it's obvious that it may happen here.
       * Thus no specific errors are tested at this
       * point, just assume that connections cannot
       * be accepted until some old is closed first.
       */
      if ((fd = accept(LOC_FD(i), NULL, NULL)) < 0)
      {
	if (errno != EWOULDBLOCK)
	  report_error("accept() failed%s: %s", NULL);
	break;
      }
#if defined(USE_SYSLOG) && defined(SYSLOG_CONNECTS)
      {				/* get an early log of all connections   --dl */
	static struct sockaddr_in peer;
	static int len;
	len = sizeof(peer);
	getpeername(fd, (struct sockaddr *)&peer, &len);
	syslog(LOG_DEBUG, "Conn: %s", inetntoa(peer.sin_addr));
      }
#endif
      ircstp->is_ac++;
      if (fd >= MAXCLIENTS)
      {
	/* Don't send more messages then one every 10 minutes */
	static int count;
	static time_t last_time;
	ircstp->is_ref++;
	++count;
	if (last_time < now - (time_t) 600)
	{
	  if (count > 0)
	  {
	    if (!last_time)
	      last_time = me.since;
	    sendto_ops
		("All connections in use!  Had to refuse %d clients in the last "
		STIME_T_FMT " minutes", count, (now - last_time) / 60);
	  }
	  else
	    sendto_ops("All connections in use. (%s)", get_client_name(cptr,
		TRUE));
	  count = 0;
	  last_time = now;
	}
	send(fd, "ERROR :All connections in use\r\n", 32, 0);
	close(fd);
	break;
      }
      /*
       * Use of add_connection (which never fails :) meLazy
       */
#ifdef	UNIXPORT
      if (IsUnixSocket(cptr))
	add_unixconnection(cptr, fd);
      else
#endif
      if (!add_connection(cptr, fd, ADCON_SOCKET))
	continue;
      nextping = now;
      if (!cptr->acpt)
	cptr->acpt = &me;
    }

  for (i = HIGHEST_INDEX; i >= 0; i--)
  {
    if (!(cptr = LOC_CLIENTS(i)) || IsMe(cptr))
      continue;
#ifdef USE_POLL
    if (DoingDNS(cptr) || DoingAuth(cptr) || !(cptr = loc_clients[LOC_FD(i)]))
      continue;
#endif /* USE_POLL */
#ifdef DEBUGMODE
    if (IsLog(cptr))
      continue;
#endif
    if (WFD_ISSET(i, &write_set, i))
    {
      int write_err = 0;
      nfds--;
      /*
       *  ...room for writing, empty some queue then...
       */
      cptr->flags &= ~FLAGS_BLOCKED;
      if (IsConnecting(cptr))
	write_err = completed_connection(cptr);
      if (!write_err)
      {
	if (cptr->listing && DBufLength(&cptr->sendQ) < 2048)
	  list_next_channels(cptr, 64);
	send_queued(cptr);
      }
      if (IsDead(cptr) || write_err)
      {
      deadsocket:
	if (RFD_ISSET(i, &read_set, i))
	{
	  nfds--;
	  RFD_CLR_OUT(i, &read_set, i);
	}
	exit_client(cptr, cptr, &me,
	    IsDead(cptr) ? LastDeadComment(cptr) : strerror(get_sockerr(cptr)));
	continue;
      }
    }
    length = 1;			/* for fall through case */
    if ((!NoNewLine(cptr) || RFD_ISSET(i, &read_set, i)) && !IsDead(cptr))
#ifndef USE_POLL
      length = read_packet(cptr, &read_set);
#else /* USE_POLL */
      length = read_packet(cptr, i);
#endif /* USE_POLL */
#if 0
    /* Bullshit, why would we want to flush sockets while using non-blocking?
     * This uses > 4% cpu! --Run */
    if (length > 0)
      flush_connections(LOC_FD(i));
#endif
    if ((length != CPTR_KILLED) && IsDead(cptr))
      goto deadsocket;
    if (!RFD_ISSET(i, &read_set, i) && length > 0)
      continue;
    nfds--;
    readcalls++;
    if (length > 0 || length == CPTR_KILLED)
      continue;

    /*
     * ...hmm, with non-blocking sockets we might get
     * here from quite valid reasons, although.. why
     * would select report "data available" when there
     * wasn't... So, this must be an error anyway...  --msa
     * actually, EOF occurs when read() returns 0 and
     * in due course, select() returns that fd as ready
     * for reading even though it ends up being an EOF. -avalon
     */
    Debug((DEBUG_ERROR, "READ ERROR: fd = %d %d %d", LOC_FD(i), errno, length));

    if ((IsServer(cptr) || IsHandshake(cptr)) && errno == 0 && length == 0)
      exit_client_msg(cptr, cptr, &me, "Server %s closed the connection (%s)",
	  get_client_name(cptr, FALSE), cptr->serv->last_error_msg);
    else
      exit_client_msg(cptr, cptr, &me, "Read error to %s: %s",
	  get_client_name(cptr, FALSE), (length < 0) ?
	  strerror(get_sockerr(cptr)) : "EOF from client");
  }
  return 0;
}

/*
 * connect_server
 */
int connect_server(aConfItem *aconf, aClient *by, struct hostent *hp)
{
  Reg1 struct sockaddr *svp;
  Reg2 aClient *cptr, *c2ptr;
  Reg3 char *s;
  int errtmp, len;

  Debug((DEBUG_NOTICE, "Connect to %s[%s] @%s",
      aconf->name, aconf->host, inetntoa(aconf->ipnum)));

  if ((c2ptr = FindClient(aconf->name)))
  {
    if (IsServer(c2ptr) || IsMe(c2ptr))
    {
      sendto_ops("Server %s already present from %s",
	  aconf->name, c2ptr->from->name);
      if (by && IsUser(by) && !MyUser(by))
      {
#ifndef NO_PROTOCOL9
	if (Protocol(by->from) < 10)
	  sendto_one(by, ":%s NOTICE %s :Server %s already present from %s",
	      me.name, by->name, aconf->name, c2ptr->from->name);
	else
#endif
	  sendto_one(by, "%s NOTICE %s%s :Server %s already present from %s",
	      NumServ(&me), NumNick(by), aconf->name, c2ptr->from->name);
      }
      return -1;
    }
    else if (IsHandshake(c2ptr) || IsConnecting(c2ptr))
    {
      if (by && IsUser(by))
      {
	if (MyUser(by) || Protocol(by->from) < 10)
	  sendto_one(by, ":%s NOTICE %s :Connection to %s already in progress",
	      me.name, by->name, get_client_name(c2ptr, TRUE));
	else
	  sendto_one(by,
	      "%s NOTICE %s%s :Connection to %s already in progress",
	      NumServ(&me), NumNick(by), get_client_name(c2ptr, TRUE));
      }
      return -1;
    }
  }

  /*
   * If we dont know the IP# for this host and itis a hostname and
   * not a ip# string, then try and find the appropriate host record.
   */
  if ((!aconf->ipnum.s_addr)
#ifdef UNIXPORT
      && ((aconf->host[2]) != '/')	/* needed for Unix domain -- dl */
#endif
      )
  {
    Link lin;

    lin.flags = ASYNC_CONNECT;
    lin.value.aconf = aconf;
    nextdnscheck = 1;
    s = strchr(aconf->host, '@');
    s++;			/* should NEVER be NULL */
    if ((aconf->ipnum.s_addr = inet_addr(s)) == INADDR_NONE)
    {
      aconf->ipnum.s_addr = INADDR_ANY;
      hp = gethost_byname(s, &lin);
      Debug((DEBUG_NOTICE, "co_sv: hp %p ac %p na %s ho %s",
	  hp, aconf, aconf->name, s));
      if (!hp)
	return 0;
      memcpy(&aconf->ipnum, hp->h_addr, sizeof(struct in_addr));
    }
  }
  cptr = make_client(NULL, STAT_UNKNOWN);
  cptr->hostp = hp;
  /*
   * Copy these in so we have something for error detection.
   */
  strncpy(cptr->name, aconf->name, sizeof(cptr->name) - 1);
  cptr->name[sizeof(cptr->name) - 1] = 0;
  strncpy(cptr->sockhost, aconf->host, HOSTLEN);
  cptr->sockhost[HOSTLEN] = 0;

#ifdef	UNIXPORT
  if (aconf->host[2] == '/')	/* (/ starts a 2), Unix domain -- dl */
    svp = connect_unix(aconf, cptr, &len);
  else
    svp = connect_inet(aconf, cptr, &len);
#else
  svp = connect_inet(aconf, cptr, &len);
#endif

  if (!svp)
  {
    if (cptr->fd >= 0)
      close(cptr->fd);
    cptr->fd = -2;
    if (by && IsUser(by) && !MyUser(by))
    {
#ifndef NO_PROTOCOL9
      if (Protocol(by->from) < 10)
	sendto_one(by, ":%s NOTICE %s :Couldn't connect to %s",
	    me.name, by->name, get_client_name(cptr, TRUE));
      else
#endif
	sendto_one(by, "%s NOTICE %s%s :Couldn't connect to %s",
	    NumServ(&me), NumNick(by), get_client_name(cptr, TRUE));
    }
    free_client(cptr);
    return -1;
  }

  set_non_blocking(cptr->fd, cptr);
  set_sock_opts(cptr->fd, cptr);
  signal(SIGALRM, dummy);
  alarm(4);
  if (connect(cptr->fd, svp, len) < 0 && errno != EINPROGRESS)
  {
    int err = get_sockerr(cptr);
    errtmp = errno;		/* other system calls may eat errno */
    alarm(0);
    report_error("Connect to host %s failed: %s", cptr);
    if (by && IsUser(by) && !MyUser(by))
    {
#ifndef NO_PROTOCOL9
      if (Protocol(by->from) < 10)
	sendto_one(by, ":%s NOTICE %s :Connect to host %s failed: %s",
	    me.name, by->name, get_client_name(cptr, TRUE), strerror(err));
      else
#endif
	sendto_one(by, "%s NOTICE %s%s :Connect to host %s failed: %s",
	    NumServ(&me), NumNick(by), get_client_name(cptr, TRUE),
	    strerror(err));
    }
    close(cptr->fd);
    cptr->fd = -2;
    free_client(cptr);
    errno = errtmp;
    if (errno == EINTR)
      errno = ETIMEDOUT;
    return -1;
  }
  alarm(0);

  /*
   * Attach config entries to client here rather than in
   * completed_connection. This to avoid null pointer references
   * when name returned by gethostbyaddr matches no C lines
   * (could happen in 2.6.1a when host and servername differ).
   * No need to check access and do gethostbyaddr calls.
   * There must at least be one as we got here C line...  meLazy
   */
  attach_confs_host(cptr, aconf->host,
      CONF_NOCONNECT_SERVER | CONF_CONNECT_SERVER);

  if (!find_conf_host(cptr->confs, aconf->host, CONF_NOCONNECT_SERVER) ||
      !find_conf_host(cptr->confs, aconf->host, CONF_CONNECT_SERVER))
  {
    sendto_ops("Host %s is not enabled for connecting:no C/N-line",
	aconf->host);
    if (by && IsUser(by) && !MyUser(by))
    {
#ifndef NO_PROTOCOL9
      if (Protocol(by->from) < 10)
	sendto_one(by,
	    ":%s NOTICE %s :Connect to host %s failed: no C/N-lines",
	    me.name, by->name, get_client_name(cptr, TRUE));
      else
#endif
	sendto_one(by,
	    "%s NOTICE %s%s :Connect to host %s failed: no C/N-lines",
	    NumServ(&me), NumNick(by), get_client_name(cptr, TRUE));
    }
    det_confs_butmask(cptr, 0);
    close(cptr->fd);
    cptr->fd = -2;
    free_client(cptr);
    return (-1);
  }
  /*
   * The socket has been connected or connect is in progress.
   */
  make_server(cptr);
  if (by && IsUser(by))
  {
    sprintf_irc(cptr->serv->by, "%s%s", NumNick(by));
    if (cptr->serv->user)
      free_user(cptr->serv->user, NULL);
    cptr->serv->user = by->user;
    by->user->refcnt++;
  }
  else
  {
    *cptr->serv->by = '\0';
    if (cptr->serv->user)
      free_user(cptr->serv->user, NULL);
    cptr->serv->user = NULL;
  }
  cptr->serv->up = &me;
  if (cptr->fd > highest_fd)
    highest_fd = cptr->fd;
  loc_clients[cptr->fd] = cptr;
  cptr->acpt = &me;
  SetConnecting(cptr);

  get_sockhost(cptr, aconf->host);
  Count_newunknown(nrof);
  add_client_to_list(cptr);
  hAddClient(cptr);
  nextping = now;

  return 0;
}

static struct sockaddr *connect_inet(aConfItem *aconf, aClient *cptr, int *lenp)
{
  static struct sockaddr_in server;
  Reg3 struct hostent *hp;
  struct sockaddr_in bindaddr;

  /*
   * Might as well get sockhost from here, the connection is attempted
   * with it so if it fails its useless.
   */
  alarm(2);
  cptr->fd = socket(AF_INET, SOCK_STREAM, 0);
  alarm(0);
  if (cptr->fd == -1 && errno == EAGAIN)
  {
    sendto_ops("opening stream socket to server %s: No more sockets",
	get_client_name(cptr, TRUE));
    return NULL;
  }
  if (cptr->fd == -1)
  {
    report_error("opening stream socket to server %s: %s", cptr);
    return NULL;
  }
  if (cptr->fd >= MAXCLIENTS)
  {
    sendto_ops("No more connections allowed (%s)", cptr->name);
    return NULL;
  }
  mysk.sin_port = 0;
  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  get_sockhost(cptr, aconf->host);

  /*
   * Bind to a local IP# (with unknown port - let unix decide) so
   * we have some chance of knowing the IP# that gets used for a host
   * with more than one IP#.
   */
  memcpy(&bindaddr, &cserv, sizeof(bindaddr));
  if (aconf->ipnum.s_addr == 0x100007f)
    bindaddr.sin_addr.s_addr = 0x100007f;	/* bind with localhost when we are connecting to localhost */
  if (bind(cptr->fd, (struct sockaddr *)&bindaddr, sizeof(bindaddr)) == -1)
  {
    report_error("error binding to local port for %s: %s", cptr);
    return NULL;
  }

  /*
   * By this point we should know the IP# of the host listed in the
   * conf line, whether as a result of the hostname lookup or the ip#
   * being present instead. If we dont know it, then the connect fails.
   */
  if (isDigit(*aconf->host) && (aconf->ipnum.s_addr == INADDR_NONE))
    aconf->ipnum.s_addr = inet_addr(aconf->host);
  if (aconf->ipnum.s_addr == INADDR_NONE)
  {
    hp = cptr->hostp;
    if (!hp)
    {
      Debug((DEBUG_FATAL, "%s: unknown host", aconf->host));
      return NULL;
    }
    memcpy(&aconf->ipnum, hp->h_addr, sizeof(struct in_addr));
  }
  memcpy(&server.sin_addr, &aconf->ipnum, sizeof(struct in_addr));
  memcpy(&cptr->ip, &aconf->ipnum, sizeof(struct in_addr));
#ifdef TESTNET
  server.sin_port = htons(((aconf->port > 0) ? aconf->port : portnum) + 10000);
#else
  server.sin_port = htons(((aconf->port > 0) ? aconf->port : portnum));
#endif
  *lenp = sizeof(server);
  return (struct sockaddr *)&server;
}

#ifdef	UNIXPORT
/*
 * connect_unix
 *
 * Build a socket structure for cptr so that it can connet to the unix
 * socket defined by the conf structure aconf.
 */
static struct sockaddr *connect_unix(aConfItem *aconf, aClient *cptr, int *lenp)
{
  static struct sockaddr_un sock;

  alarm(2);
  cptr->fd = socket(AF_UNIX, SOCK_STREAM, 0);
  alarm(0);
  if (cptr->fd == -1 && errno == EAGAIN)
  {
    sendto_ops("Unix domain connect to host %s failed: No more sockets",
	get_client_name(cptr, TRUE));
    return NULL;
  }
  if (cptr->fd == -1)
  {
    report_error("Unix domain connect to host %s failed: %s", cptr);
    return NULL;
  }
  else if (cptr->fd >= MAXCLIENTS)
  {
    sendto_ops("No more connections allowed (%s)", cptr->name);
    return NULL;
  }

  get_sockhost(cptr, aconf->host);
  /* +2 needed for working Unix domain -- dl */
  strncpy(sock.sun_path, aconf->host + 2, sizeof(sock.sun_path) - 1);
  sock.sun_path[sizeof(sock.sun_path) - 1] = 0;
  sock.sun_family = AF_UNIX;
  *lenp = strlen(sock.sun_path) + 2;

  SetUnixSock(cptr);
  return (struct sockaddr *)&sock;
}

#endif

/*
 * Find the real hostname for the host running the server (or one which
 * matches the server's name) and its primary IP#.  Hostname is stored
 * in the client structure passed as a pointer.
 */
void get_my_name(aClient *cptr, char *name, size_t len)
{
  static char tmp[HOSTLEN + 1];
#if HAVE_UNAME
  struct utsname utsn;
#endif
  struct hostent *hp;
  char *cname = cptr->name;
  size_t len2;

  /*
   * Setup local socket structure to use for binding to.
   */
  memset(&mysk, 0, sizeof(mysk));
  mysk.sin_family = AF_INET;

#if HAVE_UNAME
  if (uname(&utsn) == -1)
    return;
  len2 = strlen(utsn.nodename);
  if (len2 > len)
    len2 = len;
  strncpy(name, utsn.nodename, len2);
#else /* HAVE_GETHOSTNAME */
  if (gethostname(name, len) == -1)
    return;
#endif
  name[len] = '\0';

  /* Assume that a name containing '.' is a FQDN */
  if (!strchr(name, '.'))
    add_local_domain(name, len - strlen(name));

  /*
   * If hostname gives another name than cname, then check if there is
   * a CNAME record for cname pointing to hostname. If so accept
   * cname as our name.   meLazy
   */
  if (BadPtr(cname))
    return;
  if ((hp = gethostbyname(cname)) || (hp = gethostbyname(name)))
  {
    const char *hname;
    int i = 0;

    for (hname = hp->h_name; hname; hname = hp->h_aliases[i++])
    {
      strncpy(tmp, hname, sizeof(tmp) - 1);
      add_local_domain(tmp, sizeof(tmp) - 1 - strlen(tmp));

      /*
       * Copy the matching name over and store the
       * 'primary' IP# as 'myip' which is used
       * later for making the right one is used
       * for connecting to other hosts.
       */
      if (!strCasediff(me.name, tmp))
	break;
    }
    if (strCasediff(me.name, tmp))
      strncpy(name, hp->h_name, len);
    else
      strncpy(name, tmp, len);
    memcpy(&mysk.sin_addr, hp->h_addr, sizeof(struct in_addr));
    Debug((DEBUG_DEBUG, "local name is %s", get_client_name(&me, TRUE)));
  }
  return;
}

/*
 * Setup a UDP socket and listen for incoming packets
 */
int setup_ping(void)
{
  struct sockaddr_in from;
  int on = 1;

  memset(&from, 0, sizeof(from));
  from.sin_addr = cserv.sin_addr;
#ifdef TESTNET
  from.sin_port = htons(atoi(UDP_PORT) + 10000);
#else
  from.sin_port = htons(atoi(UDP_PORT));
#endif
  from.sin_family = AF_INET;

  if ((udpfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
  {
    Debug((DEBUG_ERROR, "socket udp : %s", strerror(errno)));
    return -1;
  }
  if (setsockopt(udpfd, SOL_SOCKET, SO_REUSEADDR,
      (OPT_TYPE *)&on, sizeof(on)) == -1)
  {
#ifdef	USE_SYSLOG
    syslog(LOG_ERR, "setsockopt udp fd %d : %m", udpfd);
#endif
    Debug((DEBUG_ERROR, "setsockopt so_reuseaddr : %s", strerror(errno)));
    close(udpfd);
    udpfd = -1;
    return -1;
  }
  on = 0;
  setsockopt(udpfd, SOL_SOCKET, SO_BROADCAST, (char *)&on, sizeof(on));
  if (bind(udpfd, (struct sockaddr *)&from, sizeof(from)) == -1)
  {
#ifdef	USE_SYSLOG
    syslog(LOG_ERR, "bind udp.%d fd %d : %m", from.sin_port, udpfd);
#endif
    Debug((DEBUG_ERROR, "bind : %s", strerror(errno)));
    close(udpfd);
    udpfd = -1;
    return -1;
  }
  if (fcntl(udpfd, F_SETFL, FNDELAY) == -1)
  {
    Debug((DEBUG_ERROR, "fcntl fndelay : %s", strerror(errno)));
    close(udpfd);
    udpfd = -1;
    return -1;
  }
  return udpfd;
}

/*
 * max # of pings set to 15/sec.
 */
static void polludp(void)
{
  Reg1 char *s;
  struct sockaddr_in from;
  int n;
  size_t fromlen = sizeof(from);
  static time_t last = 0;
  static int cnt = 0, mlen = 0;

  /*
   * find max length of data area of packet.
   */
  if (!mlen)
  {
    mlen = sizeof(readbuf) - strlen(me.name) - strlen(version);
    mlen -= 6;
    if (mlen < 0)
      mlen = 0;
  }
  Debug((DEBUG_DEBUG, "udp poll"));

  n = recvfrom(udpfd, readbuf, mlen, 0, (struct sockaddr *)&from, &fromlen);
  if (now == last)
    if (++cnt > 14)
      return;
  cnt = 0;
  last = now;

  if (n == -1)
  {
    if ((errno == EWOULDBLOCK) || (errno == EAGAIN))
      return;
    else
    {
      report_error("udp port recvfrom (%s): %s", &me);
      return;
    }
  }
  ircstp->is_udp++;
  if (n < 19)
    return;

  s = readbuf + n;
  /*
   * attach my name and version for the reply
   */
  *readbuf |= 1;
  strcpy(s, me.name);
  s += strlen(s) + 1;
  strcpy(s, version);
  s += strlen(s);
  sendto(udpfd, readbuf, s - readbuf, 0,
      (struct sockaddr *)&from, sizeof(from));
  return;
}

/*
 * do_dns_async
 *
 * Called when the fd returned from init_resolver() has been selected for
 * reading.
 */
static void do_dns_async(void)
{
  static Link ln;
  aClient *cptr;
  aConfItem *aconf;
  struct hostent *hp;

  ln.flags = ASYNC_NONE;
  hp = get_res((char *)&ln);

  Debug((DEBUG_DNS, "%p = get_res(%d,%p)", hp, ln.flags, ln.value.cptr));

  switch (ln.flags)
  {
    case ASYNC_NONE:
      /*
       * No reply was processed that was outstanding or had a client
       * still waiting.
       */
      break;
    case ASYNC_CLIENT:
      if ((cptr = ln.value.cptr))
      {
	del_queries((char *)cptr);
	ClearDNS(cptr);
	if (!DoingAuth(cptr))
	  SetAccess(cptr);
	cptr->hostp = hp;
      }
      break;
    case ASYNC_CONNECT:
      aconf = ln.value.aconf;
      if (hp && aconf)
      {
	memcpy(&aconf->ipnum, hp->h_addr, sizeof(struct in_addr));
	connect_server(aconf, NULL, hp);
      }
      else
	sendto_ops("Connect to %s failed: host lookup",
	    (aconf) ? aconf->host : "unknown");
      break;
    case ASYNC_PING:
      cptr = ln.value.cptr;
      del_queries((char *)cptr);
      if (hp)
      {
	memcpy(&cptr->ip, hp->h_addr, sizeof(struct in_addr));
	if (ping_server(cptr) == -1)
	  end_ping(cptr);
      }
      else
      {
	sendto_ops("Udp ping to %s failed: host lookup", cptr->sockhost);
	end_ping(cptr);
      }
      break;
    case ASYNC_CONF:
      aconf = ln.value.aconf;
      if (hp && aconf)
	memcpy(&aconf->ipnum, hp->h_addr, sizeof(struct in_addr));
      break;
    default:
      break;
  }
}
