/*
 * IRC - Internet Relay Chat, ircd/os_openbsd.c
 * Copyright (C) 2001 Joseph Bongaarts
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
 *
 */
#include "config.h"

#define _XOPEN_SOURCE /* Need this for IOV_MAX */

/* These typedef's are needed for socket.h to be happy. Bleep PROMISES to make
 * to make this less hackish in the future... HONEST. -GW
 */
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;

#include "ircd_osdep.h"
#include "msgq.h"

#include <assert.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef IOV_MAX
#define IOV_MAX 16	/* minimum required */
#endif

#ifdef HPUX
#include <sys/syscall.h>
#define getrusage(a,b) syscall(SYS_GETRUSAGE, a, b)
#endif

/*
 * This is part of the STATS replies. There is no offical numeric for this
 * since this isnt an official command, in much the same way as HASH isnt.
 * It is also possible that some systems wont support this call or have
 * different field names for "struct rusage".
 * -avalon
 */
int os_get_rusage(struct Client *cptr, int uptime, EnumFn enumerator)
{
  char buf[256];
#ifdef HAVE_GETRUSAGE
  struct rusage rus;
  time_t secs;

#ifdef  hz
#  define hzz hz
#else
#  ifdef HZ
#    define hzz HZ
#  else
  int hzz = 1;
#  ifdef HPUX
  hzz = sysconf(_SC_CLK_TCK);
#  endif
#endif
#endif

  assert(0 != enumerator);
  if (getrusage(RUSAGE_SELF, &rus) == -1)
    return 0;

  secs = rus.ru_utime.tv_sec + rus.ru_stime.tv_sec;
  if (secs == 0)
    secs = 1;

  sprintf(buf, "CPU Secs %ld:%ld User %ld:%ld System %ld:%ld",
          secs / 60, secs % 60,
          rus.ru_utime.tv_sec / 60, rus.ru_utime.tv_sec % 60,
          rus.ru_stime.tv_sec / 60, rus.ru_stime.tv_sec % 60);
  (*enumerator)(cptr, buf);

  sprintf(buf, "RSS %ld ShMem %ld Data %ld Stack %ld",
          rus.ru_maxrss,
          rus.ru_ixrss / (uptime * hzz), rus.ru_idrss / (uptime * hzz),
          rus.ru_isrss / (uptime * hzz));
  (*enumerator)(cptr, buf);

  sprintf(buf, "Swaps %ld Reclaims %ld Faults %ld",
          rus.ru_nswap, rus.ru_minflt, rus.ru_majflt);
  (*enumerator)(cptr, buf);

  sprintf(buf, "Block in %ld out %ld", rus.ru_inblock, rus.ru_oublock);
  (*enumerator)(cptr, buf);
  
  sprintf(buf, "Msg Rcv %ld Send %ld", rus.ru_msgrcv, rus.ru_msgsnd);
  (*enumerator)(cptr, buf);

  sprintf(buf, "Signals %ld Context Vol. %ld Invol %ld",
          rus.ru_nsignals, rus.ru_nvcsw, rus.ru_nivcsw);
  (*enumerator)(cptr, buf);

#else /* HAVE_GETRUSAGE */
#if HAVE_TIMES
  struct tms tmsbuf;
  time_t secs, mins;
  int hzz = 1, ticpermin;
  int umin, smin, usec, ssec;

  assert(0 != enumerator);
#ifdef HPUX
  hzz = sysconf(_SC_CLK_TCK);
#endif
  ticpermin = hzz * 60;

  umin = tmsbuf.tms_utime / ticpermin;
  usec = (tmsbuf.tms_utime % ticpermin) / (float)hzz;
  smin = tmsbuf.tms_stime / ticpermin;
  ssec = (tmsbuf.tms_stime % ticpermin) / (float)hzz;
  secs = usec + ssec;
  mins = (secs / 60) + umin + smin;
  secs %= hzz;

  if (times(&tmsbuf) == -1)
    return 0;
  secs = tmsbuf.tms_utime + tmsbuf.tms_stime;

  sprintf(buf, "CPU Secs %d:%d User %d:%d System %d:%d", 
          mins, secs, umin, usec, smin, ssec);
  (*enumerator)(cptr, buf);
#endif /* HAVE_TIMES */
#endif /* HAVE_GETRUSAGE */
  return 1;
}

int os_get_sockerr(int fd)
{
  int    err = 0;
#if defined(SO_ERROR)
  unsigned int len = sizeof(err);
  getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
#endif
  return err;
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
int os_set_nonblocking(int fd)
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
#ifdef  NBLOCK_POSIX
  nonb |= O_NONBLOCK;
#endif
#ifdef  NBLOCK_BSD
  nonb |= O_NDELAY;
#endif
#ifdef  NBLOCK_SYSV
  /* This portion of code might also apply to NeXT. -LynX */
  res = 1;

  if (ioctl(fd, FIONBIO, &res) == -1)
    return 0;
#else
  if ((res = fcntl(fd, F_GETFL, 0)) == -1)
    return 0;
  else if (fcntl(fd, F_SETFL, res | nonb) == -1)
    return 0;
#endif
  return 1;
}


/*
 *  set_sock_opts
 */
int os_set_reuseaddr(int fd)
{
  unsigned int opt = 1;
  return (0 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 
                          (const char*) &opt, sizeof(opt)));
}

int os_set_sockbufs(int fd, unsigned int size)
{
  unsigned int opt = size;
  return (0 == setsockopt(fd, SOL_SOCKET, SO_RCVBUF, 
                          (const char*) &opt, sizeof(opt)) &&
          0 == setsockopt(fd, SOL_SOCKET, SO_SNDBUF, 
                          (const char*) &opt, sizeof(opt)));
}

int os_set_tos(int fd,int tos)
{
  unsigned int opt = tos;
  return (0 == setsockopt(fd, IPPROTO_IP, IP_TOS, &opt, sizeof(opt)));
}

int os_disable_options(int fd)
{
#if defined(IP_OPTIONS) && defined(IPPROTO_IP)
  return (0 == setsockopt(fd, IPPROTO_IP, IP_OPTIONS, NULL, 0));
#else
  return 1;
#endif
}

/*
 * Try and find the correct name to use with getrlimit() for setting the max.
 * number of files allowed to be open by this process.
 */
#ifdef RLIMIT_FDMAX
#define RLIMIT_FD_MAX   RLIMIT_FDMAX
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

int os_set_fdlimit(unsigned int max_descriptors)
{
#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_FD_MAX)
  struct rlimit limit;

  if (!getrlimit(RLIMIT_FD_MAX, &limit)) {
    if (limit.rlim_max < MAXCONNECTIONS)
      return limit.rlim_max;
    limit.rlim_cur = limit.rlim_max;    /* make soft limit the max */
    return setrlimit(RLIMIT_FD_MAX, &limit);
  }
#endif /* defined(HAVE_SETRLIMIT) && defined(RLIMIT_FD_MAX) */
  return 0;
}

IOResult os_recv_nonb(int fd, char* buf, unsigned int length, 
                 unsigned int* count_out)
{
  int res;
  assert(0 != buf);
  assert(0 != count_out);
  *count_out = 0;
  errno = 0;

  if (0 < (res = recv(fd, buf, length, 0))) {
    *count_out = (unsigned) res;
    return IO_SUCCESS;
  }
  else if (res < 0) {
    if (EWOULDBLOCK == errno || EAGAIN == errno)
      return IO_BLOCKED;
    else
      return IO_FAILURE;
  } 
  /*
   * 0   == client closed the connection
   * < 1 == error
   */
  return IO_FAILURE;
}

IOResult os_recvfrom_nonb(int fd, char* buf, unsigned int length, 
                          unsigned int* length_out, struct sockaddr_in* sin_out)
{
  int    res;
  unsigned int len = sizeof(struct sockaddr_in);
  assert(0 != buf);
  assert(0 != length_out);
  assert(0 != sin_out);
  errno = 0;
  *length_out = 0;

  res = recvfrom(fd, buf, length, 0, (struct sockaddr*) sin_out, &len);
  if (-1 == res) {
    if (EWOULDBLOCK == errno || ENOMEM == errno)
      return IO_BLOCKED;
    return IO_FAILURE;
  }
  *length_out = res;
  return IO_SUCCESS;
}

IOResult os_send_nonb(int fd, const char* buf, unsigned int length, 
                 unsigned int* count_out)
{
  int res;
  assert(0 != buf);
  assert(0 != count_out);
  *count_out = 0;
  errno = 0;

  if (-1 < (res = send(fd, buf, length, 0))) {
    *count_out = (unsigned) res;
    return IO_SUCCESS;
  }
  else if (EWOULDBLOCK == errno || EAGAIN == errno || 
           ENOMEM == errno || ENOBUFS == errno)
    return IO_BLOCKED;
  return IO_FAILURE;
}

IOResult os_sendv_nonb(int fd, struct MsgQ* buf, unsigned int* count_in,
		       unsigned int* count_out)
{
  int res;
  int count;
  struct iovec iov[IOV_MAX];

  assert(0 != buf);
  assert(0 != count_in);
  assert(0 != count_out);

  *count_in = 0;
  *count_out = 0;
  errno = 0;

  count = msgq_mapiov(buf, iov, IOV_MAX, count_in);

  if (-1 < (res = writev(fd, iov, count))) {
    *count_out = (unsigned) res;
    return IO_SUCCESS;
  }
  else if (EWOULDBLOCK == errno || EAGAIN == errno ||
	   ENOMEM == errno || ENOBUFS == errno)
    return IO_BLOCKED;

  return IO_FAILURE;
}

IOResult os_connect_nonb(int fd, const struct sockaddr_in* sin)
{
  if (connect(fd, (struct sockaddr*) sin, sizeof(struct sockaddr_in)))
    return (errno == EINPROGRESS) ? IO_BLOCKED : IO_FAILURE;
  return IO_SUCCESS;
}
      
int os_get_sockname(int fd, struct sockaddr_in* sin_out)
{
  unsigned int len = sizeof(struct sockaddr_in);
  assert(0 != sin_out);
  return (0 == getsockname(fd, (struct sockaddr*) sin_out, &len));
}

int os_get_peername(int fd, struct sockaddr_in* sin_out)
{
  unsigned int len = sizeof(struct sockaddr_in);
  assert(0 != sin_out);
  return (0 == getpeername(fd, (struct sockaddr*) sin_out, &len));
}

int os_set_listen(int fd, int backlog)
{
  return (0 == listen(fd, backlog));
}


