/*
 * IRC - Internet Relay Chat, ircd/os_solaris.c
 * Copyright (C) 1999 Thomas Helvey
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

#include "ircd_osdep.h"
#include "msgq.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stropts.h>
#include <sys/filio.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

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
  struct rusage rus;
  time_t secs;
  int    hz = HZ;
  int    upticks = uptime * hz;

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
          rus.ru_ixrss / upticks, rus.ru_idrss / upticks,
          rus.ru_isrss / upticks);
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

  return 1;
}

int os_get_sockerr(int fd)
{
  int err = 0;
  int len = sizeof(err);
  getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*) &err, &len);
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
  int res = 1;
  return (0 == ioctl(fd, FIONBIO, &res));
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

int os_set_sockbufs(int fd, unsigned int ssize, unsigned int rsize)
{
  unsigned int sopt = ssize;
  unsigned int ropt = rsize;
  return (0 == setsockopt(fd, SOL_SOCKET, SO_RCVBUF, 
                          (const char*) &ropt, sizeof(ropt)) &&
          0 == setsockopt(fd, SOL_SOCKET, SO_SNDBUF, 
                          (const char*) &sopt, sizeof(sopt)));
}

int os_set_tos(int fd,int tos)
{
  unsigned int opt = tos;
  return (0 == setsockopt(fd, IPPROTO_IP, IP_TOS, &opt, sizeof(opt)));
}

int os_disable_options(int fd)
{
  return (0 == setsockopt(fd, IPPROTO_IP, IP_OPTIONS, NULL, 0));
}

int os_set_fdlimit(unsigned int max_descriptors)
{
  struct rlimit limit;

  if (!getrlimit(RLIMIT_NOFILE, &limit)) {
    if (limit.rlim_max < max_descriptors)
      return limit.rlim_max;
    limit.rlim_cur = limit.rlim_max;    /* make soft limit the max */
    return setrlimit(RLIMIT_NOFILE, &limit);
  }
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
    if (EAGAIN == errno || ENOBUFS == errno || 
        ENOMEM == errno || ENOSR == errno)
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

  res = recvfrom(fd, buf, length, 0, (struct sockaddr*) sin_out, &len);
  if (-1 == res) {
    if (EAGAIN == errno || ENOBUFS == errno || 
        ENOMEM == errno || ENOSR == errno)
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
  else if (EAGAIN == errno || ENOBUFS == errno || 
           ENOMEM == errno || ENOSR == errno)
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
  else if (EAGAIN == errno || ENOBUFS == errno ||
	   ENOMEM == errno || ENOSR == errno)
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
  int len = sizeof(struct sockaddr_in);
  assert(0 != sin_out);
  return (0 == getsockname(fd, (struct sockaddr*) sin_out, &len));
}

int os_get_peername(int fd, struct sockaddr_in* sin_out)
{
  int len = sizeof(struct sockaddr_in);
  assert(0 != sin_out);
  return (0 == getpeername(fd, (struct sockaddr*) sin_out, &len));
}

int os_set_listen(int fd, int backlog)
{
  return (0 == listen(fd, backlog));
}

