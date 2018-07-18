/*
 * IRC - Internet Relay Chat, ircd/os_generic.c
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
 */
/** @file
 * @brief Implementation of OS-dependent operations.
 * @version $Id$
 */
#include "config.h"

#ifdef IRCU_SOLARIS
/* Solaris requires C99 support for SUSv3, but C99 support breaks other
 * parts of the build.  So fall back to SUSv2, but request IPv6 support
 * by defining __EXTENSIONS__.
 */
#define _XOPEN_SOURCE   500
#define __EXTENSIONS__  1
#elif defined(__FreeBSD__) && __FreeBSD__ >= 5
/* FreeBSD 6.0 requires SUSv3 to support IPv6 -- but if you ask for
 * that specifically (by defining _XOPEN_SOURCE to anything at all),
 * they cleverly hide IPPROTO_IPV6.  If you don't ask for anything,
 * they give you everything.
 */
#else
#define _XOPEN_SOURCE   600
#endif

#include "ircd_osdep.h"
#include "msgq.h"
#include "ircd_log.h"
#include "res.h"
#include "s_bsd.h"
#include "sys.h"

/* Include file dependency notes:
 * FreeBSD requires struct timeval from sys/time.h before struct
 * rusage in sys/resource.h.
 * Solaris requires sys/time.h before struct rusage (indirectly) in
 * netinet/in.h.
 */
/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/uio.h>

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if defined(IPV6_BINDV6ONLY) &&!defined(IPV6_V6ONLY)
# define IPV6_V6ONLY IPV6_BINDV6ONLY
#endif

#ifndef IOV_MAX
#define IOV_MAX 16	/**< minimum required length of an iovec array */
#endif

#ifdef HPUX
#include <sys/syscall.h>
#define getrusage(a,b) syscall(SYS_GETRUSAGE, a, b)
#endif

static int is_blocked(int error)
{
  return EWOULDBLOCK == error
#ifdef ENOMEM
    || ENOMEM == error
#endif
#ifdef ENOBUFS
    || ENOBUFS == error
#endif
    || EAGAIN == error;
}

static void sockaddr_in_to_irc(const struct sockaddr_in *v4,
                               struct irc_sockaddr *irc)
{
    memset(&irc->addr, 0, 5*sizeof(int16_t));
    irc->addr.in6_16[5] = 0xffff;
    memcpy(&irc->addr.in6_16[6], &v4->sin_addr, sizeof(v4->sin_addr));
    irc->port = ntohs(v4->sin_port);
}


#ifdef IPV6
/** Native socket address type. */
#define sockaddr_native sockaddr_in6
/** Field name inside sockaddr_native to find address family. */
#define sn_family sin6_family

/** Convert native socket address to IRC format.
 * @param[in] v6 Native socket address.
 * @param[out] irc IRC format socket address.
 */
void sockaddr_to_irc(const struct sockaddr_in6 *v6, struct irc_sockaddr *irc)
{
    if (v6->sin6_family == AF_INET6) {
        memcpy(&irc->addr.in6_16[0], &v6->sin6_addr, sizeof(v6->sin6_addr));
        irc->port = ntohs(v6->sin6_port);
    }
    else if (v6->sin6_family == AF_INET) {
        sockaddr_in_to_irc((struct sockaddr_in *)v6, irc);
    }
    else assert(0 && "Unhandled native address family");
}

/** Convert IRC socket address to native format.
 * @param[out] v6 Native socket address.
 * @param[in] irc IRC socket address.
 * @param[in] compat_fd If non-negative, an FD specifying address family.
 * @return Length of address written to \a v6.
 */
int sockaddr_from_irc(struct sockaddr_in6 *v6, const struct irc_sockaddr *irc, int compat_fd, int family)
{
    struct sockaddr_in6 sin6;
    socklen_t slen;

    assert(irc != 0);
    slen = sizeof(sin6);
    if (family) {
        /* accept whatever user specified */
    } else if ((0 <= compat_fd)
        && (0 == getsockname(compat_fd, (struct sockaddr*)&sin6, &slen)))
        family = sin6.sin6_family;
    else if ((irc == &VirtualHost_v4) || irc_in_addr_is_ipv4(&irc->addr))
        family = AF_INET;
    else
        family = AF_INET6;

    memset(v6, 0, sizeof(*v6));
    if (family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in*)v6;
        v4->sin_family = AF_INET;
        memcpy(&v4->sin_addr, &irc->addr.in6_16[6], sizeof(v4->sin_addr));
        v4->sin_port = htons(irc->port);
        return sizeof(*v4);
    }
    else {
        v6->sin6_family = AF_INET6;
        memcpy(&v6->sin6_addr, &irc->addr.in6_16[0], sizeof(v6->sin6_addr));
        v6->sin6_port = htons(irc->port);
        return sizeof(*v6);
    }
}

#else
#define sockaddr_native sockaddr_in
#define sn_family sin_family
#define sockaddr_to_irc sockaddr_in_to_irc

int sockaddr_from_irc(struct sockaddr_in *v4, const struct irc_sockaddr *irc, int compat_fd, int family)
{
    assert(irc != 0);
    memset(v4, 0, sizeof(*v4));
    v4->sin_family = AF_INET;
    if (irc) {
        assert(!irc->addr.in6_16[0] && !irc->addr.in6_16[1] && !irc->addr.in6_16[2] && !irc->addr.in6_16[3] && !irc->addr.in6_16[4] && (!irc->addr.in6_16[5] || irc->addr.in6_16[5] == 0xffff));
        memcpy(&v4->sin_addr, &irc->addr.in6_16[6], sizeof(v4->sin_addr));
        v4->sin_port = htons(irc->port);
    }
    (void)compat_fd; (void)family;
    return sizeof(*v4);
}

#endif

#ifdef DEBUGMODE
/** Send resource usage information to an enumerator function.
 * @param[in] cptr Client requesting information.
 * @param[in] uptime Wall time in seconds since the server started.
 * @param[in] enumerator Function to call to send a line to \a cptr.
 * @return Zero if some usage reports could not be sent, non-zero on success.
 */
int os_get_rusage(struct Client *cptr, int uptime, EnumFn enumerator)
{
#ifdef HAVE_GETRUSAGE
  char buf[256];
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
          (long)(secs / 60), (long)(secs % 60),
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

#elif HAVE_TIMES
  char buf[256];
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
#endif /* HAVE_GETRUSAGE, elif HAVE_TIMES */
  return 1;
}
#endif

/** Look up the most recent socket error for a socket file descriptor.
 * @param[in] fd File descriptor to check.
 * @return Error code from the socket, or 0 if the OS does not support this.
 */
int os_get_sockerr(int fd)
{
  int    err = 0;
#if defined(SO_ERROR)
  unsigned int len = sizeof(err);
  getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
#endif
  return err;
}

/** Set a file descriptor to non-blocking mode.
 * @param[in] fd %Socket file descriptor.
 * @return Non-zero on success, or zero on failure.
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

/** Mark a socket's address as reusable.
 * @param[in] fd %Socket file descriptor to manipulate.
 * @return Non-zero on success, or zero on failure.
 */
int os_set_reuseaddr(int fd)
{
  unsigned int opt = 1;
  return (0 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                          (const char*) &opt, sizeof(opt)));
}

/** Set a socket's send and receive buffer sizes.
 * @param[in] fd %Socket file descriptor to manipulate.
 * @param[in] ssize New send buffer size.
 * @param[in] rsize New receive buffer size.
 * @return Non-zero on success, or zero on failure.
 */
int os_set_sockbufs(int fd, unsigned int ssize, unsigned int rsize)
{
  unsigned int sopt = ssize;
  unsigned int ropt = rsize;
  return (0 == setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                          (const char*) &ropt, sizeof(ropt)) &&
          0 == setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
                          (const char*) &sopt, sizeof(sopt)));
}

/** Set a socket's "type of service" value.
 * @param[in] fd %Socket file descriptor to manipulate.
 * @param[in] tos New type of service value to use.
 * @param[in] family Address family of \a fd (AF_INET or AF_INET6).
 * @return Non-zero on success, or zero on failure.
 */
int os_set_tos(int fd, int tos, int family)
{
  if (family == AF_INET) {
#if defined(IP_TOS) && defined(IPPROTO_IP)
    return (0 == setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)));
#endif
#if defined(AF_INET6) && defined(IPV6_TCLASS) && defined(IPPROTO_IPV6)
  } else if (family == AF_INET6) {
    return (0 == setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos)));
#endif
  }

  return 1;
}

/** Disable IP options on a socket.
 * @param[in] fd %Socket file descriptor to manipulate.
 * @return Non-zero on success, or zero on failure.
 */
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

/** Set file descriptor limit for the process.
 * @param[in] max_descriptors Ideal number of file descriptors.
 * @return Zero on success; -1 on error; positive number of possible
 * file descriptors if \a max_descriptors is too high.
 */
int os_set_fdlimit(unsigned int max_descriptors)
{
#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_FD_MAX)
  struct rlimit limit;

  if (!getrlimit(RLIMIT_FD_MAX, &limit)) {
    if (limit.rlim_max < max_descriptors)
      return limit.rlim_max;
    limit.rlim_cur = limit.rlim_max;    /* make soft limit the max */
    return setrlimit(RLIMIT_FD_MAX, &limit);
  }
#endif /* defined(HAVE_SETRLIMIT) && defined(RLIMIT_FD_MAX) */
  return 0;
}

/** Attempt to read from a non-blocking socket.
 * @param[in] fd File descriptor to read from.
 * @param[out] buf Output buffer to read into.
 * @param[in] length Number of bytes to read.
 * @param[out] count_out Receives number of bytes actually read.
 * @return An IOResult value indicating status.
 */
IOResult os_recv_nonb(int fd, char* buf, unsigned int length,
                 unsigned int* count_out)
{
  int res;
  assert(0 != buf);
  assert(0 != count_out);

  if (0 < (res = recv(fd, buf, length, 0))) {
    *count_out = (unsigned) res;
    return IO_SUCCESS;
  } else if (res == 0) {
    *count_out = 0;
    errno = 0; /* or ECONNRESET? */
    return IO_FAILURE;
  } else {
    *count_out = 0;
    return is_blocked(errno) ? IO_BLOCKED : IO_FAILURE;
  }
}

/** Attempt to read from a non-blocking UDP socket.
 * @param[in] fd File descriptor to read from.
 * @param[out] buf Output buffer to read into.
 * @param[in] length Number of bytes to read.
 * @param[out] length_out Receives number of bytes actually read.
 * @param[out] addr_out Peer address that sent the message.
 * @return An IOResult value indicating status.
 */
IOResult os_recvfrom_nonb(int fd, char* buf, unsigned int length,
                          unsigned int* length_out,
                          struct irc_sockaddr* addr_out)
{
  struct sockaddr_native addr;
  unsigned int len = sizeof(addr);
  int    res;
  assert(0 != buf);
  assert(0 != length_out);
  assert(0 != addr_out);

  res = recvfrom(fd, buf, length, 0, (struct sockaddr*) &addr, &len);
  if (-1 < res) {
    sockaddr_to_irc(&addr, addr_out);
    *length_out = res;
    return IO_SUCCESS;
  } else {
    *length_out = 0;
    return is_blocked(errno) ? IO_BLOCKED : IO_FAILURE;
  }
}

/** Attempt to write on a non-blocking UDP socket.
 * @param[in] fd File descriptor to write to.
 * @param[in] buf Output buffer to send from.
 * @param[in] length Number of bytes to write.
 * @param[out] count_out Receives number of bytes actually written.
 * @param[in] flags Flags for call to sendto().
 * @param[in] peer Destination address of the message.
 * @return An IOResult value indicating status.
 */
IOResult os_sendto_nonb(int fd, const char* buf, unsigned int length,
                        unsigned int* count_out, unsigned int flags,
                        const struct irc_sockaddr* peer)
{
  struct sockaddr_native addr;
  int res, size;
  assert(0 != buf);

  size = sockaddr_from_irc(&addr, peer, fd, 0);
  assert((addr.sn_family == AF_INET) == irc_in_addr_is_ipv4(&peer->addr));
  if (-1 < (res = sendto(fd, buf, length, flags, (struct sockaddr*)&addr, size))) {
    if (count_out)
      *count_out = (unsigned) res;
    return IO_SUCCESS;
  } else {
    if (count_out)
      *count_out = 0;
    return is_blocked(errno) ? IO_BLOCKED : IO_FAILURE;
  }
}

/** Attempt to write on a connected socket.
 * @param[in] fd File descriptor to write to.
 * @param[in] buf Output buffer to send from.
 * @param[in] length Number of bytes to write.
 * @param[out] count_out Receives number of bytes actually written.
 * @return An IOResult value indicating status.
 */
IOResult os_send_nonb(int fd, const char* buf, unsigned int length, 
                 unsigned int* count_out)
{
  int res;
  assert(0 != buf);
  assert(0 != count_out);

  if (-1 < (res = send(fd, buf, length, 0))) {
    *count_out = (unsigned) res;
    return IO_SUCCESS;
  } else {
    *count_out = 0;
    return is_blocked(errno) ? IO_BLOCKED : IO_FAILURE;
  }
}

/** Attempt a vectored write on a connected socket.
 * @param[in] fd File descriptor to write to.
 * @param[in] buf Message queue to send from.
 * @param[out] count_in Number of bytes mapped from \a buf.
 * @param[out] count_out Receives number of bytes actually written.
 * @return An IOResult value indicating status.
 */
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
  count = msgq_mapiov(buf, iov, IOV_MAX, count_in);

  if (-1 < (res = writev(fd, iov, count))) {
    *count_out = (unsigned) res;
    return IO_SUCCESS;
  } else {
    *count_out = 0;
    return is_blocked(errno) ? IO_BLOCKED : IO_FAILURE;
  }
}

/** Open a TCP or UDP socket on a particular address.
 * @param[in] local Local address to bind to.
 * @param[in] type SOCK_STREAM or SOCK_DGRAM.
 * @param[in] port_name Port name (used in error diagnostics).
 * @param[in] family A specific address family to use, or 0 for automatic.
 * @return Bound descriptor, or -1 on error.
 */
int os_socket(const struct irc_sockaddr* local, int type, const char* port_name, int family)
{
  struct sockaddr_native addr;
  int size, fd;

  assert(local != 0);
  size = sockaddr_from_irc(&addr, local, -1, family);
  fd = socket(addr.sn_family, type, 0);
  if (fd < 0) {
    report_error(SOCKET_ERROR_MSG, port_name, errno);
    return -1;
  }
  if (fd > MAXCLIENTS - 1) {
    report_error(CONNLIMIT_ERROR_MSG, port_name, 0);
    close(fd);
    return -1;
  }
  if (!os_set_reuseaddr(fd)) {
    report_error(REUSEADDR_ERROR_MSG, port_name, errno);
    close(fd);
    return -1;
  }
  if (!os_set_nonblocking(fd)) {
    report_error(NONB_ERROR_MSG, port_name, errno);
    close(fd);
    return -1;
  }
  if (local) {
#if defined(IPV6_V6ONLY)
    int on = 1;
    if (family == AF_INET6 && irc_in_addr_unspec(&local->addr))
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
#endif
    if (bind(fd, (struct sockaddr*)&addr, size)) {
      report_error(BIND_ERROR_MSG, port_name, errno);
      close(fd);
      return -1;
    }
  }
  return fd;
}

/** Accept a connection on a socket.
 * @param[in] fd Listening file descriptor.
 * @param[out] peer Peer address of connection.
 * @return File descriptor for accepted connection.
 */
int os_accept(int fd, struct irc_sockaddr* peer)
{
  struct sockaddr_native addr;
  socklen_t addrlen;
  int new_fd;

  addrlen = sizeof(addr);
  new_fd = accept(fd, (struct sockaddr*)&addr, &addrlen);
  if (new_fd < 0)
    memset(peer, 0, sizeof(*peer));
  else
    sockaddr_to_irc(&addr, peer);
  return new_fd;
}

/** Start a non-blocking connection.
 * @param[in] fd Disconnected file descriptor.
 * @param[in] sin Target address for connection.
 * @return IOResult code indicating status.
 */
IOResult os_connect_nonb(int fd, const struct irc_sockaddr* sin)
{
  struct sockaddr_native addr;
  int size;

  size = sockaddr_from_irc(&addr, sin, fd, 0);
  if (0 == connect(fd, (struct sockaddr*) &addr, size))
    return IO_SUCCESS;
  else if (errno == EINPROGRESS)
    return IO_BLOCKED;
  else
    return IO_FAILURE;
}

/** Get local address of a socket.
 * @param[in] fd File descriptor to operate on.
 * @param[out] sin_out Receives local socket address.
 * @return Non-zero on success; zero on error.
 */
int os_get_sockname(int fd, struct irc_sockaddr* sin_out)
{
  struct sockaddr_native addr;
  unsigned int len = sizeof(addr);

  assert(0 != sin_out);
  if (getsockname(fd, (struct sockaddr*) &addr, &len))
    return 0;
  sockaddr_to_irc(&addr, sin_out);
  return 1;
}

/** Get remote address of a socket.
 * @param[in] fd File descriptor to operate on.
 * @param[out] sin_out Receives remote socket address.
 * @return Non-zero on success; zero on error.
 */
int os_get_peername(int fd, struct irc_sockaddr* sin_out)
{
  struct sockaddr_native addr;
  unsigned int len = sizeof(addr);

  assert(0 != sin_out);
  if (getpeername(fd, (struct sockaddr*) &addr, &len))
    return 0;
  sockaddr_to_irc(&addr, sin_out);
  return 1;
}

/** Start listening on a socket.
 * @param[in] fd Disconnected file descriptor.
 * @param[in] backlog Maximum number of un-accept()ed connections to keep.
 * @return Non-zero on success; zero on error.
 */
int os_set_listen(int fd, int backlog)
{
  return (0 == listen(fd, backlog));
}

/** Allocate a connected pair of local sockets.
 * @param[out] sv Array of two file descriptors.
 * @return Zero on success; non-zero number on error.
 */
int os_socketpair(int sv[2])
{
    return socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
}
