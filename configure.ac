dnl Copyright (C) 2005 by Kevin L. Mitchell <klmitch@mit.edu>
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

AC_INIT([Undernet IRC Daemon],[10.13.alpha.0],[bugs@undernet.org],[ircu2])
AC_PREREQ([2.69])

AC_COPYRIGHT(
[This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA])

AC_REVISION($Revision$)

AC_CONFIG_SRCDIR([ircd/ircd.c])
AM_INIT_AUTOMAKE([foreign subdir-objects])

dnl Set the default prefix
AC_PREFIX_DEFAULT([$HOME])

dnl Define configuration header file and other output files
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

dnl What type of system is this?
AC_CANONICAL_HOST

dnl Check for a compiler and make sure to ANSIfy it
AC_PROG_CC

dnl Default to "silent" rules.
AM_SILENT_RULES([yes])

dnl Look up the lexer and yaccer
AM_PROG_LEX
AC_PROG_YACC

dnl Let's find the library containing crypt...
AC_SEARCH_LIBS(crypt, [descrypt crypt], ,
[AC_MSG_ERROR([Unable to find library containing crypt()])])

dnl Do the checks necessary to figure out -lnsl / -lsocket stuff
AC_LIBRARY_NET

dnl Check out header files
AC_HEADER_STDC
AC_CHECK_HEADERS([crypt.h poll.h inttypes.h stdint.h sys/devpoll.h \
		  sys/epoll.h sys/event.h sys/param.h sys/resource.h \
		  sys/socket.h])

dnl Checks for typedefs, structures, compiler characteristics, etc.
AC_C_CONST
AC_C_BIGENDIAN
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_TYPE_UID_T
unet_CHECK_TYPE_SIZES
AC_CHECK_TYPE([struct sockaddr_in6],
	      [unet_have_sockaddr_in6=yes],
	      [unet_have_sockaddr_in6=no],
[#include <sys/types.h>
#include <netinet/in.h>])

dnl Check for socklen_t.  In traditional BSD this is an int, but some
dnl OSes use a different type.  Test until we find something that will
dnl work properly.  Test borrowed from a patch submitted for Python.
AC_CHECK_TYPE([socklen_t], ,[
  AC_MSG_CHECKING([for socklen_t equivalent])
  AC_CACHE_VAL([curl_cv_socklen_t_equiv],
  [
dnl Systems have either "struct sockaddr*" or "void*" as second
dnl arg to getpeername.
    curl_cv_socklen_t_equiv=
    for arg2 in "struct sockaddr" void ; do
      for t in int size_t unsigned long "unsigned long" ; do
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <sys/types.h>
#include <sys/socket.h>
int getpeername (int $arg2 *, $t *);]], [[$t len;
  getpeername(0, 0, &len);]])],[curl_cv_socklen_t_equiv="$t"
  break],[])
      done
    done
  ])
  AC_MSG_RESULT($curl_cv_socklen_t_equiv)
  AC_DEFINE_UNQUOTED(socklen_t, $curl_cv_socklen_t_equiv,
      [type to use in place of socklen_t if not defined])],
  [#include <sys/types.h>
#include<sys/socket.h>])

dnl Checks for library functions.
AC_CHECK_FUNCS([kqueue setrlimit getrusage times])

dnl Figure out non-blocking and signals
unet_NONBLOCKING
unet_SIGNALS

dnl Check OS for os_dep files.
AC_MSG_CHECKING(for OS-dependent information)
case "$host" in
    *-linux*)
	AC_MSG_RESULT([Linux ($host) found.])
	unet_poll_syscall=yes
	;;

    *-solaris*)
	AC_MSG_RESULT([Solaris ($host) found.])
	if test x"$ac_cv_header_poll_h" = xyes; then
	    unet_poll_syscall=yes
	else
	    unet_poll_syscall=no
	fi
	;;

    *-sunos*)
	AC_MSG_RESULT([Solaris ($host) found.])
	unet_poll_syscall=no
	;;

    *-openbsd*)
	AC_MSG_RESULT([OpenBSD ($host) found.])
	if test x"$ac_cv_header_poll_h" = xyes; then
	    unet_poll_syscall=yes
	else
	    unet_poll_syscall=no
	fi
	;;

    *-*bsd*)
	AC_MSG_RESULT([Generic BSD ($host) found.])
	if test x"$ac_cv_header_poll_h" = xyes; then
	    unet_poll_syscall=yes
	else
	    unet_poll_syscall=no
	fi
	;;

    *-darwin*)
	AC_MSG_RESULT([Darwin (Mac OS X) ($host) found.])
	unet_poll_syscall=no
	;;

    *)
	AC_MSG_RESULT([Unknown system type $host found.])
	AC_MSG_WARN([Unknown OS type; using generic routines.])
	unet_poll_syscall=no
	;;
esac

dnl Check user configuration options

dnl Start with --enable-poll
unet_TOGGLE([poll], [$unet_poll_syscall],
    [Force poll to be used regardless of whether or not it is a system call],
    [whether to enable use of poll()],
[# Force poll to be disabled if there is no poll.h
if test x"$ac_cv_header_poll_h" != xyes; then
    unet_cv_enable_poll=no
fi])

# Set up the conditionals
if test x"$unet_cv_enable_poll" = xyes; then
    AC_DEFINE([USE_POLL], 1, [Specify whether or not to use poll()])
fi
AM_CONDITIONAL(ENGINE_POLL, [test x"$unet_cv_enable_poll" = xyes])

dnl Now --disable-devpoll...
unet_TOGGLE([devpoll], yes, [Disable the /dev/poll-based engine],
    [whether to enable the /dev/poll event engine],
[# Prohibit /dev/poll support if the header is unavailable
if test x"$ac_cv_header_sys_devpoll_h" = xno; then
    unet_cv_enable_devpoll=no
fi])

# Set up the conditionals
if test x"$unet_cv_enable_devpoll" = xyes; then
    AC_DEFINE([USE_DEVPOLL], 1, [Define to enable the /dev/poll engine])
fi
AM_CONDITIONAL(ENGINE_DEVPOLL, [test x"$unet_cv_enable_devpoll" = xyes])

dnl --disable-kqueue...
unet_TOGGLE([kqueue], yes, [Disable the kqueue-based engine],
    [whether to enable the kqueue event engine],
[# Prohibit kqueue() support if the header or functions are unavailable
if test x"$ac_cv_header_sys_event_h" = xno -o x"$ac_cv_func_kqueue" = xno; then
    unet_cv_enable_kqueue=no
fi])

# Set up the conditionals
if test x"$unet_cv_enable_kqueue" = xyes; then
    AC_DEFINE([USE_KQUEUE], 1, [Define to enable the kqueue engine])
fi
AM_CONDITIONAL(ENGINE_KQUEUE, [test x"$unet_cv_enable_kqueue" = xyes])

dnl ...and --disable-epoll
unet_TOGGLE([epoll], yes, [Disable the epoll-based engine],
    [whether to enable the epoll event engine],
[# Prohibit epoll() support if the header or functions are unavailable
if test x"$ac_cv_header_sys_epoll_h" = xno -o x"$ac_cv_func_epoll" = xno; then
    unet_cv_enable_epoll=no
fi])

# Set up the conditionals
if test x"$unet_cv_enable_epoll" = xyes; then
    AC_DEFINE([USE_EPOLL], 1, [Define to enable the epoll engine])

    # Must also check to see if we need to provide the function bodies
dnl XXX Should rework this check
    AC_MSG_CHECKING([whether epoll functions are properly defined])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <sys/epoll.h>],
				    [epoll_create(10);])],
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])
	 AC_DEFINE([EPOLL_NEED_BODY], 1,
		[Define to implement epoll system calls])])
fi
AM_CONDITIONAL(ENGINE_EPOLL, [test x"$unet_cv_enable_epoll" = xyes])

dnl Is debugging mode requested?
unet_TOGGLE([debug], no, [Enable debugging mode],
    [whether to enable debug mode])

# Set the preprocessor symbol
if test x"$unet_cv_enable_debug" = xyes; then
    AC_DEFINE([DEBUGMODE], 1, [Enable debugging code])
fi

dnl What about assertions?
unet_TOGGLE([asserts], yes, [Disable assertion checking],
    [whether to enable asserts])

# Set the preprocessor symbol
if test x"$unet_cv_enable_asserts" = xno; then
    AC_DEFINE([NDEBUG], 1, [Disable assertion checking])
fi

dnl how about IPv6 support?
unet_TOGGLE([ipv6], $unet_have_sockaddr_in6, [Disable IPv6 support],
    [whether to enable IPv6],
[# Prohibit IPv6 support if sockaddr_in6 doesn't exist
if test x"$unet_have_sockaddr_in6" = xno; then
    unet_cv_enable_ipv6=no
fi])

# Set the preprocessor symbol
if test x"$unet_cv_enable_ipv6" = xyes; then
    AC_DEFINE([IPV6], 1, [Enable IPv6 support])
fi

dnl Should we force inlines?
unet_TOGGLE([inlines], yes, [Disable inlining for a few critical functions],
    [whether to enable inlining for a few critical functions])

# Set the preprocessor symbol
if test x"$unet_cv_enable_inlines" = xyes; then
    AC_DEFINE([FORCEINLINE], 1, [Force inlining for a few critical functions])
fi

dnl How to copy one va_list to another?
AC_CACHE_CHECK([for va_copy], unet_cv_c_va_copy,
    [AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <stdarg.h>],
	[va_list ap1, ap2; va_copy(ap1, ap2);])],
    [unet_cv_c_va_copy="yes"],
    [unet_cv_c_va_copy="no"])])

if test "$unet_cv_c_va_copy" = "yes" ; then
  AC_DEFINE([HAVE_VA_COPY], 1, [Define if we have va_copy])
fi

AC_CACHE_CHECK([for __va_copy], unet_cv_c___va_copy,
    [AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <stdarg.h>],
	[va_list ap1, ap2; __va_copy(ap1, ap2);])],
    [unet_cv_c___va_copy="yes"],
    [unet_cv_c___va_copy="no"])])

if test "$unet_cv_c___va_copy" = "yes" ; then
  AC_DEFINE([HAVE___VA_COPY], 1, [Define if we have __va_copy])
fi

dnl --with-domain lets us set the domain name for some statistics-gathering
unet_domain=
if test -f /etc/resolv.conf; then
    unet_domain=`awk '/^domain/ { print $2; exit }' /etc/resolv.conf`
    if test x"$unet_domain" = x; then
	unet_domain=`awk '/^search/ { print $2; exit }' /etc/resolv.conf`
    fi
fi

unet_VALUE([domain], $unet_domain, [Domain name to use for local statistics],
    [for site domain name],
[# Sorry, but the domain *must* be set!
if test x"$unet_cv_with_domain" = x -o x"$unet_cv_with_domain" = xno; then
    AC_MSG_ERROR([Unable to determine server DNS domain])
fi])

AC_DEFINE_UNQUOTED([DOMAINNAME], "*$unet_cv_with_domain",
    [Domain name to be used for some statistics gathering])

dnl --with-maxcon allows us to set the maximum connections
unet_maxcon=`ulimit -Hn`
if test x"$unet_maxcon" = xunlimited; then
    unet_maxcon=`ulimit -Sn`
fi
unet_maxcon=`expr $unet_maxcon - 4`

unet_VALUE([maxcon], $unet_maxcon,
    [Maximum number of connections server will accept],
    [max connections],
[# Fix up a spurious --with-maxcon
if test x"$unet_cv_with_maxcon" = xyes -o x"$unet_cv_with_maxcon" = xno; then
    unet_cv_with_maxcon=$unet_maxcon
fi])

AC_DEFINE_UNQUOTED(MAXCONNECTIONS, $unet_cv_with_maxcon,
    [Maximum number of network connections])

dnl Report configuration
dnl AC_CONFIG_COMMANDS([default-1],[[echo "
dnl ircu is now hopefully configured for your system.

dnl   Host system:         $host_os
dnl   Prefix:              $prefix
dnl   Asserts:             $unet_cv_enable_asserts
dnl   Debug:               $unet_cv_enable_debug

dnl   Domain:              $unet_cv_with_domain
dnl   Maximum connections: $unet_cv_with_maxcon

dnl   poll() engine:       $unet_cv_enable_poll
dnl   kqueue() engine:     $unet_cv_enable_kqueue
dnl   /dev/poll engine:    $unet_cv_enable_devpoll
dnl   epoll() engine:      $unet_cv_enable_epoll
dnl "]],[[]])

dnl Output everything...
AC_OUTPUT
