dnl
dnl Macro: unet_PIPE_CFLAGS
dnl
dnl   If the compiler understands -pipe, add it to CFLAGS if not already
dnl   there.
dnl
AC_DEFUN(unet_PIPE_CFLAGS,
[AC_MSG_CHECKING([if the compiler understands -pipe])
unet_cv_pipe_flags="$ac_cv_prog_gcc"
if test "$ac_cv_prog_gcc" = no; then
  OLDCFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS -pipe"
  AC_TRY_COMPILE(,,unet_cv_pipe_flags=yes,)
  CFLAGS="$OLDCFLAGS"
fi
AC_MSG_RESULT($unet_cv_pipe_flags)
if test "$unet_cv_pipe_flags" = yes ; then
  x=`echo $CFLAGS | grep 'pipe' 2>/dev/null`
  if test "$x" = "" ; then
    CFLAGS="$CFLAGS -pipe"
  fi
fi
])

dnl
dnl Macro: unet_NONBLOCKING
dnl
dnl   Check whether we have posix, bsd or sysv non-blocking sockets and
dnl   define respectively NBLOCK_POSIX, NBLOCK_BSD or NBLOCK_SYSV.
dnl
AC_DEFUN(unet_NONBLOCKING,
[dnl Do we have posix, bsd or sysv non-blocking stuff ?
AC_CACHE_CHECK([for posix non-blocking], unet_cv_sys_nonblocking_posix,
[AC_TRY_RUN([#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <signal.h>
$ac_cv_type_signal alarmed() { exit(1); }
int main(void)
{
  char b[12];
  struct sockaddr x;
  size_t l = sizeof(x);
  int f = socket(AF_INET, SOCK_DGRAM, 0);
  if (f >= 0 && !(fcntl(f, F_SETFL, O_NONBLOCK)))
  {
    signal(SIGALRM, alarmed);
    alarm(2);
    recvfrom(f, b, 12, 0, &x, &l);
    alarm(0);
    exit(0);
  }
  exit(1);
}], unet_cv_sys_nonblocking_posix=yes, unet_cv_sys_nonblocking_posix=no)])
if test $unet_cv_sys_nonblocking_posix = yes; then
  AC_DEFINE(NBLOCK_POSIX)
else
AC_CACHE_CHECK([for bsd non-blocking], unet_cv_sys_nonblocking_bsd,
[AC_TRY_RUN([#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <signal.h>
$ac_cv_type_signal alarmed() { exit(1); }
int main(void)
{
  char b[12];
  struct sockaddr x;
  size_t l = sizeof(x);
  int f = socket(AF_INET, SOCK_DGRAM, 0);
  if (f >= 0 && !(fcntl(f, F_SETFL, O_NDELAY)))
  {
    signal(SIGALRM, alarmed);
    alarm(2);
    recvfrom(f, b, 12, 0, &x, &l);
    alarm(0);
    exit(0);
  }
  exit(1);
}], unet_cv_sys_nonblocking_bsd=yes, unet_cv_sys_nonblocking_bsd=no)])
if test $unet_cv_sys_nonblocking_bsd = yes; then
  AC_DEFINE(NBLOCK_BSD)
else
  AC_DEFINE(NBLOCK_SYSV)
fi
fi])

dnl
dnl Macro: unet_SIGNALS
dnl
dnl   Check if we have posix signals, reliable bsd signals or
dnl   unreliable sysv signals and define respectively POSIX_SIGNALS,
dnl   BSD_RELIABLE_SIGNALS or SYSV_UNRELIABLE_SIGNALS.
dnl
AC_DEFUN(unet_SIGNALS,
[dnl Do we have posix signals, reliable bsd signals or unreliable sysv signals ?
AC_CACHE_CHECK([for posix signals], unet_cv_sys_signal_posix,
[AC_TRY_COMPILE([#include <signal.h>],
[sigaction(SIGTERM, (struct sigaction *)0L, (struct sigaction *)0L)],
unet_cv_sys_signal_posix=yes, unet_cv_sys_signal_posix=no)])
if test $unet_cv_sys_signal_posix = yes; then
  AC_DEFINE(POSIX_SIGNALS)
else
AC_CACHE_CHECK([for bsd reliable signals], unet_cv_sys_signal_bsd,
[AC_TRY_RUN([#include <signal.h>
int calls = 0;
$ac_cv_type_signal handler()
{
  if (calls) return;
  calls++;
  kill(getpid(), SIGTERM);
  sleep(1);
}
int main(void)
{
  signal(SIGTERM, handler);
  kill(getpid(), SIGTERM);
  exit (0);
}], unet_cv_sys_signal_bsd=yes, unet_cv_sys_signal_bsd=no)])
if test $unet_cv_sys_signal_bsd = yes; then
  AC_DEFINE(BSD_RELIABLE_SIGNALS)
else
  AC_DEFINE(SYSV_UNRELIABLE_SIGNALS)
fi
fi])

dnl
dnl Macro: unet_CHECK_TYPE_SIZES
dnl
dnl Check the size of several types and define a valid int16_t and int32_t.
dnl
AC_DEFUN(unet_CHECK_TYPE_SIZES,
[dnl Check type sizes
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(void *)
if test "$ac_cv_sizeof_int" = 2 ; then
  AC_CHECK_TYPE(int16_t, int)
  AC_CHECK_TYPE(u_int16_t, unsigned int)
elif test "$ac_cv_sizeof_short" = 2 ; then
  AC_CHECK_TYPE(int16_t, short)
  AC_CHECK_TYPE(u_int16_t, unsigned short)
else
  AC_MSG_ERROR([Cannot find a type with size of 16 bits])
fi
if test "$ac_cv_sizeof_int" = 4 ; then
  AC_CHECK_TYPE(int32_t, int)
  AC_CHECK_TYPE(u_int32_t, unsigned int)
elif test "$ac_cv_sizeof_short" = 4 ; then
  AC_CHECK_TYPE(int32_t, short)
  AC_CHECK_TYPE(u_int32_t, unsigned short)
elif test "$ac_cv_sizeof_long" = 4 ; then
  AC_CHECK_TYPE(int32_t, long)
  AC_CHECK_TYPE(u_int32_t, unsigned long)
else
  AC_MSG_ERROR([Cannot find a type with size of 32 bits])
fi])

dnl Written by John Hawkinson <jhawk@mit.edu>. This code is in the Public
dnl Domain.
dnl
dnl This test is for network applications that need socket() and
dnl gethostbyname() -ish functions.  Under Solaris, those applications need to
dnl link with "-lsocket -lnsl".  Under IRIX, they should *not* link with
dnl "-lsocket" because libsocket.a breaks a number of things (for instance:
dnl gethostbyname() under IRIX 5.2, and snoop sockets under most versions of
dnl IRIX).
dnl 
dnl Unfortunately, many application developers are not aware of this, and
dnl mistakenly write tests that cause -lsocket to be used under IRIX.  It is
dnl also easy to write tests that cause -lnsl to be used under operating
dnl systems where neither are necessary (or useful), such as SunOS 4.1.4, which
dnl uses -lnsl for TLI.
dnl 
dnl This test exists so that every application developer does not test this in
dnl a different, and subtly broken fashion.
dnl 
dnl It has been argued that this test should be broken up into two seperate
dnl tests, one for the resolver libraries, and one for the libraries necessary
dnl for using Sockets API. Unfortunately, the two are carefully intertwined and
dnl allowing the autoconf user to use them independantly potentially results in
dnl unfortunate ordering dependancies -- as such, such component macros would
dnl have to carefully use indirection and be aware if the other components were
dnl executed. Since other autoconf macros do not go to this trouble, and almost
dnl no applications use sockets without the resolver, this complexity has not
dnl been implemented.
dnl
dnl The check for libresolv is in case you are attempting to link statically
dnl and happen to have a libresolv.a lying around (and no libnsl.a).
dnl
AC_DEFUN(AC_LIBRARY_NET, [
   # Most operating systems have gethostbyname() in the default searched
   # libraries (i.e. libc):
   AC_CHECK_FUNC(gethostbyname, ,
     # Some OSes (eg. Solaris) place it in libnsl:
     AC_CHECK_LIB(nsl, gethostbyname, , 
       # Some strange OSes (SINIX) have it in libsocket:
       AC_CHECK_LIB(socket, gethostbyname, ,
          # Unfortunately libsocket sometimes depends on libnsl.
          # AC_CHECK_LIB's API is essentially broken so the following
          # ugliness is necessary:
          AC_CHECK_LIB(socket, gethostbyname,
             LIBS="-lsocket -lnsl $LIBS",
               AC_CHECK_LIB(resolv, gethostbyname),
             -lnsl)
       )
     )
   )
  AC_CHECK_FUNC(socket, , AC_CHECK_LIB(socket, socket, ,
    AC_CHECK_LIB(socket, socket, LIBS="-lsocket -lnsl $LIBS", , -lnsl)))
  ])
