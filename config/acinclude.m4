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
dnl Macro: unet_CHECK_LIB_RESOLV
dnl
dnl   Check for res_mkquery in -lresolv and add that to LIBS when needed.
dnl
AC_DEFUN(unet_CHECK_LIB_RESOLV,
[AC_CACHE_CHECK([for res_mkquery in -lresolv], unet_cv_lib_resolv,
[AC_TRY_LINK([struct rrec;
extern int res_mkquery(int, const char *, int, int, const char *,
    int, struct rrec *, unsigned char *, int);],
[int op;
const char *dname;
int class, type;
const char *data;
int datalen;
struct rrec *newrr;
unsigned char *buf;
int buflen;
res_mkquery(op,dname,class,type,data,datalen,newrr,buf,buflen)],
unet_cv_lib_resolv=no, [OLD_LIBS="$LIBS"
LIBS="$LIBS -lresolv"
AC_TRY_LINK([extern char *_res;], [*_res=0],
unet_cv_lib_resolv=yes, unet_cv_lib_resolv=no)
LIBS="$OLD_LIBS"])])
if test $unet_cv_lib_resolv = yes; then
  AC_DEFINE(HAVE_LIB_RESOLV)
  LIBS="$LIBS -lresolv"
fi])

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
dnl Macro: unet_DEFINE_SIZE_T_FMT
dnl
dnl Define SIZE_T_FMT to be "%u" or "%lu", whichever seems more appropriate.
dnl
AC_DEFUN(unet_DEFINE_SIZE_T_FMT,
[dnl Make educated guess :/, if size_t is a long or not
AC_CHECK_SIZEOF(size_t)dnl
AC_MSG_CHECKING(printf format of size_t)
if test "$ac_cv_sizeof_size_t" = 4 ; then
  AC_MSG_RESULT("%u")
  AC_DEFINE(SIZE_T_FMT, "%u")
else
  AC_MSG_RESULT("%lu")
  AC_DEFINE(SIZE_T_FMT, "%lu")
fi])

dnl
dnl Macro: unet_DEFINE_TIME_T_FMT
dnl
dnl Try to figure out if time_t is an int or not, and if so define
dnl TIME_T_FMT to be "%u", otherwise define it to be "%lu".
dnl Likewise define STIME_T_FMT for the signed format.
dnl
AC_DEFUN(unet_DEFINE_TIME_T_FMT,
[dnl Make educated guess :/, if time_t is a long or not
AC_MSG_CHECKING(size of time_t)
AC_CACHE_VAL(unet_cv_sizeof_time_t,
[AC_TRY_RUN([#include <stdio.h>
#include <sys/types.h>
main()
{
  FILE *f=fopen("conftestval", "w");
  if (!f) exit(1);
  fprintf(f, "%d\n", sizeof(time_t));
  exit(0);
}], unet_cv_sizeof_time_t=`cat conftestval`,
unet_cv_sizeof_time_t=0, unet_cv_sizeof_time_t=0)])
if test "$unet_cv_sizeof_time_t" = 0 ; then
  AC_MSG_RESULT(unknown)
  AC_DEFINE(TIME_T_FMT, "%lu")
  AC_DEFINE(STIME_T_FMT, "%ld")
else
  AC_MSG_RESULT([$unet_cv_sizeof_time_t])
  AC_MSG_CHECKING(printf format of time_t)
  if test "$unet_cv_sizeof_time_t" = "$ac_cv_sizeof_long" ; then
    AC_MSG_RESULT("%lu")
    AC_DEFINE(TIME_T_FMT, "%lu")
    AC_DEFINE(STIME_T_FMT, "%ld")
  else
    AC_MSG_RESULT("%u")
    AC_DEFINE(TIME_T_FMT, "%u")
    AC_DEFINE(STIME_T_FMT, "%d")
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

dnl
dnl Macro: unet_FUNC_POLL_SYSCALL
dnl
dnl Try to figure out if we have a system call poll (not if it is emulated).
dnl Manical laughter...
dnl
AC_DEFUN(unet_FUNC_POLL_SYSCALL,
[AC_CHECK_HEADERS(poll.h)dnl
if test -z "$unet_cv_func_poll_syscall" ; then
  AC_MSG_CHECKING([if poll is a system call (please wait)])
else
  AC_MSG_CHECKING([if poll is a system call])
fi
AC_CACHE_VAL(unet_cv_func_poll_syscall,
[unet_cv_func_poll_syscall=no
dnl No need to go through the trouble when we don't have poll.h:
changequote(, )dnl
if test "$ac_cv_header_poll_h" = yes; then
  unet_dirs=`find /usr/include/sys -type f -name '*.h' -exec egrep '^#include <[^/]*/.*>' {} \; | sed -e 's/^.*<//' -e 's%/.*$%%' | sort | uniq`
  for i in $unet_dirs ; do
    if test "$unet_cv_func_poll_syscall" = no ; then
      unet_files=`ls /usr/include/$i/*.h 2> /dev/null`
      if test -n "$unet_files" ; then
	for j in $unet_files ; do
	  if test "$unet_cv_func_poll_syscall" = no ; then
	    unet_line=`egrep '^#define[[:space:]]+[[:alnum:]_]*[Pp][Oo][Ll][Ll]' $j`
	    if test -n "$unet_line" ; then
	      unet_sig=`echo "$unet_line" | sed -e 's/poll/fork/g' -e 's/POLL/FORK/g' -e 's/[[:space:]]//g' -e 's%/\*.*\*/%%g' -e 's/[0-9]//g'`
	      unet_set=`for k in "$unet_sig" ; do echo $k; done | sed -e 's% %|%g'`
	      unet_match=`sed -e 's/[[:space:]]//g' -e 's%/\*.*\*/%%g' -e 's/[0-9]//g' $j | egrep "$unet_set"`
	      if test -n "$unet_match" ; then
		unet_cv_func_poll_syscall=yes
	      fi
	    fi
	  fi
	done
      fi
    fi
  done
fi
changequote([, ])dnl
])
AC_MSG_RESULT([$unet_cv_func_poll_syscall])
])
