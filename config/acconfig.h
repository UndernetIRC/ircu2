/* Define if you have the resolv library (-lresolv) */
#undef HAVE_LIB_RESOLV

/* Define if you have the setrlimit function */
#undef HAVE_SETRLIMIT

/* Define one of these, depending on wether you have
   POSIX, BSD or SYSV non-blocking stuff */
#undef NBLOCK_POSIX
#undef NBLOCK_BSD
#undef NBLOCK_SYSV

/* Define on of these, depending on wether you have
   POSIX, BSD or SYSV signal handling */
#undef POSIX_SIGNALS
#undef BSD_RELIABLE_SIGNALS
#undef SYSV_UNRELIABLE_SIGNALS

/* Define these to be unsigned integral internal types,
 * of respecitvely 2 and 4 bytes in size, when not already
 * defined in <sys/types.h>, <stdlib.h> or <stddef.h> */
#undef u_int16_t
#undef u_int32_t

/* Define this to the printf format for size_t */
#undef SIZE_T_FMT

/* Define this to the printf format for time_t */
#undef TIME_T_FMT

/* Define this to the printf signed format for time_t */
#undef STIME_T_FMT
