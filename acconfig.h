#ifndef INCLUDED_config_h
#define INCLUDED_config_h
/*
 * IRC - Internet Relay Chat, acconfig.h
 * Copyright (C) 2000 Kevin L. Mitchell <klmitch@mit.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
@TOP@

/* Define if you have the setrlimit function */
#undef HAVE_SETRLIMIT

/* Define one of these, depending on wether you have
 * POSIX, BSD or SYSV non-blocking stuff
 */
#undef NBLOCK_POSIX
#undef NBLOCK_BSD
#undef NBLOCK_SYSV

/* Define on of these, depending on wether you have
 * POSIX, BSD or SYSV signal handling
 */
#undef POSIX_SIGNALS
#undef BSD_RELIABLE_SIGNALS
#undef SYSV_UNRELIABLE_SIGNALS

/* Define these to be unsigned integral internal types,
 * of respecitvely 2 and 4 bytes in size, when not already
 * defined in <sys/types.h>, <stdlib.h> or <stddef.h>
 */
#undef u_int16_t
#undef u_int32_t

/* Define to force the poll() function to be used */
#undef USE_POLL
/* Define to enable the /dev/poll engine */
#undef USE_DEVPOLL
/* Define to enable the kqueue engine */
#undef USE_KQUEUE

/* Define to enable various debugging code in the server; DO NOT USE
 * THIS ON PRODUCTION SERVERS ON PAIN OF DELINKING!
 */
#undef DEBUGMODE

/* Define this to DISable various assertion checking statements */
#undef NDEBUG

/* Define to force certain critical functions to be inlined */
#undef FORCEINLINE

/* Define to be the local domain name for some statics gathering */
#undef DOMAINNAME

/* Define to be the name of the executable to be executed on /restart */
#undef SPATH

/* Define to be the path to the data directory */
#undef DPATH

/* Define to be the name of the configuration file */
#undef CPATH

/* Define to be the name of the debugging log file */
#undef LPATH

/* Define to be the maximum number of network connections */
#undef MAXCONNECTIONS

@BOTTOM@
#endif /* INCLUDED_config_h */
