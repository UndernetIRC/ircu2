/*
** Copyright (C) 2002 by Kevin L. Mitchell <klmitch@mit.edu>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**
** @(#)$Id$
*/
/*
 * This file contains two separate pieces, along with some common
 * gunk.  If RINGLOG_INSTRUMENT is defined, the two special functions
 * __cyg_profile_func_enter() and __cyg_profile_func_exit() are
 * defined; otherwise a main function is defined.  The common gunk is
 * init_log(), which opens and, if necessary, initializes a special
 * binary log file that is treated as a ring buffer (to prevent the
 * file from growing unboundedly).
 *
 * The object produced when compiled with RINGLOG_INSTRUMENT is
 * designed to work with the special gcc option
 * -finstrument-functions; this option causes the
 * __cyg_profile_func_*() functions mentioned above to be called when
 * a function is entered or exited.  (Of course, ringlog.o should
 * *not* be compiled with this option.)  These functions will in turn
 * call store_entry(), which will call init_log() as needed to open
 * the log file, ensure that a start record is output, and then will
 * store records for the function calls.  The log file used is
 * "call.ringlog" in the directory from which the program was
 * started.
 *
 * When RINGLOG_INSTRUMENT is *not* defined while building, a main
 * function is defined, and the result is an executable for
 * interpretation of a ringlog.  Usage is very simple:  All arguments
 * not beginning with '-' are treated as files to open, and all
 * arguments beginning with '-' are treated as a specification for the
 * number of entries new files should be created with.  If this
 * specification is 0 (which it is by default), files will not be
 * created if they do not already exist.
 *
 * For every filename argument, at least one line will be printed
 * out.  If the file is not empty, the entries in the file will be
 * printed out, one to a line.  Each entry is numbered with a logical
 * number.  The entry numbers are followed by a two word description
 * of the entry type ("Log start," "Function entry," "Function exit,"
 * and "Invalid entry"), followed by a colon (":"), followed by the
 * word "addr" and the address of the function, followed by the word
 * "call" and the address from which the function was called.  The
 * ringlog program is not able to convert these addresses to symbols
 * or file and line numbers--that can be done with a program like
 * addr2line (part of the binutils package).  The output has been
 * carefully contrived to be parsable by a script.
 *
 * The file format is documented below.  Note that data is stored in
 * host byte order.
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Magic number                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          First entry          |          Last entry           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                            Records                            |
 * \                                                               \
 * \                                                               \
 * |                            Records                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Record format:
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Type code                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Function address                        |
 * /                                                               /
 * /                                                               /
 * |                       Function address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Calling location                        |
 * /                                                               /
 * /                                                               /
 * |                       Calling location                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Some systems may have pointers larger than 32 bits, which is why these
 * fields are allowed to be variable width.
 */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* /etc/magic rules:
 *
 * 0	belong	0x52e45fd4	RingLog call trace file, big endian
 * >4	beshort	x		(First entry %u,
 * >>6	beshort	x		last entry %u)
 * 0	lelong	0x52e45fd4	RingLog call trace file, little endian
 * >4	leshort	x		(First entry %u,
 * >>6	leshort	x		last entry %u)
 */
#define RINGLOG_MAGIC 0x52e45fd4	/* verify file format */

#define RINGLOG_INIT  0x00000000	/* mark when a session was initiated */
#define RINGLOG_ENTER 0x01010101	/* record function entry */
#define RINGLOG_EXIT  0x02020202	/* record function exit */

#define RINGLOG_FNAME "call.ringlog"	/* default file name */
#define RINGLOG_ILEN  2000		/* default number of entries */

/* length of the header and of individual entries */
#define HEAD_LEN      (sizeof(u_int32_t) + 2 * sizeof(u_int16_t))
#define ENTRY_LEN     (sizeof(u_int32_t) + 2 * sizeof(void *))

/* return an lvalue to the specified type stored at the specified location */
#define rl_ref(log, loc, type) (*((type *)((log) + (loc))))

/* access particular header fields */
#define rl_magic(log) rl_ref((log), 0, u_int32_t)
#define rl_first(log) rl_ref((log), 4, u_int16_t)
#define rl_last(log)  rl_ref((log), 6, u_int16_t)

/* translate physical entry number to a file location */
#define rl_addr(loc)  ((loc) * ENTRY_LEN + HEAD_LEN)

/* extract the type, function, and call fields of an entry */
#define rl_type(log, loc) rl_ref((log), rl_addr(loc), u_int32_t)
#define rl_func(log, loc) rl_ref((log), rl_addr(loc) + sizeof(u_int32_t), \
				 void *)
#define rl_call(log, loc) rl_ref((log), rl_addr(loc) + sizeof(u_int32_t) + \
				 sizeof(void *), void *)

static char *log = 0; /* the log has to be global data */
static size_t log_size = 0; /* remember the size of the log */
static int log_length = 0; /* remember how many entries it'll hold */

/* Open and initialize the log file */
static int
init_log(char *fname, size_t init_len)
{
  char c = 0;
  int fd, err = 0, size = -1;
  struct stat buf;

  /* open file */
  if ((fd = open(fname, O_RDWR | (init_len > 0 ? O_CREAT : 0),
		 S_IRUSR | S_IWUSR)) < 0)
    return errno; /* return error */

  if (fstat(fd, &buf)) { /* get size */
    err = errno; /* save errno... */
    close(fd); /* close file descriptor */
    return err; /* return error */
  }

  if (buf.st_size <= 8) /* too small */
    size = HEAD_LEN + ENTRY_LEN * init_len;
  else if ((buf.st_size - 8) % ENTRY_LEN) /* not a multiple of entry length */
    size = ((buf.st_size - 8) / ENTRY_LEN + 1) * ENTRY_LEN + 8; /* round up */

  if (size >= 0) { /* need to set the size */
    if (lseek(fd, size - 1, SEEK_SET) < 0) { /* seek to the end of our file */
      err = errno; /* save errno... */
      close(fd); /* close file descriptor */
      return err; /* return error */
    }

    if (write(fd, &c, 1) < 0) { /* write a zero to set the new size */
      err = errno; /* save errno... */
      close(fd); /* close file descriptor */
      return err; /* return error */
    }

    log_size = size; /* record log size */
  } else
    log_size = buf.st_size; /* record log size */

  /* map the file to memory */
  if ((log = (char *)mmap(0, log_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, fd, 0)) == MAP_FAILED)
    err = errno; /* save errno... */

  close(fd); /* don't need the file descriptor anymore */

  if (err) /* an error occurred while mapping the file; return it */
    return err;

  log_length = (log_size - HEAD_LEN) / ENTRY_LEN; /* store number of entries */

  if (rl_magic(log) == 0) { /* initialize if necessary */
    rl_magic(log) = RINGLOG_MAGIC;
    rl_first(log) = -1;
    rl_last(log) = -1;
  }

  if (rl_magic(log) != RINGLOG_MAGIC) { /* verify file format */
    munmap(log, log_size); /* unmap file */
    return -1; /* -1 indicates file format error */
  }

  return 0; /* return success */
}

#ifdef RINGLOG_INSTRUMENT

/* store an entry in the log file */
static void
store_entry(u_int32_t type, void *this_fn, void *call_site)
{
  if (!log) { /* open the log file if necessary; die if unable */
    assert(init_log(RINGLOG_FNAME, RINGLOG_ILEN) == 0);
    store_entry(RINGLOG_INIT, 0, 0); /* mark start of logging */
  }

  if (++(rl_last(log)) >= log_length) /* select next entry to fill */
    rl_last(log) = 0; /* wrap if needed */

  if (rl_first(log) == rl_last(log)) { /* advance start pointer if collision */
    if (++(rl_first(log)) >= log_length) /* wrap if necessary */
      rl_first(log) = 0;
  } else if (rl_first(log) == (u_int16_t)-1) /* no entries yet; enter one */
    rl_first(log) = 0;

  rl_type(log, rl_last(log)) = type; /* record the entry */
  rl_func(log, rl_last(log)) = this_fn;
  rl_call(log, rl_last(log)) = call_site;
}

/* called upon function entry */
void
__cyg_profile_func_enter(void *this_fn, void *call_site)
{
  store_entry(RINGLOG_ENTER, this_fn, call_site);
}

/* called upon function exit */
void
__cyg_profile_func_exit(void *this_fn, void *call_site)
{
  store_entry(RINGLOG_EXIT, this_fn, call_site);
}

#else /* !defined(RINGLOG_INSTRUMENT) */

/* converts a type to a printable string */
static char *
get_type(u_int32_t type)
{
  switch (type) {
  case RINGLOG_INIT:
    return " Logging start";
    break;
  case RINGLOG_ENTER:
    return "Function entry";
    break;
  case RINGLOG_EXIT:
    return " Function exit";
    break;
  }

  return " Invalid entry";
}

/* Print out entries from a starting point to an end point */
static void
extract(int *count, u_int16_t start, u_int16_t end)
{
  for (; start <= end; start++)
    printf("% 4d %s: addr %p call %p\n", (*count)++,
	   get_type(rl_type(log, start)), rl_func(log, start),
	   rl_call(log, start));
}

int
main(int argc, char **argv)
{
  char *arg;
  int i, err, size = 0;

  while ((arg = *++argv)) {
    if (arg[0] == '-') { /* -<number> turns into log file size */
      size = atoi(arg + 1);
      continue;
    }

    log = 0; /* initialize our data */
    log_size = 0;
    log_length = 0;

    switch ((err = init_log(arg, size))) { /* initialize the log */
    case -1: /* file is in an invalid format */
      printf("File %s not a valid ringlog file\n", arg);
      continue;
      break;

    case 0: /* file has opened and is ready to be read */
      break;

    default: /* some error occurred */
      printf("Error %d opening file %s: %s\n", err, arg, strerror(err));
      continue;
      break;
    }

    if (rl_first(log) == (u_int16_t)-1) /* it's an empty file */
      printf("File %s is empty\n", arg);
    else { /* print out file contents */
      printf("File %s contents:\n", arg);

      i = 0; /* initialize counter */
      if (rl_last(log) <= rl_first(log)) { /* print out log file */
	extract(&i, rl_first(log), log_length - 1); /* end of buffer... */
	extract(&i, 0, rl_last(log)); /* then beginning of buffer */
      } else
	extract(&i, rl_first(log), rl_last(log));
    }

    munmap(log, log_size); /* unmap the file */
  }

  return 0;
}

#endif /* !RINGLOG_INSTRUMENT */
