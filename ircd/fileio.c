/*
 * IRC - Internet Relay Chat, ircd/fileio.c
 * Copyright (C) 1998 Thomas Helvey <tomh@inxpress.net>
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                  University of Oulu, Co Center
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
 * @brief ANSI FILE* clone API implementation.
 * @version $Id$
 */
#include "config.h"

#include "fileio.h"
#include "ircd_alloc.h"         /* MyMalloc, MyFree */
#include "ircd_log.h"           /* assert */

/* #include <assert.h> -- Now using assert in ircd_log.h */       /* assert */
#include <fcntl.h>              /* O_RDONLY, O_WRONLY, ... */
#include <stdio.h>              /* BUFSIZ, EOF */
#include <sys/stat.h>           /* struct stat */
#include <unistd.h>             /* read, write, open, close */
#include <string.h>

#define FB_EOF  0x01            /**< File has reached EOF. */
#define FB_FAIL 0x02            /**< File operation failed. */

/** Tracks status and buffer for a file on disk. */
struct FileBuf {
  int fd;                       /**< file descriptor */
  char *endp;                   /**< one past the end */
  char *ptr;                    /**< current read pos */
  int flags;                    /**< file state */
  char buf[BUFSIZ];             /**< buffer */
};

/** Open a new FBFILE.
 * @param[in] filename Name of file to open.
 * @param[in] mode fopen()-style mode string.
 * @return Pointer to newly allocated FBFILE.
 */
FBFILE* fbopen(const char *filename, const char *mode)
{
  int openmode = 0;
  int pmode = 0;
  FBFILE *fb = NULL;
  int fd;
  assert(filename);
  assert(mode);

  while (*mode) {
    switch (*mode) {
    case 'r':
      openmode = O_RDONLY;
      break;
    case 'w':
      openmode = O_WRONLY | O_CREAT | O_TRUNC;
      pmode = S_IRUSR | S_IWUSR;
      break;
    case 'a':
      openmode = O_WRONLY | O_CREAT | O_APPEND;
      pmode = S_IRUSR | S_IWUSR;
      break;
    case '+':
      openmode &= ~(O_RDONLY | O_WRONLY);
      openmode |= O_RDWR;
      break;
    default:
      break;
    }
    ++mode;
  }
  /*
   * stop NFS hangs...most systems should be able to open a file in
   * 3 seconds. -avalon (courtesy of wumpus)
   */
  alarm(3);
  if ((fd = open(filename, openmode, pmode)) == -1) {
    alarm(0);
    return fb;
  }
  alarm(0);

  if (NULL == (fb = fdbopen(fd, NULL)))
    close(fd);
  return fb;
}

/** Open a FBFILE from a file descriptor.
 * @param[in] fd File descriptor to use.
 * @param[in] mode fopen()-style mode string (ignored).
 */
FBFILE* fdbopen(int fd, const char *mode)
{
  /*
   * ignore mode, if file descriptor hasn't been opened with the
   * correct mode, the first use will fail
   */
  FBFILE *fb = (FBFILE *) MyMalloc(sizeof(FBFILE));
  assert(0 != fb);
  fb->ptr   = fb->endp = fb->buf;
  fb->fd    = fd;
  fb->flags = 0;

  return fb;
}

/** Close a FBFILE.
 * @param[in] fb File buffer to close.
 */
void fbclose(FBFILE* fb)
{
  assert(fb);
  close(fb->fd);
  MyFree(fb);
}

/** Attempt to fill a file's buffer.
 * @param[in] fb File to operate on.
 * @return Number of bytes read into buffer, or a negative number on error.
 */
static int fbfill(FBFILE * fb)
{
  int n;
  assert(fb);
  if (fb->flags)
    return -1;
  n = read(fb->fd, fb->buf, BUFSIZ);
  if (0 < n)
  {
    fb->ptr = fb->buf;
    fb->endp = fb->buf + n;
  }
  else if (n < 0)
    fb->flags |= FB_FAIL;
  else
    fb->flags |= FB_EOF;
  return n;
}

/** Get a single character from a file.
 * @param[in] fb File to fetch from.
 * @return Character value read, or EOF on error or end-of-file.
 */
int fbgetc(FBFILE * fb)
{
  assert(fb);
  if (fb->ptr < fb->endp || fbfill(fb) > 0)
    return *fb->ptr++;
  return EOF;
}

/** Get a line of input from a file.
 * @param[out] buf Output buffer to read to.
 * @param[in] len Maximum number of bytes to write to buffer
 * (including terminating NUL).
 * @param[in] fb File to read from.
 */
char *fbgets(char *buf, size_t len, FBFILE * fb)
{
  char *p = buf;
  assert(buf);
  assert(fb);
  assert(0 < len);

  if (fb->ptr == fb->endp && fbfill(fb) < 1)
    return 0;
  --len;
  while (len--) {
    *p = *fb->ptr++;
    if ('\n' == *p)
    {
      ++p;
      break;
    }
    /*
     * deal with CR's
     */
    else if ('\r' == *p) {
      if (fb->ptr < fb->endp || fbfill(fb) > 0) {
        if ('\n' == *fb->ptr)
          ++fb->ptr;
      }
      *p++ = '\n';
      break;
    }
    ++p;
    if (fb->ptr == fb->endp && fbfill(fb) < 1)
      break;
  }
  *p = '\0';
  return buf;
}

/** Write a string to a file.
 * @param[in] str String to write to file.
 * @param[in] fb File to write to.
 * @return Number of bytes written, or -1 on error.
 */
int fbputs(const char *str, FBFILE * fb)
{
  int n = -1;
  assert(str);
  assert(fb);

  if (0 == fb->flags) {
    n = write(fb->fd, str, strlen(str));
    if (-1 == n)
      fb->flags |= FB_FAIL;
  }
  return n;
}

/** Get file status.
 * @param[out] sb Receives file status.
 * @param[in] fb File to get status for.
 * @return Zero on success, -1 on error.
 */
int fbstat(struct stat *sb, FBFILE * fb)
{
  assert(sb);
  assert(fb);
  return fstat(fb->fd, sb);
}

