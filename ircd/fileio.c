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
#include "config.h"

#include "fileio.h"
#include "ircd_alloc.h"         /* MyMalloc, MyFree */

#include <assert.h>             /* assert */
#include <fcntl.h>              /* O_RDONLY, O_WRONLY, ... */
#include <stdio.h>              /* BUFSIZ, EOF */
#include <sys/stat.h>           /* struct stat */
#include <unistd.h>             /* read, write, open, close */
#include <string.h>

#define FB_EOF  0x01
#define FB_FAIL 0x02

struct FileBuf {
  int fd;                       /* file descriptor */
  char *endp;                   /* one past the end */
  char *ptr;                    /* current read pos */
  int flags;                    /* file state */
  char buf[BUFSIZ];             /* buffer */
};

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
      pmode = S_IREAD | S_IWRITE;
      break;
    case 'a':
      openmode = O_WRONLY | O_CREAT | O_APPEND;
      pmode = S_IREAD | S_IWRITE;
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
   * 3 seconds. -avalon (curtesy of wumpus)
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

void fbclose(FBFILE* fb)
{
  assert(fb);
  close(fb->fd);
  MyFree(fb);
}

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

int fbgetc(FBFILE * fb)
{
  assert(fb);
  if (fb->ptr < fb->endp || fbfill(fb) > 0)
    return *fb->ptr++;
  return EOF;
}

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

int fbstat(struct stat *sb, FBFILE * fb)
{
  assert(sb);
  assert(fb);
  return fstat(fb->fd, sb);
}

