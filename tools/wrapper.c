/*
** Copyright (C) 2000 by Kevin L. Mitchell <klmitch@mit.edu>
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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>

/*
 * Try and find the correct name to use with getrlimit() for setting the max.
 * number of files allowed to be open by this process.
 *
 * Shamelessly stolen from ircu...
 */
#ifdef RLIMIT_FDMAX
#define RLIMIT_FD_MAX RLIMIT_FDMAX
#else
#ifdef RLIMIT_NOFILE
#define RLIMIT_FD_MAX RLIMIT_NOFILE
#else
#ifdef RLIMIT_OPEN_MAX
#define RLIMIT_FD_MAX RLIMIT_OPEN_MAX
#else
#error Unable to find a valid RLIMIT_FD_MAX
#endif
#endif
#endif

/*fix for change uid/gid with chroot #ubra 08/02/03*/
int uid, gid;

/*
 * Set the hard and soft limits for maximum file descriptors.
 */
int
set_fdlimit(unsigned int max_descriptors)
{
  struct rlimit limit;

  limit.rlim_max = limit.rlim_cur = max_descriptors;

  return setrlimit(RLIMIT_FD_MAX, &limit);
}

/*
 * Change directories to the indicated root directory, then make it the
 * root directory.
 */
int
change_root(char *root)
{
  if (chdir(root))
    return -1;
  if (chroot(root))
    return -1;

  return 0;
}

/*
 * Change the user and group ids--including supplementary groups!--as
 * appropriate.
 *
 * fix for change uid/gid with chroot #ubra 08/02/03
 * old change_user() got splited into get_user() and set_user()
 */
int
get_user(char *user, char *group)
{
  struct passwd *pwd;
  struct group *grp;
  char *tmp;

  /* Track down a struct passwd describing the desired user */
  uid = strtol(user, &tmp, 10); /* was the user given as a number? */
  if (*tmp) { /* strtol() failed to parse; look up as a user name */
    if (!(pwd = getpwnam(user)))
      return -1;
  } else if (!(pwd = getpwuid(uid))) /* look up uid */
      return -1;

  uid = pwd->pw_uid; /* uid to change to */
  gid = pwd->pw_gid; /* default gid for user */

  if (group) { /* a group was specified; track down struct group */
    gid = strtol(group, &tmp, 10); /* was the group given as a number? */
    if (*tmp) { /* strtol() failed to parse; look up as a group name */
      if (!(grp = getgrnam(group)))
	return -1;
    } else if (!(grp = getgrgid(gid))) /* look up gid */
      return -1;

    gid = grp->gr_gid; /* set the gid */
  }

  if (initgroups(pwd->pw_name, gid)) /* initialize supplementary groups */
    return -1;
  return 0; /* success! */
}

int
set_user(void) {
  if (setgid(gid)) /* change our current group */
    return -1;
  if (setuid(uid)) /* change our current user */
    return -1;

  return 0; /* success! */
}

/*
 * Explain how to use this program.
 */
void
usage(char *prog, int retval)
{
  fprintf(stderr, "Usage: %s [-u <user>] [-g <group>] [-l <limit>] [-c <root>]"
	  " -- \\\n\t\t<cmd> [<cmdargs>]\n", prog);
  fprintf(stderr, "       %s -h\n", prog);

  exit(retval);
}

int
main(int argc, char **argv)
{
  int c, limit = -1;
  char *prog, *user = 0, *group = 0, *root = 0;

  /* determine program name for error reporting */
  if ((prog = strrchr(argv[0], '/')))
    prog++;
  else
    prog = argv[0];

  /* process command line arguments */
  while ((c = getopt(argc, argv, "hu:g:l:c:")) > 0)
    switch (c) {
    case 'h': /* requested help */
      usage(prog, 0);
      break;

    case 'u': /* suggested a user */
      user = optarg;
      break;

    case 'g': /* suggested a group */
      group = optarg;
      break;

    case 'l': /* file descriptor limit */
      limit = strtol(optarg, 0, 10);
      break;

    case 'c': /* select a root directory */
      root = optarg;
      break;

    default: /* unknown command line argument */
      usage(prog, 1);
      break;
    }

  /* Not enough arguments; we must have a command to execute! */
  if (optind >= argc)
    usage(prog, 1);

  if (limit > 0) /* set the requested fd limit */
    if (set_fdlimit(limit) < 0) {
      perror(prog);
      return 1;
    }

  if(user) /* get the selected user account uid/gid*/
   if (get_user(user, group)) {
     perror(prog);
     return 1;
   }


  if (root) /* change root directories */
    if (change_root(root)) {
      perror(prog);
      return 1;
    }

  if (user) /* change to selected user account */
    if (set_user()) {
      perror(prog);
      return 1;
    }

  /* execute the requested command */
  execvp(argv[optind], argv + optind);

  /* If we got here, execvp() failed; report the error */
  perror(prog);
  return 1;
}
