/*
 * IRC - Internet Relay Chat, ircd/chkconf.c
 * Copyright (C) 1993 Darren Reed
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

#include "sys.h"
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <ctype.h>
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HPUX
#include <arpa/inet.h>
#endif /* HPUX */
#ifdef	R_LINES
#include <signal.h>
#endif
#include "h.h"
#include "s_conf.h"
#include "class.h"
#include "common.h"
#include "ircd.h"
#include "fileio.h"

RCSTAG_CC("$Id$");

/*
 * For the connect rule patch..  these really should be in a header,
 * but i see h.h isn't included for some reason..  so they're here.
 */
char *crule_parse(char *rule);
void crule_free(char **elem);

static void new_class(int cn);
static char confchar(unsigned int status);
static char *getfield(char *newline);
static int validate(aConfItem *top);
static aConfItem *chk_initconf(void);
static aConfClass *get_class(int cn, int ism);

static int numclasses = 0, *classarr = (int *)NULL, debugflag = 0;
static char *chk_configfile = CPATH;
static char nullfield[] = "";
static char maxsendq[12];

/* A few dummy variables and functions needed to link with runmalloc.o */
time_t now;
struct Client {
  time_t since;
  char name[1];
} me;
void debug(int UNUSED(level), const char *form, ...)
{
  va_list vl;
  va_start(vl, form);
  if (debugflag > 8)
  {
    vfprintf(stderr, form, vl);
    fprintf(stderr, "\n");
  }
  va_end(vl);
}
void sendto_one(aClient *UNUSED(to), char *UNUSED(pattern), ...)
{
}
char *rpl_str(int UNUSED(numeric))
{
  return "";
}

int main(int argc, char *argv[])
{
  const char *dpath = DPATH;
  chk_configfile = "ircd.conf";

  while (argc > 1)
  {
    if (*argv[1] == '-')
    {
      switch (argv[1][1])
      {
	case 'd':
	  if (argc > 2)
	  {
	    dpath = argv[2];
	    --argc;
	    ++argv;
	  }
	  else
	  {
	    fprintf(stderr, "-d: Missing path\n");
	    exit(-1);
	  }
	  break;
	case 'x':
	  debugflag = 1;
	  if (isdigit((int)argv[1][2]))
	    debugflag = atoi(&argv[1][2]);
	  break;
	default:
	  fprintf(stderr, "Ignoring unknown option -%c\n", argv[1][1]);
      }
    }
    else
      chk_configfile = argv[1];
    --argc;
    ++argv;
  }

  if (chdir(dpath))
  {
    fprintf(stderr, "chdir(\"%s\") : %s\n", dpath, strerror(errno));
    exit(-1);
  }
  else if (debugflag > 1)
    fprintf(stderr, "chdir(\"%s\") : Success", dpath);

  new_class(0);

  return validate(chk_initconf());
}

/*
 * chk_initconf()
 *
 * Read configuration file.
 *
 * Returns -1, if file cannot be opened
 *          0, if file opened.
 */
static aConfItem *chk_initconf(void)
{
  FBFILE *file;
  char line[512], *tmp, *s, *crule;
  int ccount = 0, ncount = 0, flags = 0;
  aConfItem *aconf = NULL, *ctop = NULL;

  fprintf(stderr, "chk_initconf(): ircd.conf = %s\n", chk_configfile);
  if (NULL == (file = fbopen(chk_configfile, "r")))
  {
    perror("open");
    return NULL;
  }

  while (fbgets(line, sizeof(line) - 1, file))
  {
    if (aconf)
    {
      if (aconf->host)
	RunFree(aconf->host);
      if (aconf->passwd)
	RunFree(aconf->passwd);
      if (aconf->name)
	RunFree(aconf->name);
    }
    else
      aconf = (aConfItem *)RunMalloc(sizeof(*aconf));
    aconf->host = (char *)NULL;
    aconf->passwd = (char *)NULL;
    aconf->name = (char *)NULL;
    aconf->confClass = (aConfClass *) NULL;
    if ((tmp = strchr(line, '\n')))
      *tmp = 0;
    /*
     * Do quoting of characters and # detection.
     */
    for (tmp = line; *tmp; tmp++)
    {
      if (*tmp == '\\')
      {
	switch (*(tmp + 1))
	{
	  case 'n':
	    *tmp = '\n';
	    break;
	  case 'r':
	    *tmp = '\r';
	    break;
	  case 't':
	    *tmp = '\t';
	    break;
	  case '0':
	    *tmp = '\0';
	    break;
	  default:
	    *tmp = *(tmp + 1);
	    break;
	}
	if (!*(tmp + 1))
	  break;
	else
	  for (s = tmp; (*s = *++s);)
	    ;
	tmp++;
      }
      else if (*tmp == '#')
	*tmp = '\0';
    }
    if (!*line || *line == '#' || *line == '\n' ||
	*line == ' ' || *line == '\t')
      continue;

    if (line[1] != ':')
    {
      fprintf(stderr, "ERROR: Bad config line (%s)\n", line);
      continue;
    }

    if (debugflag)
      printf("\n%s\n", line);
    fflush(stdout);

    tmp = getfield(line);
    if (!tmp)
    {
      fprintf(stderr, "\tERROR: no fields found\n");
      continue;
    }

    aconf->status = CONF_ILLEGAL;

    switch (*tmp)
    {
      case 'A':		/* Name, e-mail address of administrator */
      case 'a':		/* of this server. */
	aconf->status = CONF_ADMIN;
	break;
      case 'C':		/* Server where I should try to connect */
      case 'c':		/* in case of lp failures             */
	ccount++;
	aconf->status = CONF_CONNECT_SERVER;
	break;
	/* Connect rule */
      case 'D':
	aconf->status = CONF_CRULEALL;
	break;
	/* Connect rule - autos only */
      case 'd':
	aconf->status = CONF_CRULEAUTO;
	break;
      case 'H':		/* Hub server line */
      case 'h':
	aconf->status = CONF_HUB;
	break;
      case 'I':		/* Just plain normal irc client trying  */
      case 'i':		/* to connect me */
	aconf->status = CONF_CLIENT;
	break;
      case 'K':		/* Kill user line on irc.conf           */
	aconf->status = CONF_KILL;
	break;
      case 'k':		/* Kill user line based on IP in ircd.conf */
	aconf->status = CONF_IPKILL;
	break;
	/* Operator. Line should contain at least */
	/* password and host where connection is  */
      case 'L':		/* guaranteed leaf server */
      case 'l':
	aconf->status = CONF_LEAF;
	break;
	/* Me. Host field is name used for this host */
	/* and port number is the number of the port */
      case 'M':
      case 'm':
	aconf->status = CONF_ME;
	break;
      case 'N':		/* Server where I should NOT try to     */
      case 'n':		/* connect in case of lp failures     */
	/* but which tries to connect ME        */
	++ncount;
	aconf->status = CONF_NOCONNECT_SERVER;
	break;
      case 'O':
	aconf->status = CONF_OPERATOR;
	break;
	/* Local Operator, (limited privs --SRB) */
      case 'o':
	aconf->status = CONF_LOCOP;
	break;
      case 'P':		/* listen port line */
      case 'p':
	aconf->status = CONF_LISTEN_PORT;
	break;
#ifdef R_LINES
      case 'R':		/* extended K line */
      case 'r':		/* Offers more options of how to restrict */
	aconf->status = CONF_RESTRICT;
	break;
#endif
      case 'T':
      case 't':
	aconf->status = CONF_TLINES;
	break;
      case 'U':
      case 'u':
	aconf->status = CONF_UWORLD;
	break;
      case 'Y':
      case 'y':
	aconf->status = CONF_CLASS;
	break;
      default:
	fprintf(stderr, "\tERROR: unknown conf line letter (%c)\n", *tmp);
	break;
    }

    if (IsIllegal(aconf))
      continue;

    for (;;)			/* Fake loop, that I can use break here --msa */
    {
      if ((tmp = getfield(NULL)) == NULL)
	break;
      DupString(aconf->host, tmp);
      if ((tmp = getfield(NULL)) == NULL)
	break;
      DupString(aconf->passwd, tmp);
      if ((tmp = getfield(NULL)) == NULL)
	break;
      DupString(aconf->name, tmp);
      if ((tmp = getfield(NULL)) == NULL)
	break;
      aconf->port = atoi(tmp);
      if ((tmp = getfield(NULL)) == NULL)
	break;
      if (!(aconf->status & (CONF_CLASS | CONF_ME)))
      {
	aconf->confClass = get_class(atoi(tmp), 0);
	break;
      }
      if (aconf->status & CONF_ME)
	aconf->confClass = get_class(atoi(tmp), 1);
      break;
    }
    if (!aconf->confClass && (aconf->status & (CONF_CONNECT_SERVER |
	CONF_ME | CONF_NOCONNECT_SERVER | CONF_OPS | CONF_CLIENT)))
    {
      fprintf(stderr, "\tWARNING: No class.	 Default 0\n");
      aconf->confClass = get_class(0, 0);
    }
    /*
     * If conf line is a class definition, create a class entry
     * for it and make the conf_line illegal and delete it.
     */
    if (aconf->status & CONF_CLASS)
    {
      if (!aconf->host)
      {
	fprintf(stderr, "\tERROR: no class #\n");
	continue;
      }
      if (!tmp)
      {
	fprintf(stderr, "\tWARNING: missing sendq field\n");
	fprintf(stderr, "\t\t default: %d\n", DEFAULTMAXSENDQLENGTH);
	sprintf(maxsendq, "%d", DEFAULTMAXSENDQLENGTH);
      }
      else
	sprintf(maxsendq, "%d", atoi(tmp));
      new_class(atoi(aconf->host));
      aconf->confClass = get_class(atoi(aconf->host), 0);
      goto print_confline;
    }

    if (aconf->status & CONF_LISTEN_PORT)
    {
#ifdef	UNIXPORT
      struct stat sb;

      if (!aconf->host)
	fprintf(stderr, "\tERROR: %s\n", "null host field in P-line");
      else if (strchr(aconf->host, '/'))
      {
	if (stat(aconf->host, &sb) == -1)
	{
	  fprintf(stderr, "\tERROR: (%s) ", aconf->host);
	  perror("stat");
	}
	else if ((sb.st_mode & S_IFMT) != S_IFDIR)
	  fprintf(stderr, "\tERROR: %s not directory\n", aconf->host);
      }
#else
      if (!aconf->host)
	fprintf(stderr, "\tERROR: %s\n", "null host field in P-line");
      else if (strchr(aconf->host, '/'))
	fprintf(stderr, "\t%s\n", "WARNING: / present in P-line "
	    "for non-UNIXPORT configuration");
#endif
      aconf->confClass = get_class(0, 0);
      goto print_confline;
    }

    if (aconf->status & CONF_SERVER_MASK &&
	(!aconf->host || strchr(aconf->host, '*') || strchr(aconf->host, '?')))
    {
      fprintf(stderr, "\tERROR: bad host field\n");
      continue;
    }

    if (aconf->status & CONF_SERVER_MASK && BadPtr(aconf->passwd))
    {
      fprintf(stderr, "\tERROR: empty/no password field\n");
      continue;
    }

    if (aconf->status & CONF_SERVER_MASK && !aconf->name)
    {
      fprintf(stderr, "\tERROR: bad name field\n");
      continue;
    }

    if (aconf->status & (CONF_SERVER_MASK | CONF_OPS))
      if (!strchr(aconf->host, '@'))
      {
	char *newhost;
	int len = 3;		/* *@\0 = 3 */

	len += strlen(aconf->host);
	newhost = (char *)RunMalloc(len);
	sprintf(newhost, "*@%s", aconf->host);
	RunFree(aconf->host);
	aconf->host = newhost;
      }

    /* parse the connect rules to detect errors, but free
     *  any allocated storage immediately -- we're just looking
     *  for errors..  */
    if (aconf->status & CONF_CRULE)
      if ((crule = (char *)crule_parse(aconf->name)) != NULL)
	crule_free(&crule);

    if (!aconf->confClass)
      aconf->confClass = get_class(0, 0);
    sprintf(maxsendq, "%d", ConfClass(aconf));

    if ((aconf->status & CONF_ADMIN) && (!aconf->name ||
	!aconf->passwd || !aconf->host))
      fprintf(stderr, "ERROR: Your A: line must have 4 fields!\n");

    if (!aconf->name)
      DupString(aconf->name, nullfield);
    if (!aconf->passwd)
      DupString(aconf->passwd, nullfield);
    if (!aconf->host)
      DupString(aconf->host, nullfield);
    if (aconf->status & (CONF_ME | CONF_ADMIN))
    {
      if (flags & aconf->status)
	fprintf(stderr, "ERROR: multiple %c-lines\n",
	    toUpper(confchar(aconf->status)));
      else
	flags |= aconf->status;
    }
  print_confline:
    if (debugflag > 8)
      printf("(%d) (%s) (%s) (%s) (%u) (%s)\n",
	  aconf->status, aconf->host, aconf->passwd,
	  aconf->name, aconf->port, maxsendq);
    fflush(stdout);
    if (aconf->status & (CONF_SERVER_MASK | CONF_HUB | CONF_LEAF))
    {
      aconf->next = ctop;
      ctop = aconf;
      aconf = NULL;
    }
  }
  fbclose(file);
  return ctop;
}

static aConfClass *get_class(int cn, int ism)
{
  static aConfClass cls;
  if (ism == 1)
  {
    cls.conClass = (unsigned int)-1;
    if ((cn >= 1) && (cn <= 64))
      cls.conClass = cn;
    else
      fprintf(stderr, "\tWARNING: server numeric %d is not 1-64\n", cn);
  }
  else
  {
    int i = numclasses - 1;
    cls.conClass = (unsigned int)-1;
    for (; i >= 0; i--)
      if (classarr[i] == cn)
      {
	cls.conClass = cn;
	break;
      }
    if (i == -1)
      fprintf(stderr, "\tWARNING: class %d not found\n", cn);
  }
  return &cls;
}

static void new_class(int cn)
{
  numclasses++;
  if (classarr)
    classarr = (int *)RunRealloc(classarr, sizeof(int) * numclasses);
  else
    classarr = (int *)RunMalloc(sizeof(int));
  classarr[numclasses - 1] = cn;
}

/*
 * field breakup for ircd.conf file.
 */
static char *getfield(char *newline)
{
  static char *line = NULL;
  char *end, *field;

  if (newline)
    line = newline;
  if (line == NULL)
    return (NULL);

  field = line;
  if ((end = strchr(line, ':')) == NULL)
  {
    line = NULL;
    if ((end = strchr(field, '\n')) == NULL)
      end = field + strlen(field);
  }
  else
    line = end + 1;
  *end = '\0';
  return (field);
}

static int validate(aConfItem *top)
{
  Reg1 aConfItem *aconf, *bconf;
  unsigned int otype, valid = 0;

  if (!top)
    return 0;

  for (aconf = top; aconf; aconf = aconf->next)
  {
    if (aconf->status & CONF_MATCH)
      continue;

    if (aconf->status & CONF_SERVER_MASK)
    {
      if (aconf->status & CONF_CONNECT_SERVER)
	otype = CONF_NOCONNECT_SERVER;
      else if (aconf->status & CONF_NOCONNECT_SERVER)
	otype = CONF_CONNECT_SERVER;
      else			/* Does this ever happen ? */
	continue;

      for (bconf = top; bconf; bconf = bconf->next)
      {
	if (bconf == aconf || !(bconf->status & otype))
	  continue;
	if (bconf->confClass == aconf->confClass &&
	    !strCasediff(bconf->name, aconf->name) &&
	    !strCasediff(bconf->host, aconf->host))
	{
	  aconf->status |= CONF_MATCH;
	  bconf->status |= CONF_MATCH;
	  break;
	}
      }
    }
    else
      for (bconf = top; bconf; bconf = bconf->next)
      {
	if ((bconf == aconf) || !(bconf->status & CONF_SERVER_MASK))
	  continue;
	if (!strCasediff(bconf->name, aconf->name))
	{
	  aconf->status |= CONF_MATCH;
	  break;
	}
      }
  }

  fprintf(stderr, "\n");
  for (aconf = top; aconf; aconf = aconf->next)
    if (aconf->status & CONF_MATCH)
      valid++;
    else
      fprintf(stderr, "Unmatched %c:%s:%s:%s\n",
	  confchar(aconf->status), aconf->host, aconf->passwd, aconf->name);
  return valid ? 0 : -1;
}

static char confchar(unsigned int status)
{
  static char letrs[] = "ICNoOMKARYLPH";
  char *s = letrs;

  status &= ~(CONF_MATCH | CONF_ILLEGAL);

  for (; *s; s++, status >>= 1)
    if (status & 1)
      return *s;
  return '-';
}
