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
 *
 * $Id$
 */
#include "config.h"

#include "s_conf.h"
#include "client.h"
#include "class.h"
#include "fileio.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_string.h"
#include "sys.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * stuff that isn't used by s_conf.c anymore
 */
#define CONF_ME                 0x0040
#define CONF_KILL               0x0080
#define CONF_ADMIN              0x0100
#define CONF_CLASS              0x0400
#define CONF_LISTEN_PORT        0x2000
#define CONF_IPKILL             0x00010000
#define CONF_CRULEALL           0x00200000
#define CONF_CRULEAUTO          0x00400000
#define CONF_TLINES             0x00800000

#define CONF_KLINE              (CONF_KILL | CONF_IPKILL)
#define CONF_CRULE              (CONF_CRULEALL | CONF_CRULEAUTO)

/* DEFAULTMAXSENDQLENGTH went into the features subsystem... */
#define DEFAULTMAXSENDQLENGTH 40000

/*
 * For the connect rule patch..  these really should be in a header,
 * but i see h.h isn't included for some reason..  so they're here.
 */
struct CRuleNode;

struct CRuleNode* crule_parse(const char* rule);
void crule_free(struct CRuleNode** elem);

static void new_class(int cn);
static char confchar(unsigned int status);
static char *getfield(char *newline);
static int validate(struct ConfItem *top);
static struct ConfItem *chk_initconf(void);
static struct ConnectionClass *get_class(int cn, int ism);

static int numclasses = 0, *classarr = (int *)NULL, debugflag = 0;
static char *chk_configfile = "";
static char nullfield[] = "";
static char maxsendq[12];

/* A few dummy variables and functions needed to link with runmalloc.o */
time_t CurrentTime;
struct Client me;
void debug(int level, const char *form, ...)
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
void sendto_one(struct Client *to, char *pattern, ...)
{
}
char *rpl_str(int numeric)
{
  return "";
}

int main(int argc, char *argv[])
{
  const char *dpath = "./";
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
          if (isdigit(argv[1][2]))
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
    fprintf(stderr, "chdir(\"%s\") : %s\n", dpath, 
            (strerror(errno)) ? strerror(errno) : "Unknown error");
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
static struct ConfItem *chk_initconf(void)
{
  FBFILE *file;
  char line[512];
  char *tmp;
  struct CRuleNode* crule;
  int ccount = 0, flags = 0;
  struct ConfItem *aconf = NULL, *ctop = NULL;

  fprintf(stderr, "chk_initconf(): ircd.conf = %s\n", chk_configfile);
  if (NULL == (file = fbopen(chk_configfile, "r")))
  {
    perror("open");
    return NULL;
  }

  while (fbgets(line, sizeof(line) - 1, file))
  {
    if (aconf) {
      if (aconf->host)
        MyFree(aconf->host);
      if (aconf->passwd)
        MyFree(aconf->passwd);
      if (aconf->name)
        MyFree(aconf->name);
    }
    else {
      aconf = (struct ConfItem*) MyMalloc(sizeof(struct ConfItem));
      assert(0 != aconf);
    }
    aconf->host        = NULL;
    aconf->passwd      = NULL;
    aconf->name        = NULL;
    aconf->conn_class   = NULL;
    aconf->dns_pending = 0;

    if ((tmp = strchr(line, '\n')))
      *tmp = 0;
    /*
     * Do quoting of characters and # detection.
     */
    for (tmp = line; *tmp; ++tmp) {
      if (*tmp == '\\') {
        switch (*(tmp + 1)) {
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
        if ('\0' == *(tmp + 1))
          break;
        else
          strcpy(tmp + 1, tmp + 2);
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
      case 'A':         /* Name, e-mail address of administrator */
      case 'a':         /* of this server. */
        aconf->status = CONF_ADMIN;
        break;
      case 'C':         /* Server where I should try to connect */
      case 'c':         /* in case of lp failures             */
        ccount++;
        aconf->status = CONF_SERVER;
        break;
        /* Connect rule */
      case 'D':
        aconf->status = CONF_CRULEALL;
        break;
        /* Connect rule - autos only */
      case 'd':
        aconf->status = CONF_CRULEAUTO;
        break;
      case 'H':         /* Hub server line */
      case 'h':
        aconf->status = CONF_HUB;
        break;
      case 'I':         /* Just plain normal irc client trying  */
      case 'i':         /* to connect me */
        aconf->status = CONF_CLIENT;
        break;
      case 'K':         /* Kill user line on irc.conf           */
        aconf->status = CONF_KILL;
        break;
      case 'k':         /* Kill user line based on IP in ircd.conf */
        aconf->status = CONF_IPKILL;
        break;
        /* Operator. Line should contain at least */
        /* password and host where connection is  */
      case 'L':         /* guaranteed leaf server */
      case 'l':
        aconf->status = CONF_LEAF;
        break;
        /* Me. Host field is name used for this host */
        /* and port number is the number of the port */
      case 'M':
      case 'm':
        aconf->status = CONF_ME;
        break;
      case 'O':
        aconf->status = CONF_OPERATOR;
        break;
        /* Local Operator, (limited privs --SRB) */
      case 'o':
        aconf->status = CONF_LOCOP;
        break;
      case 'P':         /* listen port line */
      case 'p':
        aconf->status = CONF_LISTEN_PORT;
        break;
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

    for (;;)                    /* Fake loop, that I can use break here --msa */
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
        aconf->conn_class = get_class(atoi(tmp), 0);
        break;
      }
      if (aconf->status & CONF_ME)
        aconf->conn_class = get_class(atoi(tmp), 1);
      break;
    }
    if (!aconf->conn_class && (aconf->status & (CONF_SERVER |
        CONF_ME | CONF_OPS | CONF_CLIENT)))
    {
      fprintf(stderr, "\tWARNING: No class.      Default 0\n");
      aconf->conn_class = get_class(0, 0);
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
      aconf->conn_class = get_class(atoi(aconf->host), 0);
      goto print_confline;
    }

    if (aconf->status & CONF_LISTEN_PORT)
    {
      if (!aconf->host)
        fprintf(stderr, "\tERROR: %s\n", "null host field in P-line");
      else if (strchr(aconf->host, '/'))
        fprintf(stderr, "\t%s\n", "WARNING: / present in P-line "
            "for non-UNIXPORT configuration");
      aconf->conn_class = get_class(0, 0);
      goto print_confline;
    }

    if (aconf->status & CONF_SERVER &&
        (!aconf->host || strchr(aconf->host, '*') || strchr(aconf->host, '?')))
    {
      fprintf(stderr, "\tERROR: bad host field\n");
      continue;
    }

    if (aconf->status & CONF_SERVER && BadPtr(aconf->passwd))
    {
      fprintf(stderr, "\tERROR: empty/no password field\n");
      continue;
    }

    if (aconf->status & CONF_SERVER && !aconf->name)
    {
      fprintf(stderr, "\tERROR: bad name field\n");
      continue;
    }

    if (aconf->status & (CONF_OPS))
      if (!strchr(aconf->host, '@'))
      {
        char *newhost;
        int len = 3;            /* *@\0 = 3 */

        len += strlen(aconf->host);
        newhost = (char *)MyMalloc(len);
        sprintf(newhost, "*@%s", aconf->host);
        MyFree(aconf->host);
        aconf->host = newhost;
      }

    /* parse the connect rules to detect errors, but free
     *  any allocated storage immediately -- we're just looking
     *  for errors..  */
    if (aconf->status & CONF_CRULE)
      if ((crule = crule_parse(aconf->name)) != NULL)
        crule_free(&crule);

    if (!aconf->conn_class)
      aconf->conn_class = get_class(0, 0);
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
                ToUpper(confchar(aconf->status)));
      else
        flags |= aconf->status;
    }
print_confline:
    if (debugflag > 8)
      printf("(%d) (%s) (%s) (%s) (%u) (%s)\n",
          aconf->status, aconf->host, aconf->passwd,
          aconf->name, aconf->port, maxsendq);
    fflush(stdout);
    if (aconf->status & (CONF_SERVER | CONF_HUB | CONF_LEAF))
    {
      aconf->next = ctop;
      ctop = aconf;
      aconf = NULL;
    }
  }
  fbclose(file);
  return ctop;
}

static struct ConnectionClass *get_class(int cn, int ism)
{
  static struct ConnectionClass cls;
  if (ism == 1)
  {
    cls.cc_class = (unsigned int)-1;
    if ((cn >= 1) && (cn <= 64))
      cls.cc_class = cn;
    else
      fprintf(stderr, "\tWARNING: server numeric %d is not 1-64\n", cn);
  }
  else
  {
    int i = numclasses - 1;
    cls.cc_class = (unsigned int)-1;
    for (; i >= 0; i--)
      if (classarr[i] == cn)
      {
        cls.cc_class = cn;
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
    classarr = (int *)MyRealloc(classarr, sizeof(int) * numclasses);
  else
    classarr = (int *)MyMalloc(sizeof(int));
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

static int validate(struct ConfItem *top)
{
  struct ConfItem *aconf, *bconf;
  unsigned int otype, valid = 0;

  if (!top)
    return 0;

  for (aconf = top; aconf; aconf = aconf->next)
  {
    if (aconf->status & CONF_MATCH)
      continue;

    if (aconf->status & CONF_SERVER)
    {
      otype = CONF_SERVER;

      for (bconf = top; bconf; bconf = bconf->next)
      {
        if (bconf == aconf || !(bconf->status & otype))
          continue;
        if (bconf->conn_class == aconf->conn_class &&
            0 == ircd_strcmp(bconf->name, aconf->name) &&
            0 == ircd_strcmp(bconf->host, aconf->host))
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
        if ((bconf == aconf) || !(bconf->status & CONF_SERVER))
          continue;
        if (0 == ircd_strcmp(bconf->name, aconf->name))
        {
          aconf->status |= CONF_MATCH;
          break;
        }
      }
  }

  fprintf(stderr, "\n");
  for (aconf = top; aconf; aconf = aconf->next) {
    if (aconf->status & CONF_MATCH)
      valid++;
    else if ('N' != confchar(aconf->status)) 
      fprintf(stderr, "Unmatched %c:%s:%s:%s\n",
          confchar(aconf->status), aconf->host, aconf->passwd, aconf->name);
  }
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
