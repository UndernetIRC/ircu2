/*
 * IRC - Internet Relay Chat, ircd/umkpasswd.c
 * Copyright (C) 2002 hikari
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
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
/* #include <assert.h> -- Now using assert in ircd_log.h */

/* ircu headers */
#include "ircd_alloc.h"
#include "ircd_log.h" /* for ircd's assert.h */
#include "ircd_string.h"
#include "umkpasswd.h"
#include "s_debug.h"
#include "ircd_md5.h"

/* crypto mech headers */
#include "ircd_crypt.h"
#include "ircd_crypt_smd5.h"
#include "ircd_crypt_native.h"
#include "ircd_crypt_plain.h"

/* bleah, evil globals */
umkpasswd_conf_t* umkpasswd_conf;
crypt_mechs_t* crypt_mechs_root;
int log_inassert = 0;
time_t CurrentTime;

void sendto_opmask_butone(struct Client *one, unsigned int mask,
			  const char *pattern, ...)
{
  /* only needed with memdebug, which also calls Debug() */
}

void copyright(void)
{
  fprintf(stderr, "umkpasswd - Copyright (c) 2002 hikari\n");
return;
}

void show_help(void)
{
#ifdef DEBUGMODE
 char *debughelp = "[-d <level>] ";
#else
 char *debughelp = "";
#endif

 copyright();
 /*fprintf(stderr, "umkpasswd [-l] [[[-a]||[-u]] <username>] [-y <class>] %s[-c <file>] -m <mech> [password]\n\n", debughelp);*/
 fprintf(stderr, "umkpasswd [-l] %s-m <mech> [password]\n\n", debughelp);
 fprintf(stderr, "  -l            List mechanisms available.\n");
#if 0
 fprintf(stderr, "  -a <user>     Add user to conf file.\n");
 fprintf(stderr, "  -u <user>     Update user's password field.\n");
 fprintf(stderr, "  -y <class>    Class to place oper in.\n");
#endif
 fprintf(stderr, "  -m <mech>     Mechanism to use [MANDATORY].\n");
#ifdef DEBUGMODE
 fprintf(stderr, "  -d <level>    Debug level to run at.\n");
#endif
/*
 fprintf(stderr, "  -c <file>     Conf file to use, default is DPATH/CPATH.\n\n");
*/
return;
}

/* our implementation of debug() */
void debug(int level, const char *form, ...)
{
va_list vl;
int err = errno;

  if (level <= (umkpasswd_conf->debuglevel))
  {
    va_start(vl, form);
    vfprintf(stderr, form, vl);
    fprintf(stderr, "\n");
    va_end(vl);
  }
  errno = err;
}

/* quick implementation of log_write() for assert() call */
void log_write(enum LogSys subsys, enum LogLevel severity,
	       unsigned int flags, const char *fmt, ...)
{
  va_list vl;
  va_start(vl, fmt);
  vfprintf(stderr, fmt, vl);
  fprintf(stderr, "\n");
  va_end(vl);
}

/* quick and dirty salt generator */
char *make_salt(const char *salts)
{
char *tmp = NULL;
long int n = 0;

 /* try and get around them running this time after time in quick succession */
 sleep(1);
 srandom((unsigned int)time(NULL));

 if((tmp = calloc(3, sizeof(char))) != NULL)
 {
  /* can't optimize this much more than just doing it twice */
  n = ((float)(strlen(salts))*random()/(RAND_MAX+1.0));
  memcpy(tmp, (salts+n), 1);
  sleep(2);
  n = ((float)(strlen(salts))*random()/(RAND_MAX+1.0));
  memcpy((tmp+1), (salts+n), 1);

  Debug((DEBUG_DEBUG, "salts = %s", salts));
  Debug((DEBUG_DEBUG, "strlen(salts) = %d", strlen(salts)));
 }

return tmp;
}

/* our implementation of ircd_crypt_register_mech() */
int ircd_crypt_register_mech(crypt_mech_t* mechanism)
{
crypt_mechs_t* crypt_mech;

 Debug((DEBUG_INFO, "ircd_crypt_register_mech: registering mechanism: %s", mechanism->shortname));

 /* try to allocate some memory for the new mechanism */
 if ((crypt_mech = (crypt_mechs_t*)MyMalloc(sizeof(crypt_mechs_t))) == NULL)
 {
  /* aww poot, we couldn't get any memory, scream a little then back out */
  Debug((DEBUG_MALLOC, "ircd_crypt_register_mech: could not allocate memory for %s", mechanism->shortname));
  return -1;
 }

 /* ok, we have memory, initialise it */
 memset(crypt_mech, 0, sizeof(crypt_mechs_t));

 /* assign the data */
 crypt_mech->mech = mechanism;
 crypt_mech->next = crypt_mech->prev = NULL;

 /* first of all, is there anything there already? */
 if(crypt_mechs_root->next == NULL)
 {
  /* nope, just add ourself */
  crypt_mechs_root->next = crypt_mechs_root->prev = crypt_mech;
 } else {
  /* nice and simple, put ourself at the end */
  crypt_mech->prev = crypt_mechs_root->prev;
  crypt_mech->next = NULL;
  crypt_mechs_root->prev = crypt_mech->prev->next = crypt_mech;
 }

 /* we're done */
 Debug((DEBUG_INFO, "ircd_crypt_register_mech: registered mechanism: %s, crypt_function is at 0x%X.", crypt_mech->mech->shortname, &crypt_mech->mech->crypt_function));
 Debug((DEBUG_INFO, "ircd_crypt_register_mech: %s: %s", crypt_mech->mech->shortname, crypt_mech->mech->description));

return 0;
}

void sum(char* tmp)
{
char* str;
FILE* file;
MD5_CTX context;
int len;
unsigned char buffer[1024], digest[16], vstr[32];

vstr[0] = '\0';
 str = tmp + strlen(tmp);
 while (str[-1] == '\r' || str[-1] == '\n') *--str = '\0';
 if (NULL == (file = fopen(tmp, "r")))
 {
  fprintf(stderr, "unable to open %s: %s", tmp, strerror(errno));
  exit(0);
 }
 MD5Init(&context);
 while ((fgets((char*)buffer, sizeof(buffer), file)) != NULL)
 {
  MD5Update(&context, buffer, strlen((char*)buffer));
  str = strstr((char*)buffer, "$Id: ");
  if (str != NULL)
  {
   for (str += 5; !isspace(*str); ++str) {}
   while (isspace(*++str)) {}
   for (len = 0; !isspace(str[len]); ++len) vstr[len] = str[len];
   vstr[len] = '\0';
   break;
  }
 }
 while ((len = fread (buffer, 1, sizeof(buffer), file)))
  MD5Update(&context, buffer, len);
 MD5Final(digest, &context);
 fclose(file);

 str = strrchr(tmp, '/');
 printf("    \"[ %s: ", str ? (str + 1) : tmp);
 for (len = 0; len < 16; len++)
  printf ("%02x", digest[len]);
 printf(" %s ]\",\n", vstr);
}

/* dump the loaded mechs list */
void show_mechs(void)
{
crypt_mechs_t* mechs;

 copyright();
 printf("\nAvailable mechanisms:\n");

 if(crypt_mechs_root == NULL)
  return;

 mechs = crypt_mechs_root->next;

 for(;;)
 {
  if(mechs == NULL)
   return;

  printf(" %s\t\t%s\n", mechs->mech->mechname, mechs->mech->description);

  mechs = mechs->next;
 }
}

/* load in the mech "modules" */
void load_mechs(void)
{
 /* we need these loaded by hand for now */

 ircd_register_crypt_native();
 ircd_register_crypt_smd5();
 ircd_register_crypt_plain(); /* yes I know it's slightly pointless */

return;
}

crypt_mechs_t* hunt_mech(const char* mechname)
{
crypt_mechs_t* mech;

 assert(NULL != mechname);

 if(crypt_mechs_root == NULL)
  return NULL;

 mech = crypt_mechs_root->next;

 for(;;)
 {
  if(mech == NULL)
   return NULL;

  if(0 == (ircd_strcmp(mech->mech->mechname, mechname)))
   return mech;

  mech = mech->next;
 }
}

char* crypt_pass(const char* pw, const char* mech)
{
crypt_mechs_t* crypt_mech;
char* salt, *untagged, *tagged;

 assert(NULL != pw);
 assert(NULL != mech);

 Debug((DEBUG_DEBUG, "pw = %s\n", pw));
 Debug((DEBUG_DEBUG, "mech = %s\n", mech));

 if (NULL == (crypt_mech = hunt_mech(mech)))
 {
  printf("Unable to find mechanism %s\n", mech);
  return NULL;
 }

 salt = make_salt(default_salts);

 untagged = (char *)CryptFunc(crypt_mech->mech)(pw, salt);
 tagged = (char *)MyMalloc(strlen(untagged)+CryptTokSize(crypt_mech->mech)+1);
 memset(tagged, 0, strlen(untagged)+CryptTokSize(crypt_mech->mech)+1);
 strncpy(tagged, CryptTok(crypt_mech->mech), CryptTokSize(crypt_mech->mech));
 strncpy(tagged+CryptTokSize(crypt_mech->mech), untagged, strlen(untagged));

return tagged;
}

char* parse_arguments(int argc, char **argv)
{
int len = 0, c = 0;
const char* options = "a:d:lm:u:y:5";

 umkpasswd_conf = (umkpasswd_conf_t*)MyMalloc(sizeof(umkpasswd_conf_t));

 umkpasswd_conf->flags = 0;
 umkpasswd_conf->debuglevel = 0;
 umkpasswd_conf->operclass = 0;
 umkpasswd_conf->user = NULL;
 umkpasswd_conf->mech = NULL;


 len = strlen(DPATH) + strlen(CPATH) + 2;
 umkpasswd_conf->conf = (char *)MyMalloc(len*sizeof(char));
 memset(umkpasswd_conf->conf, 0, len*sizeof(char));
 ircd_strncpy(umkpasswd_conf->conf, DPATH, strlen(DPATH));
 *((umkpasswd_conf->conf) + strlen(DPATH)) = '/';
 ircd_strncpy((umkpasswd_conf->conf) + strlen(DPATH) + 1, CPATH, strlen(CPATH));

 len = 0;

 while ((EOF != (c = getopt(argc, argv, options))) && !len)
 {
  switch (c)
  {
   case '5':
   {
    char t1[1024];
    while (fgets(t1, sizeof(t1), stdin)) sum(t1);
   }
   exit(0);

   case 'y':
    umkpasswd_conf->operclass = atoi(optarg);
    if (umkpasswd_conf->operclass < 0)
     umkpasswd_conf->operclass = 0;
   break;

   case 'u':
    if(umkpasswd_conf->flags & ACT_ADDOPER)
    {
     fprintf(stderr, "-a and -u are mutually exclusive.  Use either or neither.\n");
     abort(); /* b0rk b0rk b0rk */
    }

    umkpasswd_conf->flags |= ACT_UPDOPER;
    umkpasswd_conf->user = optarg;
   break;

   case 'm':
    umkpasswd_conf->mech = optarg;
   break;

   case 'l':
    load_mechs();
    show_mechs();
    exit(0);
   break;

   case 'd':
    umkpasswd_conf->debuglevel = atoi(optarg);
    if (umkpasswd_conf->debuglevel < 0)
     umkpasswd_conf->debuglevel = 0;
   break;

   case 'c':
    umkpasswd_conf->conf = optarg;
   break;

   case 'a':
    if(umkpasswd_conf->flags & ACT_UPDOPER) 
    {
     fprintf(stderr, "-a and -u are mutually exclusive.  Use either or neither.\n");
     abort(); /* b0rk b0rk b0rk */
    }

    umkpasswd_conf->flags |= ACT_ADDOPER;
    umkpasswd_conf->user = optarg;
   break;

   default:
    /* unknown option - spit out syntax and b0rk */
    show_help();
    exit(1);
   break;
  }
 }

 Debug((DEBUG_DEBUG, "flags = %d", umkpasswd_conf->flags));
 Debug((DEBUG_DEBUG, "operclass = %d", umkpasswd_conf->operclass));
 Debug((DEBUG_DEBUG, "debug = %d", umkpasswd_conf->debuglevel));

 if (NULL != umkpasswd_conf->mech)
  Debug((DEBUG_DEBUG, "mech = %s", umkpasswd_conf->mech));
 else
  Debug((DEBUG_DEBUG, "mech is unset"));

 if (NULL != umkpasswd_conf->conf)
  Debug((DEBUG_DEBUG, "conf = %s", umkpasswd_conf->conf));
 else
  Debug((DEBUG_DEBUG, "conf is unset"));

 if (NULL != umkpasswd_conf->user)
  Debug((DEBUG_DEBUG, "user = %s", umkpasswd_conf->user));
 else
  Debug((DEBUG_DEBUG, "user is unset"));

/* anything left over should be password */
return argv[optind];
}

int main(int argc, char **argv)
{
char* pw, *crypted_pw;

 crypt_mechs_root = (crypt_mechs_t*)MyMalloc(sizeof(crypt_mechs_t));
 crypt_mechs_root->mech = NULL;
 crypt_mechs_root->next = crypt_mechs_root->prev = NULL;

 if (argc < 2)
 {
  show_help();
  exit(0);
 }

 pw = parse_arguments(argc, argv);
 load_mechs();

 if (NULL == umkpasswd_conf->mech)
 {
  fprintf(stderr, "No mechanism specified.\n");
  abort();
 }

 if (NULL == pw)
 {
  pw = getpass("Password: ");
 }
 crypted_pw = crypt_pass(pw, umkpasswd_conf->mech);

 printf("Crypted Pass: %s\n", crypted_pw);
 memset(pw, 0, strlen(pw));

return 0;
}
