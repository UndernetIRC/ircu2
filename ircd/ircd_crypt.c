/*
 * IRC - Internet Relay Chat, ircd/ircd_crypt.c
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
 */

/**
 * @file
 * @brief Core password encryption routines.
 * @version $Id$
 * 
 * This is a new look crypto API for ircu, it can handle different
 * password formats by the grace of magic tokens at the beginning of the 
 * password e.g. $SMD5 for Salted MD5, $CRYPT for native crypt(), etc.
 *
 * Currently crypt routines are implemented for: the native crypt() 
 * function, Salted MD5 and a plain text mechanism which should only
 * be used for testing.  I intend to add Blowfish, 3DES and possibly
 * SHA1 support as well at some point, but I'll need to check the
 * possible problems that'll cause with stupid crypto laws.
 *
 * It's also designed to be "ready" for the modularisation of ircu, so 
 * someone get round to doing it, because I'm not doing it ;)
 * 
 * The plan for Stage B is to semi-modularise the authentication
 * mechanism to allow authentication against some other sources than 
 * the conf file (whatever takes someones fancy, kerberos, ldap, sql, etc).
 *
 *                   -- blessed be, hikari.
 */

#include "config.h"
#include "ircd_crypt.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "s_debug.h"

/* while we're not modular, we need their init functions */
#include "ircd_crypt_native.h"
#include "ircd_crypt_plain.h"
#include "ircd_crypt_smd5.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <unistd.h>
#include <string.h>

/* evil global */
crypt_mechs_t* crypt_mechs_root;

/** Add a crypt mechanism to the list 
 * @param mechanism Pointer to the mechanism details struct
 * @return 0 on success, anything else on fail.
 * 
 * This routine registers a new crypt mechanism in the loaded mechanisms list, 
 * making it availabe for comparing passwords.
*/
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

/** Remove a crypt mechanism from the list 
 * @param mechanism Pointer to the mechanism we want to remove
 * @return 0 on success, anything else on fail.
*/
int ircd_crypt_unregister_mech(crypt_mech_t* mechanism)
{

return 0;
}

/** Wrapper for generating a hashed password passed on the supplied password
 * @param key Pointer to the password we want crypted
 * @param salt Pointer to the password we're comparing to (for the salt)
 * @return Pointer to the generated password (must be MyFree()'d).
 *
 * This is a wrapper function which attempts to establish the password
 * format and funnel it off to the correct mechanism handler function.  The
 * returned password is compared in the oper_password_match() routine.
*/
char* ircd_crypt(const char* key, const char* salt)
{
char *hashed_pass = NULL;
const char *temp_hashed_pass, *mysalt;
crypt_mechs_t* crypt_mech;

 assert(NULL != key);
 assert(NULL != salt);

 Debug((DEBUG_DEBUG, "ircd_crypt: key is %s", key));
 Debug((DEBUG_DEBUG, "ircd_crypt: salt is %s", salt));

 crypt_mech = crypt_mechs_root->next;

 /* by examining the first n characters of a password string we
  * can discover what kind of password it is.  hopefully. */
 for (;crypt_mech;)
 {
  if (strlen(salt) < crypt_mech->mech->crypt_token_size)
  {
   /* try the next mechanism instead */
   Debug((DEBUG_DEBUG, "ircd_crypt: salt is too short, will try next mech at 0x%X", crypt_mech->next));
   crypt_mech = crypt_mech->next;
   continue;
  }

  Debug((DEBUG_DEBUG, "ircd_crypt: comparing %s with %s", 
   salt, crypt_mech->mech->crypt_token));

  if(0 == ircd_strncmp(crypt_mech->mech->crypt_token, salt, crypt_mech->mech->crypt_token_size))
  {
   Debug((DEBUG_DEBUG, "ircd_crypt: type is %s", 
    crypt_mech->mech->shortname));

   /* before we send this all off to the crypt_function, we need to remove
      the tag from it */

   /* make sure we won't end up with a password comprised entirely of 
      a single \0 */
   if(strlen(salt) < crypt_mech->mech->crypt_token_size + 1)
    return NULL;

   mysalt = salt + crypt_mech->mech->crypt_token_size;

   if(NULL == (temp_hashed_pass = crypt_mech->mech->crypt_function(key, mysalt)))
    return NULL;

   Debug((DEBUG_DEBUG, "ircd_crypt: untagged pass is %s", temp_hashed_pass));

   /* ok, now we need to prefix the password we just got back
      with the right tag */
   if(NULL == (hashed_pass = (char *)MyMalloc(sizeof(char)*strlen(temp_hashed_pass) + crypt_mech->mech->crypt_token_size + 1)))
   {
    Debug((DEBUG_MALLOC, "ircd_crypt: unable to allocate memory for temp_hashed_pass"));
    return NULL;
   }
   memset(hashed_pass, 0, sizeof(char)*strlen(temp_hashed_pass)
    +crypt_mech->mech->crypt_token_size + 1);
   ircd_strncpy(hashed_pass, crypt_mech->mech->crypt_token, 
    crypt_mech->mech->crypt_token_size);
   ircd_strncpy(hashed_pass + crypt_mech->mech->crypt_token_size, temp_hashed_pass, strlen(temp_hashed_pass));
   Debug((DEBUG_DEBUG, "ircd_crypt: tagged pass is %s", hashed_pass));
  } else {
   Debug((DEBUG_DEBUG, "ircd_crypt: will try next mechanism at 0x%X", 
    crypt_mech->next));
   crypt_mech = crypt_mech->next;
   continue;
  }
  return hashed_pass;
 }

 /* try to use native crypt for an old-style (untagged) password */
 if (strlen(salt) > 2)
 {
   char *s;
   temp_hashed_pass = (char*)ircd_crypt_native(key, salt);
   if (!ircd_strcmp(temp_hashed_pass, salt))
   {
     DupString(s, temp_hashed_pass);
     return s;
   }
 }

 return NULL;
}

/** Some basic init.
 * This function loads initalises the crypt mechanisms linked list and 
 * currently loads the default mechanisms (Salted MD5, Crypt() and PLAIN).  
 * The last step is only needed while ircu is not properly modular.
 *  
 * When ircu is modular this will be the entry function for the ircd_crypt
 * module.
 * 
*/
void ircd_crypt_init(void)
{

 if((crypt_mechs_root = MyMalloc(sizeof(crypt_mechs_t))) == NULL)
 {
  /* awooga - can't allocate memory for the root structure */
  Debug((DEBUG_MALLOC, "init_crypt: Could not allocate memory for crypt_mechs_root"));
  return;
 }

 crypt_mechs_root->mech = NULL;
 crypt_mechs_root->next = crypt_mechs_root->prev = NULL;

/* temporary kludge until we're modular.  manually call the
   register functions for crypt mechanisms */
 ircd_register_crypt_smd5();
 ircd_register_crypt_plain();
 ircd_register_crypt_native();

return;
}
