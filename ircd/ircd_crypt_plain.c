/*
 * IRC - Internet Relay Chat, ircd/ircd_crypt_plain.c
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
 * @brief Routines for PLAIN passwords.
 * @version $Id$
 * 
 * PLAIN text encryption.  Oxymoron and a half that.
 */
#include "config.h"
#include "ircd_crypt.h"
#include "ircd_crypt_plain.h"
#include "ircd_log.h"
#include "s_debug.h"
#include "ircd_alloc.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <unistd.h>

/** Just sends back the supplied password.
 * @param key The password
 * @param salt The salt
 * @return The password
 * 
 * Yes I know it's an oxymoron, but still, it's handy for testing.
 * 
 * What you need more help with seeing what this does?
 * 
 */
const char* ircd_crypt_plain(const char* key, const char* salt)
{
  assert(NULL != salt);
  assert(NULL != key);

 Debug((DEBUG_DEBUG, "ircd_crypt_plain: key is %s", key));
 Debug((DEBUG_DEBUG, "ircd_crypt_plain: salt is %s", salt));

  /* yes, that's it.  we just send key back out again, 
     pointless I know */
  return key;
}

/** register ourself with the list of crypt mechanisms 
 * Registers the PLAIN mechanism in the list of available crypt mechanisms.  
 * When we're modular this will be the entry function for the module.
 * 
 * -- hikari */
void ircd_register_crypt_plain(void)
{
crypt_mech_t* crypt_mech;

 if ((crypt_mech = (crypt_mech_t*)MyMalloc(sizeof(crypt_mech_t))) == NULL)
 {
  Debug((DEBUG_MALLOC, "Could not allocate space for crypt_plain"));
  return;
 }

 crypt_mech->mechname = "plain";
 crypt_mech->shortname = "crypt_plain";
 crypt_mech->description = "Plain text \"crypt\" mechanism.";
 crypt_mech->crypt_function = &ircd_crypt_plain;
 crypt_mech->crypt_token = "$PLAIN$";
 crypt_mech->crypt_token_size = 7;

 ircd_crypt_register_mech(crypt_mech);
 
return;
}
