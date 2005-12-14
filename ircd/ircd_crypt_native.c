/*
 * IRC - Internet Relay Chat, ircd/ircd_xopen.c
 * Copyright (C) 1990, 1991 Armin Gruner
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
/**
 * @file
 * @brief Native crypt() function routines
 * @version $Id$
 * 
 * Routines for handling passwords encrypted with the system's native crypt()
 * function (typically a DES encryption routine, but can be anything nowadays).
 * 
 */
#define _XOPEN_SOURCE 500

#include "config.h"
#include "ircd_crypt.h"
#include "ircd_crypt_native.h"
#include "ircd_log.h"
#include "s_debug.h"
#include "ircd_alloc.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <unistd.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

/** Simple routine that just calls crypt() with the supplied password and salt
 * @param key The password we're encrypting.
 * @param salt The salt we're using to encrypt key
 * @return The encrypted password.
 * 
 * Well this bit is (kinda) intact from the original oper password routines :) 
 * It's a very simple wrapper routine that just calls crypt and returns the 
 * result.
 *   -- hikari
 */
const char* ircd_crypt_native(const char* key, const char* salt)
{
 assert(NULL != key);
 assert(NULL != salt);

 Debug((DEBUG_DEBUG, "ircd_crypt_native: key is %s", key));
 Debug((DEBUG_DEBUG, "ircd_crypt_native: salt is %s", salt));

 return (const char*)crypt(key, salt);
}

/* register ourself with the list of crypt mechanisms -- hikari */
void ircd_register_crypt_native(void)
{
crypt_mech_t* crypt_mech;

 if ((crypt_mech = (crypt_mech_t*)MyMalloc(sizeof(crypt_mech_t))) == NULL)
 {
  Debug((DEBUG_MALLOC, "Could not allocate space for crypt_native"));
  return;
 }

 crypt_mech->mechname = "native";
 crypt_mech->shortname = "crypt_native";
 crypt_mech->description = "System native crypt() function mechanism.";
 crypt_mech->crypt_function = &ircd_crypt_native;
 crypt_mech->crypt_token = "$CRYPT$";
 crypt_mech->crypt_token_size = 7;

 ircd_crypt_register_mech(crypt_mech);
 
return;
}
