/*
 * IRC - Internet Relay Chat, include/ircd_crypt_plain.h
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
 */
/** @file
 * @brief Declarations for plaintext password "crypting".
 * @version $Id$
 */
#ifndef INCLUDED_ircd_crypt_plain_h
#define INCLUDED_ircd_crypt_plain_h

extern const char* ircd_crypt_plain(const char* key, const char* salt);
extern void ircd_register_crypt_plain(void);


#endif /* INCLUDED_ircd_crypt_plain_h */

