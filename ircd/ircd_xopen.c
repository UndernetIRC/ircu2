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
 *
 * $Id$
 */
#include "config.h"

#define _XOPEN_SOURCE
#define _XOPEN_VERSION 4
#include "ircd_xopen.h"

#include <assert.h>
#include <unistd.h>

const char* ircd_crypt(const char* key, const char* salt)
{
  assert(0 != key);
  assert(0 != salt);
  return crypt(key, salt);
}

