/*
 * IRC - Internet Relay Chat, include/patchlevel.h
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
 *
 */
 
/*
 * I choose NDEBUG - No production server should have it on (and if they do
 * I don't think they'd last long), however people that are testing development
 * versions /should/ have it on.  If you want to comment this out fine, it's
 * just to prevent accidently running the wrong code
 */
#ifdef NDEBUG
#error This version of ircu is development only.  Please wait until it's
#error released
#endif

#define PATCHLEVEL "pl11"

#define RELEASE ".10."

/*
 * Deliberate empty lines
 */

/* Do NOT edit those: */

#ifndef BASE_VERSION
#define BASE_VERSION "u2.10"
#endif

#ifndef MAJOR_PROTOCOL
#define MAJOR_PROTOCOL "10"
#endif
