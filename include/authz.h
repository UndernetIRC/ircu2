/*
 * IRC - Internet Relay Chat, include/authz.h
 * Copyright (C) 2009 Kevin L. Mitchell
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * @brief Structures and functions for handling client authorization.
 * @version $Id$
 */
#ifndef INCLUDED_authz_h
#define INCLUDED_authz_h
#ifndef INCLUDED_client_h
#include "client.h"
#endif
#ifndef INCLUDED_stdarg_h
#include <stdarg.h>	/* va_list */
#define INCLUDED_stdarg_h
#endif

/** Describes an authorization check. */
typedef struct AuthZ authz_t;
/** Describes a set of authorization checks. */
typedef struct AuthZSet authzset_t;

/** Authorization check callback for authz().
 * @param[in] client Client for which authorization is being checked.
 * @param[in] flags Flags affecting the check.  In particular,
 * AUTHZ_NOMSG should inhibit sending messages to clients.
 * @param[in] authz Authorization to check.
 * @param[in] vl Optional extra parameters passed to authz().
 * @return AUTHZ_DENY to deny authorization, AUTHZ_PASS to continue
 * checking authorizations, or AUTHZ_GRANT to grant authorization.
 */
typedef unsigned int (*authz_check_t)(struct Client* client,
				      unsigned int flags,
				      authz_t* authz,
				      va_list vl);

/** Describes an authorization check. */
struct AuthZ {
  unsigned long	az_magic;	/**< Magic number */
  authz_check_t*az_check;	/**< Check callback */
  void*		az_e_ptr;	/**< Extra pointer data for use by az_check */
  unsigned int	az_e_int;	/**< Extra integer data for use by az_check */
};

/** Magic number for authz_t. */
#define AUTHZ_MAGIC		0x4bae2e0e

/** Initialize an authz_t.
 * @param[in] check Callback for checking authorization.
 * @param[in] e_ptr Extra pointer data for use by check.
 * @param[in] e_int Extra integer data for use by check.
 */
#define AUTHZ_INIT(check, e_ptr, e_int)		\
  { AUTHZ_MAGIC, (check), (e_ptr), (e_int) }

/** Check the authz_t magic number. */
#define AUTHZ_CHECK(az)		((az) && (az)->az_magic == AUTHZ_MAGIC)

/** Authorization denied. */
#define AUTHZ_DENY		0x0000
/** Pass on authorization check. */
#define AUTHZ_PASS		0x0001
/** Authorization granted. */
#define AUTHZ_GRANT		0x0002
/** Mask authorization return values. */
#define AUTHZ_MASK		0x0003

/** If set, indicates that a message has already been sent to the
 * client indicating the authorization failure.
 */
#define AUTHZ_MSGSENT		0x0010

/** Retrieve check function pointer.
 * @param[in] az Pointer to authz_t.
 * @return Pointer to authorization check function.
 */
#define az_check(az)		((az)->az_check)

/** Retrieve extra pointer data.
 * @param[in] az Pointer to authz_t.
 * @return Extra pointer data.
 */
#define az_e_ptr(az)		((az)->az_e_ptr)

/** Retrieve extra integer data.
 * @param[in] az Pointer to authz_t.
 * @return Extra integer data.
 */
#define az_e_int(az)		((az)->az_e_int)

/** Describes a set of authorization checks. */
struct AuthZSet {
  unsigned long	azs_magic;	/**< Magic number */
  unsigned int	azs_mode;	/**< Authorization mode */
  authz_t**	azs_set;	/**< NULL-terminated list of authz_t
				     pointers. */
};

/** Magic number for authzset_t. */
#define AUTHZSET_MAGIC		0x8a5ce114

/** Initialize an authzset_t.
 * @param[in] mode Set mode; can be one of AUTHZ_AND or AUTHZ_OR.
 * @param[in] set NULL-terminated array of authz_t pointers.
 */
#define AUTHZSET_INIT(mode, set)		\
  { AUTHZSET_MAGIC, (mode), (set) }

/** Check the authzset_t magic number. */
#define AUTHZSET_CHECK(azs)	((azs) && (azs)->azs_magic == AUTHZSET_MAGIC)

/** Authorization set is checked in short-circuiting AND mode--all
 * checks must return AUTHZ_GRANT or AUTHZ_PASS.  If all checks return
 * AUTHZ_PASS, authorization is denied.
 */
#define AUTHZ_AND	0x0000
/** Authorization set is checked in short-circuiting OR mode--the
 * first check that returns AUTHZ_GRANT causes authorization to be
 * granted.  If all checks return AUTHZ_PASS, authorization is
 * denied.  AUTHZ_DENY is ignored, except that it will force
 * authorization to be denied even if the AUTHZ_ACCEPT flag is set and
 * all other checks returned AUTHZ_PASS.
 */
#define AUTHZ_OR	0x0001

/** Mask for the mode. */
#define AUTHZ_MODEMASK	0x0003

/** If set on mode, changes the default authorization return to grant
 * authorization if all checks return with AUTHZ_PASS.
 */
#define AUTHZ_ACCEPT	0x0010

/** If set on flags, inhibits the sending of authorization denied
 * messages to the user.
 */
#define AUTHZ_NOMSG	0x8000

/** If set on flags, causes AUTHZ_PASS to be returned if all checks
 * returned AUTHZ_PASS.  This is used for chaining authorization sets.
 */
#define AUTHZ_PASSTHRU	0x4000

/** Check client authorization.
 * @param[in] client Client for which authorization is being checked.
 * @param[in] flags Flags affecting the check.  In particular,
 * AUTHZ_NOMSG should inhibit sending messages to clients.
 * @param[in] authz Authorization to check.
 * @return Boolean TRUE if authorization is granted, else FALSE.
 */
extern unsigned int authz(struct Client* client, unsigned int flags,
			  authzset_t* set, ...);

#endif /* INCLUDED_authz_h */
