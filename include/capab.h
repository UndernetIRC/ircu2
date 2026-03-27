#ifndef INCLUDED_capab_h
#define INCLUDED_capab_h
/*
 * IRC - Internet Relay Chat, include/capab.h
 * Copyright (C) 2004 Kevin L. Mitchell <klmitch@mit.edu>
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
 * @brief Interface and public definitions for capabilities extension
 * @version $Id$
 */

#ifndef INCLUDED_client_h
#include "client.h"
#endif

#ifndef INCLUDED_ircd_features_h
#include "ircd_features.h"
#endif

#define CAPFL_HIDDEN    	0x0001	/**< Do not advertize this capability */
#define CAPFL_HIDDEN_302   	0x0002	/**< Do not advertize this capability to users supporting LS 302 */
#define CAPFL_PROHIBIT  	0x0004	/**< Client may not set this capability */
#define CAPFL_PROTO    		0x0008	/**< Cap must be acknowledged by client */
#define CAPFL_STICKY		0x0010	/**< Cap may not be cleared once set */
#define CAPFL_STICKY_302   	0x0020  /**< Cap may not be cleared once set by users supporting LS 302 */
#define CAPFL_UNAVAILABLE 	(CAPFL_HIDDEN | CAPFL_PROHIBIT)

#define CAPLIST	\
	_CAP(ACCOUNTNOTIFY, FEAT_CAP_ACCOUNTNOTIFY, 0, "account-notify"), \
	_CAP(AWAYNOTIFY, FEAT_CAP_AWAYNOTIFY, 0 , "away-notify"), \
	_CAP(CHGHOST, FEAT_CAP_CHGHOST, 0, "chghost"), \
	_CAP(ECHOMESSAGE, FEAT_CAP_ECHOMESSAGE, 0, "echo-message"), \
	_CAP(EXTJOIN, FEAT_CAP_EXTJOIN, 0, "extended-join"), \
	_CAP(INVITENOTIFY, FEAT_CAP_INVITENOTIFY, 0, "invite-notify"), \
	_CAP(UHNAMES, FEAT_CAP_UHNAMES, 0, "userhost-in-names"), \
	_CAP(CAPNOTIFY, 0, CAPFL_HIDDEN_302 | CAPFL_STICKY_302, "cap-notify"), \
	_CAP(SASL, FEAT_CAP_SASL, CAPFL_UNAVAILABLE, "sasl")

/** Client capabilities, counting by index. */
enum Capab {
#define _CAP(cap, config, flags, name)	E_CAP_ ## cap
  CAPLIST,
#undef _CAP
  _E_CAP_LAST_CAP
};

/** Client capabilities, bit mask version. */
enum CapabBits {
#define _CAP(cap, config, flags, name) CAP_ ## cap = 1u << E_CAP_ ## cap
  CAPLIST,
#undef _CAP
  _CAP_LAST_CAP = 1u << _E_CAP_LAST_CAP
};

#define CapHas(cs, cap)	(cs & cap)
#define CapSet(cs, cap)	(cs |= cap)
#define CapClr(cs, cap)	(cs &= ~cap)

/** Set capability value dynamically */
void cap_set_value(enum Capab cap, const char *value);

/** Update capability availability and send CAP NEW/DEL as needed */
void cap_update_availability(enum Capab cap, int available);

/** Send CAP NEW to clients with cap-notify capability */
void cap_new(enum Capab cap);

/** Send CAP DEL to clients with cap-notify capability */
void cap_del(enum Capab cap);

#endif /* INCLUDED_capab_h */
