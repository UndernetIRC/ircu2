/*
 * IRC - Internet Relay Chat, include/mode-compat.h
 * Copyright (C) 2008 Kevin L. Mitchell
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/** @file
 * @brief Temporary structures and functions for handling mode compatibility.
 * @version $Id$
 */
#ifndef INCLUDED_mode_compat_h
#define INCLUDED_mode_compat_h
#ifndef INCLUDED_mode_h
#include "mode.h"
#endif

/** Known channel modes.  Note that this must be the same order as
 * _cmodes[]!
 */
enum ChanModes {
  _CMODE_CHANOP,	/**< Channel operator (+o) */
  _CMODE_VOICE,		/**< Has voice (+v) */
  _CMODE_PRIVATE,	/**< Channel is private (+p) */
  _CMODE_SECRET,	/**< Channel is secret (+s) */
  _CMODE_MODERATED,	/**< Channel is moderated (+m) */
  _CMODE_TOPICLIMIT,	/**< Topic control limited (+t) */
  _CMODE_INVITEONLY,	/**< Invite-only channel (+i) */
  _CMODE_NOPRIVMSGS,	/**< No external private messages (+n) */
  _CMODE_KEY,		/**< Channel key (+k) */
  _CMODE_BAN,		/**< Channel ban (+b) */
  _CMODE_LIMIT,		/**< Channel limit (+l) */
  _CMODE_REGONLY,	/**< Only +r users may join (+r) */
  _CMODE_DELJOINS,	/**< Join messages delayed (+D) */
  _CMODE_REGISTERED,	/**< Channel is registered (+R) */
  _CMODE_UPASS,		/**< Channel user pass (+U) */
  _CMODE_APASS,		/**< Channel admin pass (+A) */
  _CMODE_WASDELJOINS	/**< Channel has delayed joins (+d) */
};

/** Channel operator (+o). */
#define CMODE_CHANOP		(&_cmodes[_CMODE_CHANOP])
/** Has voice (+v). */
#define CMODE_VOICE		(&_cmodes[_CMODE_VOICE])
/** Channel is private (+p). */
#define CMODE_PRIVATE		(&_cmodes[_CMODE_PRIVATE])
/** Channel is secret (+s). */
#define CMODE_SECRET		(&_cmodes[_CMODE_SECRET])
/** Channel is moderated (+m). */
#define CMODE_MODERATED		(&_cmodes[_CMODE_MODERATED])
/** Topic control limited (+t). */
#define CMODE_TOPICLIMIT	(&_cmodes[_CMODE_TOPICLIMIT])
/** Invite-only channel (+i). */
#define CMODE_INVITEONLY	(&_cmodes[_CMODE_INVITEONLY])
/** No external private messages (+n). */
#define CMODE_NOPRIVMSGS	(&_cmodes[_CMODE_NOPRIVMSGS])
/** Channel key (+k). */
#define CMODE_KEY		(&_cmodes[_CMODE_KEY])
/** Channel ban (+b). */
#define CMODE_BAN		(&_cmodes[_CMODE_BAN])
/** Channel limit (+l). */
#define CMODE_LIMIT		(&_cmodes[_CMODE_LIMIT])
/** Only +r users may join (+r). */
#define CMODE_REGONLY		(&_cmodes[_CMODE_REGONLY])
/** Join messages delayed (+D). */
#define CMODE_DELJOINS		(&_cmodes[_CMODE_DELJOINS])
/** Channel is registered (+R). */
#define CMODE_REGISTERED	(&_cmodes[_CMODE_REGISTERED])
/** Channel user pass (+U). */
#define CMODE_UPASS		(&_cmodes[_CMODE_UPASS])
/** Channel admin pass (+A). */
#define CMODE_APASS		(&_cmodes[_CMODE_APASS])
/** Channel has delayed joins (+d). */
#define CMODE_WASDELJOINS	(&_cmodes[_CMODE_WASDELJOINS])

/** Known user modes.  Note that this must be the same order as
 * _umodes[]!
 */
enum UserModes {
  _UMODE_LOCOP,		/**< Local IRC operator (+O) */
  _UMODE_OPER,		/**< Global IRC operator (+o) */
  _UMODE_SERVNOTICE,	/**< Receive server notices (+s) */
  _UMODE_INVISIBLE,	/**< User invisible (+i) */
  _UMODE_WALLOP,	/**< User receives /WALLOPS (+w) */
  _UMODE_DEAF,		/**< User is deaf (+d) */
  _UMODE_CHSERV,	/**< User is a channel service (+k) */
  _UMODE_DEBUG,		/**< User receives debug messages (+g) */
  _UMODE_ACCOUNT,	/**< User is logged in (+r) */
  _UMODE_HIDDENHOST	/**< User's host is hidden (+x) */
};

/** Local IRC operator (+O). */
#define UMODE_LOCOP		(&_umodes[_UMODE_LOCOP])
/** Global IRC operator (+o). */
#define UMODE_OPER		(&_umodes[_UMODE_OPER])
/** Receive server notices (+s). */
#define UMODE_SERVNOTICE	(&_umodes[_UMODE_SERVNOTICE])
/** User invisible (+i). */
#define UMODE_INVISIBLE		(&_umodes[_UMODE_INVISIBLE])
/** User receives /WALLOPS (+w). */
#define UMODE_WALLOP		(&_umodes[_UMODE_WALLOP])
/** User is deaf (+d). */
#define UMODE_DEAF		(&_umodes[_UMODE_DEAF])
/** User is a channel service (+k). */
#define UMODE_CHSERV		(&_umodes[_UMODE_CHSERV])
/** User receives debug messages (+g). */
#define UMODE_DEBUG		(&_umodes[_UMODE_DEBUG])
/** User is logged in (+r). */
#define UMODE_ACCOUNT		(&_umodes[_UMODE_ACCOUNT])
/** User's host is hidden (+x). */
#define UMODE_HIDDENHOST	(&_umodes[_UMODE_HIDDENHOST])

/** Known server modes.  Note that this must be the same order as
 * _smodes[]!
 */
enum ServModes {
  _SMODE_HUB,		/**< Server is a hub (+h) */
  _SMODE_SERVICE,	/**< Server is a service (+s) */
  _SMODE_IPV6		/**< Server supports IPv6 (+6) */
};

/** Server is a hub (+h). */
#define SMODE_HUB		(&_umodes[_SMODE_HUB])
/** Server is a service (+s). */
#define SMODE_SERVICE		(&_umodes[_SMODE_SERVICE])
/** Server supports IPv6 (+6). */
#define SMODE_IPV6		(&_umodes[_SMODE_IPV6])

/* Arrays of mode descriptors. */
extern modedesc_t _cmodes[];
extern modedesc_t _umodes[];
extern modedesc_t _smodes[];

/* Mode list descriptors. */
extern modelist_t chanmodes;
extern modelist_t usermodes;
extern modelist_t servmodes;

/* Initialize mode compatibility layer. */
extern void mode_compat_init(void);

#endif /* INCLUDED_mode_compat_h */
