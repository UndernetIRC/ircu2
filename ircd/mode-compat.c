/*
 * IRC - Internet Relay Chat, include/mode-compat.c
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
#include "config.h"

#include "mode-compat.h"
#include "mode.h"

/** Initial list of channel modes.  Note that this must be the same
 * order as enum ChanModes!
 */
modedesc_t _cmodes[] = {
  MODE_DESC_INIT("CHANOP",	'o', "Channel operator.",
		 MDPAR_ARG_CLI | MDPAR_TYPE_REQARG | MDPOL_AUTHZ_CHOP,
		 '@', 15),
  MODE_DESC_INIT("VOICE",	'v', "Has voice.",
		 MDPAR_ARG_CLI | MDPAR_TYPE_REQARG | MDPOL_AUTHZ_CHOP,
		 '+', 0),
  MODE_DESC_INIT("PRIVATE",	'p', "Channel is private.",
		 MDPOL_AUTHZ_CHOP, 0, 0),
  MODE_DESC_INIT("SECRET",	's', "Channel is secret.",
		 MDPOL_AUTHZ_CHOP, 0, 0),
  MODE_DESC_INIT("MODERATED",	'm', "Channel is moderated.",
		 MDPOL_AUTHZ_CHOP, 0, 0),
  MODE_DESC_INIT("TOPICLIMIT",	't', "Topic control limited.",
		 MDPOL_AUTHZ_CHOP, 0, 0),
  MODE_DESC_INIT("INVITEONLY",	'i', "Invite-only channel.",
		 MDPOL_AUTHZ_CHOP, 0, 0),
  MODE_DESC_INIT("NOPRIVMSGS",	'n', "No external private messages.",
		 MDPOL_AUTHZ_CHOP, 0, 0),
  MODE_DESC_INIT("KEY",		'k', "Channel key.",
		 MDPAR_ARG_STR | MDPAR_TYPE_REQARG | MDPOL_AUTHZ_CHOP |
		 MDFLAG_VIS_CHOP | MDFLAG_ONESHOT, 0, 0),
  MODE_DESC_INIT("BAN",		'b', "Channel ban.",
		 MDPAR_ARG_STR | MDPAR_TYPE_REQARG | MDPOL_AUTHZ_CHOP |
		 MDFLAG_LIST, 0, 0),
  MODE_DESC_INIT("LIMIT",	'l', "Channel limit.",
		 MDPAR_ARG_INT | MDPAR_TYPE_ADDARG | MDPOL_AUTHZ_CHOP |
		 MDFLAG_ONESHOT, 0, 0),
  MODE_DESC_INIT("REGONLY",	'r', "Only +r users may join.",
		 MDPOL_AUTHZ_CHOP, 0, 0),
  MODE_DESC_INIT("DELJOINS",	'D', "Join messages delayed.",
		 MDPOL_AUTHZ_CHOP, 0, 0),
  MODE_DESC_INIT("REGISTERED",	'R', "Channel is registered.",
		 MDPOL_AUTHZ_SERV, 0, 0),
  MODE_DESC_INIT("UPASS",	'U', "Channel user pass.",
		 MDPAR_ARG_STR | MDPAR_TYPE_REQARG | MDPOL_AUTHZ_CHOP |
		 MDFLAG_VIS_CHOP | MDFLAG_ONESHOT, 0, 0),
  MODE_DESC_INIT("APASS",	'A', "Channel admin pass.",
		 MDPAR_ARG_STR | MDPAR_TYPE_REQARG | MDPOL_AUTHZ_CHOP |
		 MDFLAG_VIS_CHOP | MDFLAG_ONESHOT, 0, 0),
  MODE_DESC_INIT("WASDELJOINS",	'd', "Channel has delayed joins.",
		 MDFLAG_AUTHZ_NONE, 0, 0)
};

/** Initial list of user modes.  Note that this must be the same order
 * as enum UserModes!
 */
modedesc_t _umodes[] = {
  MODE_DESC_INIT("LOCOP",	'O', "Local IRC operator.",
		 MDPOL_AUTHZ_OPER, 0, 0),
  MODE_DESC_INIT("OPER",	'o', "Global IRC operator.",
		 MDPOL_AUTHZ_GOP, 0, 0),
  MODE_DESC_INIT("SERVNOTICE",	's', "Receive server notices.",
		 MDPAR_ARG_INT | MDPAR_TYPE_OPTARG | MDFLAG_HEXINT |
		 MDFLAG_LOCAL, 0, 0),
  MODE_DESC_INIT("INVISIBLE",	'i', "User invisible.",
		 0, 0, 0),
  MODE_DESC_INIT("WALLOP",	'w', "User receives /WALLOPS.",
		 0, 0, 0),
  MODE_DESC_INIT("DEAF",	'd', "User is deaf.",
		 0, 0, 0),
  MODE_DESC_INIT("CHSERV",	'k', "User is a channel service.",
		 MDPOL_AUTHZ_SERV, 0, 0),
  MODE_DESC_INIT("DEBUG",	'g', "User receives debug messages.",
		 0, 0, 0),
  MODE_DESC_INIT("ACCOUNT",	'r', "User is logged in.",
		 MDPAR_ARG_STR | MDPAR_TYPE_REQARG | MDPOL_AUTHZ_SERV |
		 MDFLAG_VIS_SERV, 0, 0),
  MODE_DESC_INIT("HIDDENHOST",	'x', "User's host is hidden.",
		 0, 0, 0)
};

/** Initial list of server modes.  Note that this must be the same
 * order as enum ServModes!
 */
modedesc_t _smodes[] = {
  MODE_DESC_INIT("HUB",		'h', "Server is a hub.",
		 MDPOL_AUTHZ_SERV, 0, 0),
  MODE_DESC_INIT("SERVICE",	's', "Server is a service.",
		 MDPOL_AUTHZ_SERV, 0, 0),
  MODE_DESC_INIT("IPV6",	'6', "Server supports IPv6.",
		 MDPOL_AUTHZ_SERV, 0, 0)
};

/** Mode list for channels. */
modelist_t chanmodes = MODE_LIST_INIT("channel", 0);

/** Mode list for users. */
modelist_t usermodes = MODE_LIST_INIT("user", 0);

/** Mode list for servers. */
modelist_t servmodes = MODE_LIST_INIT("server", 0);

/** Initialize the mode compatibility layer. */
void
mode_compat_init(void)
{
}
