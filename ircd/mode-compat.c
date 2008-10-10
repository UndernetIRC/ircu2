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

#include "ircd_features.h"
#include "mode-compat.h"
#include "mode.h"
#include "register.h"

/** Compute the number of entries in a mode_desc_t array. */
#define mdcount(arr)		(sizeof(arr) / sizeof(mode_desc_t))

/** Initial list of channel modes.  Note that this must be the same
 * order as enum ChanModes!
 */
mode_desc_t _cmodes[] = {
  MODE_DESC_PFX("CHANOP",	'o', "Channel operator.",
		MDPAR_ARG_CLI | MDPAR_TYPE_REQARG | MDPOL_AUTHZ_CHOP |
		MDFLAG_LIST, '@', 15),
  MODE_DESC_PFX("VOICE",	'v', "Has voice.",
		MDPAR_ARG_CLI | MDPAR_TYPE_REQARG | MDPOL_AUTHZ_CHOP |
		MDFLAG_LIST, '+', 0),
  MODE_DESC("PRIVATE",		'p', "Channel is private.",
	    MDPOL_AUTHZ_CHOP),
  MODE_DESC("SECRET",		's', "Channel is secret.",
	    MDPOL_AUTHZ_CHOP),
  MODE_DESC("MODERATED",	'm', "Channel is moderated.",
	    MDPOL_AUTHZ_CHOP),
  MODE_DESC("TOPICLIMIT",	't', "Topic control limited.",
	    MDPOL_AUTHZ_CHOP),
  MODE_DESC("INVITEONLY",	'i', "Invite-only channel.",
	    MDPOL_AUTHZ_CHOP),
  MODE_DESC("NOPRIVMSGS",	'n', "No external private messages.",
	    MDPOL_AUTHZ_CHOP),
  MODE_DESC("KEY",		'k', "Channel key.",
	    MDPAR_ARG_STR | MDPAR_TYPE_REQARG | MDPOL_AUTHZ_CHOP |
	    MDFLAG_VIS_CHOP | MDFLAG_ONESHOT),
  MODE_DESC("BAN",		'b', "Channel ban.",
	    MDPAR_ARG_STR | MDPAR_TYPE_REQARG | MDPOL_AUTHZ_CHOP |
	    MDFLAG_LIST),
  MODE_DESC("LIMIT",		'l', "Channel limit.",
	    MDPAR_ARG_INT | MDPAR_TYPE_ADDARG | MDPOL_AUTHZ_CHOP |
	    MDFLAG_ONESHOT),
  MODE_DESC("REGONLY",		'r', "Only +r users may join.",
	    MDPOL_AUTHZ_CHOP),
  MODE_DESC("DELJOINS",		'D', "Join messages delayed.",
	    MDPOL_AUTHZ_CHOP),
  MODE_DESC("REGISTERED",	'R', "Channel is registered.",
	    MDPOL_AUTHZ_SERV),
  MODE_DESC_FEAT("UPASS",	'U', "Channel user pass.",
		 MDPAR_ARG_STR | MDPAR_TYPE_REQARG | MDPOL_AUTHZ_CHOP |
		 MDFLAG_VIS_CHOP | MDFLAG_ONESHOT, FEAT_OPLEVELS),
  MODE_DESC_FEAT("APASS",	'A', "Channel admin pass.",
		 MDPAR_ARG_STR | MDPAR_TYPE_REQARG | MDPOL_AUTHZ_CHOP |
		 MDFLAG_VIS_CHOP | MDFLAG_ONESHOT, FEAT_OPLEVELS),
  MODE_DESC("WASDELJOINS",	'd', "Channel has delayed joins.",
	    MDPOL_AUTHZ_NONE)
};

/** Initial list of user modes.  Note that this must be the same order
 * as enum UserModes!
 */
mode_desc_t _umodes[] = {
  MODE_DESC("LOCOP",		'O', "Local IRC operator.",
	    MDPOL_AUTHZ_OPER),
  MODE_DESC("OPER",		'o', "Global IRC operator.",
	    MDPOL_AUTHZ_GOP),
  MODE_DESC("SERVNOTICE",	's', "Receive server notices.",
	    MDPAR_ARG_INT | MDPAR_TYPE_OPTARG | MDFLAG_HEXINT |
	    MDFLAG_LOCAL),
  MODE_DESC("INVISIBLE",	'i', "User invisible.",
	    0),
  MODE_DESC("WALLOP",		'w', "User receives /WALLOPS.",
	    0),
  MODE_DESC("DEAF",		'd', "User is deaf.",
	    0),
  MODE_DESC("CHSERV",		'k', "User is a channel service.",
	    MDPOL_AUTHZ_SERV),
  MODE_DESC("DEBUG",		'g', "User receives debug messages.",
	    0),
  MODE_DESC("ACCOUNT",		'r', "User is logged in.",
	    MDPAR_ARG_STR | MDPAR_TYPE_REQARG | MDPOL_AUTHZ_SERV |
	    MDFLAG_VIS_SERV),
  MODE_DESC("HIDDENHOST",	'x', "User's host is hidden.",
	    0)
};

/** Initial list of server modes.  Note that this must be the same
 * order as enum ServModes!
 */
mode_desc_t _smodes[] = {
  MODE_DESC("HUB",		'h', "Server is a hub.",
	    MDPOL_AUTHZ_SERV),
  MODE_DESC("SERVICE",		's', "Server is a service.",
	    MDPOL_AUTHZ_SERV),
  MODE_DESC("IPV6",		'6', "Server supports IPv6.",
	    MDPOL_AUTHZ_SERV)
};

/** Mode list for channels. */
mode_list_t chanmodes = MODE_LIST_INIT("channel", 0);

/** Mode list for users. */
mode_list_t usermodes = MODE_LIST_INIT("user", 0);

/** Mode list for servers. */
mode_list_t servmodes = MODE_LIST_INIT("server", 0);

/** Initialize the mode compatibility layer. */
void
mode_compat_init(void)
{
  /* Let's first register the mode lists... */
  reg(MODE_TABLE, &chanmodes);
  reg(MODE_TABLE, &usermodes);
  reg(MODE_TABLE, &servmodes);

  /* Now, let's register the mode descriptors. */
  regtab_n((regtab_t*) &chanmodes, _cmodes, mdcount(_cmodes),
	   sizeof(mode_desc_t));
  regtab_n((regtab_t*) &usermodes, _umodes, mdcount(_umodes),
	   sizeof(mode_desc_t));
  regtab_n((regtab_t*) &servmodes, _smodes, mdcount(_smodes),
	   sizeof(mode_desc_t));
}
