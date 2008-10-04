/*
 * IRC - Internet Relay Chat, include/mode.h
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
 * @brief Structures and functions for handling generic modes.
 * @version $Id$
 */
#ifndef INCLUDED_mode_h
#define INCLUDED_mode_h
#ifndef INCLUDED_register_h
#include "register.h"
#endif
#ifndef INCLUDED_flagset_h
#include "flagset.h"
#endif
#ifndef INCLUDED_keyspace_h
#include "keyspace.h"
#endif

struct Client;

/** Specifies the maximum number of modes permitted on any entity. */
#define MAX_MODES		64
/** Specifies the maximum number of mode params permitted in one message. */
#define MAX_MODEPARAMS		6

/** Registration table for mode lists. */
#define MODE_TABLE		"mode"

/** Specifies the numerical value of a mode switch. */
typedef key_t mode_t;

/** Describes a single mode, including parsing flags and policy flags. */
typedef struct ModeDesc mode_desc_t;
/** Describes a list of modes available for a channel, user, etc. */
typedef struct ModeList mode_list_t;
/** Describes the set of modes applicable to a specific channel, user, etc. */
typedef struct ModeSet mode_set_t;
/** Describes some modes with arguments. */
typedef struct ModeArgs mode_args_t;
/** Describes the difference between two sets of modes. */
typedef struct ModeDelta mode_delta_t;

/** Describes a single mode. */
struct ModeDesc {
  regent_t		md_regent;	/**< Registration entry. */
  int			md_switch;	/**< Mode switch (character). */
  int			md_prefix;	/**< Indicator prefix for mode. */
  mode_t		md_mode;	/**< Numerical value of mode. */
  const char*		md_desc;	/**< Textual description of mode. */
  flagpage_t		md_flags;	/**< Flags affecting mode. */
};

/** Magic number for a mode descriptor. */
#define MODE_DESC_MAGIC 0x54aacaed

/** Initialize a modedesc_t.
 * @param[in] name Descriptive name for the mode.
 * @param[in] sw "Switch" character for the mode.
 * @param[in] desc Description of the mode.
 * @param[in] flags Flags affecting the mode.
 * @param[in] pfx Prefix character used in /NAMES reply.
 * @param[in] prio Priority for ordering prefix characters; unused otherwise.
 */
#define MODE_DESC_INIT(name, sw, desc, flags, pfx, prio)		\
  { REGENT_INIT(MODE_DESC_MAGIC, (name)), (sw), (pfx), 0, (desc),	\
    (flags) | (((prio) & 0x0f) << 16) }

/** Check the mode descriptor for validity. */
#define MODE_DESC_CHECK(md)	REGENT_CHECK((md), MODE_DESC_MAGIC)

/** Mode maintains a list. */
#define MDFLAG_LIST		0x80000000
/** Mode should not be propagated to other servers. */
#define MDFLAG_LOCAL		0x40000000
/** Accept octal or hexadecimal integers, not just decimal. */
#define MDFLAG_HEXINT		0x20000000
/** Mode can only be set or reset once per message. */
#define MDFLAG_ONESHOT		0x10000000
/** Mode defaults to extended syntax. */
#define MDFLAG_ARGEXTENDED	0x08000000

/** Mask for prefix ordering priority. */
#define MDFLAG_PRIO		0x000f0000

/** Mode is visible to anyone. */
#define MDFLAG_VIS_OPEN		0x00000000
/** Mode is visible only to channel operators. */
#define MDFLAG_VIS_CHOP		0x00001000
/** Mode is visible only to IRC operators. */
#define MDFLAG_VIS_OPER		0x00002000
/** Mode is visible only to global IRC operators. */
#define MDFLAG_VIS_GOP		0x00003000
/** Mode is visible only to servers. */
#define MDFLAG_VIS_SERV		0x00004000
/** Mode visibility mask. */
#define MDFLAG_VIS_MASK		0x0000f000

/** Anyone can set or clear mode. */
#define MDPOL_AUTHZ_OPEN	0x00000000
/** Only channel operator can set or clear mode. */
#define MDPOL_AUTHZ_CHOP	0x00000100
/** Only IRC operators can set or clear mode. */
#define MDPOL_AUTHZ_OPER	0x00000200
/** Only global IRC operators can set or clear mode. */
#define MDPOL_AUTHZ_GOP		0x00000300
/** Only servers can set or clear mode. */
#define MDPOL_AUTHZ_SERV	0x00000400
/** No one can set or clear mode (mode under software control). */
#define MDPOL_AUTHZ_NONE	0x00000500
/** Mode authorization mask. */
#define MDPOL_AUTHZ_MASK	0x00000f00

/** Mode describes a simple switch, e.g., +t channel mode. */
#define MDPAR_TYPE_SWITCH	0x00000000
/** Mode takes an optional argument, e.g., +s user mode. */
#define MDPAR_TYPE_OPTARG	0x00000010
/** Mode takes an argument only when added, e.g., +l channel mode. */
#define MDPAR_TYPE_ADDARG	0x00000020
/** Mode takes a required argument, e.g., +k channel mode. */
#define MDPAR_TYPE_REQARG	0x00000030
/** Mode type mask. */
#define MDPAR_TYPE_MASK		0x000000f0

/** Mode takes no argument. */
#define MDPAR_ARG_NONE		0x00000000
/** Mode takes an integer argument, e.g., +l channel mode. */
#define MDPAR_ARG_INT		0x00000001
/** Mode takes a simple string argument, e.g., +k channel mode. */
#define MDPAR_ARG_STR		0x00000002
/** Mode takes an argument indicating a client, e.g., +o channel mode. */
#define MDPAR_ARG_CLI		0x00000003
/** Mode argument type mask. */
#define MDPAR_ARG_MASK		0x0000000f

/** Describes the list of modes available for a channel, user, etc. */
struct ModeList {
  regtab_t		ml_table;	/**< Registration table. */
  size_t		ml_offset;	/**< Offset of mode structure
					     within entity. */
  keyspace_t*		ml_keyspace;	/**< Keyspace for mode value
					     allocation. */
  mode_desc_t*		ml_smap[256];	/**< Mode switch map. */
  mode_desc_t*		ml_mmap[MAX_MODES];
					/**< Mode value map. */
};

/** Initialize a modelist_t.
 * @param[in] name Descriptive name for the mode list.
 * @param[in] offset Offset of modeset_t entry in entity structure.
 */
#define MODE_LIST_INIT(name, offset)					\
  { REGTAB_INIT((name), MODE_DESC_MAGIC, (reg_t) _mode_desc_reg,	\
		(unreg_t) _mode_desc_unreg), (offset),			\
    KEYSPACE_INIT(MAX_MODES, 0, 0, 0) }

/** Check the mode list for validity. */
#define MODE_LIST_CHECK(ml)	(REGTAB_CHECK(ml) &&			\
				 reg_magic(&(ml->ml_table)) == MODE_DESC_MAGIC)

/** Describes the set of modes set on a specific channel, user, etc. */
DECLARE_FLAGSET(ModeSet, MAX_MODES);

/** Direction not yet selected. */
#define MDIR_NONE		0x00000000
/** Adding modes. */
#define MDIR_ADD		0x00000001
/** Removing modes. */
#define MDIR_REM		0x00000002
/** Direction mask. */
#define MDIR_MASK		0x00000003

/** Contains a set of modes with arguments. */
struct ModeArgs {
  mode_args_t*		ma_next;	/**< Chain to next set of modes with
					     arguments. */
  mode_args_t*		ma_prev;	/**< Chain to previous set of modes
					     with arguments. */
  struct {
    mode_desc_t*	mam_mode;	/**< The mode. */
    mode_dir_t		mam_dir;	/**< Direction of mode. */
    union {
      unsigned int	mama_int;	/**< Unsigned integer argument. */
      const char*	mama_str;	/**< String argument (keys). */
      struct Client*	mama_cli;	/**< Client argument (chanops). */
    }			mam_arg;	/**< Argument for mode. */
    unsigned short	mam_oplevel;	/**< Oplevel for a bounce. */
  }			ma_modeargs[MAX_MODEPARAMS];
					/**< Modes with arguments. */
};

/** Describes the difference between two mode_set_t's. */
struct ModeDelta {
  struct Client*	md_origin;	/**< Origin of delta. */
  mode_list_t*		md_modes;	/**< Mode list used by this delta. */

  mode_set_t		md_add;		/**< Simple modes to be added. */
  mode_set_t		md_rem;		/**< Simple modes to be removed. */

  flagpage_t		md_flags;	/**< Flags affecting the delta. */
  int			md_count;	/**< Number of modes with args. */

  mode_args_t*		md_tail;	/**< Tail of modes-with-args list. */
  mode_args_t		md_head;	/**< First element of modes-with-args
					     list. */
};

/** The delta should not be automatically flushed. */
#define MDELTA_NOAUTOFLUSH	0x80000000
/** The delta is in reverse-sense mode. */
#define MDELTA_REVERSE		0x40000000

/* Assign mode and add to appropriate tables. */
extern int _mode_desc_reg(regtab_t* table, modedesc_t* md);
/* Release mode and remove from tables. */
extern int _mode_desc_unreg(regtab_t* table, modedesc_t* md);

/* Initialize mode subsystem. */
extern void mode_init(void);

/* Build mode list strings for RPL_MYINFO. */
extern char* mode_str_info(modelist_t* ml, char* buf, int* len, int args);
/* Build mode list strings for CHANMODES in RPL_ISUPPORT. */
extern char* mode_str_modes(modelist_t* ml, char* buf, int* len);
/* Build prefix string for PREFIX in RPL_ISUPPORT. */
extern char* mode_str_prefix(modelist_t* ml, char* buf, int* len);

#endif /* INCLUDED_mode_h */
