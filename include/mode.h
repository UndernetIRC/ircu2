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
#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"
#endif
#ifndef INCLUDED_features_h
#include "ircd_features.h"
#endif
#ifndef INCLUDED_keyspace_h
#include "keyspace.h"
#endif

struct Client;
struct Channel;

/** Specifies the maximum number of modes permitted on any entity. */
#define MAX_MODES		64
/** Specifies the maximum number of mode params permitted in one message. */
#define MAX_MODEPARAMS		6
/** Specifies the maximum number of destinations for a mode_delta_t. */
#define MAX_DESTS		6

/** Registration table for mode lists. */
#define MODE_TABLE		"mode"

/** Specifies the numerical value of a mode switch. */
typedef ircd_key_t mode_t;

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
/** Describes a destination a mode delta may be flushed to. */
typedef struct ModeDest mode_dest_t;
/** Buffer for mode delta data currently being sent to a destination. */
typedef struct ModeBuffer mode_buf_t;

/** Indicate type of target. */
typedef enum ModeTargetType {
  MTT_NONE,		/**< No specific target. */
  MTT_USER,		/**< Target is a user. */
  MTT_CHANNEL,		/**< Target is a channel. */
  MTT_SERVER		/**< Target is a server. */
} mode_targ_t;

/** Indicate flag operation. */
typedef enum ModeFlagOp {
  MFO_SET,		/**< Set the specified flags. */
  MFO_CLEAR,		/**< Clear the specified flags. */
  MFO_REPLACE		/**< Replace with the specified flags. */
} mode_flagop_t;

/** Processor for delta destinations.
 * @param[in] delta Delta being processed.
 * @param[in] dest Destination description, including extra data.
 * @param[in] buf Buffer containing the data to send to destination.
 * @param[in] flags Any flags passed to mode_delta_flush().  If this
 * is an autoflush, this will contain MDFLUSH_AUTO.
 */
typedef void (*mode_dproc_t)(mode_delta_t* delta, mode_dest_t* dest,
			     mode_buf_t* buf, flagpage_t flags);

/** Describes a single mode. */
struct ModeDesc {
  regent_t		md_regent;	/**< Registration entry. */
  int			md_switch;	/**< Mode switch (character). */
  int			md_prefix;	/**< Indicator prefix for mode. */
  mode_t		md_mode;	/**< Numerical value of mode. */
  const char*		md_desc;	/**< Textual description of mode. */
  flagpage_t		md_flags;	/**< Flags affecting mode. */
  enum Feature		md_feat;	/**< Features controlling mode. */
};

/** Magic number for a mode descriptor. */
#define MODE_DESC_MAGIC 0x54aacaed

/** Initialize a mode_desc_t.
 * @param[in] name Descriptive name for the mode.
 * @param[in] sw "Switch" character for the mode.
 * @param[in] desc Description of the mode.
 * @param[in] flags Flags affecting the mode.
 */
#define MODE_DESC(name, sw, desc, flags)				\
  { REGENT_INIT(MODE_DESC_MAGIC, (name)), (sw), 0, 0, (desc), (flags),	\
      FEAT_LAST_F }

/** Initialize a mode_desc_t.
 * @param[in] name Descriptive name for the mode.
 * @param[in] sw "Switch" character for the mode.
 * @param[in] desc Description of the mode.
 * @param[in] flags Flags affecting the mode.
 * @param[in] pfx Prefix character used in /NAMES reply.
 * @param[in] prio Priority for ordering prefix characters; unused otherwise.
 */
#define MODE_DESC_PFX(name, sw, desc, flags, pfx, prio)			\
  { REGENT_INIT(MODE_DESC_MAGIC, (name)), (sw), (pfx), 0, (desc),	\
      (flags) | (((prio) & 0x0f) << MDFLAG_PRIO_SHIFT), FEAT_LAST_F }

/** Initialize a mode_desc_t.
 * @param[in] name Descriptive name for the mode.
 * @param[in] sw "Switch" character for the mode.
 * @param[in] desc Description of the mode.
 * @param[in] flags Flags affecting the mode.
 * @param[in] pfx Prefix character used in /NAMES reply.
 * @param[in] prio Priority for ordering prefix characters; unused otherwise.
 * @param[in] feat Feature controlling availability of mode.
 */
#define MODE_DESC_FEAT(name, sw, desc, flags, feat)		\
  { REGENT_INIT(MODE_DESC_MAGIC, (name)), (sw), 0, 0, (desc),	\
      (flags) | MDFLAG_FEATURE, (feat) }

/** Initialize a mode_desc_t.
 * @param[in] name Descriptive name for the mode.
 * @param[in] sw "Switch" character for the mode.
 * @param[in] desc Description of the mode.
 * @param[in] flags Flags affecting the mode.
 * @param[in] pfx Prefix character used in /NAMES reply.
 * @param[in] prio Priority for ordering prefix characters; unused otherwise.
 * @param[in] feat Feature controlling availability of mode.
 */
#define MODE_DESC_FEAT_PFX(name, sw, desc, flags, pfx, prio, feat)	\
  { REGENT_INIT(MODE_DESC_MAGIC, (name)), (sw), (pfx), 0, (desc),	\
      (flags) | (((prio) & 0x0f) << MDFLAG_PRIO_SHIFT) | MDFLAG_FEATURE, \
      (feat) }

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
/** Mode is controlled by a feature. */
#define MDFLAG_FEATURE		0x04000000
/** Mode can be changed, i.e., by "-M+M old new". */
#define MDFLAG_ONECHANGE	0x02000000
/** Mode argument can be displayed under certain circumstances. */
#define MDFLAG_SHOWARG		0x01000000

/** Helper macro to convert a value to a flag. */
#define MDFLAG_VAL2FLAG(val, shift)			\
				((val) << (shift))
/** Helper macro to convert a flag to a value. */
#define MDFLAG_FLAG2VAL(flags, mask, shift)			\
				(((flags) & (mask)) >> (shift))

/** Bit offset for prefix ordering priority. */
#define MDFLAG_PRIO_SHIFT	15
/** Bit offset for argument visibility. */
#define MDFLAG_AVIS_SHIFT	12
/** Bit offset for mode visibility. */
#define MDFLAG_VIS_SHIFT	 9
/** Bit offset for authorization policy. */
#define MDPOL_AUTHZ_SHIFT	 6
/** Bit offset for parser mode type. */
#define MDPAR_TYPE_SHIFT	 3
/** Bit offset for parser argument type. */
#define MDPAR_TYPE_SHIFT	 0

/** Mask for prefix ordering priority. */
#define MDFLAG_PRIO		MDFLAG_VAL2FLAG(15, MDFLAG_PRIO_SHIFT)

/** Mode argument is visible to anyone. */
#define MDFLAG_AVIS_OPEN	MDFLAG_VAL2FLAG(0, MDFLAG_AVIS_SHIFT)
/** Mode argument is visible only to channel operators. */
#define MDFLAG_AVIS_CHOP	MDFLAG_VAL2FLAG(1, MDFLAG_AVIS_SHIFT)
/** Mode argument is visible only to IRC operators. */
#define MDFLAG_AVIS_OPER	MDFLAG_VAL2FLAG(2, MDFLAG_AVIS_SHIFT)
/** Mode argument is visible only to global IRC operators. */
#define MDFLAG_AVIS_GOP		MDFLAG_VAL2FLAG(3, MDFLAG_AVIS_SHIFT)
/** Mode argument is visible only to servers. */
#define MDFLAG_AVIS_SERV	MDFLAG_VAL2FLAG(4, MDFLAG_AVIS_SHIFT)
/** Mode argument visibility mask. */
#define MDFLAG_AVIS_MASK	MDFLAG_VAL2FLAG(7, MDFLAG_AVIS_SHIFT)

/** Mode is visible to anyone. */
#define MDFLAG_VIS_OPEN		MDFLAG_VAL2FLAG(0, MDFLAG_VIS_SHIFT)
/** Mode is visible only to channel operators. */
#define MDFLAG_VIS_CHOP		MDFLAG_VAL2FLAG(1, MDFLAG_VIS_SHIFT)
/** Mode is visible only to IRC operators. */
#define MDFLAG_VIS_OPER		MDFLAG_VAL2FLAG(2, MDFLAG_VIS_SHIFT)
/** Mode is visible only to global IRC operators. */
#define MDFLAG_VIS_GOP		MDFLAG_VAL2FLAG(3, MDFLAG_VIS_SHIFT)
/** Mode is visible only to servers. */
#define MDFLAG_VIS_SERV		MDFLAG_VAL2FLAG(4, MDFLAG_VIS_SHIFT)
/** Mode visibility mask. */
#define MDFLAG_VIS_MASK		MDFLAG_VAL2FLAG(7, MDFLAG_VIS_SHIFT)

/** Anyone can set or clear mode. */
#define MDPOL_AUTHZ_OPEN	MDFLAG_VAL2FLAG(0, MDPOL_AUTHZ_SHIFT)
/** Only channel operator can set or clear mode. */
#define MDPOL_AUTHZ_CHOP	MDFLAG_VAL2FLAG(1, MDPOL_AUTHZ_SHIFT)
/** Only IRC operators can set or clear mode. */
#define MDPOL_AUTHZ_OPER	MDFLAG_VAL2FLAG(2, MDPOL_AUTHZ_SHIFT)
/** Only global IRC operators can set or clear mode. */
#define MDPOL_AUTHZ_GOP		MDFLAG_VAL2FLAG(3, MDPOL_AUTHZ_SHIFT)
/** Only servers can set or clear mode. */
#define MDPOL_AUTHZ_SERV	MDFLAG_VAL2FLAG(4, MDPOL_AUTHZ_SHIFT)
/** No one can set or clear mode (mode under software control). */
#define MDPOL_AUTHZ_NONE	MDFLAG_VAL2FLAG(5, MDPOL_AUTHZ_SHIFT)
/** Mode authorization mask. */
#define MDPOL_AUTHZ_MASK	MDFLAG_VAL2FLAG(7, MDPOL_AUTHZ_SHIFT)

/** Mode describes a simple switch, e.g., +t channel mode. */
#define MDPAR_TYPE_SWITCH	MDFLAG_VAL2FLAG(0, MDPAR_TYPE_SHIFT)
/** Mode takes an optional argument, e.g., +s user mode. */
#define MDPAR_TYPE_OPTARG	MDFLAG_VAL2FLAG(1, MDPAR_TYPE_SHIFT)
/** Mode takes an argument only when added, e.g., +l channel mode. */
#define MDPAR_TYPE_ADDARG	MDFLAG_VAL2FLAG(2, MDPAR_TYPE_SHIFT)
/** Mode takes a required argument, e.g., +k channel mode. */
#define MDPAR_TYPE_REQARG	MDFLAG_VAL2FLAG(3, MDPAR_TYPE_SHIFT)
/** Mode type mask. */
#define MDPAR_TYPE_MASK		MDFLAG_VAL2FLAG(7, MDPAR_TYPE_SHIFT)

/** Mode takes no argument. */
#define MDPAR_ARG_NONE		MDFLAG_VAL2FLAG(0, MDPAR_ARG_SHIFT)
/** Mode takes an integer argument, e.g., +l channel mode. */
#define MDPAR_ARG_INT		MDFLAG_VAL2FLAG(1, MDPAR_ARG_SHIFT)
/** Mode takes a simple string argument, e.g., +k channel mode. */
#define MDPAR_ARG_STR		MDFLAG_VAL2FLAG(2, MDPAR_ARG_SHIFT)
/** Mode takes an argument indicating a client, e.g., +o channel mode. */
#define MDPAR_ARG_CLI		MDFLAG_VAL2FLAG(3, MDPAR_ARG_SHIFT)
/** Mode argument type mask. */
#define MDPAR_ARG_MASK		MDFLAG_VAL2FLAG(7, MDPAR_ARG_SHIFT)

/** Describes the list of modes available for a channel, user, etc. */
struct ModeList {
  regtab_t		ml_table;	/**< Registration table. */
  size_t		ml_offset;	/**< Offset of mode structure
					     within entity. */
  keyspace_t		ml_keyspace;	/**< Keyspace for mode value
					     allocation. */
  mode_desc_t*		ml_smap[256];	/**< Mode switch map. */
  mode_desc_t*		ml_mmap[MAX_MODES];
					/**< Mode value map. */
};

/** Initialize a mode_list_t.
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

/** Check if a mode is set.
 * @param[in] set Mode set to check.
 * @param[in] mode mode_desc_t describing the mode.
 */
#define ModeHas(set, mode)	FlagHas((set), (mode)->md_mode)

/** Set a mode.
 * @param[in,out] set Mode set.
 * @param[in] mode mode_desc_t describing the mode.
 */
#define ModeSet(set, mode)	FlagSet((set), (mode)->md_mode)

/** Clear a mode.
 * @param[in,out] set Mode set.
 * @param[in] mode mode_desc_t describing the mode.
 */
#define ModeClr(set, mode)	FlagClr((set), (mode)->md_mode)

/** Direction not yet selected. */
#define MDIR_NONE		0x00000000
/** Adding modes. */
#define MDIR_ADD		0x00000001
/** Removing modes. */
#define MDIR_REM		0x00000002
/** Direction mask. */
#define MDIR_MASK		0x00000003

/** String needs to be freed. */
#define MDIRFLAG_FREE		0x80000000

/** Contains a set of modes with arguments. */
struct ModeArgs {
  mode_args_t*		ma_next;	/**< Chain to next set of modes with
					     arguments. */
  mode_args_t*		ma_prev;	/**< Chain to previous set of modes
					     with arguments. */
  struct {
    mode_desc_t*	mam_mode;	/**< The mode. */
    flagpage_t		mam_dir;	/**< Direction of mode. */
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
  unsigned long		md_magic;	/**< Magic number. */
  mode_list_t*		md_modes;	/**< Mode list used by this delta. */

  struct Client*	md_origin;	/**< Origin of delta. */
  mode_targ_t		md_targtype;	/**< Target type for delta. */
  union {
    struct Client*	md_client;	/**< Client target. */
    struct Channel*	md_channel;	/**< Channel target. */
  }			md_target;	/**< Target of delta. */

  mode_set_t		md_add;		/**< Simple modes to be added. */
  mode_set_t		md_rem;		/**< Simple modes to be removed. */

  flagpage_t		md_flags;	/**< Flags affecting the delta. */
  int			md_count;	/**< Number of modes with args. */

  mode_args_t*		md_tail;	/**< Tail of modes-with-args list. */
  mode_args_t		md_head;	/**< First element of modes-with-args
					     list. */

  int			md_dcnt;	/**< Count of destinations. */
  mode_dest_t*		md_dest[MAX_DESTS];
					/**< Destinations to which to flush
					     mode delta. */
};

/** Magic number for a mode delta. */
#define MODE_DELTA_MAGIC 0xc4c75949

/** Check a mode delta for validity. */
#define MODE_DELTA_CHECK(md)	((md) && (md)->md_magic == MODE_DELTA_MAGIC)

/** The delta should not be automatically flushed. */
#define MDELTA_NOAUTOFLUSH	0x80000000
/** The delta is in reverse-sense mode. */
#define MDELTA_REVERSE		0x40000000

/** Application-specific delta flag mask. */
#define MDELTA_APPMASK		0x0000ffff

/** Describes a destination for a mode_delta_t to be flushed to. */
struct ModeDest {
  unsigned long		md_magic;	/**< Magic number. */
  mode_dproc_t		md_proc;	/**< Destination processor. */
  flagpage_t		md_flags;	/**< Flags for destination. */
  void*			md_extra;	/**< Extra information for
					     processor. */
};

/** Magic number for a mode destination. */
#define MODE_DEST_MAGIC 0xf5bedaef

/** Initialize a destination.
 * @param[in] proc Processor callback for destination.
 * @param[in] flags Flags for the destination.  One of MDEST_LOCAL or
 * MDEST_REMOTE is required to be set.
 * @param[in] extra Extra data needed by the processor callback.
 */
#define MODE_DEST_INIT(proc, flags, extra)	\
  { MODE_DEST_MAGIC, (proc), (flags), (extra) }

/** Check a mode destination for validity. */
#define MODE_DEST_CHECK(md)	((md) && (md)->md_magic == MODE_DEST_MAGIC)

/** The destination is local. */
#define MDEST_LOCAL		0x80000000
/** The destination is remote. */
#define MDEST_REMOTE		0x40000000
/** Allow flagged modes to reveal the mode argument. */
#define MDEST_SHOWARG		0x20000000

/** Destination-specific flag mask. */
#define MDEST_SPECMASK		0x0000ffff

/* XXX This string buffer stuff really should be in ircd_string */
/** Declare a string buffer storing up to \a size characters. */
#define STRBUF(size)				\
  struct {					\
    char		s_buf[(size)];		\
    int			s_len;			\
  }

/** Initializer for a string buffer. */
#define STRBUF_INIT		{ "", 0 }

/** Worst-case size for mode specification.  There can be at most
 * MAX_MODES different kinds of modes, so the buffer should be at
 * least that long.  Additionally, some of those modes may be repeated
 * up to MAX_MODEPARAMS times.  Since one instance is already
 * accounted for in MAX_MODES, we need MAX_MODEPARAMS-1 more
 * positions...but we also need a terminating '\\0', so we drop the -1
 * and that gets you the value selected here.
 */
#define MDSWITCHBUF		(MAX_MODES + MAX_MODEPARAMS)

/** Mode buffer group. */
struct ModeBufGroup {
  STRBUF(MDSWITCHBUF)	mbg_switch;	/**< Simple switches. */
  STRBUF(BUFSIZE)	mbg_extended;	/**< Extended modes. */
  STRBUF(BUFSIZE)	mbg_param;	/**< Parameters for simple switches. */
};

/** Initializer for a mode buffer group. */
#define MBG_INIT		{ STRBUF_INIT, STRBUF_INIT, STRBUF_INIT }

/** Buffer for the mode delta data currently being sent to a destination. */
struct ModeBuffer {
  struct ModeBufGroup	mb_add;		/**< Modes being added. */
  struct ModeBufGroup	mb_locadd;	/**< Local modes being added. */
  struct ModeBufGroup	mb_rem;		/**< Modes being removed. */
  struct ModeBufGroup	mb_locrem;	/**< Local modes being removed. */
  int			mb_buflen;	/**< Maximum length to assume. */
};

/** Initializer for a mode buffer.  The initial value for mb_buflen is
 * set with a 200-byte fuzz factor to avoid overrunning the buffers in
 * the destination processors.
 */
#define MODE_BUF_INIT						\
  { MBG_INIT, MBG_INIT, MBG_INIT, MBG_INIT, BUFSIZE - 200 }

/* Assign mode and add to appropriate tables. */
extern int _mode_desc_reg(mode_list_t* table, mode_desc_t* md);
/* Release mode and remove from tables. */
extern int _mode_desc_unreg(mode_list_t* table, mode_desc_t* md);

/* Initialize mode subsystem. */
extern void mode_init(void);

/* Build mode list strings for RPL_MYINFO. */
extern char* mode_str_info(mode_list_t* ml, char* buf, int* len, int args);
/* Build mode list strings for CHANMODES in RPL_ISUPPORT. */
extern char* mode_str_modes(mode_list_t* ml, char* buf, int* len);
/* Build prefix string for PREFIX in RPL_ISUPPORT. */
extern char* mode_str_prefix(mode_list_t* ml, char* buf, int* len);

/* Initialize a mode_delta_t. */
extern void mode_delta_init(mode_delta_t* md, mode_list_t* ml,
			    struct Client* source, mode_targ_t targtype,
			    void *target, flagpage_t flags);
/* Add a destination for flushing the mode_delta_t. */
extern void mode_delta_dest(mode_delta_t* md, mode_dest_t* dest, int n);
/* Change flags set on the delta. */
extern void mode_delta_flags(mode_delta_t* md, mode_flagop_t op,
			     flagpage_t flags);
/* Set or clear the specified modes. */
extern void mode_delta_mode(mode_delta_t* md, flagpage_t dir,
			    mode_desc_t* mode);
/* Set or clear the specified modes, with an integer argument. */
extern void mode_delta_mode_int(mode_delta_t* md, flagpage_t dir,
				mode_desc_t* mode, unsigned int value);
/* Set or clear the specified modes, with a string argument. */
extern void mode_delta_mode_str(mode_delta_t* md, flagpage_t dir,
				mode_desc_t* mode, const char* value);
/* Set or clear the specified modes, with a client argument. */
extern void mode_delta_mode_cli(mode_delta_t* md, flagpage_t dir,
				mode_desc_t* mode, struct Client* value,
				int oplevel);
/* Flush the delta. */
extern void mode_delta_flush(mode_delta_t* md, flagpage_t flags);
/* Apply the delta to a target. */
extern void mode_delta_apply(mode_delta_t* md, mode_targ_t targtype,
			     void* target, mode_dest_t* dest, int n,
			     flagpage_t flags);

/** Flag indicating that flush was automatically triggered.  Not
 * accepted in the flags parameter of mode_delta_flush().
 */
#define MDFLUSH_AUTO		0x80000000

/** Indicates that all modes should be flushed.  Implied by the call
 * to mode_delta_flush().
 */
#define MDFLUSH_ALL		0x40000000

/** Indicates that modes should not be applied to the target. */
#define MDFLUSH_NOAPPLY		0x20000000

/** Indicates that the mode delta should not be released. */
#define MDFLUSH_NORELEASE	0x10000000

/** Destination-specific flag mask. */
#define MDFLUSH_MASK		0x0000ffff

#endif /* INCLUDED_mode_h */
