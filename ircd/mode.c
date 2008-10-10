/*
 * IRC - Internet Relay Chat, include/mode.c
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
 * @brief Implementation of generic modes.
 * @version $Id$
 */
#include "config.h"

#include "mode.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "register.h"
#include "s_debug.h"

#include <string.h>

/** Initialize a mode list.
 * @param[in] table Pointer to md_table.
 * @param[in,out] ml Mode list to verify.
 * @return 0 for valid mode list, non-zero otherwise.
 */
static int
ml_reg(regtab_t* table, mode_list_t* ml)
{
  /* Sanity-check the mode list */
  if (reg_magic(&ml->ml_table) != MODE_DESC_MAGIC ||
      reg_reg(&ml->ml_table) != (reg_t) _mode_desc_reg ||
      reg_unreg(&ml->ml_table) != (unreg_t) _mode_desc_unreg)
    return -2;

  /* Initialize the keyspace and the maps */
  ks_init(&ml->ml_keyspace, MAX_MODES, 0, 0, ml);
  memset(&ml->ml_smap, 0, sizeof(mode_desc_t*) * 256);
  memset(&ml->ml_mmap, 0, sizeof(mode_desc_t*) * MAX_MODES);

  return 0; /* all set! */
}

/** Remove all existing mode descriptors from a mode list.
 * @param[in,out] ml Pointer to mode_list_t.
 * @param[in,out] md Pointer to mode_desc_t.
 * @param[in] extra Extra pointer passed to regtab_iter().
 * @return 0 to continue iteration.
 */
static int
ml_unreg_flush(mode_list_t* ml, mode_desc_t* md, void* extra)
{
  /* unregister the mode descriptor */
  unregtab((regtab_t*) ml, md);

  return 0;
}

/** Clean up a mode list.
 * @param[in] table Pointer to md_table.
 * @param[in,out] ml Mode list to flush.
 * @return 0 to accept unregistration.
 */
static int
ml_unreg(regtab_t* table, mode_list_t* ml)
{
  /* Remove all descriptors from the table */
  regtab_iter(&ml->ml_table, (regiter_t) ml_unreg_flush, 0);

  /* Clean up the keyspace and clear the maps */
  ks_clean(&ml->ml_keyspace);
  memset(&ml->ml_smap, 0, sizeof(mode_desc_t*) * 256);
  memset(&ml->ml_mmap, 0, sizeof(mode_desc_t*) * MAX_MODES);

  return 0;
}

/** Table of mode lists. */
static regtab_t md_table = REGTAB_INIT(MODE_TABLE, REGTAB_MAGIC,
				       (reg_t) ml_reg, (unreg_t) ml_unreg);

/** Assign mode and add to appropriate tables.
 * @param[in,out] ml Pointer to mode list.
 * @param[in,out] md Mode descriptor to add.
 * @return 0 for valid mode descriptor, non-zero otherwise.
 */
int
_mode_desc_reg(mode_list_t* ml, mode_desc_t* md)
{
  /* First, verify that the mode descriptor is valid */
  if (!md->md_switch)
    return -2;

  /* Do we already have that switch registered? */
  if (ml->ml_smap[md->md_switch])
    return -3;

  /* OK, let's reserve a mode from the keyspace */
  if ((md->md_mode = ks_reserve(&ml->ml_keyspace)) == KEY_INVKEY)
    return 1;

  /* Enter the mode into the modelist maps */
  ml->ml_smap[md->md_switch] = md;
  ml->ml_mmap[md->md_mode] = md;

  return 0;
}

/** Release mode and remove from tables.
 * @param[in,out] ml Pointer to mode list.
 * @param[in] md Mode descriptor to remove.
 * @return 0 to accept unregistration.
 */
int
_mode_desc_unreg(mode_list_t* ml, mode_desc_t* md)
{
  /* Make sure the mode really is in the list... */
  if (ml->ml_smap[md->md_switch] != md || ml->ml_mmap[md->md_mode] != md)
    return -1;

  /* Clear the modelist map entries */
  ml->ml_smap[md->md_switch] = 0;
  ml->ml_mmap[md->md_mode] = 0;

  /* Return the key to the keyspace */
  ks_release(&ml->ml_keyspace, md->md_mode);

  return 0;
}

/** Initialize mode subsystem. */
void
mode_init(void)
{
  reg(REG_TABLE, &md_table);
}

/** Current state of informative mode string buffer. */
struct info_state {
  char*		buf;		/**< String buffer. */
  int		size;		/**< Size of buffer. */
  int		len;		/**< Current length of buffer. */
  int		args;		/**< If true, skip modes without arguments. */
};

/** Determine if a specific mode should be added to the informative
 * mode string.
 * @param[in] table Registration table mode_desc_t is in.
 * @param[in] md Mode descriptor.
 * @param[in,out] is Info string state.
 * @return 0 to continue iteration.
 */
static int
mi_build(regtab_t* table, mode_desc_t* md, struct info_state *is)
{
  assert(MODE_DESC_CHECK(md));

  /* Check if we're including this mode */
  if (!(md->md_flags & MDFLAG_ARGEXTENDED) &&
      (md->md_flags & MDFLAG_VIS_MASK) < MDFLAG_VIS_SERV &&
      (!is->args || (md->md_flags & MDPAR_TYPE_MASK) > MDPAR_TYPE_OPTARG) &&
      (!(md->md_flags & MDFLAG_FEATURE) || feature_bool(md->md_feat)))
    /* Add this mode to the buffer */
    is->buf[is->len++] = md->md_switch;

  return is->len >= is->size;
}

/** Assemble informative mode string for RPL_MYINFO.
 * @param[in] ml Mode list to build mode string from.
 * @param[out] buf Buffer in which to build informative mode string.
 * @param[in,out] len Size of buffer; on return, length of string.
 * @param[in] args If 1, select only modes with parameters.
 * @return Buffer containing informative mode string.
 */
char*
mode_str_info(mode_list_t* ml, char* buf, int* len, int args)
{
  struct info_state is = { buf, 0, 0, args };

  assert(MODE_LIST_CHECK(ml));
  assert(buf);
  assert(len);

  /* Set up the full info */
  is.size = *len;

  /* Now, let's iterate over all the mode descriptors */
  if (regtab_iter(&ml->ml_table, (regiter_t) mi_build, &is))
    return 0; /* some kind of failure occurred */

  /* Terminate the buffer and store the new size */
  is.buf[is.len] = '\0';
  *len = is.len;

  return is.buf; /* return the buffer */
}

/** Current state of mode description accumulation. */
struct mode_state {
  char*		buf;		/**< String buffer. */
  int		size;		/**< Size of buffer. */
  int		len;		/**< Current length of buffer. */
  char*		types[4];	/**< Pointers to string components. */
};

/** Type of mode. */
enum mode_type {
  TYPE_A,	/**< Type A mode--maintains a list. */
  TYPE_B,	/**< Type B mode--always has an argument. */
  TYPE_C,	/**< Type C mode--only has an argument when set. */
  TYPE_D	/**< Type D mode--no argument. */
};

/** Add specific modes to the appropriate string component.
 * @param[in] table Registration table mode_desc_t is in.
 * @param[in] md Mode descriptor.
 * @param[in,out] ms String buffer state.
 * @return 0 to continue iteration.
 */
static int
mm_build(regtab_t* table, mode_desc_t* md, struct mode_state *ms)
{
  enum mode_type type;

  assert(MODE_DESC_CHECK(md));

  /* Check if we need to omit this mode */
  if ((md->md_flags & MDFLAG_ARGEXTENDED) ||
      (md->md_flags & MDFLAG_VIS_MASK) >= MDFLAG_VIS_SERV ||
      md->md_prefix ||
      ((md->md_flags & MDFLAG_FEATURE) && !feature_bool(md->md_feat)))
    return 0; /* skip this one */

  Debug((DEBUG_DEBUG, "mm_build() processing mode %s (%c)", rl_id(md),
	 md->md_switch));

  /* Check the length... */
  if (ms->len + 1 >= ms->size)
    return -1;

  /* Figure out which type of mode this is. */
  if (md->md_flags & MDFLAG_LIST)
    type = TYPE_A;
  else
    switch (md->md_flags & MDPAR_TYPE_MASK) {
    case MDPAR_TYPE_SWITCH: /* plain switch */
    case MDPAR_TYPE_OPTARG: /* shouldn't happen, but treat like plain switch */
      type = TYPE_D;
      break;

    case MDPAR_TYPE_ADDARG: /* only has an argument when set */
      type = TYPE_C;
      break;

    case MDPAR_TYPE_REQARG: /* requires an argument */
      type = TYPE_B;
      break;

    default: /* uh... */
      return 0;
      break;
    }

  Debug((DEBUG_DEBUG, "Mode is type %d (%c)", type,
	 type == TYPE_A ? 'A' :
	 (type == TYPE_B ? 'B' :
	  (type == TYPE_C ? 'C' :
	   (type == TYPE_D ? 'D' : '?')))));
  Debug((DEBUG_DEBUG, "Buffer offsets: (%d, %d, %d, %d); contents \"%s\" (%p)",
	 ms->types[TYPE_A] - ms->buf, ms->types[TYPE_B] - ms->buf,
	 ms->types[TYPE_C] - ms->buf, ms->types[TYPE_D] - ms->buf,
	 ms->buf, ms->buf));
  Debug((DEBUG_DEBUG, "memmove(%p, %p, %d)", ms->types[type] + 1,
	 ms->types[type], ms->len + 1 - (ms->types[type] - ms->buf)));

  /* OK, let's shift the string over one position */
  memmove(ms->types[type] + 1, ms->types[type],
	  ms->len + 1 - (ms->types[type] - ms->buf));

  /* add this mode to the string */
  *ms->types[type] = md->md_switch;

  /* shift up the component pointers... */
  for (; type <= TYPE_D; type++)
    ms->types[type]++;

  /* increment the length */
  ms->len++;

  Debug((DEBUG_DEBUG, "Buffer offsets now: (%d, %d, %d, %d); "
	 "contents \"%s\" (%p)",
	 ms->types[TYPE_A] - ms->buf, ms->types[TYPE_B] - ms->buf,
	 ms->types[TYPE_C] - ms->buf, ms->types[TYPE_D] - ms->buf,
	 ms->buf, ms->buf));

  return 0;
}

/** Assemble string for CHANMODES component of RPL_ISUPPORT.
 * @param[in] ml Mode list to build mode string from.
 * @param[out] buf Buffer in which to build the string.
 * @param[in,out] len Size of buffer; on return, length of string.
 * @return Buffer containing modes string.
 */
char*
mode_str_modes(mode_list_t* ml, char* buf, int* len)
{
  struct mode_state ms = { buf, 0, 0, { 0, 0, 0, 0 } };

  assert(MODE_LIST_CHECK(ml));
  assert(buf);
  assert(len);

  /* Set up the full info */
  ms.size = *len;

  /* Do we have enough space for the initial set-up? */
  if (ms.size < 4)
    return 0;

  /* OK, initialize the buffer appropriately */
  *(ms.types[TYPE_A] = buf + 0) = ',';
  *(ms.types[TYPE_B] = buf + 1) = ',';
  *(ms.types[TYPE_C] = buf + 2) = ',';
  *(ms.types[TYPE_D] = buf + 3) = '\0';

  /* Current length: 3 */
  ms.len = 3;

  /* Now let's iterate over all the mode descriptors */
  if (regtab_iter(&ml->ml_table, (regiter_t) mm_build, &ms))
    return 0; /* some kind of failure occurred */

  return ms.buf; /* return the buffer */
}

/** Convert a flag value with prefix priority into just the priority. */
#define flag2prio(f)	(((f) & MDFLAG_PRIO) >> 16)

/** Current state of prefix accumulation. */
struct pfx_state {
  int		count;		/**< Number of modes to enter. */
  int		max;		/**< Maximum number of modes to enter. */
  mode_desc_t*	modes[flag2prio(MDFLAG_PRIO) + 1];
				/**< Modes contributing to prefix. */
};

/** Determine if a specific mode participates in the prefix calculation.
 * @param[in] table Registration table mode_desc_t is in.
 * @param[in] md Mode descriptor.
 * @param[in,out] ps Prefix string state.
 * @return 0 to continue iteration, non-zero if there is a problem.
 */
static int
mp_build(regtab_t* table, mode_desc_t* md, struct pfx_state *ps)
{
  assert(MODE_DESC_CHECK(md));

  /* Does this mode have an associated prefix? */
  if (md->md_prefix &&
      (!(md->md_flags & MDFLAG_FEATURE) || feature_bool(md->md_feat))) {
    if (ps->modes[flag2prio(md->md_flags)] || ps->count >= ps->max)
      return -1; /* two modes of the same priority, or buffer too small */

    ps->modes[flag2prio(md->md_flags)] = md; /* save it */
    ps->count++;
  }

  return 0; /* keep iterating */
}

/** Assemble string for PREFIX component of RPL_ISUPPORT.
 * @param[in] ml Mode list to build mode string from.
 * @param[out] buf Buffer in which to build the string.
 * @param[in,out] len Size of buffer; on return, length of string.
 * @return Buffer containing prefix string.
 */
char*
mode_str_prefix(mode_list_t* ml, char* buf, int* len)
{
  struct pfx_state ps;
  int i, j, offset;

  assert(MODE_LIST_CHECK(ml));
  assert(buf);
  assert(len);

  /* let's clear the status */
  memset(&ps, 0, sizeof(ps));
  ps.max = (*len - 3) / 2; /* -3 for '(', ')', and '\0' */

  /* Iterate over all the mode descriptors */
  if (regtab_iter(&ml->ml_table, (regiter_t) mp_build, &ps))
    return 0; /* some kind of failure occurred */

  /* We've now built the prefix list; set up the buffer */
  buf[0] = '(';
  buf[ps.count + 1] = ')';
  offset = ps.count + 2;
  buf[(*len = offset + ps.count)] = '\0';

  /* Now fill it in */
  for (j = 0, i = flag2prio(MDFLAG_PRIO); i >= 0; i--)
    if (ps.modes[i]) {
      buf[j + 1] = ps.modes[i]->md_switch;
      buf[j + offset] = ps.modes[i]->md_prefix;
      j++;
    }

  return buf; /* and return the assembled buffer */
}
