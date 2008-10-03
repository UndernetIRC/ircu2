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
#include "ircd_log.h"
#include "register.h"

/** Initialize a mode list.
 * @param[in] table Pointer to md_table.
 * @param[in] ml Mode list to verify.
 * @return 0 for valid mode list, non-zero otherwise.
 */
static int
ml_reg(regtab_t* table, modelist_t* ml)
{
}

/** Clean up a mode list.
 * @param[in] table Pointer to md_table.
 * @param[in] ml Mode list to flush.
 * @return 0 to accept unregistration.
 */
static int
ml_unreg(regtab_t* table, modelist_t* ml)
{
}

/** Table of mode lists. */
static regtab_t md_table = REGTAB_INIT(MODE_TABLE, REGTAB_MAGIC,
				       (reg_t) ml_reg, (unreg_t) ml_unreg);

/** Assign mode and add to appropriate tables.
 * @param[in] table Pointer to mode list.
 * @param[in] md Mode descriptor to add.
 * @return 0 for valid mode descriptor, non-zero otherwise.
 */
int
_mode_desc_reg(regtab_t* table, modedesc_t* md)
{
}

/** Release mode and remove from tables.
 * @param[in] table Pointer to mode list.
 * @param[in] md Mode descriptor to remove.
 * @return 0 to accept unregistration.
 */
int
_mode_desc_unreg(regtab_t* table, modedesc_t* md)
{
}

/** Initialize mode subsystem. */
void
mode_init(void)
{
  reg(REG_TABLE, &md_table);
}
