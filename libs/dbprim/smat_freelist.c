/*
** Copyright (C) 2002 by Kevin L. Mitchell <klmitch@mit.edu>
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of the GNU Library General Public
** License as published by the Free Software Foundation; either
** version 2 of the License, or (at your option) any later version.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Library General Public License for more details.
**
** You should have received a copy of the GNU Library General Public
** License along with this library; if not, write to the Free
** Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
** MA 02111-1307, USA
**
** @(#)$Id$
*/
#include <stdlib.h>

#include "dbprim.h"
#include "dbprim_int.h"

RCSTAG("@(#)$Id$");

static link_head_t _smat_freelist = LINK_HEAD_INIT(0);

smat_entry_t *
_smat_alloc(void)
{
  link_elem_t *le;
  smat_entry_t *se;

  if (!ll_count(&_smat_freelist) || !(le = ll_first(&_smat_freelist)) ||
      ll_remove(&_smat_freelist, le)) {
    /* Must allocate a new element */
    if (!(se = (smat_entry_t *)malloc(sizeof(smat_entry_t))))
      return 0; /* couldn't allocate an entry... */
  } else
    se = le_object(le); /* get smat entry object */

  /* initialize a smat entry */
  if (he_init(&se->se_hash, se) || le_init(&se->se_link[SMAT_LOC_FIRST], se) ||
      le_init(&se->se_link[SMAT_LOC_SECOND], se)) {
    free(se); /* initialization failed... */
    return 0;
  }

  se->se_table = 0; /* initialize the rest of the structure */
  se->se_object[SMAT_LOC_FIRST] = 0;
  se->se_object[SMAT_LOC_SECOND] = 0;

  se->se_magic = SMAT_ENTRY_MAGIC; /* set up the magic number */

  return se; /* return the object */
}

void
_smat_free(smat_entry_t *entry)
{
  entry->se_magic = 0; /* clear magic number to prevent use */

  /* Add the entry to the free list */
  if (ll_add(&_smat_freelist, _se_link(entry), LINK_LOC_HEAD, 0))
    free(entry); /* addition failed, so free the entry */
}

/** \ingroup dbprim_smat
 * \brief Clean up the smat free list.
 *
 * This function frees all smat_entry_t objects on the internal free
 * list.  It is always successful and returns 0.
 */
unsigned long
smat_cleanup(void)
{
  link_elem_t *entry;

  initialize_dbpr_error_table(); /* set up error tables */

  /* walk the free list */
  while ((entry = ll_first(&_smat_freelist))) {
    ll_remove(&_smat_freelist, entry); /* remove entry */
    free(le_object(entry)); /* free the element */
  }

  return 0;
}

/** \ingroup dbprim_smat
 * \brief Report how much memory is used by the free list.
 *
 * This function returns the amount of memory being used by the
 * internal free list of smat_entry_t objects.
 *
 * \return	A number indicating the size, in bytes, of the memory
 *		allocated for smat_entry_t objects on the free list.
 */
unsigned long
smat_freemem(void)
{
  initialize_dbpr_error_table(); /* set up error tables */

  /* tell caller how much memory we're using */
  return ll_count(&_smat_freelist) * sizeof(smat_entry_t);
}
