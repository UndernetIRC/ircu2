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
#ifndef __include_dbprim_int_h__
#define __include_dbprim_int_h__

#ifdef __GNUC__
# if (__GNUC__ < 2) || (__GNUC__ == 2 && __GNUC_MINOR__ < 7)
#  define __attribute__(A)
# endif
#else
# define __extension__
# define __attribute__(A)
#endif

#define RCSTAG(tag) static char rcsid[] __attribute__((unused)) = tag

unsigned long _hash_prime(unsigned long start);

#define _hash_rollover(mod)	(((mod) * 4) / 3)
#define _hash_rollunder(mod)	(((mod) * 3) / 4)
#define _hash_fuzz(mod)		(((mod) * 4) / 3)

unsigned long _st_remove(smat_table_t *table, smat_entry_t *entry,
			 unsigned int remflag);

#define ST_REM_FIRST	0x0001	/* remove from first list */
#define ST_REM_SECOND	0x0002	/* remove from second list */
#define ST_REM_HASH	0x0004	/* remove from hash table */
#define ST_REM_FREE	0x0008	/* free the entry */

smat_entry_t *_smat_alloc(void);
void _smat_free(smat_entry_t *entry);

#endif /* __include_dbprim_int_h__ */
