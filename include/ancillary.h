/*
 * IRC - Internet Relay Chat, include/ancillary.h
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Structures and functions for handling generic ancillary data.
 * @version $Id$
 */
#ifndef INCLUDED_ancillary_h
#define INCLUDED_ancillary_h
#ifndef INCLUDED_register_h
#include "register.h"
#endif
#ifndef INCLUDED_limits_h
#include <limits.h>
#define INCLUDED_limits_h
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

/** Registration table for ancillary data. */
#define ANC_TABLE	"ancillary"

/** Invalid anckey_t value for returning errors from ad_key_create(). */
#define ANC_INVKEY	UINT_MAX

/** Description of an object accepting ancillary data. */
typedef struct AncModule ancmodule_t;
/** Ancillary data to attach to an object. */
typedef struct AncData ancdata_t;

/** Key for accessing specific ancillary data. */
typedef unsigned int anckey_t;

/** Iteration callback for visiting all objects of specified type.
 * @param[in] mod The ancillary data module.
 * @param[in] obj The object being iterated over.
 * @param[in,out] extra Extra data for the iteration.
 * @return 0 to continue iteration, non-zero to stop iteration.
 */
typedef int (*anciter_t)(ancmodule_t* mod, void* obj, void* extra);

/** Function to call to perform iteration.
 * @param[in] mod The ancillary data module.
 * @param[in] func Iteration function to execute.
 * @param[in,out] extra Extra data to pass to iteration funciton.
 * @return 0 or whatever non-zero value \a func returns.  (Iteration
 * terminates if \a func returns non-zero.)
 */
typedef int (*ancwalk_t)(ancmodule_t* mod, anciter_t func, void* extra);

/** Destructor function for ancillary data.
 * @param[in] datum The datum to destroy.
 */
typedef void (*ancdestroy_t)(void* datum);

/** Describes ancillary data. */
struct AncModule {
  regent_t	am_regent;	/**< Registration entry. */
  ancwalk_t	am_walk;	/**< Iteration callback function. */
  size_t	am_offset;	/**< Offset of data element. */
  unsigned int	am_alloc;	/**< Number of destroy entries allocated. */
  ancdestroy_t*	am_destroy;	/**< Destroy callback functions. */
};

/** Magic number for ancmodule_t. */
#define ANCMODULE_MAGIC 0xdadf751

/** Initialize an ancmodule_t.
 * @param[in] name Name of the object accepting ancillary data.
 * @param[in] walk Iteration function to visit all objects.  May not
 * be NULL.
 * @param[in] offset Offset of ancdata_t element in objects.  Use
 * offsetof() macro to compute this.
 */
#define ANCMODULE_INIT(name, walk, offset)				\
  { REGENT_INIT(ANCMODULE_MAGIC, (name)), (walk), (offset), 0, 0 }

/** Check an ancillary data module. */
#define ANCMODULE_CHECK(am)	REGENT_CHECK((am), ANCMODULE_MAGIC)
/** Get the name of the data module. */
#define am_name(am)		rl_id(am)
/** Retrieve the walk function. */
#define am_walk(am)		((am)->am_walk)
/** Retrieve the ancillary data element object offset. */
#define am_offset(am)		((am)->am_offset)

/** Retrieve the ancillary data element from an object. */
#define am_data(am, obj)	((ancdata_t*) (((char*) (obj)) +	\
					       (am)->am_offset))

/** Contains ancillary data. */
struct AncData {
  ancmodule_t*	ad_module;	/**< Module for ancillary data. */
  unsigned int	ad_alloc;	/**< Number of entries allocated. */
  void**	ad_data;	/**< Array of ancillary data. */
};

/** Initialize an ancdata_t. */
#define ANCDATA_INIT(module)			\
  { (module), 0, 0 }

/** Dynamically initialize an ancdata_t.
 * @param[in,out] ad A pointer to the ancdata_t to be initialized.
 * @param[in] module The module the object is in.
 */
#define ancdata_init(ad, module)		\
  do {						\
    ancdata_t *_ad = (ad);			\
    _ad->ad_module = (module);			\
    _ad->ad_alloc = 0;				\
    _ad->ad_data = 0;				\
  } while (0)

/** Retrieve ancillary data with a specified key.
 * @param[in] ad Pointer to the relevant ancdata_t.
 * @param[in] key Key for the datum.
 * @return Pointer to the ancillary data.
 */
#define ad_get(ad, key)							\
  (((anckey_t) (key)) < (ad)->ad_alloc ? (ad)->ad_data[(key)] : (void*) 0)

/* Set ancillary data for a specified key. */
extern int ad_set(ancdata_t* ad, anckey_t key, void* value);

/* Create an ancillary data key. */
extern anckey_t ad_key_create(const char* module, ancdestroy_t destroy);

/* Destroy an ancillary data key. */
extern void ad_key_destroy(const char* module, anckey_t key);

/* Iterate over all objects in a module. */
extern int ad_iter(const char* module, anciter_t func, void* extra);

/* Flush all data in a particular object. */
extern void ad_flush(ancmodule_t* am, ancdata_t* ad);

/* Initialize ancillary data subsystem. */
extern void ad_init(void);

#endif /* INCLUDED_ancillary_h */
