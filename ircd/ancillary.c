/*
 * IRC - Internet Relay Chat, ircd/ancillary.c
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
 * @brief Implementation of generic ancillary data.
 */
#include "config.h"

#include "ancillary.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "register.h"

/** @page ancillary Generic ancillary data subsystem.
 *
 * @section introanc Introduction
 *
 * The database is full of all sorts of objects--connections, servers,
 * users, etc.  Many modules have ancillary data stored in the
 * database structures for these objects.  This violates the
 * abstraction boundary--those modules have to have intimate
 * information about the details of those structures, and the database
 * also has to know about what ancillary data is to be stored in them.
 * This also prevents dynamically loaded modules from being able to
 * add their own ancillary data to these structures.
 *
 * The ancillary data subsystem is an attempt to solve these basic
 * issues.  Its API is modeled on the POSIX threads routines
 * pthread_getspecific() and pthread_setspecific(), which in turn
 * interact with pthread_key_create() and pthread_key_delete().  The
 * basic concept is that each object which permits ancillary data to
 * be associated with it must register an ancmodule_t through the
 * registration system (see \subpage register), and must include an
 * ancdata_t somewhere within the object's data structure.  Then, any
 * other module may associate ancillary data with those objects by
 * obtaining a key and passing that key, along with the object, to a
 * get or set function.
 *
 * @section keyanc Managing Keys
 *
 * Keys may be obtained by calling the ad_key_create() routine,
 * passing it the name of an ancillary data module and the address of
 * a function to destroy objects stored under that key.  (Note that
 * this destructor may not be NULL.)  When done with the key, such as
 * when the module storing the ancillary data is being unloaded, the
 * ad_key_destroy() routine should be called.  It will call the
 * destructor on all ancillary data stored under that key.
 *
 * @section getsetanc Getting and Setting Ancillary Data
 *
 * Ancillary data is retrieved and set using ad_get() and ad_set(),
 * respectively.  These routines require both a pointer to the
 * object's ancdata_t ancillary data storage location and the key
 * under which the ancillary data is to be stored.  If a key is
 * undefined, ad_set() will return a non-zero value, whereas ad_get()
 * will simply return NULL.
 *
 * @section otheropsanc Other Ancillary Data Operations
 *
 * The ancillary data subsystem provides the ad_iter() function, which
 * causes a function to be executed on every object in an ancillary
 * data module.  Additionally, when an ancillary data module is
 * releasing one of its objects, it can clean up all ancillary data in
 * that object by calling ad_flush().
 *
 * @section enableanc Enabling Ancillary Data
 *
 * "This sound great!" you say.  "But how do I create objects that are
 * ancillary data-enabled?"  This turns out to be simple.  In your
 * structure for the object, you must have one element that is an
 * ancdata_t; this element will be used for storing the actual
 * ancillary data.  You must initialize this element with the
 * ANCDATA_INIT() macro or with the ancdata_init() macro if you need
 * dynamic initialization; both these macros require a pointer to your
 * ancmodule_t for the module.
 *
 * This ancmodule_t stores the data about allocated keys, such as the
 * pointers to the destructors.  It also contains the offset of the
 * ancdata_t element of your structure and a pointer to a "walk"
 * function, both of which are mandatory arguments.  The "walk"
 * function must be compatible with ancwalk_t, and the offset may be
 * computed by the offsetof() macro.  You should statically allocate
 * this ancmodule_t and initialize it with the ANCMODULE_INIT() macro.
 * It must also be passed to the reg() function, passing ANC_TABLE as
 * the value of the \a table parameter.
 *
 * @section infoanc Important Subsystem Information
 *
 * This subsystem provides two structures--struct AncModule and struct
 * AncData--and 6 types: ancmodule_t and ancdata_t, corresponding to
 * the two structures; anckey_t, for keys; anciter_t, for the
 * iteration callback needed by ancwalk_t, which must iterate over all
 * objects in the module; and ancdestroy_t, which represents a
 * function used to destroy abandoned ancillary data.  In particular,
 * ancmodule_t, ancdata_t, and anckey_t should be treated as opaque by
 * all callers, and struct AncModule and struct AncData should not be
 * referenced directly.  Any data needed from these structures may be
 * obtained using the provided macros.
 *
 * This subsystem makes use of ircu's registration subsystem and its
 * allocation routines.  In addition, it references the assert() macro
 * in ircd_log.h.  This module requires explicit initialization, which
 * may be performed by calling ad_init().  This must be done before
 * any module which is ancillary data-enabled.
 *
 * Memory allocated by the subsystem is managed solely by the
 * subsystem; the caller will never see any allocated memory, and need
 * not worry about calling MyFree() on any result of calling any
 * function in this subsystem.  Only the destructor callbacks should
 * need to call MyFree(), in order to release memory allocated for the
 * ancillary data itself.
 */

/** Define a chunk size for allocation of keyspace. */
#define AD_CHUNK	4

/* pre-declare am_reg() and am_unreg() */
static int am_reg(regtab_t* table, ancmodule_t* am);
static int am_unreg(regtab_t* table, ancmodule_t* am);

/** Table of ancillary data modules. */
static regtab_t ad_table = REGTAB_INIT(ANC_TABLE, ANCMODULE_MAGIC,
				       (reg_t) am_reg, (unreg_t) am_unreg);

/** Check that ancillary data module is valid.
 * @param[in] table Pointer to ad_table.
 * @param[in] am Ancillary data module to verify.
 * @return 0 for valid ancillary data modules, non-zero otherwise.
 */
static int am_reg(regtab_t* table, ancmodule_t* am)
{
  if (!am->am_walk) /* must have a walk function */
    return 1;

  return 0; /* it passes the tests */
}

/** Iteration callback for flushing all ancillary data from an object.
 * @param[in] mod The ancillary data module.
 * @param[in] obj The object being iterated over.
 * @param[in] extra Unused.
 * @return 0 to continue iteration.
 */
static int am_unreg_flush(ancmodule_t* mod, void* obj, void* extra)
{
  /* simply flush the data away */
  ad_flush(mod, am_data(mod, obj));

  return 0;
}

/** Flush away all allocated memory.  Nominally, all objects will be
 * destroyed before unreg() is called, but this is for that
 * just-in-case eventuality.
 * @param[in] table Pointer to ad_table.
 * @param[in] am Ancillary data module to flush.
 * @return 0 to accept unregistration.
 */
static int am_unreg(regtab_t* table, ancmodule_t* am)
{
  /* iterate over all the objects in the module and flush them */
  (am->am_walk)(am, am_unreg_flush, 0);

  return 0;
}

/** Set ancillary data for a specified key.
 * @param[in,out] ad Pointer to the relevant ancdata_t.
 * @param[in] key Key for the datum.
 * @param[in] value Value of the datum to set; can be NULL.
 * @return 0 if the value is set properly; -1 if key is undefined.
 */
int ad_set(ancdata_t* ad, anckey_t key, void* value)
{
  ancmodule_t *am;
  anckey_t i;

  assert(0 != ad);

  /* obtain a pointer to the responsible module */
  am = ad->ad_module;

  assert(ANCMODULE_CHECK(am));

  /* check to see if it's a defined key */
  if (key >= am->am_alloc || !am->am_destroy[key])
    return -1;

  /* If this key hasn't been created in the object yet, resize... */
  if (ad->ad_alloc <= key) {
    if (!value) /* not storing anything anyway, so bail out */
      return 0;

    /* resize the ancillary data storage array... */
    ad->ad_data = MyRealloc(ad->ad_data, sizeof(void*) * (key + 1));

    /* initialize the new pointers */
    for (i = ad->ad_alloc; i <= key; i++)
      ad->ad_data[i] = 0;

    ad->ad_alloc = key + 1; /* store new allocation count */
  }

  /* if there is an existing setting, call the destructor on it. */
  if (ad->ad_data[key])
    (am->am_destroy[key])(ad->ad_data[key]);

  /* set the new value and return */
  ad->ad_data[key] = value;

  return 0;
}

/** Create an ancillary data key.
 * @param[in] module Name of an object module accepting ancillary
 * data.
 * @param[in] destroy Pointer to a destructor function.  May not be
 * NULL.
 * @return A new ancillary data key, or ANC_INVKEY if module not found
 * or no keys available.
 */
anckey_t ad_key_create(const char* module, ancdestroy_t destroy)
{
  anckey_t i, j;
  ancmodule_t *mod;

  assert(0 != destroy);

  /* look up the named module */
  if (!(mod = reg_find(ANC_TABLE, module)))
    return ANC_INVKEY;

  /* see if we can find an available key... */
  for (i = 0; i < mod->am_alloc; i++)
    if (!mod->am_destroy[i]) /* found an empty slot! */
      break;
    else if (i == ANC_INVKEY) /* can't allocate another */
      return ANC_INVKEY; /* yeah, how likely is *this*?  :) */

  if (i >= mod->am_alloc) { /* have to allocate more slots */
    if (i == ANC_INVKEY) /* make sure we can actually allocate some more */
      return ANC_INVKEY;

    /* do the resize... */
    mod->am_destroy = MyRealloc(mod->am_destroy, sizeof(ancdestroy_t) *
				(mod->am_alloc + AD_CHUNK));

    /* initialize the new slots */
    for (j = i; j < mod->am_alloc + AD_CHUNK; j++)
      mod->am_destroy[j] = 0;

    /* save the new allocation size */
    mod->am_alloc += AD_CHUNK;
  }

  assert(i < mod->am_alloc);

  /* set the new slot with the destructor and return the key */
  mod->am_destroy[i] = destroy;
  return i;
}

/** Destroy datum in object during iteration.
 * @param[in] mod The ancillary data module.
 * @param[in] obj The object being iterated over.
 * @param[in] key Key being released.
 * @return 0 to continue iteration.
 */
static int ad_key_release(ancmodule_t* mod, void* obj, anckey_t* key)
{
  ancdata_t *data = am_data(mod, obj);

  if (data->ad_alloc > *key && data->ad_data[*key]) {
    (mod->am_destroy[*key])(data->ad_data[*key]);
    data->ad_data[*key] = 0; /* zero the object data */
  }

  return 0;
}

/** Destroy an ancillary data key.
 * @param[in] module Name of an object module accepting ancillary
 * data.
 * @param[in] key Key to destroy.
 */
void ad_key_destroy(const char* module, anckey_t key)
{
  ancmodule_t *mod;

  assert(ANC_INVKEY != key);

  /* look up the named module */
  if (!(mod = reg_find(ANC_TABLE, module)) || key >= mod->am_alloc ||
      !mod->am_destroy[key])
    return;

  /* now iterate over all the objects, releasing the datum */
  (mod->am_walk)(mod, (anciter_t) ad_key_release, (void*) &key);

  /* finally, mark the slot empty */
  mod->am_destroy[key] = 0;
}

/** Iterate over all objects in a module.
 * @param[in] module Name of an object module accepting ancillary
 * data.
 * @param[in] func Iteration function to execute.
 * @param[in,out] extra Extra data to pass to iteration function.
 * @return -1 if table doesn't exist; otherwise 0 or whatever non-zero
 * value \a func returns.  (Iteration terminates if \a func returns
 * non-zero.)
 */
int ad_iter(const char* module, anciter_t func, void* extra)
{
  ancmodule_t *mod;

  assert(0 != func);

  /* look up the named module */
  if (!(mod = reg_find(ANC_TABLE, module)))
    return -1;

  /* now call the module's walk callback */
  return (mod->am_walk)(mod, func, extra);
}

/** Flush all data in a particular object.
 * @param[in] am The module the object is in.
 * @param[in] ad A pointer to the object's ancillary data.
 */
void ad_flush(ancmodule_t* am, ancdata_t* ad)
{
  anckey_t i;

  /* walk all the data */
  for (i = 0; i < ad->ad_alloc; i++)
    if (ad->ad_data[i]) { /* have to destroy a datum */
      assert(0 != am->am_destroy[i]);
      (am->am_destroy[i])(ad->ad_data[i]); /* so destroy it */
    }

  /* we've released all the data, so let's clean up after ourselves */
  MyFree(ad->ad_data);

  ad->ad_alloc = 0;
  ad->ad_data = 0; /* should be done by MyFree(), but I don't rely on that */
}

/** Initialize ancillary data subsystem. */
void ad_init(void)
{
  reg(REG_TABLE, &ad_table);
}
