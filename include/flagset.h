/*
 * IRC - Internet Relay Chat
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
 * @brief Structures and macros for handling sets of boolean flags.
 * @version $Id$
 */

#ifndef INCLUDED_flagset_h
#define INCLUDED_flagset_h

/** Single element in a flag bitset array. */
typedef unsigned long flagpage_t;

/** Number of bits in a flagpage_t. */
#define FLAGSET_NBITS (8 * sizeof(flagpage_t))
/** Element number for flag \a flag. */
#define FLAGSET_INDEX(flag) ((flag) / FLAGSET_NBITS)
/** Element bit for flag \a flag. */
#define FLAGSET_MASK(flag) (1ul<<((flag) % FLAGSET_NBITS))

/** Declare a flagset structure of a particular size. */
#define DECLARE_FLAGSET(name,max) \
  struct name \
  { \
    flagpage_t bits[((max + FLAGSET_NBITS - 1) / FLAGSET_NBITS)]; \
  }

/** Test whether a flag is set in a flagset. */
#define FlagHas(set,flag) ((set)->bits[FLAGSET_INDEX(flag)] & FLAGSET_MASK(flag))
/** Set a flag in a flagset. */
#define FlagSet(set,flag) ((set)->bits[FLAGSET_INDEX(flag)] |= FLAGSET_MASK(flag))
/** Clear a flag in a flagset. */
#define FlagClr(set,flag) ((set)->bits[FLAGSET_INDEX(flag)] &= ~FLAGSET_MASK(flag))

/** Zero a flagset. */
#define FlagZero(set,max) \
  do { \
    unsigned int _max = FLAGSET_INDEX(max), _i; \
    for (_i = 0; _i < _max; _i++) \
      (set)->bits[_i] = 0; \
  } while (0)

/** Swap two flagsets. */
#define FlagSwap(s1,s2,max) \
  do { \
    unsigned int _max = FLAGSET_INDEX(max), _i; \
    flagpage_t _tmp; \
    for (_i = 0; _i < _max; _i++) { \
      _tmp = (s1)->bits[_i]; \
      (s1)->bits[_i] = (s2)->bits[_i]; \
      (s2)->bits[_i] = _tmp; \
    } \
  } while (0)

#endif /* ndef INCLUDED_flagset_h */
