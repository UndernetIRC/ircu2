/*
 * fdatest.c - Free Debug Allocator
 * Copyright (C) 1997 Thomas Helvey <tomh@inxpress.net>
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
#include "fda.h"
#include <stdio.h>
#include <assert.h>

#define ALLOC_SIZE 100000

static int empty_slots   = 0;
static int longest_chain = 0;

void location_enumerator(const char* file, int line, int count)
{
  printf("%s line: %d count: %d\n", file, line, count);
}

void leak_enumerator(const char* file, int line, size_t size, void* ptr)
{
  printf("Memory leak: %s: %d - %d bytes (%p)\n", file, line, size, ptr);
}

void hash_enumerator(int slot, int links)
{
  /* printf("s: %d l: %d\n", slot, links); */
  if (0 == links)
    ++empty_slots;
  else if (longest_chain < links)
    longest_chain = links;
}

void test_hash(int count)
{
  int i = 0;
  void** bufs = (void**) malloc(sizeof(void*) * count);
  memset(bufs, 0, sizeof(void*) * count);

  for (i = 0; i < count; ++i)
    bufs[i] = malloc(i * 2 + 1);

  empty_slots   = 0;
  longest_chain = 0;
  
  fda_dump_hash(hash_enumerator);
  printf("empty: %d longest: %d\n", empty_slots, longest_chain);
  
  for (i = 0; i < count; ++i)
    bufs[i] = realloc(bufs[i], i * 3 + 1);

  empty_slots   = 0;
  longest_chain = 0;

  fda_dump_hash(hash_enumerator);
  printf("empty: %d longest: %d\n", empty_slots, longest_chain);
  
  for (i = 0; i < count; ++i) {
    free(bufs[i]);
    bufs[i] = malloc(i * 4 + 1);
  }

  empty_slots   = 0;
  longest_chain = 0;

  fda_dump_hash(hash_enumerator);
  printf("empty: %d longest: %d\n", empty_slots, longest_chain);
  
  for (i = 0; i < count; ++i)
    free(bufs[i]);
  free((void*)bufs);
}

int main(void)
{
  static void* allocations[100];
  char* str;
  char* realloc_ptr;
  int i;
  
  test_hash(100); 
  test_hash(256); 
  test_hash(800); 
  for (i = 0; i < 100; ++i) {
    allocations[i] = malloc(ALLOC_SIZE);
    assert(valid_ptr(allocations[i], ALLOC_SIZE));
    assert(fda_sizeof(allocations[i]) == ALLOC_SIZE);
  }
  
  str = strdup("This is a string test");
  realloc_ptr = malloc(100);
  realloc_ptr = realloc(realloc_ptr, 1000);
  printf("Allocations ok\n");
  printf("str has %d bytes allocated\n", fda_sizeof(str));
  test_hash(10); 
  for (i = 0; i < 100; ++i)
    fda_set_ref(allocations[i]);
  fda_set_ref(str);
  fda_set_ref(realloc_ptr);
  test_hash(100); 
  printf("Location listing\n");
  i = fda_enum_locations(location_enumerator);
  printf("Total locations: %d\n", i);
  fda_assert_refs();
  fda_clear_refs();
  for (i = 0; i < 100; ++i)
    free(allocations[i]);
  realloc_ptr = realloc(realloc_ptr, 100);
  fda_set_ref(str);
  fda_set_ref(realloc_ptr);
  assert(valid_ptr(realloc_ptr, 100));
  fda_assert_refs();
  free(str);
  free(realloc_ptr);
  fda_assert_refs();
  str = strdup("Hello There");
  realloc_ptr = str++;
  str++;
  printf("checking offset ptr\n");
  assert(valid_ptr(str, 9));
  free(realloc_ptr);
  printf("Listing memory leaks\n");
  i = fda_enum_leaks(leak_enumerator);
  printf("Total Leaks: %d\n", i);
  fda_assert_refs();
  printf("fdatest completed with no errors\n");
  return 0;
}

