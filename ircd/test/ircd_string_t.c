/*
 * ircd_string_t.c - string test program
 */
#include "ircd_string.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
  char* vector[20];
  char* names;
  int count;
  int i;

  names = strdup(",,,a,b,a,X,ne,blah,A,z,#foo,&Bar,foo,,crud,Foo,z,x,bzet,,");
  printf("input: %s\n", names);
  count = unique_name_vector(names, ',', vector, 20);
  printf("count: %d\n", count);
  printf("output:");
  for (i = 0; i < count; ++i)
    printf(" %s", vector[i]);
  printf("\n");
  free(names);

  names = strdup("foo");
  printf("input: %s\n", names);
  count = unique_name_vector(names, ',', vector, 20);
  printf("count: %d\n", count);
  printf("output:");
  for (i = 0; i < count; ++i)
    printf(" %s", vector[i]);
  printf("\n");
  free(names);
  
  names = strdup("");
  printf("input: %s\n", names);
  count = unique_name_vector(names, ',', vector, 20);
  printf("count: %d\n", count);
  printf("output:");
  for (i = 0; i < count; ++i)
    printf(" %s", vector[i]);
  printf("\n");
  free(names);

  names = strdup("a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z");
  printf("input: %s\n", names);
  count = unique_name_vector(names, ',', vector, 20);
  printf("count: %d\n", count);
  printf("output:");
  for (i = 0; i < count; ++i)
    printf(" %s", vector[i]);
  printf("\n");
  free(names);

  /* atotime(): parse timestamps at full time_t width, unlike atoi(),
   * which truncates at INT_MAX (2038-01-19) and breaks the wire
   * timestamps carried on server links. */
  assert(atotime("0") == (time_t)0);
  assert(atotime("1000000000") == (time_t)1000000000);
  /* INT_MAX is the last value atoi() can represent. */
  assert(atotime("2147483647") == (time_t)INT_MAX);
  if (sizeof(time_t) >= 8) {
    /* 2200000000 (2039-09-13) is past INT_MAX; atoi() would truncate it,
     * atotime() must preserve it. */
    time_t t = atotime("2200000000");
    assert(t == (time_t)2200000000LL);
    assert(t > (time_t)INT_MAX);
    printf("atotime: post-2038 value 2200000000 preserved.\n");
  } else {
    printf("atotime: 32-bit time_t build, skipping post-2038 check.\n");
  }
  printf("atotime tests passed.\n");

  return 0;
}
  
