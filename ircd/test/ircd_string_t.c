/*
 * ircd_string_t.c - string test program
 */
#include "ircd_string.h"
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

  return 0;
}
  
