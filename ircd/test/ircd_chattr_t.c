/*
 * ircd_chattr_t.c - Test file for character attributes
 */
#include "ircd_chattr.h"
#include <assert.h>
#include <stdio.h>

typedef int (*EvalFn)(char);

int eval_alnum(char c)
{
  return (0 != IsAlnum(c));
}

int eval_alpha(char c)
{
  return (0 != IsAlpha(c));
}

int eval_digit(char c)
{
  return (0 != IsDigit(c));
}

int eval_lower(char c)
{
  return (0 != IsLower(c));
}

int eval_space(char c)
{
  return (0 != IsSpace(c));
}

int eval_upper(char c)
{
  return (0 != IsUpper(c));
}

int eval_cntrl(char c)
{
  return (0 != IsCntrl(c));
}

int eval_channel_char(char c)
{
  return (0 != IsChannelChar(c));
}

int eval_channel_lower(char c)
{
  return (0 != IsChannelLower(c));
}

int eval_channel_prefix(char c)
{
  return (0 != IsChannelPrefix(c));
}

int eval_nick_char(char c)
{
  return (0 != IsNickChar(c));
}

int eval_user_char(char c)
{
  return (0 != IsUserChar(c));
}

int eval_host_char(char c)
{
  return (0 != IsHostChar(c));
}

int eval_ip_char(char c)
{
  return (0 != IsIPChar(c));
}

int eval_eol(char c)
{
  return (0 != IsEol(c));
}

int eval_ktime_char(char c)
{
  return (0 != IsKTimeChar(c));
}

struct CharTest {
  const char* name;
  EvalFn      evaluator;
} testList[] = {
  { "IsAlnum:         ", eval_alnum },
  { "IsAlpha:         ", eval_alpha },
  { "IsDigit:         ", eval_digit },
  { "IsLower:         ", eval_lower },
  { "IsSpace:         ", eval_space },
  { "IsUpper:         ", eval_upper },
  { "IsCntrl:         ", eval_cntrl },
  { "IsChannelChar:   ", eval_channel_char },
  { "IsChannelLower:  ", eval_channel_lower },
  { "IsChannelPrefix: ", eval_channel_prefix },
  { "IsNickChar:      ", eval_nick_char },
  { "IsUserChar:      ", eval_user_char },
  { "IsHostChar:      ", eval_host_char },
  { "IsIPChar:        ", eval_ip_char },
  { "IsEol:           ", eval_eol },
  { "IsKTimeChar:     ", eval_ktime_char }
};

#define TESTLIST_SIZE sizeof(testList) / sizeof(struct CharTest)

void print_char(unsigned char c)
{
  if (c < 0x20) {
    switch (c) {
    case '\a': printf("\\a"); break;
    case '\b': printf("\\b"); break;
    case '\f': printf("\\f"); break;
    case '\n': printf("\\n"); break;
    case '\r': printf("\\r"); break;
    case '\t': printf("\\t"); break;
    case '\v': printf("\\v"); break;
    default:
      printf("\\%x", c); break;
    }
  }
  else if (c < 0x7F) {
    printf("%c", c);
  }
  else {
    printf("\\%x", c);
  }
}

void print_char_attr(struct CharTest* test)
{
  int i;

  printf("%s", test->name);

  for (i = 0; i < 256; ++i) {
    if ((*test->evaluator)(i))
      print_char(i);
  }
  printf("\n");
}

    
int main(void)
{
  int i;

  for (i = 0; i < TESTLIST_SIZE; ++i)
    print_char_attr(&testList[i]);

  return 0;
}

