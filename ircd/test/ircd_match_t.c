/*
 * ircd_match_t.c - test cases for irc glob matching
 */

#include "ircd_log.h"
#include "match.h"
#include <stdio.h>
#include <string.h>

struct match_test {
  const char *glob;
  const char *should_match;
  const char *shouldnt_match;
};

const struct match_test match_tests[] = {
  { "\\*",
    "*\0",
    "a\0*PeacefuL*\0" },
  { "*a*",
    "a\0pizza\0abe\0brack\0",
    "b\0" },
  { "?",
    "*\0a\0?\0",
    "*PeacefuL*\0pizza\0???\0" },
  { "abc",
    "abc\0",
    "abcd\0cabc\0" },
  { "*abc",
    "abc\0fooabc\0ababc\0",
    "abra\0abcd\0" },
  { "\\?",
    "?\0",
    "a\0" },
  { NULL, NULL, NULL }
};

void do_match_test(const struct match_test *test)
{
  const char *candidate;
  unsigned int matched, not_matched;
  int res;

  for (candidate = test->should_match, matched = 0;
       *candidate;
       candidate += strlen(candidate) + 1, ++matched) {
    res = match(test->glob, candidate);
    if (res != 0) {
      fprintf(stderr, "\"%s\" failed to match \"%s\".\n", test->glob, candidate);
      assert(0);
    }
  }

  for (candidate = test->shouldnt_match, not_matched = 0;
       *candidate;
       candidate += strlen(candidate) + 1, ++not_matched) {
    res = match(test->glob, candidate);
    if (res == 0) {
      fprintf(stderr, "\"%s\" incorrectly matched \"%s\".\n", test->glob, candidate);
      assert(0);
    }
  }

  printf("Passed: %s (%u matches, %u non-matches)\n",
         test->glob, matched, not_matched);
}

int main(int argc, char *argv[])
{
  const struct match_test *match;
  for (match = match_tests; match->glob; ++match)
    do_match_test(match);
  return 0;
}
