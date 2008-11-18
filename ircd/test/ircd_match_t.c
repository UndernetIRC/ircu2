/*
 * ircd_match_t.c - test cases for irc glob matching
 */

#include "ircd_log.h"
#include "match.h"

#include <errno.h>    /* errno */
#include <fcntl.h>    /* O_RDONLY */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h> /* mmap(), munmap() */
#include <unistd.h>   /* sysconf() */

#if !defined(MAP_ANONYMOUS)
# if defined(MAP_ANON)
#  define MAP_ANONYMOUS MAP_ANON
# else
#  error I do not know how to request an anonymous mmap from your OS.
# endif
#endif

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
  { "*\\\\[*!~*",
    "har\\[dy!~boy\0",
    "dark\\s|de!pimp\0joe\\[mama\0" },
  { NULL, NULL, NULL }
};

int test_match(const char glob[], const char name[])
{
  static unsigned int page_size;
  static char *pages;
  char *test_glob;
  char *test_name;
  size_t length;
  int res;

  /* If we have not yet set up our test mappings, do so. */
  if (!page_size)
  {
    int dev_zero_fd;

    page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size == 0 || page_size == (unsigned int)-1)
    {
      fprintf(stderr, "sysconf(_SC_PAGE_SIZE) failed: %s\n", strerror(errno));
      assert(0);
    }
    dev_zero_fd = open("/dev/zero", O_RDONLY);
    /* If dev_zero_fd == -1 (failed), we may still be able to mmap anonymously. */
    pages = mmap(NULL, 4 * page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, dev_zero_fd, 0);
    if (pages == MAP_FAILED)
    {
      /* Try using fd == -1 for MAP_ANONYMOUS, which BSD systems require. */
      pages = mmap(NULL, 4 * page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (pages == MAP_FAILED)
    {
      fprintf(stderr, "Unable to map pages: %s\n", strerror(errno));
      assert(0);
    }
    if (dev_zero_fd >= 0)
    {
      close(dev_zero_fd);
      dev_zero_fd = -1;
    }
    res = munmap(pages + page_size * 1, page_size);
    if (res < 0)
    {
      fprintf(stderr, "Unable to unmap page 2/4: %s\n", strerror(errno));
      /* Dysfunctional OSes */
    }
    munmap(pages + page_size * 3, page_size);
    if (res < 0)
    {
      fprintf(stderr, "Unable to unmap page 4/4: %s\n", strerror(errno));
    }
  }

  /* Copy the strings to the end of their respective pages. */
  length = strlen(glob) + 1;
  test_glob = pages + page_size * 1 - length;
  memcpy(test_glob, glob, length);
  length = strlen(name) + 1;
  test_name = pages + page_size * 3 - length;
  memcpy(test_name, name, length);

  /* Perform the test. */
  return match(test_glob, test_name);
}

void do_match_test(const struct match_test *test)
{
  const char *candidate;
  unsigned int matched, not_matched;
  int res;

  for (candidate = test->should_match, matched = 0;
       *candidate;
       candidate += strlen(candidate) + 1, ++matched) {
    res = test_match(test->glob, candidate);
    if (res != 0) {
      fprintf(stderr, "\"%s\" failed to match \"%s\".\n", test->glob, candidate);
      assert(0);
    }
  }

  for (candidate = test->shouldnt_match, not_matched = 0;
       *candidate;
       candidate += strlen(candidate) + 1, ++not_matched) {
    res = test_match(test->glob, candidate);
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
