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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define BUFSIZE 512 /* buffer size */
#define ARGBUF  8   /* number of arguments to start with */

#define CONTINUELINE  0x1000 /* line continuation "character" */

#define Q_D -3 /* quote decimal */
#define Q_X -2 /* quote hexadecimal */
#define Q_S -1 /* quote self */

#define QUOTE_SINGLE  0x0010 /* we're in single-quote mode */
#define QUOTE_DOUBLE  0x0020 /* we're in double-quote mode */
#define QUOTE_FILE    0x0040 /* we're in file quote mode */
#define QUOTED	      0x0080 /* it's a quoted character */
#define SAVE_QUOTE    0x0100 /* preserve quote on ungetc'd char */
#define EOS	      0x0200 /* end of string */
#define EOD	      0x0400 /* end of directive */
#define STOP	      0x0800 /* stop processing the file */

enum test_result {
  TR_NOTRUN,	 /* test has not yet been run */
  TR_PASS,	 /* test passed */
  TR_UPASS,	 /* test passed, but was not expected to pass */
  TR_FAIL,	 /* test failed */
  TR_XFAIL,	 /* test failed, but was expected to fail */
  TR_UNRESOLVED, /* unknown whether test passed or not */
  TR_UNTESTED,	 /* test case not yet ready */
  TR_UNSUPPORTED /* tested feature unsupported here */
};

enum test_status {
  TP_PENDING, /* test program is not yet running */
  TP_RUNNING, /* test program has been started */
  TP_FAILED,  /* test program errored out */
  TP_COMPLETE /* test program has been completed */
};

struct test {
  struct test	   *t_next;   /* next test for program */
  char		   *t_name;   /* test's name */
  char		   *t_desc;   /* description of test */
  enum test_result  t_result; /* result of test */
  enum test_result  t_expect; /* expected result of test */
  struct test_prog *t_prog;   /* structure describing program for test */
  char		   *t_info;   /* any extra information from test program */
};

struct test_prog {
  struct test_prog  *tp_next;	/* next test program */
  struct test_prog **tp_prev_p;	/* what points to us */
  char		    *tp_name;	/* program invocation name */
  char		    *tp_prog;	/* file name of testing program */
  char		   **tp_argv;	/* arguments to feed to test program */
  char		    *tp_desc;	/* description of program */
  struct test	    *tp_tests;	/* linked list of tests run by program */
  struct test	    *tp_last;	/* last test added so far */
  int		     tp_count;	/* count of number of tests run by program */
  struct test_dep   *tp_deps;	/* program dependencies */
  enum test_status   tp_status;	/* status of test program--has it run yet? */
  int		     tp_fd;	/* file descriptor for test program */
  FILE		    *tp_file;	/* FILE for test program */
  int		     tp_pid;	/* process ID for test program */
};

struct test_dep {
  struct test_dep  *td_next; /* next dependency */
  struct test_prog *td_prog; /* program we're dependent upon */
};

static struct {
  const char	  *m_name;  /* name for value */
  enum test_result m_value; /* value for name */
} result_map[] = {
#define M(name) { #name, TR_ ## name }
  M(NOTRUN), M(PASS), M(UPASS), M(FAIL), M(XFAIL), M(UNRESOLVED), M(UNTESTED),
  M(UNSUPPORTED),
#undef M
  { 0, 0 }
};

static int xform[] = {
  '\a',  '\b',   Q_S,   Q_D,'\033',  '\f',   Q_S,   Q_S,   Q_S,
   Q_S,   Q_S,   Q_S,   Q_S,  '\n',   Q_S,   Q_S,   Q_S,   Q_S,
   Q_S,  '\t',   Q_S,  '\v',   Q_S,   Q_X,   Q_S,   Q_S
};

static struct {
  char		   *conf_file;	     /* file name of config file */
  char		   *log_file;	     /* file name of log file */
  char		   *prog_name;	     /* program's name */
  struct test_prog *prog_list;	     /* list of test programs */
  struct test_prog *prog_last;	     /* last program in list */
  int		    prog_count;	     /* count of test programs */
  int		    prog_running;    /* count of running programs */
  int		    prog_max;	     /* maximum simultaneous programs */
  char		  **include_dirs;    /* directories to be searched for progs */
  int		    include_cnt;     /* count of include directories */
  int		    include_size;    /* total memory for include_dirs */
  char		  **argv;	     /* argument vector */
  int		    argc;	     /* argument count */
  unsigned int	    flags;	     /* any special flags */
  int		    test_total;	     /* total number of tests */
  FILE		   *log_fp;	     /* log FILE object */
  int		    log_fd;	     /* log file file descriptor */
  int		    high_fd;	     /* highest fd so far allocated */
  int		    result_count[8]; /* count of all results */
  fd_set	    read_fds;	     /* descriptors to be read */
} glob_data = { "test-harness.dat", "test-harness.log", 0, 0, 0, 0, 0, 1, 0, 0,
		0, 0, 0, 0, 0, 0, -1, -1,
		{ 0, 0, 0, 0, 0, 0, 0, 0 } };

#define FLAG_VERBOSE  0x0001 /* verbose output enabled */
#define FLAG_VVERBOSE 0x0002 /* very verbose output enabled */
#define FLAG_POSIX    0x0004 /* POSIX-compliant output only */
#define FLAG_FINISHED 0x1000 /* finished starting all tests */

/* If allocation of memory fails, we must exit */
static void *
xmalloc(size_t size)
{
  void *ptr;

  if (!(ptr = malloc(size))) { /* get some memory */
    perror(glob_data.prog_name); /* error occurred, bail out */
    exit(1);
  }

  return ptr; /* return the memory allocated */
}

/* Similar function to realloc memory */
static void *
xrealloc(void *ptr, size_t size)
{
  void *nptr;

  if (!(nptr = realloc(ptr, size))) { /* reallocate the memory */
    perror(glob_data.prog_name); /* error occurred, bail out */
    exit(1);
  }

  return nptr; /* return new memory allocation */
}

/* Duplicate a string */
static char *
xstrdup(const char *str)
{
  char *ptr;

  if (!str) /* if no string to allocate, allocate none */
    return 0;

  if (!(ptr = strdup(str))) { /* duplicate the string */
    perror(glob_data.prog_name); /* error occurred, bail out */
    exit(1);
  }

  return ptr; /* return the new string */
}

/* Duplicate a parameter list */
static char **
argvdup(char * const *params, int count)
{
  char **nparams;
  int i;

  if (!params) /* no parameters to duplicate? */
    return 0;

  if (count <= 0) /* must count it ourselves */
    for (count = 0; params[count]; count++) /* count through params */
      ; /* empty for loop */

  nparams = xmalloc(sizeof(char *) * (count + 1)); /* allocate memory */

  for (i = 0; i < count; i++) /* go through params */
    nparams[i] = xstrdup(params[i]); /* and duplicate each one */

  nparams[count] = 0; /* zero out end of vector */

  return nparams; /* and return the vector */
}

/* Create a new program */
static struct test_prog *
add_prog(const char *name, const char *prog, const char *desc,
	 char * const *params, int count)
{
  struct test_prog *tp;

  tp = xmalloc(sizeof(struct test_prog)); /* allocate memory */

  tp->tp_next = 0; /* initialize the struct test_prog */
  tp->tp_prev_p = 0;
  tp->tp_name = xstrdup(name);
  tp->tp_prog = xstrdup(prog);
  tp->tp_argv = argvdup(params, count);
  tp->tp_desc = xstrdup(desc);
  tp->tp_tests = 0;
  tp->tp_last = 0;
  tp->tp_count = 0;
  tp->tp_deps = 0;
  tp->tp_status = TP_PENDING;
  tp->tp_fd = -1;
  tp->tp_file = 0;
  tp->tp_pid = 0;

  if (!glob_data.prog_list) { /* add it to the global data list */
    glob_data.prog_list = tp;
    tp->tp_prev_p = &glob_data.prog_list;
  } else if (glob_data.prog_last) {
    glob_data.prog_last->tp_next = tp;
    tp->tp_prev_p = &glob_data.prog_last->tp_next;
  }
  glob_data.prog_last = tp;
  glob_data.prog_count++;

  return tp; /* return it */
}

/* Create a new test */
static struct test *
add_test(struct test_prog *tp, const char *name, const char *desc,
	 enum test_result expect)
{
  struct test *t;

  t = xmalloc(sizeof(struct test)); /* allocate memory */

  t->t_next = 0; /* initialize the struct test */
  t->t_name = xstrdup(name);
  t->t_desc = xstrdup(desc);
  t->t_result = TR_NOTRUN;
  t->t_expect = expect;
  t->t_prog = tp;
  t->t_info = 0;

  if (!tp->tp_tests) /* add it to the program's data list */
    tp->tp_tests = t;
  else if (tp->tp_last)
    tp->tp_last->t_next = t;
  tp->tp_last = t;
  tp->tp_count++; /* keep count */

  glob_data.test_total++; /* total number of tests */
  glob_data.result_count[TR_NOTRUN]++; /* keep a count */

  return t; /* return it */
}

/* Add a dependency */
static struct test_dep *
add_dep(struct test_prog *tp, struct test_prog *dep)
{
  struct test_dep *td;

  td = xmalloc(sizeof(struct test_dep)); /* allocate memory */

  td->td_next = tp->tp_deps; /* initialize dependency structure */
  td->td_prog = dep;

  tp->tp_deps = td; /* add it to the list */

  return td; /* return dependency */
}

/* Close all test program input file descriptors before forking */
static void
close_progs(void)
{
  struct test_prog *tp;

  for (tp = glob_data.prog_list; tp; tp = tp->tp_next) /* walk linked list */
    if (tp->tp_fd >= 0) /* if fd is open... */
      close(tp->tp_fd); /* close it! */
}

/* Find a test program given its name */
static struct test_prog *
find_prog(const char *name)
{
  struct test_prog *tp;

  for (tp = glob_data.prog_list; tp; tp = tp->tp_next) /* walk linked list */
    if (!strcmp(tp->tp_name, name))
      return tp; /* found it, return it */

  return 0; /* nothing found */
}

/* Find a test given its name */
static struct test *
find_test(struct test_prog *tp, const char *name)
{
  struct test *t;

  for (t = tp->tp_tests; t; t = t->t_next) /* walk linked list */
    if (!strcmp(t->t_name, name))
      return t; /* found it, return it */

  return 0; /* nothing found */
}

/* Get a value given a name */
static enum test_result
find_result(const char *name)
{
  int i;

  for (i = 0; result_map[i].m_name; i++) /* walk through array */
    if (!strcasecmp(result_map[i].m_name, name))
      return result_map[i].m_value; /* found it, return it */

  return TR_UNRESOLVED; /* couldn't map name to value; must be resolved */
}

/* Get a name given a value */
#define name_result(val)	(result_map[(val)].m_name)

/* Set the result of a given test */
static void
set_result(struct test *t, enum test_result result, const char *info)
{
  glob_data.result_count[t->t_result]--; /* decrement one count */

  switch (result) { /* check result */
  case TR_NOTRUN: /* these should never be reported by a test program */
  case TR_UPASS:
  case TR_XFAIL:
    t->t_result = TR_UNRESOLVED; /* so mark it unresolved due to test error */
    break;

  case TR_PASS: /* a test passed */
    if (t->t_expect == TR_FAIL)
      t->t_result = TR_UPASS; /* expected to fail!  mark unexpected pass */
    else
      t->t_result = TR_PASS; /* normal pass */
    break;

  case TR_FAIL: /* a test failed */
    if (t->t_expect == TR_FAIL)
      t->t_result = TR_XFAIL; /* expected to fail; mark it as such */
    else
      t->t_result = TR_FAIL; /* wasn't expected to fail! */
    break;

  default:
    t->t_result = result; /* some other result */
    break;
  }

  glob_data.result_count[t->t_result]++; /* increment another count */

  t->t_info = xstrdup(info); /* remember extra information */

  result = t->t_result;

  /* save the result to the log file */
  fprintf(glob_data.log_fp, "%s: (%s/%s) %s\n", name_result(result),
	  t->t_prog->tp_name, t->t_name, t->t_desc);
  fprintf(glob_data.log_fp, "INFO: %s\n", t->t_info);

  if (!(glob_data.flags & FLAG_VERBOSE)) /* only output if verbose */
    return;

  if (glob_data.flags & FLAG_POSIX) { /* adjust for POSIX */
    if (result == TR_UPASS)
      result = TR_PASS;
    else if (result == TR_XFAIL)
      result = TR_FAIL;
  }

  /* print the result */
  printf("%s: (%s/%s) %s\n", name_result(result), t->t_prog->tp_name,
	 t->t_name, t->t_desc);
  if ((glob_data.flags & (FLAG_POSIX | FLAG_VVERBOSE)) == FLAG_VVERBOSE)
    printf("INFO: %s\n", t->t_info);
}

/* Mark all tests for a given program unresolved */
static void
mark_all(struct test_prog *tp, enum test_result result, const char *info)
{
  struct test *t;

  for (t = tp->tp_tests; t; t = t->t_next) /* walk linked list */
    if (t->t_result == TR_NOTRUN)
      set_result(t, result, info); /* mark it unresolved */
}

/* Find the test program */
static char *
locate_file(const char *prog, char *buf, int mode)
{
  int i;
  char *dir;

  if (glob_data.include_cnt) /* search include directories */
    for (i = 0; i < glob_data.include_cnt; i++) {
      dir = glob_data.include_dirs[i];

      sprintf(buf, "%s/%s", dir, prog); /* form program file name */

      if (!access(buf, mode)) /* check access */
	return buf; /* Ok, return program name */
    }
  else {
    sprintf(buf, "./%s", prog); /* form program file name */

    if (!access(buf, mode)) /* check access */
      return buf; /* Ok, return program name */
  }

  return 0; /* failed to find the program */
}

/* Build an argument list for executing a program */
static char **
build_argv(char *name, char **params)
{
  char **nparams;
  int i, count = 1;

  if (glob_data.argv) { /* global arguments to pass */
    for (i = 0; glob_data.argv[i]; i++) /* step through those arguments... */
      ; /* but do nothing other than count them */

    count += i; /* now add them to the count */
  }

  if (params) { /* arguments for this specific test program */
    for (i = 0; params[i]; i++) /* step through them... */
      ; /* but do nothing other than count them */

    count += i; /* now add them to the count */
  }

  nparams = xmalloc(sizeof(char *) * (count + 1)); /* allocate memory */

  nparams[0] = name; /* program name, first */
  count = 1; /* next place to put an argument */

  if (glob_data.argv) /* now global arguments... */
    for (i = 0; glob_data.argv[i]; i++) /* step through the arguments... */
      nparams[count++] = glob_data.argv[i]; /* set argument value */

  if (params) /* next test program arguments */
    for (i = 0; params[i]; i++) /* step through them */
      nparams[count++] = params[i]; /* set argument value */

  nparams[count] = 0; /* end with a 0 value */

  return nparams; /* return parameters */
}

/* Execute a test program */
static int
execute_prog(struct test_prog *tp)
{
  int fds[2], stat, err;
  char progbuf[BUFSIZE], *prog;

  if (!(prog = locate_file(tp->tp_prog, progbuf, X_OK))) { /* find program */
    mark_all(tp, TR_UNTESTED, "Unable to locate test program");
    tp->tp_status = TP_FAILED;
    return 0;
  }

  if (pipe(fds)) { /* now set up the pipe for it */
    mark_all(tp, TR_UNRESOLVED, strerror(errno));
    tp->tp_status = TP_FAILED;
    return 0;
  }

  switch ((tp->tp_pid = fork())) {
  case -1: /* couldn't fork! */
    err = errno; /* save errno */
    close(fds[0]); /* close file descriptors */
    close(fds[1]);
    mark_all(tp, TR_UNRESOLVED, strerror(err));
    tp->tp_status = TP_FAILED;
    return 0;
    break;

  case 0: /* we're in the child */
    close(fds[0]); /* close read end of the pipe */
    close(0); /* close stdin */
    close(1); /* close stdout */
    close(2); /* close stderr */
    close_progs(); /* close all test programs' input descriptors */

    dup2(fds[1], 1); /* make stdout point to write end of pipe */
    close(fds[1]); /* close redundant file descriptor */

    dup2(glob_data.log_fd, 2); /* make stderr go to log file */
    close(glob_data.log_fd); /* close redundant file descriptor */

    execv(prog, build_argv(prog, tp->tp_argv)); /* execute program */

    printf("UNRESOLVED/ALL:Couldn't execute test: %s\n", strerror(errno));
    exit(1); /* report error and exit child */
    break;

  default: /* we're in the parent */
    close(fds[1]); /* close write end of the pipe */
    if (!(tp->tp_file = fdopen(fds[0], "r"))) { /* open FILE object */
      err = errno; /* save value of errno */
      close(fds[0]); /* it failed; close the file descriptor */
      kill(tp->tp_pid, SIGKILL); /* kill the child */
      waitpid(tp->tp_pid, &stat, 0); /* wait for child */
      tp->tp_pid = 0; /* clear PID */
      mark_all(tp, TR_UNRESOLVED, strerror(err));
      tp->tp_status = TP_FAILED;
      return 0;
    }
    tp->tp_fd = fds[0]; /* store the fd */
    tp->tp_status = TP_RUNNING;
    FD_SET(fds[0], &glob_data.read_fds); /* record interest in fd */
    if (fds[0] > glob_data.high_fd) /* remember the highest fd so far */
      glob_data.high_fd = fds[0];
    break;
  }

  return 1;
}

/* Find a test program to execute */
static struct test_prog *
next_test(struct test_prog *tp)
{
  struct test_dep *td;

  if (!tp) /* start at beginning of prog list if no test prog passed in */
    tp = glob_data.prog_list;

  for (; tp; tp = tp->tp_next) {
    if (tp->tp_status != TP_PENDING) /* skip non-pending tests */
      continue;

    if (!tp->tp_deps) /* no dependencies?  just return it */
      return tp;

    for (td = tp->tp_deps; td; td = td->td_next) {
      if (!td->td_prog) /* broken dependency, ignore it */
	continue;

      switch (td->td_prog->tp_status) {
      case TP_FAILED: /* dependent test failed... */
	mark_all(tp, TR_UNTESTED, "Test dependency failed");
	tp->tp_status = TP_FAILED; /* mark us failed */
	*tp->tp_prev_p = tp->tp_next; /* clip us out of the list */
	/*FALLTHROUGH*/
      case TP_PENDING: /* hasn't been executed yet */
      case TP_RUNNING: /* dependent test is currently executing... */
	break; /* bail out and process the next test program */

      case TP_COMPLETE: /* dependent test is complete, cool */
	continue; /* Go check next dependency */
	break;
      }

      break;
    }

    if (!td) /* checked all dependencies, everything checks out. */
      return tp;
  }

  return 0;
}

/* Start some test programs */
static void
run_test(void)
{
  struct test_prog *tp;

  if (glob_data.flags & FLAG_FINISHED) /* are we already done? */
    return;

  /* start some test programs */
  for (tp = next_test(0); tp && !(glob_data.flags & FLAG_FINISHED);
       tp = next_test(tp)) {
    if (glob_data.prog_running >= glob_data.prog_max) /* too many running? */
      return; /* just wait for a bit */
    else { /* execute and update count of how many are running */
      if (execute_prog(tp) && ++glob_data.prog_running >= glob_data.prog_max)
	return; /* if we've hit the limit, don't look for another */
    }
  }

  /* If no programs are running, we're either done or have a cycle */
  if (!tp && glob_data.prog_running == 0) {
    /* mark any pending tests as failed */
    for (tp = glob_data.prog_list; tp; tp = tp->tp_next) {
      if (tp->tp_status != TP_PENDING) /* skip non-pending entries */
	continue;

      /* Inform user about dependancy loop */
      fprintf(stderr, "Dependencies for %s failed due to cycle\n",
	      tp->tp_name);

      /* Fail everything */
      mark_all(tp, TR_UNTESTED, "Test dependency failed--cycle");
      tp->tp_status = TP_FAILED;
      *tp->tp_prev_p = tp->tp_next;
    }

    glob_data.flags |= FLAG_FINISHED; /* we're done! */
  }
}

/* Place the results of the test in a file */
static void
report_test_fp(FILE *fp, int posix)
{
  int count;

  fprintf(fp, "================== Test Results Summary ==================\n");

  fprintf(fp, "Total tests: %d\n", glob_data.test_total);

  if (glob_data.result_count[TR_NOTRUN] > 0)
    fprintf(fp, "Tests not run: %d\n", glob_data.result_count[TR_NOTRUN]);

  count = glob_data.result_count[TR_PASS] + glob_data.result_count[TR_UPASS];
  if (count > 0)
    fprintf(fp, "Tests passed: %d\n", count);
  if (!posix && glob_data.result_count[TR_PASS] != count) {
    if (glob_data.result_count[TR_PASS] > 0)
      fprintf(fp, "  Expected: %d\n", glob_data.result_count[TR_PASS]);
    if (glob_data.result_count[TR_UPASS] > 0)
      fprintf(fp, "  Unexpected: %d\n", glob_data.result_count[TR_UPASS]);
  }

  count = glob_data.result_count[TR_FAIL] + glob_data.result_count[TR_XFAIL];
  if (count > 0)
    fprintf(fp, "Tests failed: %d\n", count);
  if (!posix && glob_data.result_count[TR_XFAIL] != count) {
    if (glob_data.result_count[TR_XFAIL] > 0)
      fprintf(fp, "  Expected: %d\n", glob_data.result_count[TR_XFAIL]);
    if (glob_data.result_count[TR_FAIL] > 0)
      fprintf(fp, "  Unexpected: %d\n", glob_data.result_count[TR_FAIL]);
  }

  if (glob_data.result_count[TR_UNRESOLVED] > 0)
    fprintf(fp, "Unresolved tests: %d\n",
	    glob_data.result_count[TR_UNRESOLVED]);

  if (glob_data.result_count[TR_UNTESTED] > 0)
    fprintf(fp, "Untested test cases: %d\n",
	    glob_data.result_count[TR_UNTESTED]);

  if (glob_data.result_count[TR_UNSUPPORTED] > 0)
    fprintf(fp, "Unsupported tests: %d\n",
	    glob_data.result_count[TR_UNSUPPORTED]);

  fprintf(fp, "==========================================================\n");
}

/* Report the results of the test */
static void
report_test(void)
{
  report_test_fp(glob_data.log_fp, 0);
  report_test_fp(stdout, glob_data.flags & FLAG_POSIX);
}

/* Read data from a test program */
static void
read_test(struct test_prog *tp)
{
  int stat;
  struct test *t = 0;
  enum test_result result;
  char buf[BUFSIZE], *rescode = 0, *testcode = 0, *info = 0, *tmp;

  if (!fgets(buf, sizeof(buf), tp->tp_file)) { /* child exited */
    waitpid(tp->tp_pid, &stat, 0); /* wait for child */
    if (WIFEXITED(stat)) {
      sprintf(buf, "Test program exited with status %d", WEXITSTATUS(stat));
      mark_all(tp, WEXITSTATUS(stat) ? TR_UNRESOLVED : TR_UNTESTED, buf);
      tp->tp_status = WEXITSTATUS(stat) ? TP_FAILED : TP_COMPLETE;
    } else if (WIFSIGNALED(stat)) {
      sprintf(buf, "Test program terminated by signal %d", WTERMSIG(stat));
      mark_all(tp, TR_UNRESOLVED, buf);
      tp->tp_status = TP_FAILED;
    } else {
      mark_all(tp, TR_UNRESOLVED, "Test program exited with unknown code");
      tp->tp_status = TP_FAILED;
    }

    close(tp->tp_fd); /* close file descriptor */
    fclose(tp->tp_file); /* close file object */

    FD_CLR(tp->tp_fd, &glob_data.read_fds); /* clear fd bit in read set */

    tp->tp_fd = -1; /* clear out the struct test_prog object's run status */
    tp->tp_file = 0;
    tp->tp_pid = 0;

    if (--glob_data.prog_running < glob_data.prog_max)
      run_test(); /* freed up a slot for a new test program */
  } else {
    if ((tmp = strchr(buf, '\n'))) /* remove newline */
      *tmp = '\0';

    rescode = buf; /* find result code */

    if (!(testcode = strchr(buf, '/'))) /* locate test code */
      return;

    *(testcode++) = '\0'; /* nul-terminate and advance in one swell foop */

    if ((info = strchr(testcode, ':'))) /* locate extra info */
      *(info++) = '\0'; /* nul-terminate and advance in one swell foop */

    result = find_result(rescode); /* get the result */

    if (!strcmp(testcode, "ALL")) /* special test code marks every test */
      mark_all(tp, result, info);
    else if ((t = find_test(tp, testcode)))
      set_result(t, result, info); /* set the result if we found test */
    else {
      fprintf(glob_data.log_fp, "%s: (%s/%s) Unknown test (will not be "
	      "counted)\n", name_result(result), tp->tp_name, testcode);
      fprintf(glob_data.log_fp, "INFO: %s\n", info);
      if (glob_data.flags & FLAG_VERBOSE)
	printf("%s: (%s/%s) Unknown test (will not be counted)\n",
	       name_result(result), tp->tp_name, testcode);
      if ((glob_data.flags & (FLAG_POSIX | FLAG_VVERBOSE)) == FLAG_VVERBOSE)
	printf("INFO: %s\n", info);
    }
  }
}

/* Wait for data from test programs */
static void
run_select(void)
{
  int nfds;
  fd_set read_set;
  struct test_prog *tp;

  while (glob_data.prog_running || !(glob_data.flags & FLAG_FINISHED)) {
    read_set = glob_data.read_fds; /* all hail structure copy! */

    nfds = select(glob_data.high_fd + 1, &read_set, 0, 0, 0);

    for (tp = glob_data.prog_list; tp; tp = tp->tp_next) /* walk linked list */
      if (tp->tp_fd >= 0 && FD_ISSET(tp->tp_fd, &read_set)) { /* found one */
	read_test(tp); /* read the data... */
	if (--nfds) /* are we done yet? */
	  break;
      }
  }
}

/* Retrieves a \ quoted sequence from a file and produces the correct
 * output character
 */
static int
unquote(FILE *fp)
{
  int c = 0, i, cnt = 0;

  if ((i = getc(fp)) == EOF) /* retrieve the character after the \ */
    return EOF;

  if (i == '\n') /* just a line continuation */
    return CONTINUELINE;
  if (i >= 'a' && i <= 'z') { /* special lower-case letters... */
    switch (xform[i - 'a']) {
    case Q_S: /* insert the character itself */
      return i;
      break;

    case Q_X: /* \xHH--introduces a hex char code */
      while (cnt < 2 && (i = getc(fp)) != EOF) {
	if (!isxdigit(i)) { /* wasn't a hex digit? put it back */
	  ungetc(i, fp);
	  return cnt ? c : EOF; /* return error if no chars */
	} else {
	  if (isdigit(i)) /* calculate character code */
	    c = (c << 4) | (i - '0');
	  else if (isupper(i))
	    c = (c << 4) | ((i - 'A') + 10);
	  else
	    c = (c << 4) | ((i - 'a') + 10);
	}
	cnt++;
      }
      return cnt ? c : EOF; /* return error if no chars */
      break;

    case Q_D: /* \dNNN--introduces a decimal char code */
      while (cnt < 3 && (i = getc(fp)) != EOF) {
	if (!isdigit(i)) { /* wasn't a digit? put it back */
	  ungetc(i, fp);
	  return cnt ? c : EOF; /* return error if no chars */
	} else {
	  c = (c * 10) + (i - '0'); /* calculate character code */
	  if (c > 255) { /* oops, char overflow, backup */
	    ungetc(i, fp);
	    return c / 10;
	  }
	}
	cnt++;
      }
      return cnt ? c : EOF; /* return error if no chars */
      break;

    default: /* insert the specified code */
      return xform[i - 'a'];
      break;
    }
  } else if (i >= '0' && i <= '7') { /* octal number */
    c = (i - '0'); /* accumulate first code... */
    while (cnt < 2 && (i = getc(fp)) != EOF) { /* get the rest */
      if (i < '0' || i > '7') { /* not a valid octal number, put it back */
	ungetc(i, fp);
	return c;
      } else
	c = (c << 3) | (i - '0'); /* accumulate the next code */
      cnt++;
    }
    return c;
  }

  return i; /* return the character itself */
}

/* Create a program */
static void
create_prog(const char *name, const char *prog, const char *desc,
	    char * const *params, int count)
{
  struct test_prog *tp;

  if ((tp = find_prog(name))) /* don't add duplicate programs */
    fprintf(stderr, "%s: Duplicate \"program\" directive for \"%s\" found; "
	    "ignoring\n", glob_data.prog_name, name);
  else
    add_prog(name, prog, desc, params, count);
}

/* Create a test case */
static void
create_test(const char *name, const char *prog, const char *expect_code,
	    const char *desc)
{
  struct test_prog *tp;
  struct test *t;
  enum test_result expect;

  switch ((expect = find_result(expect_code))) {
  case TR_NOTRUN: /* invalid values for expectation */
  case TR_UPASS:
  case TR_XFAIL:
  case TR_UNRESOLVED:
  case TR_UNTESTED:
  case TR_UNSUPPORTED:
    fprintf(stderr, "%s: Invalid expectation code \"%s\" for test \"%s\"; "
	    "ignoring\n", glob_data.prog_name, expect_code, name);
    return;
    break;

  default:
    break;
  }

  if (!(tp = find_prog(prog))) /* must have a program directive */
    fprintf(stderr, "%s: No \"program\" directive for test \"%s\"; ignoring\n",
	    glob_data.prog_name, name);
  else if ((t = find_test(tp, name))) /* no duplicate tests */
    fprintf(stderr, "%s: Duplicate \"test\" directive for \"%s\" in program "
	    "\"%s\" found; ignoring\n", glob_data.prog_name, name, prog);
  else /* create the test */
    add_test(tp, name, desc, expect);
}

/* Create a dependency */
static void
create_dep(const char *prog, char * const *deps, int count)
{
  struct test_prog *tp, *dep;
  struct test_dep *td;

  if (!(tp = find_prog(prog))) /* must have a program directive */
    fprintf(stderr, "%s: No \"program\" directive for dependency \"%s\"; "
	    "ignoring\n", glob_data.prog_name, prog);
  else /* create the dependencies */
    for (; count; count--, deps++) {
      if (!(dep = find_prog(*deps))) { /* does the dependency exist? */
	fprintf(stderr, "%s: Program \"%s\" dependent on non-existant "
		"program \"%s\"; ignoring\n", glob_data.prog_name, prog,
		*deps);
	continue;
      }

      /* Walk through the dependencies to weed out duplicates */
      for (td = tp->tp_deps; ; td = td->td_next)
	if (!td) {
	  add_dep(tp, dep); /* add the dependency */
	  break; /* explicitly exit the loop */
	} else if (td->td_prog == dep)
	  break; /* silently ignore identical dependencies */
    }
}

/* Report too few arguments problems */
static void
check_args(int count, int min, char *directive)
{
  if (count >= min) /* Check argument count */
    return;

  fprintf(stderr, "%s: Too few arguments for %s directive\n",
	  glob_data.prog_name, directive);
  exit(1);
}

/* Read the configuration file */
static void
read_conf(char *filename)
{
  enum {
    s_space, s_comment, s_string
  } state = s_space, save = s_space;
  char *buf = 0, **args = 0, filebuf[BUFSIZE], *file, file2buf[BUFSIZE];
  char *file2, *s;
  int buflen = BUFSIZE, pos = 0, arglen = ARGBUF, argidx = 0, c, flags = 0;
  int file2pos = 0;
  FILE *fp;

  if (!(file = locate_file(filename, filebuf, R_OK))) { /* find file */
    fprintf(stderr, "%s: Unable to locate config file %s for reading\n",
	    glob_data.prog_name, filename);
    exit(1);
  }

  if (!(fp = fopen(file, "r"))) { /* open config file */
    fprintf(stderr, "%s: Unable to open config file %s for reading\n",
	    glob_data.prog_name, file);
    exit(1);
  }

  buf = xmalloc(buflen); /* get some memory for the buffers */
  args = xmalloc(sizeof(char *) * arglen);

  while (!(flags & STOP)) {
    c = getc(fp); /* get a character */
    flags &= ~(QUOTED | EOS | EOD); /* reset quoted and end-of-* flags */

    if (state == s_comment) {
      if (c != '\n' && c != EOF)
	continue; /* skip comment... */
      else
	state = save; /* but preserve ending character and process */
    }

    if (flags & SAVE_QUOTE)
      flags = (flags & ~SAVE_QUOTE) | QUOTED;
    else {
      if (!(flags & QUOTE_SINGLE) && c == '"') { /* process double quote */
	flags ^= QUOTE_DOUBLE;
	continue; /* get next character */
      } else if (!(flags & QUOTE_DOUBLE) && c == '\'') { /* single quote */
	flags ^= QUOTE_SINGLE;
	continue; /* get next character */
      } else if (!(flags & QUOTE_SINGLE) && c == '<') { /* open file quote */
	file2pos = pos;
	flags |= QUOTE_FILE;
	continue; /* skip the < */
      } else if (!(flags & QUOTE_SINGLE) && c == '>') { /* close file quote */
	if (!(flags & QUOTE_FILE)) { /* close file quote with no open? */
	  fprintf(stderr, "%s: Mismatched closing file quote ('>') while "
		  "parsing config file %s\n", glob_data.prog_name, file);
	  exit(1);
	}
	flags &= ~QUOTE_FILE; /* turn off file quote flag */
	buf[pos] = '\0'; /* terminate buffer temporarily */
	if (!(file2 = locate_file(&buf[file2pos], file2buf, R_OK)))
	  fprintf(stderr, "%s: WARNING: Unable to find file %s\n",
		  glob_data.prog_name, &buf[file2pos]);
	else {
	  pos = file2pos; /* rewind in buffer... */
	  while (*file2) { /* copy filename into buffer */
	    if (pos + 1 > buflen) /* get more memory for buffer if needed */
	      buf = xrealloc(buf, buflen <<= 1);
	    buf[pos++] = *(file2++); /* copy the character */
	  }
	}
	continue; /* skip the > */
      } else if (!(flags & QUOTE_SINGLE) && c == '\\') { /* character quote */
	if ((c = unquote(fp)) == EOF) { /* unquote the character */
	  fprintf(stderr, "%s: Hanging \\ while parsing config file %s\n",
		  glob_data.prog_name, file);
	  exit(1);
	} else if (c == CONTINUELINE) /* continue line--not a quoted char */
	  c = ' ';
	else
	  flags |= QUOTED; /* mark character as quoted */
      }
      /* Check to see if the character appears in quotes; this is not part
       * of an if-else chain because a '\' followed by a newline inside a
       * double-quoted string should produce a _quoted_ space, and the
       * test above gives us an _unquoted_ space!
       */
      if (flags & (QUOTE_SINGLE | QUOTE_DOUBLE | QUOTE_FILE)) {
	if (c == EOF) {
	  fprintf(stderr, "%s: Unmatched %s quote (%s) while parsing config "
		  "file %s\n", glob_data.prog_name, flags & QUOTE_SINGLE ?
		  "single" : (flags & QUOTE_DOUBLE ? "double" : "file"),
		  flags & QUOTE_SINGLE ? "\"'\"" : (flags & QUOTE_DOUBLE ?
						    "'\"'" : "'<'"), file);
	  exit(1);
	} else if (!(flags & QUOTE_FILE)) /* file quotes aren't real quotes */
	  flags |= QUOTED; /* mark character as quoted */
      }
    }

    if (!(flags & QUOTED) && c == '#') { /* found beginning of a comment */
      save = state; /* save current state--we'll restore to here */
      state = s_comment; /* switch to comment state */
      continue; /* skip all characters in the comment */
    }

    /* Now let's figure out what to do with this thing... */
    if (c == EOF) /* end of file? */
      flags |= (state == s_string ? EOS : 0) | EOD | STOP; /* ends directive */
    else /* ok, switch on state */
      switch (state) {
      case s_space: /* Looking for the *end* of a string of spaces */
	if ((flags & QUOTED) || !isspace(c)) { /* non-space character! */
	  state = s_string; /* Switch to string state */
	  ungetc(c, fp); /* push character back onto stream */
	  if (flags & QUOTED) /* save quote flag */
	    flags |= SAVE_QUOTE;
	  if (argidx + 1 > arglen) /* get more memory for args if needed */
	    args = xrealloc(args, sizeof(char *) * (arglen <<= 1));
	  args[argidx++] = buf + pos; /* point to starting point of next arg */
	  args[argidx] = 0; /* make sure to terminate the array */
	}
	if (c == '\n') /* hit end of line? */
	  flags |= EOD; /* end of the directive, then */
	else
	  continue; /* move on to next character */
	break;

      case s_comment: /* should never be in this state here */
	break;

      case s_string: /* part of a string */
	/* unquoted space or end of file ends string */
	if ((!(flags & QUOTED) && isspace(c))) {
	  state = s_space; /* will need to search for next non-space */
	  /* finished accumulating this string--if it's \n, done with the
	   * directive, as well.
	   */
	  flags |= EOS | (c == '\n' ? EOD : 0);
	}
	break;
      }

    if (pos + 1 > buflen) /* get more memory for buffer if needed */
      buf = xrealloc(buf, buflen <<= 1);

    if (flags & EOS) /* end of string? */
      buf[pos++] = '\0'; /* end the string in the buffer */

    if (flags & EOD) { /* end of directive? */
      if (pos == 0) /* nothing's actually been accumulated */
	continue; /* so go on */

      if (!strcmp(args[0], "program")) { /* program directive */
	check_args(argidx, 3, args[0]);
	create_prog(args[1], args[2], argidx > 3 ? args[3] : "",
		    argidx > 4 ? args + 4 : 0, argidx > 4 ? argidx - 4 : 0);
      } else if (!strcmp(args[0], "test")) { /* test directive */
	check_args(argidx, 4, args[0]);
	create_test(args[1], args[2], args[3], argidx > 4 ? args[4] : "");
      } else if (!strcmp(args[0], "include")) { /* include directive */
	check_args(argidx, 2, args[0]);
	read_conf(args[1]);
      } else if ((s = strchr(args[0], ':')) && *(s + 1) == '\0') {
	*s = '\0'; /* it's a dependency specification */
	create_dep(args[0], args + 1, argidx - 1);
      } else {
	fprintf(stderr, "%s: Unknown directive \"%s\"\n", glob_data.prog_name,
		args[0]);
	exit(1);
      }

      if (flags & STOP) /* if we were told to stop, well, STOP! */
	break;

      pos = 0; /* prepare for the next round through */
      argidx = 0;
      flags = 0;
      args[0] = buf;
      state = s_space;
      continue; /* go on */
    }

    if (!(flags & (EOS | EOD))) /* insert character into buffer */
      buf[pos++] = c;
  }

  fclose(fp); /* clean up */
  free(buf);
  free(args);
}

/* Add another include directory to the list */
static void
add_include(char *dir)
{
  if (glob_data.include_cnt + 1 > glob_data.include_size) /* get more memory */
    glob_data.include_dirs =
      xrealloc(glob_data.include_dirs,
	       sizeof(char *) * (glob_data.include_size <<= 1));
  glob_data.include_dirs[glob_data.include_cnt++] = dir;
}

/* Output a standard usage message and exit */
static void
usage(int ret)
{
  fprintf(stderr, "Usage: %s -hvp [-c <conf>] [-l <log>] [-i <include>]\n",
	  glob_data.prog_name);
  fprintf(stderr, "       %*s [-I <include>] [-j <max>]\n",
	  (int)strlen(glob_data.prog_name), "");
  fprintf(stderr, "\n  -h\t\tPrint this help message\n");
  fprintf(stderr, "  -v\t\tVerbose output; multiple usages increase verbosity "
	  "level\n");
  fprintf(stderr, "  -p\t\tRequest POSIX-compliant test output\n");
  fprintf(stderr, "  -c <conf>\tUse <conf> as the configuration file\n");
  fprintf(stderr, "  -l <log>\tUse <log> as the log file for test programs\n");
  fprintf(stderr, "  -i <include>\tAdd <include> to list of directories "
	  "searched for test programs.\n");
  fprintf(stderr, "  -I <include>\tSynonymous with \"-i\"\n");
  fprintf(stderr, "  -j <max>\tSpecifies the maximum number of test programs "
	  "that may be\n");
  fprintf(stderr, "\t\texecuted simultaneously\n");
  fprintf(stderr, "\nArguments following a \"--\" are passed to all "
	  "test programs run by this program.\n");

  exit(ret);
}

/* Here's what drives it all */
int
main(int argc, char **argv)
{
  int c;

  FD_ZERO(&glob_data.read_fds); /* first, zero out the fd set */

  if (!(glob_data.prog_name = strrchr(argv[0], '/'))) /* set program name */
    glob_data.prog_name = argv[0];
  else
    glob_data.prog_name++;

  while ((c = getopt(argc, argv, "c:l:I:i:j:vph")) != EOF)
    switch (c) {
    case 'c': /* set the config file */
      glob_data.conf_file = optarg;
      break;

    case 'l': /* set the log file */
      glob_data.log_file = optarg;
      break;

    case 'I': /* add an include dir */
    case 'i':
      if (!glob_data.include_dirs)
	glob_data.include_dirs =
	  xmalloc(sizeof(char *) * (glob_data.include_size = ARGBUF));
      add_include(optarg);
      break;

    case 'j': /* maximum number of simultaneous test programs to run */
      if ((glob_data.prog_max = atoi(optarg)) < 1) {
	fprintf(stderr, "%s: Must be able to run a test program!\n",
		glob_data.prog_name);
	usage(1);
      }
      break;

    case 'v': /* requesting verbosity */
      if (glob_data.flags & FLAG_VERBOSE)
	glob_data.flags |= FLAG_VVERBOSE; /* double-verbosity! */
      else
	glob_data.flags |= FLAG_VERBOSE;
      break;

    case 'p': /* requesting POSIX-compliant output */
      glob_data.flags |= FLAG_POSIX;
      break;

    case 'h': /* requesting a usage message */
      usage(0);
      break;

    case '?': /* unknown option */
    default:
      usage(1);
      break;
    }

  if (optind < argc) {
    glob_data.argv = argv + optind; /* save trailing arguments */
    glob_data.argc = argc - optind;
  }

  if ((glob_data.log_fd =
       open(glob_data.log_file, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) < 0) {
    fprintf(stderr, "%s: Cannot open log file: %s\n", glob_data.prog_name,
	    strerror(errno));
    exit(1);
  } else if (!(glob_data.log_fp = fdopen(glob_data.log_fd, "a"))) {
    perror(glob_data.prog_name);
    exit(1);
  }

  setvbuf(glob_data.log_fp, 0, _IOLBF, 0);

  read_conf(glob_data.conf_file); /* read the configuration file */
  run_test(); /* start some tests */
  run_select(); /* now wait for the test results */

  report_test(); /* issue final report */

  return 0;
}
