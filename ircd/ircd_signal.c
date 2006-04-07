/*
 * IRC - Internet Relay Chat, ircd/ircd_signal.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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
 * @brief Signal handlers for ircu.
 * @version $Id$
 */
#include "config.h"

#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_log.h"
#include "ircd_signal.h"
#include "s_conf.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/** Records a function to be called when a child process terminates. */
struct ChildRecord {
  struct ChildRecord *next;
  SigChldCallBack call;
  void *datum;
  pid_t cpid;
};

/** Counts various types of signals that we receive. */
static struct tag_SignalCounter {
  unsigned int alrm; /**< Received SIGALRM count. */
  unsigned int hup;  /**< Received SIGHUP count. */
  unsigned int chld; /**< Received SIGCHLD count. */
} SignalCounter;

/** Event generator for SIGHUP. */
static struct Signal sig_hup;
/** Event generator for SIGINT. */
static struct Signal sig_int;
/** Event generator for SIGTERM. */
static struct Signal sig_term;
/** Event generator for SIGCHLD. */
static struct Signal sig_chld;
/** List of active child process callback requests. */
static struct ChildRecord *children;
/** List of inactive (free) child records. */
static struct ChildRecord *crec_freelist;

/* Make sure we have a definition for SIGCHLD. */
#if !defined(SIGCHLD)
# define SIGCHLD SIGCLD
#endif

/** Signal handler for SIGALRM.
 * @param[in] sig Signal number (ignored).
 */
static void sigalrm_handler(int sig)
{
  ++SignalCounter.alrm;
}

/** Signal callback for SIGTERM.
 * @param[in] ev Signal event descriptor.
 */
static void sigterm_callback(struct Event* ev)
{
  assert(0 != ev_signal(ev));
  assert(ET_SIGNAL == ev_type(ev));
  assert(SIGTERM == sig_signal(ev_signal(ev)));
  assert(SIGTERM == ev_data(ev));

  server_die("received signal SIGTERM");
}

/** Signal callback for SIGHUP.
 * @param[in] ev Signal event descriptor.
 */
static void sighup_callback(struct Event* ev)
{
  assert(0 != ev_signal(ev));
  assert(ET_SIGNAL == ev_type(ev));
  assert(SIGHUP == sig_signal(ev_signal(ev)));
  assert(SIGHUP == ev_data(ev));

  ++SignalCounter.hup;
  rehash(&me, 1);
}

/** Signal callback for SIGINT.
 * @param[in] ev Signal event descriptor.
 */
static void sigint_callback(struct Event* ev)
{
  assert(0 != ev_signal(ev));
  assert(ET_SIGNAL == ev_type(ev));
  assert(SIGINT == sig_signal(ev_signal(ev)));
  assert(SIGINT == ev_data(ev));

  server_restart("caught signal: SIGINT");
}

/** Allocate a child callback record.
 * @return Newly allocated callback record.
 */
static struct ChildRecord *alloc_crec(void)
{
  struct ChildRecord *crec;

  if (crec_freelist)
  {
    crec = crec_freelist;
    crec_freelist = crec->next;
  }
  else
  {
    crec = MyCalloc(1, sizeof(*crec));
  }

  memset(crec, 0, sizeof(*crec));
  crec->next = NULL;
  return crec;
}

/** Release \a crec, which is after \a prev.
 * @param[in] crec Child process callback record to release.
 */
static void release_crec(struct ChildRecord *crec)
{
  memset(crec, 0, sizeof(*crec));
  crec->next = crec_freelist;
  crec_freelist = crec;
}

/** Register a function to be called when a child process terminates.
 * @param[in] child Child process ID.
 * @param[in] call Function to call when process \a child terminates.
 * @param[in] datum Additional data parameter to pass to \a call.
 */
void register_child(pid_t child, SigChldCallBack call, void *datum)
{
  struct ChildRecord *crec;

  crec = alloc_crec();
  /* Link into #children list. */
  crec->next = children;
  children = crec;
  /* Fill in user fields. */
  crec->call = call;
  crec->datum = datum;
  crec->cpid = child;
}

/** Unregister all callbacks for a child process, optionally calling
 * them first.
 * @param[in] child Child process ID to unregister.
 * @param[in] do_call If non-zero, make the callbacks.
 * @param[in] status If \a do_call is non-zero, the child's exit status.
 */
static void do_unregister_child(pid_t child, int do_call, int status)
{
  struct ChildRecord *crec = children;
  struct ChildRecord *prev = NULL;

  while (crec != NULL)
  {
    if (crec->cpid == child)
    {
      if (do_call)
        crec->call(child, crec->datum, status);

      if (prev)
        prev->next = crec->next;
      else
        children = crec->next;

      release_crec(crec);
    }
    else
      prev = crec;
    crec = prev ? prev->next : children;
  }
}

/** Unregister all callbacks for a child process.
 * @param[in] child Child process ID to unregister.
 */
void unregister_child(pid_t child)
{
  do_unregister_child(child, 0, 0);
}

/** Signal handler for SIGCHLD.
 * @param[in] ev Signal event descriptor.
 */
static void sigchld_callback(struct Event *ev)
{
  pid_t cpid;
  int status;

  ++SignalCounter.chld;
  do {
    cpid = waitpid(-1, &status, WNOHANG);
    if (cpid > 0)
      do_unregister_child(cpid, 1, status);
  } while (cpid > 0);
}

/** Register all necessary signal handlers. */
void setup_signals(void)
{
  struct sigaction act;

  act.sa_handler = SIG_IGN;
  act.sa_flags = 0;
  sigemptyset(&act.sa_mask);
  sigaddset(&act.sa_mask, SIGPIPE);
  sigaddset(&act.sa_mask, SIGALRM);
#ifdef  SIGWINCH
  sigaddset(&act.sa_mask, SIGWINCH);
  sigaction(SIGWINCH, &act, 0);
#endif
  sigaction(SIGPIPE, &act, 0);

  act.sa_handler = sigalrm_handler;
  sigaction(SIGALRM, &act, 0);

  signal_add(&sig_hup, sighup_callback, 0, SIGHUP);
  signal_add(&sig_int, sigint_callback, 0, SIGINT);
  signal_add(&sig_term, sigterm_callback, 0, SIGTERM);
  signal_add(&sig_chld, sigchld_callback, 0, SIGCHLD);

#ifdef HAVE_RESTARTABLE_SYSCALLS
  /*
   * At least on Apollo sr10.1 it seems continuing system calls
   * after signal is the default. The following 'siginterrupt'
   * should change that default to interrupting calls.
   */
  siginterrupt(SIGALRM, 1);
#endif
}

/** Kill and clean up all child processes. */
void reap_children(void)
{
  /* Send SIGTERM to all children in process group.  Sleep for a
   * second to let them exit before we try to clean them up.
   */
  kill(0, SIGTERM);
  sleep(1);
  sigchld_callback(NULL);
}
