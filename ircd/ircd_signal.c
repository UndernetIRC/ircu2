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
 *
 * $Id$
 */
#include "config.h"

#include "ircd.h"
#include "ircd_events.h"
#include "ircd_signal.h"
#include "s_conf.h"

#include <assert.h>
#include <signal.h>

static struct tag_SignalCounter {
  unsigned int alrm;
  unsigned int hup;
} SignalCounter;

static struct Signal sig_hup;
static struct Signal sig_int;
static struct Signal sig_term;

static void sigalrm_handler(int sig)
{
  ++SignalCounter.alrm;
}

static void sigterm_callback(struct Event* ev)
{
  assert(0 != ev_signal(ev));
  assert(ET_SIGNAL == ev_type(ev));
  assert(SIGTERM == sig_signal(ev_signal(ev)));
  assert(SIGTERM == ev_data(ev));

  server_die("received signal SIGTERM");
}

static void sighup_callback(struct Event* ev)
{
  assert(0 != ev_signal(ev));
  assert(ET_SIGNAL == ev_type(ev));
  assert(SIGHUP == sig_signal(ev_signal(ev)));
  assert(SIGHUP == ev_data(ev));

  ++SignalCounter.hup;
  rehash(&me, 1);
}

static void sigint_callback(struct Event* ev)
{
  assert(0 != ev_signal(ev));
  assert(ET_SIGNAL == ev_type(ev));
  assert(SIGINT == sig_signal(ev_signal(ev)));
  assert(SIGINT == ev_data(ev));

  server_restart("caught signal: SIGINT");
}

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

#ifdef HAVE_RESTARTABLE_SYSCALLS
  /*
   * At least on Apollo sr10.1 it seems continuing system calls
   * after signal is the default. The following 'siginterrupt'
   * should change that default to interrupting calls.
   */
  siginterrupt(SIGALRM, 1);
#endif
}

