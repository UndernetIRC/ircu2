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
#include "ircd_signal.h"
#include "ircd.h"

#include <signal.h>

static struct tag_SignalCounter {
  unsigned int alrm;
  unsigned int hup;
} SignalCounter;

void sigalrm_handler(int sig)
{
  ++SignalCounter.alrm;
}

void sigterm_handler(int sig)
{
  server_die("received signal SIGTERM");
}

static void sighup_handler(int sig)
{
  ++SignalCounter.hup;
  GlobalRehashFlag = 1;
}

static void sigint_handler(int sig)
{
  GlobalRestartFlag = 1;
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

  sigemptyset(&act.sa_mask);

  act.sa_handler = sighup_handler;
  sigaction(SIGHUP, &act, 0);

  act.sa_handler = sigint_handler;
  sigaction(SIGINT, &act, 0);

  act.sa_handler = sigterm_handler;
  sigaction(SIGTERM, &act, 0);

#ifdef HAVE_RESTARTABLE_SYSCALLS
  /*
   * At least on Apollo sr10.1 it seems continuing system calls
   * after signal is the default. The following 'siginterrupt'
   * should change that default to interrupting calls.
   */
  siginterrupt(SIGALRM, 1);
#endif
}

