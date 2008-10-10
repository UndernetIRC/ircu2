/*
 * IRC - Internet Relay Chat, ircd/m_mtest.c
 * Copyright (C) 2008 Kevin L. Mitchell
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include "config.h"

#include "handlers.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "mode.h"
#include "mode-compat.h"
#include "msg.h"
#include "register.h"
#include "send.h"

#include <stdlib.h>
#include <string.h>

typedef int (*bqcmp)(const void*, const void*);
typedef int (*mt_subcmd_t)(struct Client* sptr, mode_list_t* ml,
			   int parc, char* parv[]);

static int
mt_info(struct Client* sptr, mode_list_t* ml, int parc, char* parv[])
{
  char buf[512];
  int len = sizeof(buf);

  if (!ml)
    ml = &chanmodes;

  sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :mode_str_info() returned %s",
		sptr, mode_str_info(ml, buf, &len, parc));

  return 0;
}

static int
mt_modes(struct Client* sptr, mode_list_t* ml, int parc, char* parv[])
{
  char buf[512];
  int len = sizeof(buf);

  if (!ml)
    ml = &chanmodes;

  sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :mode_str_modes() returned %s",
		sptr, mode_str_modes(ml, buf, &len));
  sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :buffer contains %s", sptr, buf);

  return 0;
}

static int
mt_prefix(struct Client* sptr, mode_list_t* ml, int parc, char* parv[])
{
  char buf[512];
  int len = sizeof(buf);

  if (!ml)
    ml = &chanmodes;

  sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :mode_str_prefix() returned %s",
		sptr, mode_str_prefix(ml, buf, &len));

  return 0;
}

/* Command descriptor structure. */
static struct mt_subcmd {
  const char* cmd;
  mt_subcmd_t proc;
} cmdlist[] = {
#define SC(cmd) { #cmd, mt_ ## cmd }
  SC(info), SC(modes), SC(prefix)
#undef SC
};

#define cmdlist_cnt	(sizeof(cmdlist) / sizeof(struct mt_subcmd))

static int
subcmd_search(const char* cmd, const struct mt_subcmd *elem)
{
  return ircd_strcmp(cmd, elem->cmd);
}

int
m_mtest(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *subcmd, *modelist;
  struct mt_subcmd *cmd;
  mode_list_t *ml = 0;

  if (parc < 2)
    return need_more_params(sptr, "MTEST");

  subcmd = parv[1];
  parc -= 2;
  parv += 2;

  if (!(cmd = (struct mt_subcmd*) bsearch(subcmd, cmdlist, cmdlist_cnt,
					  sizeof(struct mt_subcmd),
					  (bqcmp) subcmd_search))) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Unknown subcommand %s",
		  sptr, subcmd);
    return 0;
  }

  if (parc > 0 && *parv[0] == '%') {
    modelist = parv[0] + 1;
    parc--;
    parv++;

    if (!(ml = reg_find(MODE_TABLE, modelist))) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Unknown mode list %s",
		    sptr, modelist);
      return 0;
    }
  }

  return (cmd->proc)(sptr, ml, parc, parv);
}
