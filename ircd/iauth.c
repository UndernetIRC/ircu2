/************************************************************************
 *   IRC - Internet Relay Chat, src/listener.c
 *   Copyright (C) 2001 Perry Lorier <isomer@coders.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  $Id$
 */
#include "config.h"
#include "iauth.h"
#include <sys/types.h>
#include <sys/socket.h>

struct Iauth_Outstanding {
	struct iauth_outstanding *next;
	int client_id;
}

static struct Iauth_Outstanding *iauth_freelist=NULL;
struct Iauth IauthPollList = NULL;

void iauth_new(char *service)
{
	/* TODO: Check to see if the service is a hostname, and if so
         *       connect to it like hybrid does.  Hybrid uses a blocking
	 *       gethostbyname here (bletch!!).  On the other hand a
	 *       nonblocking solutions likely to be worse....
         */	
	struct Iauth* tmp = (struct Iauth *)malloc(sizeof(struct Iauth));
	int fd[2];
	tmp->next = IauthPollList;
	tmp->fd = 0;
	tmp->service=strdup(service);
	tmp->ref_count=0;
	tmp->active=0;
	if (socketpair(domain,type,protocol,fd)<0) {
		free(tmp->service);
		free(tmp);
		return;		
	}
	tmp->fd=fd[0];
	if (0 == fork()) {
                (void)close(pi[0]);
		(void)dup2(pi[1],0);
		(void)dup2(pi[1],1);
                for (i = 2; i < MAXCONNECTIONS; i++)
                       (void)close(i);
                if (pi[1] != 0 && pi[1] != 1)
                      (void)close(pi[1]);
                (void)execlp(tmp->service, tmp->service, 0);
                exit(-1);
	} else {
		/* TODO: Put the real servername in there */
		(void)write(tmp->fd,"Server undernet.org 1.1");
	}
	IauthPollList=tmp;
}
