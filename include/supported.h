/*
 * IRC - Internet Relay Chat, include/supported.h
 * Copyright (C) 1999 Perry Lorier.
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id$
 *
 * Description: This file has the featureset that ircu announces on connecting
 *              a client.  It's in this .h because it's likely to be appended
 *              to frequently and s_user.h is included by basically everyone.
 */
#ifndef INCLUDED_supported_h
#define INCLUDED_supported_h

#include "config.h"
#include "channel.h"
#include "ircd_defs.h"

/* 
 * 'Features' supported by this ircd
 */
#define FEATURES "SILENCE=15"\
                " WHOX"\
                " WALLCHOPS"\
                " USERIP"\
                " CPRIVMSG"\
                " CNOTICE"\
                " MAP" \
                " MODES=%i" \
                " MAXCHANNELS=%i" \
                " MAXBANS=%i" \
                " NICKLEN=%i" \
                " TOPICLEN=%i" \
                " KICKLEN=%i" \
		" CHANTYPES=%s" \
		" CHANMODES=%s" \
		" CHARSET=%s" 
                 
#define FEATURESVALUES MAXMODEPARAMS,MAXCHANNELSPERUSER,MAXBANS, \
        NICKLEN,TOPICLEN,TOPICLEN, "+#^", "(ov)@+", "b,k,l,imnpst", "rfc1459"

#endif /* INCLUDED_supported_h */

