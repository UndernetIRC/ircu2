/*
 * IRC - Internet Relay Chat, include/websocket.h
 * Copyright (C) 2026 MrIron <mriron@undernet.org>
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

#ifndef INCLUDED_WEBSOCKET_H
#define INCLUDED_WEBSOCKET_H

#include <stddef.h>
#include "client.h"

/* Maximum size of a WebSocket header */
#define WEBSOCKET_MAX_HEADER 4096

int websocket_handshake_handler(struct Client *cptr);
int websocket_parse_frame(struct Client *cptr, const char *buf, size_t buflen);
struct MsgBuf *websocket_frame_msgbuf(struct Client *cptr, const char *line, size_t linelen);
/** RFC 6455 Ping (not IRC PING); 0 on success, -1 on write failure. */
int websocket_send_keepalive_ping(struct Client *cptr);

#endif /* INCLUDED_WEBSOCKET_H */
