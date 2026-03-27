#ifndef INCLUDED_sasl_h
#define INCLUDED_sasl_h
/*
 * IRC - Internet Relay Chat, include/sasl.h
 * Copyright (C) 2025 MrIron <mriron@undernet.org>
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
 */

/** @file
 * @brief SASL authentication support
 */

#ifndef INCLUDED_time_h
#include <time.h>
#define INCLUDED_time_h
#endif

struct Client;
struct StatDesc;

/* Public SASL functions */
extern void sasl_init(void);
extern int sasl_available(void);
extern int sasl_mechanism_supported(const char* mechanism);
extern void sasl_check_capability(void);
extern void sasl_send_xreply(struct Client* sptr, const char* routing, const char* reply);
extern struct Client* find_sasl_client(unsigned long cookie);
extern void sasl_stats(struct Client* sptr, const struct StatDesc* sd, char* param);
extern void sasl_stop_timeout(struct Client* cptr);
extern void sasl_session_add(unsigned long cookie, struct Client* client);
extern void sasl_session_remove(unsigned long cookie);

#endif /* INCLUDED_sasl_h */