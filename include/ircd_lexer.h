/*
 * IRC - Internet Relay Chat, include/ircd_lexer.h
 * Copyright (C) 2021 Michael Poole
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
 */
/** @file
 * @brief Message handler types and definitions.
 */
#ifndef INCLUDED_ircd_lexer_h
#define INCLUDED_ircd_lexer_h

extern int init_lexer(void);
extern void lexer_include(const char *fname, unsigned int allowed);
extern const char *lexer_position(int *lineno);
extern int lexer_allowed(unsigned int bitnum);
extern void deinit_lexer(void);

extern int yyparse();

#endif /* INCLUDED_ircd_lexer_h */
