/*
 * IRC - Internet Relay Chat, ircd/s_err.c
 * Copyright (C) 1992 Darren Reed
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
#include "numeric.h"
#include "s_debug.h"
#include "sprintf_irc.h"

#include <assert.h>

static Numeric local_replies[] = {
/* 000 */
  { 0 },
/* 001 */
  { RPL_WELCOME, ":Welcome to the Internet Relay Network %s", "001" },
/* 002 */
  { RPL_YOURHOST, ":Your host is %s, running version %s", "002" },
/* 003 */
  { RPL_CREATED, ":This server was created %s", "003" },
/* 004 */
  { RPL_MYINFO, "%s %s dioswkg biklmnopstv", "004" },
/* 005 */
  { RPL_ISUPPORT, "%s :are supported by this server", "005" },
/* 006 */
  { 0 },
/* 007 */
  { 0 },
/* 008 */
  { RPL_SNOMASK, "%d :: Server notice mask (%#x)", "008" },
/* 009 */
  { RPL_STATMEMTOT, "%u %u :Bytes Blocks", "009" },
/* 010 */
#ifdef MEMSIZESTATS
  { RPL_STATMEM, "%u %u %s %u", "010" },
#else
  { RPL_STATMEM, "%u %u %s", "010" },
#endif
/* 011 */
  { 0 },
/* 012 */
  { 0 },
/* 013 */
  { 0 },
/* 014 */
  { 0 },
/* 015 */
  { RPL_MAP, ":%s%s%s %s [%i clients]", "015" },
/* 016 */
  { RPL_MAPMORE, ":%s%s --> *more*", "016" },
/* 017 */
  { RPL_MAPEND, ":End of /MAP", "017" },
  { 0 }
};

static Numeric numeric_errors[] = {
/* 400 */
  { ERR_FIRSTERROR, "", "400" },
/* 401 */
  { ERR_NOSUCHNICK, "%s :No such nick", "401" },
/* 402 */
  { ERR_NOSUCHSERVER, "%s :No such server", "402" },
/* 403 */
  { ERR_NOSUCHCHANNEL, "%s :No such channel", "403" },
/* 404 */
  { ERR_CANNOTSENDTOCHAN, "%s :Cannot send to channel", "404" },
/* 405 */
  { ERR_TOOMANYCHANNELS, "%s :You have joined too many channels", "405" },
/* 406 */
  { ERR_WASNOSUCHNICK, "%s :There was no such nickname", "406" },
/* 407 */
  { ERR_TOOMANYTARGETS, "%s :Duplicate recipients. No message delivered", "407" },
/* 408 */
  { 0 },
/* 409 */
  { ERR_NOORIGIN, ":No origin specified", "409" },
/* 410 */
  { 0 },
/* 411 */
  { ERR_NORECIPIENT, ":No recipient given (%s)", "411" },
/* 412 */
  { ERR_NOTEXTTOSEND, ":No text to send", "412" },
/* 413 */
  { ERR_NOTOPLEVEL, "%s :No toplevel domain specified", "413" },
/* 414 */
  { ERR_WILDTOPLEVEL, "%s :Wildcard in toplevel Domain", "414" },
/* 415 */
  { 0 },
/* 416 */
  { ERR_QUERYTOOLONG, "%s :Too many lines in the output, restrict your query", "416" },
/* 417 */
  { 0 },
/* 418 */
  { 0 },
/* 419 */
  { 0 },
/* 420 */
  { 0 },
/* 421 */
  { ERR_UNKNOWNCOMMAND, "%s :Unknown command", "421" },
/* 422 */
  { ERR_NOMOTD, ":MOTD File is missing", "422" },
/* 423 */
  { ERR_NOADMININFO, "%s :No administrative info available", "423" },
/* 424 */
  { 0 },
/* 425 */
  { 0 },
/* 426 */
  { 0 },
/* 427 */
  { 0 },
/* 428 */
  { 0 },
/* 429 */
  { 0 },
/* 430 */
  { 0 },
/* 431 */
  { ERR_NONICKNAMEGIVEN, ":No nickname given", "431" },
/* 432 */
  { ERR_ERRONEUSNICKNAME, "%s :Erroneus Nickname", "432" },
/* 433 */
  { ERR_NICKNAMEINUSE, "%s :Nickname is already in use.", "433" },
/* 434 */
  { 0 },
/* 435 */
  { 0 },
/* 436 */
  { ERR_NICKCOLLISION, "%s :Nickname collision KILL", "436" },
/* 437 */
  { ERR_BANNICKCHANGE, "%s :Cannot change nickname while banned on channel", "437" },
/* 438 */
  { ERR_NICKTOOFAST, "%s :Nick change too fast. Please wait %d seconds.", "438" },
/* 439 */
  { ERR_TARGETTOOFAST, "%s :Target change too fast. Please wait %d seconds.", "439" },
/* 440 */
  { 0 },
/* 441 */
  { ERR_USERNOTINCHANNEL, "%s %s :They aren't on that channel", "441" },
/* 442 */
  { ERR_NOTONCHANNEL, "%s :You're not on that channel", "442" },
/* 443 */
  { ERR_USERONCHANNEL, "%s %s :is already on channel", "443" },
/* 444 */
  { 0 },
/* 445 */
  { 0 },
/* 446 */
  { 0 },
/* 447 */
  { 0 },
/* 448 */
  { 0 },
/* 449 */
  { 0 },
/* 450 */
  { 0 },
/* 451 */
  { ERR_NOTREGISTERED, ":You have not registered", "451" },
/* 452 */
  { 0 },
/* 453 */
  { 0 },
/* 454 */
  { 0 },
/* 455 */
  { 0 },
/* 456 */
  { 0 },
/* 457 */
  { 0 },
/* 458 */
  { 0 },
/* 459 */
  { 0 },
/* 460 */
  { 0 },
/* 461 */
  { ERR_NEEDMOREPARAMS, "%s :Not enough parameters", "461" },
/* 462 */
  { ERR_ALREADYREGISTRED, ":You may not reregister", "462" },
/* 463 */
  { ERR_NOPERMFORHOST, ":Your host isn't among the privileged", "463" },
/* 464 */
  { ERR_PASSWDMISMATCH, ":Password Incorrect", "464" },
/* 465 */
  { ERR_YOUREBANNEDCREEP, ":You are banned from this server", "465" },
/* 466 */
  { ERR_YOUWILLBEBANNED, "", "466" },
/* 467 */
  { ERR_KEYSET, "%s :Channel key already set", "467" },
/* 468 */
  { ERR_INVALIDUSERNAME, "", "468" },
/* 469 */
  { 0 },
/* 470 */
  { 0 },
/* 471 */
  { ERR_CHANNELISFULL, "%s :Cannot join channel (+l)", "471" },
/* 472 */
  { ERR_UNKNOWNMODE, "%c :is unknown mode char to me", "472" },
/* 473 */
  { ERR_INVITEONLYCHAN, "%s :Cannot join channel (+i)", "473" },
/* 474 */
  { ERR_BANNEDFROMCHAN, "%s :Cannot join channel (+b)", "474" },
/* 475 */
  { ERR_BADCHANNELKEY, "%s :Cannot join channel (+k)", "475" },
/* 476 */
  { ERR_BADCHANMASK, "%s :Bad Channel Mask", "476" },
/* 477 */
  { 0 },
/* 478 */
  { ERR_BANLISTFULL, "%s %s :Channel ban/ignore list is full", "478" },
/* 479 */
  { ERR_BADCHANNAME, "%s :Cannot join channel (access denied on this server)", "479" },
/* 480 */
  { 0 },
/* 481 */
  { ERR_NOPRIVILEGES, ":Permission Denied: You're not an IRC operator", "481" },
/* 482 */
  { ERR_CHANOPRIVSNEEDED, "%s :You're not channel operator", "482" },
/* 483 */
  { ERR_CANTKILLSERVER, ":You cant kill a server!", "483" },
/* 484 */
  { ERR_ISCHANSERVICE, "%s %s :Cannot kill, kick or deop channel service", "484" },
/* 485 */
  { 0 },
/* 486 */
  { 0 },
/* 487 */
  { 0 },
/* 488 */
  { 0 },
/* 489 */
  { ERR_VOICENEEDED, "%s :You're neither voiced nor channel operator", "489" },
/* 490 */
  { 0 },
/* 491 */
  { ERR_NOOPERHOST, ":No O-lines for your host", "491" },
/* 492 */
  { 0 },
/* 493 */
  { 0 },
/* 494 */
  { 0 },
/* 495 */
  { 0 },
/* 496 */
  { 0 },
/* 497 */
  { 0 },
/* 498 */
  { ERR_ISOPERLCHAN, "%s %s :Cannot kick or deop an IRC Operator on a local channel", "498" },
/* 499 */
  { 0 },
/* 500 */
  { 0 },
/* 501 */
  { ERR_UMODEUNKNOWNFLAG, ":Unknown MODE flag", "501" },
/* 502 */
  { ERR_USERSDONTMATCH, ":Cant change mode for other users", "502" },
/* 503 */
  { 0 },
/* 504 */
  { 0 },
/* 505 */
  { 0 },
/* 506 */
  { 0 },
/* 507 */
  { 0 },
/* 508 */
  { 0 },
/* 509 */
  { 0 },
/* 510 */
  { 0 },
/* 511 */
  { ERR_SILELISTFULL, "%s :Your silence list is full", "511" },
/* 512 */
  { ERR_NOSUCHGLINE, "%s@%s :No such gline", "512" },
/* 513 */
  { ERR_BADPING, "", "513" },
/* 514 */
  { ERR_NOSUCHJUPE, "%s :No such jupe", "514" },
/* 515 */
  { ERR_BADEXPIRE, TIME_T_FMT " :Bad expire time", "515" }
};

static Numeric numeric_replies[] = {
/* 300 */
  { RPL_NONE, 0, "300" },
/* 301 */
  { RPL_AWAY, "%s :%s", "301" },
/* 302 */
  { RPL_USERHOST, ":", "302" },
/* 303 */
  { RPL_ISON, ":", "303" },
/* 304 */
  { RPL_TEXT, 0, "304" },
/* 305 */
  { RPL_UNAWAY, ":You are no longer marked as being away", "305" },
/* 306 */
  { RPL_NOWAWAY, ":You have been marked as being away", "306" },
/* 307 */
  { RPL_USERIP, ":", "307" },
/* 308 */
  { 0 },
/* 309 */
  { 0 },
/* 310 */
  { 0 },
/* 311 */
  { RPL_WHOISUSER, "%s %s %s * :%s", "311" },
/* 312 */
  { RPL_WHOISSERVER, "%s %s :%s", "312" },
/* 313 */
  { RPL_WHOISOPERATOR, "%s :is an IRC Operator", "313" },
/* 314 */
  { RPL_WHOWASUSER, "%s %s %s * :%s", "314" },
/* 315 */
  { RPL_ENDOFWHO, "%s :End of /WHO list.", "315" },
/* 316 */
  { 0 },
/* 317 */
  { RPL_WHOISIDLE, "%s %ld %ld :seconds idle, signon time", "317" },
/* 318 */
  { RPL_ENDOFWHOIS, "%s :End of /WHOIS list.", "318" },
/* 319 */
  { RPL_WHOISCHANNELS, "%s :%s", "319" },
/* 320 */
  { 0 },
/* 321 */
  { RPL_LISTSTART, "Channel :Users  Name", "321" },
/* 322 */
  { RPL_LIST, "%s %d :%s", "322" },
/* 323 */
  { RPL_LISTEND, ":End of /LIST", "323" },
/* 324 */
  { RPL_CHANNELMODEIS, "%s %s %s", "324" },
/* 325 */
  { 0 },
/* 326 */
  { 0 },
/* 327 */
  { 0 },
/* 328 */
  { 0 },
/* 329 */
  { RPL_CREATIONTIME, "%s " TIME_T_FMT, "329" },
/* 330 */
  { 0 },
/* 331 */
  { RPL_NOTOPIC, "%s :No topic is set.", "331" },
/* 332 */
  { RPL_TOPIC, "%s :%s", "332" },
/* 333 */
  { RPL_TOPICWHOTIME, "%s %s " TIME_T_FMT, "333" },
/* 334 */
  { RPL_LISTUSAGE, ":%s", "334" },
/* 335 */
  { 0 },
/* 336 */
  { 0 },
/* 337 */
  { 0 },
/* 338 */
  { 0 },
/* 339 */
  { 0 },
/* 340 */
  { 0 },
/* 341 */
  { RPL_INVITING, "%s %s", "341" },
/* 342 */
  { 0 },
/* 343 */
  { 0 },
/* 344 */
  { 0 },
/* 345 */
  { 0 },
/* 346 */
  { RPL_INVITELIST, ":%s", "346" },
/* 347 */
  { RPL_ENDOFINVITELIST, ":End of Invite List", "347" },
/* 348 */
  { 0 },
/* 349 */
  { 0 },
/* 350 */
  { 0 },
/* 351 */
  { RPL_VERSION, "%s.%s %s :%s", "351" },
/* 352 */
  { RPL_WHOREPLY, "%s", "352" },
/* 353 */
  { RPL_NAMREPLY, "%s", "353" },
/* 354 */
  { RPL_WHOSPCRPL, "%s", "354" },
/* 355 */
  { 0 },
/* 356 */
  { 0 },
/* 357 */
  { 0 },
/* 358 */
  { 0 },
/* 359 */
  { 0 },
/* 360 */
  { 0 },
/* 361 */
  { RPL_KILLDONE, 0, "361" },
/* 362 */
  { RPL_CLOSING, "%s :Closed. Status = %d", "362" },
/* 363 */
  { RPL_CLOSEEND, "%d: Connections Closed", "363" },
/* 364 */
#ifndef GODMODE
  { RPL_LINKS, "%s %s :%d P%u %s", "364" },
#else /* GODMODE */
  { RPL_LINKS, "%s %s :%d P%u " TIME_T_FMT " (%s) %s", "364" },
#endif /* GODMODE */
/* 365 */
  { RPL_ENDOFLINKS, "%s :End of /LINKS list.", "365" },
/* 366 */
  { RPL_ENDOFNAMES, "%s :End of /NAMES list.", "366" },
/* 367 */
  { RPL_BANLIST, "%s %s %s " TIME_T_FMT, "367" },
/* 368 */
  { RPL_ENDOFBANLIST, "%s :End of Channel Ban List", "368" },
/* 369 */
  { RPL_ENDOFWHOWAS, "%s :End of WHOWAS", "369" },
/* 370 */
  { 0 },
/* 371 */
  { RPL_INFO, ":%s", "371" },
/* 372 */
  { RPL_MOTD, ":- %s", "372" },
/* 373 */
  { RPL_INFOSTART, ":Server INFO", "373" },
/* 374 */
  { RPL_ENDOFINFO, ":End of /INFO list.", "374" },
/* 375 */
  { RPL_MOTDSTART, ":- %s Message of the Day - ", "375" },
/* 376 */
  { RPL_ENDOFMOTD, ":End of /MOTD command.", "376" },
/* 377 */
  { 0 },
/* 378 */
  { 0 },
/* 379 */
  { 0 },
/* 380 */
  { 0 },
/* 381 */
  { RPL_YOUREOPER, ":You are now an IRC Operator", "381" },
/* 382 */
  { RPL_REHASHING, "%s :Rehashing", "382" },
/* 383 */
  { 0 },
/* 384 */
  { RPL_MYPORTIS, "%d :Port to local server is", "384" },
/* 385 */
  { RPL_NOTOPERANYMORE, 0, "385" },
/* 386 */
  { 0 },
/* 387 */
  { 0 },
/* 388 */
  { 0 },
/* 389 */
  { 0 },
/* 390 */
  { 0 },
/* 391 */
  { RPL_TIME, "%s " TIME_T_FMT " %ld :%s", "391" },
/* 392 */
  { 0 },
/* 393 */
  { 0 },
/* 394 */
  { 0 },
/* 395 */
  { 0 },
/* 396 */
  { 0 },
/* 397 */
  { 0 },
/* 398 */
  { 0 },
/* 399 */
  { 0 },
/* 200 */
#ifndef GODMODE
  { RPL_TRACELINK, "Link %s%s %s %s", "200" },
#else /* GODMODE */
  { RPL_TRACELINK, "Link %s%s %s %s " TIME_T_FMT, "200" },
#endif /* GODMODE */
/* 201 */
  { RPL_TRACECONNECTING, "Try. %d %s", "201" },
/* 202 */
  { RPL_TRACEHANDSHAKE, "H.S. %d %s", "202" },
/* 203 */
  { RPL_TRACEUNKNOWN, "???? %d %s", "203" },
/* 204 */
  { RPL_TRACEOPERATOR, "Oper %d %s %ld", "204" },
/* 205 */
  { RPL_TRACEUSER, "User %d %s %ld", "205" },
/* 206 */
  { RPL_TRACESERVER, "Serv %d %dS %dC %s %s!%s@%s %ld %ld", "206" },
/* 207 */
  { 0 },
/* 208 */
  { RPL_TRACENEWTYPE, "<newtype> 0 %s", "208" },
/* 209 */
  { RPL_TRACECLASS, "Class %d %d", "209" },
/* 210 */
  { 0 },
/* 211 */
  { RPL_STATSLINKINFO, 0, "211" },
/* 212 */
  { RPL_STATSCOMMANDS, "%s %u %u", "212" },
/* 213 */
  { RPL_STATSCLINE, "%c %s * %s %d %d", "213" },
/* 214 */
  { RPL_STATSNLINE, "%c %s * %s %d %d", "214" },
/* 215 */
  { RPL_STATSILINE, "%c %s * %s %d %d", "215" },
/* 216 */
  { RPL_STATSKLINE, "%c %s %s %s %d %d", "216" },
/* 217 */
  { RPL_STATSPLINE, "P %d %d %s %s", "217" },
/* 218 */
  { RPL_STATSYLINE, "%c %d %d %d %d %ld", "218" },
/* 219 */
  { RPL_ENDOFSTATS, "%c :End of /STATS report", "219" },
/* 220 */
  { 0 },
/* 221 */
  { RPL_UMODEIS, "%s", "221" },
/* 222 */
  { 0 },
/* 223 */
  { 0 },
/* 224 */
  { 0 },
/* 225 */
  { 0 },
/* 226 */
  { 0 },
/* 227 */
  { 0 },
/* 228 */
  { 0 },
/* 229 */
  { 0 },
/* 230 */
  { 0 },
/* 231 */
  { RPL_SERVICEINFO, 0, "231" },
/* 232 */
  { RPL_ENDOFSERVICES, 0, "232" },
/* 233 */
  { RPL_SERVICE, 0, "233" },
/* 234 */
  { RPL_SERVLIST, 0, "234" },
/* 235 */
  { RPL_SERVLISTEND, 0, "235" },
/* 236 */
  { 0 },
/* 237 */
  { 0 },
/* 238 */
  { 0 },
/* 239 */
  { 0 },
/* 240 */
  { 0 },
/* 241 */
  { RPL_STATSLLINE, "%c %s * %s %d %d", "241" },
/* 242 */
  { RPL_STATSUPTIME, ":Server Up %d days, %d:%02d:%02d", "242" },
/* 243 */
  { RPL_STATSOLINE, "%c %s * %s %d %d", "243" },
/* 244 */
  { RPL_STATSHLINE, "%c %s * %s %d %d", "244" },
/* 245 */
  { 0 },
/* 246 */
  { RPL_STATSTLINE, "%c %s %s", "246" },
/* 247 */
  { RPL_STATSGLINE, "%c %s@%s " TIME_T_FMT " :%s", "247" },
/* 248 */
  { RPL_STATSULINE, "%c %s %s %s %d %d", "248" },
/* 249 */
  { 0 },
/* 250 */
  { RPL_STATSCONN, ":Highest connection count: %d (%d clients)", "250" },
/* 251 */
  { RPL_LUSERCLIENT, ":There are %d users and %d invisible on %d servers", "251" },
/* 252 */
  { RPL_LUSEROP, "%d :operator(s) online", "252" },
/* 253 */
  { RPL_LUSERUNKNOWN, "%d :unknown connection(s)", "253" },
/* 254 */
  { RPL_LUSERCHANNELS, "%d :channels formed", "254" },
/* 255 */
  { RPL_LUSERME, ":I have %d clients and %d servers", "255" },
/* 256 */
  { RPL_ADMINME, ":Administrative info about %s", "256" },
/* 257 */
  { RPL_ADMINLOC1, ":%s", "257" },
/* 258 */
  { RPL_ADMINLOC2, ":%s", "258" },
/* 259 */
  { RPL_ADMINEMAIL, ":%s", "259" },
/* 260 */
  { 0 },
/* 261 */
  { RPL_TRACELOG, "File %s %d", "261" },
/* 262 */
  { RPL_TRACEPING, "Ping %s %s", "262" },
/* 263 */
  { 0 },
/* 264 */
  { 0 },
/* 265 */
  { 0 },
/* 266 */
  { 0 },
/* 267 */
  { 0 },
/* 268 */
  { 0 },
/* 269 */
  { 0 },
/* 270 */
  { 0 },
/* 271 */
  { RPL_SILELIST, "%s %s", "271" },
/* 272 */
  { RPL_ENDOFSILELIST, "%s :End of Silence List", "272" },
/* 273 */
  { 0 },
/* 274 */
  { 0 },
/* 275 */
  { RPL_STATSDLINE, "%c %s %s", "275" },
/* 276 */
  { 0 },
/* 277 */
  { 0 },
/* 278 */
  { 0 },
/* 279 */
  { 0 },
/* 280 */
  { RPL_GLIST, "%s@%s " TIME_T_FMT " %s%s", "280" },
/* 281 */
  { RPL_ENDOFGLIST, ":End of G-line List", "281" },
/* 282 */
  { RPL_JUPELIST, "%s " TIME_T_FMT " %s %c :%s", "282" },
/* 283 */
  { RPL_ENDOFJUPELIST, ":End of Jupe List", "283" },
/* 284 */
  { 0 }
};

const struct Numeric* get_error_numeric(int numeric)
{
  int num = numeric;
  assert(ERR_FIRSTERROR < num);
  assert(num < ERR_INVALID_ERROR);

  num -= ERR_FIRSTERROR;
  assert(0 != numeric_errors[num].value);

  return &numeric_errors[num];
}

static char numbuff[512];

/* "inline" */
#define prepbuf(buffer, num, tail)                      \
{                                                       \
  char *s = buffer + 4;                 \
  const char *ap = atoi_tab + (num << 2);       \
                                                        \
  strcpy(buffer, ":%s 000 %s ");                        \
  *s++ = *ap++;                                         \
  *s++ = *ap++;                                         \
  *s = *ap;                                             \
  strcpy(s + 5, tail);                                  \
}

char *err_str(int numeric)
{
  Numeric *nptr;
  int num = numeric;

  num -= numeric_errors[0].value;

#ifdef DEBUGMODE
  if (num < 0 || num > ERR_USERSDONTMATCH)
    sprintf_irc(numbuff,
        ":%%s %d %%s :INTERNAL ERROR: BAD NUMERIC! %d", numeric, num);
  else
  {
    nptr = &numeric_errors[num];
    if (!nptr->format || !nptr->value)
      sprintf_irc(numbuff, ":%%s %d %%s :NO ERROR FOR NUMERIC ERROR %d",
          numeric, num);
    else
      prepbuf(numbuff, nptr->value, nptr->format);
  }
#else
  nptr = &numeric_errors[num];
  prepbuf(numbuff, nptr->value, nptr->format);
#endif

  return numbuff;
}

char *rpl_str(int numeric)
{
  Numeric *nptr;
  int num = numeric;

  if (num > (int)(sizeof(local_replies) / sizeof(Numeric) - 2))
    num -= (num > 300) ? 300 : 100;

#ifdef DEBUGMODE
  if (num < 0 || num > 200)
    sprintf_irc(numbuff, ":%%s %d %%s :INTERNAL REPLY ERROR: BAD NUMERIC! %d",
        numeric, num);
  else
  {
    if (numeric > 99)
      nptr = &numeric_replies[num];
    else
      nptr = &local_replies[num];
    Debug((DEBUG_NUM, "rpl_str: numeric %d num %d %d %s",
        numeric, num, nptr->value, nptr->format ? nptr->format : ""));
    if (!nptr->format || !nptr->value)
      sprintf_irc(numbuff, ":%%s %d %%s :NO REPLY FOR NUMERIC ERROR %d",
          numeric, num);
    else
      prepbuf(numbuff, nptr->value, nptr->format);
  }
#else
  if (numeric > 99)
    nptr = &numeric_replies[num];
  else
    nptr = &local_replies[num];
  prepbuf(numbuff, nptr->value, nptr->format);
#endif

  return numbuff;
}
