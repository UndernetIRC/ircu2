/*
 * IRC - Internet Relay Chat, include/numeric.h
 * Copyright (C) 1990 Jarkko Oikarinen
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
#ifndef INCLUDED_numeric_h
#define INCLUDED_numeric_h

typedef struct Numeric {
  int         value;
  const char* format;
  const char* str;
} Numeric;

/*
 * Prototypes
 */
extern char* err_str(int numeric);
extern char* rpl_str(int numeric);
extern const struct Numeric* get_error_numeric(int err);

/*
 * References:
 *  aircd - aircd source.  Doesn't appear to be available on the web.
 *	    anywhere.  Ask me (Isomer) if you'd like a copy. (it's gpl)
 *  Numeric List - http://www.contactor.se/~dast/irc/numerics.txt
 */


/*
 * Reserve numerics 000-099 for server-client connections where the client
 * is local to the server. If any server is passed a numeric in this range
 * from another server then it is remapped to 100-199. -avalon
 */
#define RPL_WELCOME            1
#define RPL_YOURHOST           2
#define RPL_CREATED            3
#define RPL_MYINFO             4
#define RPL_ISUPPORT           5        /* Undernet/Dalnet extension */
     /* RPL_BOUNCE                         IRCnet extension */
#define RPL_SNOMASK            8        /* Undernet extension */
#define RPL_STATMEMTOT         9        /* Undernet extension */
#define RPL_STATMEM           10        /* Undernet extension */
/*      RPL_YOURCOOKIE        14           IRCnet extension */
#define RPL_MAP               15        /* Undernet extension */
#define RPL_MAPMORE           16        /* Undernet extension */
#define RPL_MAPEND            17        /* Undernet extension */
/*      RPL_ATTEMPTINGJUNC    50           aircd extension */
/*      RPL_ATTEMPTINGREROUTE 51           aircd extension */

/*
 * Numberic replies from server commands.
 * These are currently in the range 200-399.
 */

#define RPL_TRACELINK        200
#define RPL_TRACECONNECTING  201
#define RPL_TRACEHANDSHAKE   202
#define RPL_TRACEUNKNOWN     203
#define RPL_TRACEOPERATOR    204
#define RPL_TRACEUSER        205
#define RPL_TRACESERVER      206
#define RPL_TRACENEWTYPE     208
#define RPL_TRACECLASS       209
/*      RPL_STATS            210 aircd extension, used instead of having
                                 multiple stats numerics */
/*      RPL_TRACERECONNECT   210 IRCnet extension */                                 
#define RPL_STATSLINKINFO    211
#define RPL_STATSCOMMANDS    212
#define RPL_STATSCLINE       213
#define RPL_STATSNLINE       214 /* unused */
#define RPL_STATSILINE       215
#define RPL_STATSKLINE       216
#define RPL_STATSPLINE       217        /* Undernet extenstion */
/*      RPL_STATSQLINE       217           Various */
#define RPL_STATSYLINE       218
#define RPL_ENDOFSTATS       219        /* See also RPL_STATSDLINE */
/*      RPL_STATSPLINE       220           Hybrid - Because 217 was for
                                           old Q: lines. */
/*      RPL_STATSBLINE       220	   Numerics List: Dalnet */
#define RPL_UMODEIS          221
/*	RPL_SQLINE_NICK	     222	   Numerics List: Dalnet */
/*      RPL_STATSFLINE       224           Hybrid extension */
/*      RPL_STATSDLINE       225           Hybrid extension */

#define RPL_SERVICEINFO      231	/* unused */
#define RPL_ENDOFSERVICES    232	/* unused */
#define RPL_SERVICE          233	/* unused */
#define RPL_SERVLIST         234	/* unused */
#define RPL_SERVLISTEND      235	/* unused */

#define RPL_STATSFLINE       238	/* Undernet feature lines */
/*      RPL_STATSIAUTH       239           IRCnet extension */
/*      RPL_STATSVLINE       240           IRCnet extension */
#define RPL_STATSLLINE       241	
#define RPL_STATSUPTIME      242
#define RPL_STATSOLINE       243
#define RPL_STATSHLINE       244
/*      RPL_STATSSLINE       245           Reserved / Dalnet / IRCnet / EFnet */
/*	RPL_STATSSPING	     246	   Numerics List: IRCnet */
#define RPL_STATSTLINE       246        /* Undernet extension */
#define RPL_STATSGLINE       247        /* Undernet extension */
/*      RPL_STATSXLINE       247           hybrid extension */
/*	RPL_STATSBLINE	     247	   Numerics List: IRCnet */
#define RPL_STATSULINE       248        /* Undernet extension */
/*	RPL_STATSDEFINE	     248	   Numerics List: IRCnet */
#define RPL_STATSDEBUG       249        /* Extension to RFC1459 */
#define RPL_STATSCONN        250        /* Undernet extension */
/*	RPL_STATSDLINE	     250	   Numerics List: IRCnet */

#define RPL_LUSERCLIENT      251
#define RPL_LUSEROP          252
#define RPL_LUSERUNKNOWN     253
#define RPL_LUSERCHANNELS    254
#define RPL_LUSERME          255
#define RPL_ADMINME          256
#define RPL_ADMINLOC1        257
#define RPL_ADMINLOC2        258
#define RPL_ADMINEMAIL       259

#define RPL_TRACELOG         261	/* unused */
#define RPL_TRACEPING        262        /* Extension to RFC1459, unused */
/*	RPL_TRACEEND	     262	   efnet(?) Numerics List: IRCnet */
/*      RPL_LOAD_THROTTLED   263           efnet/hybrid */
/*	RPL_TRYAGAIN	     263	   Numerics List: IRCnet */

/*      RPL_CURRENT_LOCAL    265           aircd/efnet/hybrid*/
/*      RPL_CURRENT_GLOBAL   266           aircd/efnet/hybrid */
/*      RPL_START_NETSTAT    267           aircd */
/*      RPL_NETSTAT          268           aircd */
/*      RPL_END_NETSTAT      269           aircd */

#define RPL_SILELIST         271        /* Undernet extension */
#define RPL_ENDOFSILELIST    272        /* Undernet extension */
/*      RPL_NOTIFY           273           aircd */
/*      RPL_END_NOTIFY       274           aircd */
/*      RPL_STATSDELTA       274           IRCnet extension */
#define RPL_STATSDLINE       275        /* Undernet extension */

#define RPL_GLIST            280        /* Undernet extension */
#define RPL_ENDOFGLIST       281        /* Undernet extension */
#define RPL_JUPELIST         282        /* Undernet extension - jupe -Kev */
#define RPL_ENDOFJUPELIST    283        /* Undernet extension - jupe -Kev */
#define RPL_FEATURE	     284	/* Undernet extension - features */
/*      RPL_CHANINFO_HANDLE  285           aircd */
/*      RPL_CHANINFO_USERS   286           aircd */
/*      RPL_CHANINFO_CHOPS   287           aircd */
/*      RPL_CHANINFO_VOICES  288           aircd */
/*      RPL_CHANINFO_AWAY    289           aircd */
/*      RPL_CHANINFO_OPERS   290           aircd */
/*	RPL_HELPHDR	     290	Numeric List: Dalnet */
/*      RPL_CHANINFO_BANNED  291           aircd */
/*	RPL_HELPOP	     291	Numeric List: Dalnet */
/*      RPL_CHANINFO_BANS    292           aircd */
/*	RPL_HELPTLR	     292	Numeric List: Dalnet */
/*      RPL_CHANINFO_INVITE  293           aircd */
/*	RPL_HELPHLP	     293	Numeric List: Dalnet */
/*      RPL_CHANINFO_INVITES 294           aircd */
/*	RPL_HELPFWD	     294	Numeric List: Dalnet */
/*      RPL_CHANINFO_KICK    295           aircd */
/*	RPL_HELPIGN	     295	Numeric List: Dalnet */
/*      RPL_CHANINFO_KICKS   296           aircd */

/*      RPL_END_CHANINFO     299           aircd */

#define RPL_NONE             300	/* unused */
#define RPL_AWAY             301
#define RPL_USERHOST         302
#define RPL_ISON             303
#define RPL_TEXT             304 	/* unused */
#define RPL_UNAWAY           305
#define RPL_NOWAWAY          306
#define RPL_USERIP           307        /* Undernet extension */
                                        /* NotAway, aircd */
/*	RPL_WHOISREGNICK     307 	Numeric List: Dalnet */                                      
/*      RPL_NOTIFYACTION     308         aircd */
/*	RPL_WHOISADMIN	     308	Numeric List: Dalnet */
/*      RPL_NICKTRACE        309         aircd */
/*	RPL_WHOISSADMIN	     309	Numeric List: Dalnet */
/*      RPL_WHOISHELPOP      310         Dalnet */
#define RPL_WHOISUSER        311        /* See also RPL_ENDOFWHOIS */
#define RPL_WHOISSERVER      312
#define RPL_WHOISOPERATOR    313
#define RPL_WHOWASUSER       314        /* See also RPL_ENDOFWHOWAS */
#define RPL_ENDOFWHO         315        /* See RPL_WHOREPLY/RPL_WHOSPCRPL */
/*      RPL_WHOISCHANOP      316           removed from RFC1459 */
#define RPL_WHOISIDLE        317
#define RPL_ENDOFWHOIS       318        /* See RPL_WHOISUSER/RPL_WHOISSERVER/
                                           RPL_WHOISOPERATOR/RPL_WHOISIDLE */
#define RPL_WHOISCHANNELS    319
/*      RPL_WHOIS_HIDDEN     320         Anothernet +h, ick! */
#define RPL_LISTSTART        321
#define RPL_LIST             322
#define RPL_LISTEND          323
#define RPL_CHANNELMODEIS    324
/*      RPL_CHANNELPASSIS    325           IRCnet extension */
/*      RPL_UNIQOPIS         325           IRCnet extension */
/*      RPL_NOCHANPASS       326           IRCnet extension */
/*      RPL_CHPASSUNKNOWN    327           IRCnet extension */
/*      RPL_CHANNEL_URL      328           dalnet, anothernet */
#define RPL_CREATIONTIME     329
/*      RPL_WHOWAS_TIME      330               ? */
#define RPL_NOTOPIC          331
#define RPL_TOPIC            332
#define RPL_TOPICWHOTIME     333        /* Undernet extension */
#define RPL_LISTUSAGE        334        /* Undernet extension */
/*      RPL_CHANPASSOK       338           IRCnet extension */
/*      RPL_BADCHANPASS      339           IRCnet extension */

#define RPL_INVITING         341
/*      RPL_SUMMONING        342           removed from RFC1459 */

#define RPL_INVITELIST       346        /* IRCnet, Undernet extension */
#define RPL_ENDOFINVITELIST  347        /* IRCnet, Undernet extension */
/*      RPL_EXCEPTLIST       348           IRCnet extension */
/*      RPL_ENDOFEXCEPTLIST  349           IRCnet extension */

#define RPL_VERSION          351
#define RPL_WHOREPLY         352        /* See also RPL_ENDOFWHO */
#define RPL_NAMREPLY         353        /* See also RPL_ENDOFNAMES */
#define RPL_WHOSPCRPL        354        /* Undernet extension,
                                           See also RPL_ENDOFWHO */

#define RPL_KILLDONE         361	/* not used */
#define RPL_CLOSING          362
#define RPL_CLOSEEND         363
#define RPL_LINKS            364
#define RPL_ENDOFLINKS       365
#define RPL_ENDOFNAMES       366        /* See RPL_NAMREPLY */
#define RPL_BANLIST          367
#define RPL_ENDOFBANLIST     368
#define RPL_ENDOFWHOWAS      369

#define RPL_INFO             371
#define RPL_MOTD             372
#define RPL_INFOSTART        373	/* not used */
#define RPL_ENDOFINFO        374
#define RPL_MOTDSTART        375
#define RPL_ENDOFMOTD        376

/*      RPL_KICKEXPIRED      377   aircd */
/*      RPL_BANEXPIRED       378   aircd */
/*      RPL_KICKLINKED       379   aircd */
/*      RPL_BANLINKED        380   aircd */

#define RPL_YOUREOPER        381
#define RPL_REHASHING        382
/*	RPL_YOURSERVICE	     383	   Numeric List: various */
#define RPL_MYPORTIS         384	/* not used */
#define RPL_NOTOPERANYMORE   385        /* Extension to RFC1459, not used */

#define RPL_TIME             391
/*      RPL_START_USERS      392        Dalnet/EFnet/IRCnet */
/*      RPL_USERS            393        Dalnet/EFnet/IRCnet */
/*      RPL_END_USERS        394        Dalnet/EFnet/IRCnet */
/*      RPL_NOUSERS          395        Dalnet/EFnet/IRCnet */

/*
 * Errors are in the range from 400-599 currently and are grouped by what
 * commands they come from.
 */
#define ERR_FIRSTERROR       400	/* unused */
#define ERR_NOSUCHNICK       401
#define ERR_NOSUCHSERVER     402
#define ERR_NOSUCHCHANNEL    403
#define ERR_CANNOTSENDTOCHAN 404
#define ERR_TOOMANYCHANNELS  405
#define ERR_WASNOSUCHNICK    406
#define ERR_TOOMANYTARGETS   407
/*      ERR_NOSUCHSERVICE    408  IRCnet */
#define ERR_NOORIGIN         409

#define ERR_NORECIPIENT      411
#define ERR_NOTEXTTOSEND     412
#define ERR_NOTOPLEVEL       413
#define ERR_WILDTOPLEVEL     414
     /* ERR_BADMASK          415           IRCnet extension */
#define ERR_QUERYTOOLONG     416        /* Undernet extension */
     /* ERR_TOOMANYMATCHES   416           IRCnet extension */
/*      ERR_LENGTHTRUNCATED  419           aircd */

#define ERR_UNKNOWNCOMMAND   421
#define ERR_NOMOTD           422
#define ERR_NOADMININFO      423
/*      ERR_FILEERROR        424           removed from RFC1459 */

#define ERR_NONICKNAMEGIVEN  431
#define ERR_ERRONEUSNICKNAME 432
#define ERR_NICKNAMEINUSE    433
/*      ERR_SERVICENAMEINUSE 434 ? */
/*      ERR_SERVICECONFUSED  435 ? */
#define ERR_NICKCOLLISION    436
#define ERR_BANNICKCHANGE    437        /* Undernet extension */
     /* ERR_UNAVAILRESOURCE  437           IRCnet extension */
#define ERR_NICKTOOFAST      438        /* Undernet extension */
     /* ERR_DEAD             438           IRCnet reserved for later use */
#define ERR_TARGETTOOFAST    439        /* Undernet extension */

#define ERR_USERNOTINCHANNEL 441
#define ERR_NOTONCHANNEL     442
#define ERR_USERONCHANNEL    443
/*      ERR_NOLOGIN          444           removed from RFC1459 */
/*      ERR_SUMMONDISABLED   445           removed from RFC1459 */
/*      ERR_USERSDISABLED    446           removed from RFC1459 */

#define ERR_NOTREGISTERED    451
/*      ERR_IDCOLLISION      452           IRCnet extension ? */
/*      ERR_NICKLOST         453           IRCnet extension ? */

#define ERR_NEEDMOREPARAMS   461
#define ERR_ALREADYREGISTRED 462
#define ERR_NOPERMFORHOST    463
#define ERR_PASSWDMISMATCH   464
#define ERR_YOUREBANNEDCREEP 465
#define ERR_YOUWILLBEBANNED  466
#define ERR_KEYSET           467        /* Undernet extension */
#define ERR_INVALIDUSERNAME  468        /* Undernet extension */

/*      ERR_KICKEDFROMCHAN   470         aircd */ 
#define ERR_CHANNELISFULL    471
#define ERR_UNKNOWNMODE      472
#define ERR_INVITEONLYCHAN   473
#define ERR_BANNEDFROMCHAN   474
#define ERR_BADCHANNELKEY    475
#define ERR_BADCHANMASK      476        /* Undernet extension */
/*      ERR_NEEDREGGEDNICK   477           DalNet Extention */
#define ERR_BANLISTFULL      478        /* Undernet extension */
#define ERR_BADCHANNAME      479        /* EFNet extension */
                                        /* 479 Undernet extension badchan */
#define ERR_NOPRIVILEGES     481
#define ERR_CHANOPRIVSNEEDED 482
#define ERR_CANTKILLSERVER   483
#define ERR_ISCHANSERVICE    484        /* Undernet extension */
/*      ERR_UNIQOPRIVSNEEDED 485           IRCnet extension */
/*      ERR_CHANTOORECENT    487           IRCnet extension */
/*      ERR_TSLESSCHAN       488           IRCnet extension */
#define ERR_VOICENEEDED      489        /* Undernet extension */

#define ERR_NOOPERHOST       491
/*      ERR_NOSERVICEHOST    492 ? */

#define ERR_NOFEATURE	     493	/* Undernet extension - features */
#define ERR_BADLOGTYPE	     494	/* Undernet extension - features */
#define ERR_BADLOGSYS	     495	/* Undernet extension - features */
#define ERR_BADLOGVALUE	     496	/* Undernet extension - features */

#define ERR_ISOPERLCHAN      498        /* Undernet extension */

#define ERR_UMODEUNKNOWNFLAG 501
#define ERR_USERSDONTMATCH   502
/*      ERR_GHOSTEDCLIENT    503           efnet */

#define ERR_SILELISTFULL     511        /* Undernet extension */
/*      ERR_NOTIFYFULL       512           aircd */
/*	ERR_TOOMANYWATCH     512           Numeric List: Dalnet */
#define ERR_NOSUCHGLINE      512        /* Undernet extension */
#define ERR_BADPING          513        /* Undernet extension */
/*      ERR_NEEDPONG	     512           Numeric List: Dalnet */
#define ERR_NOSUCHJUPE       514        /* Undernet extension - jupe -Kev */
#define ERR_BADEXPIRE        515        /* Undernet extension - jupe -Kev */
#define ERR_DONTCHEAT	     516	/* Undernet extension */
#define ERR_DISABLED	     517	/* Undernet extension -Kev */
#define ERR_LASTERROR        518

#endif /* INCLUDED_numeric_h */
