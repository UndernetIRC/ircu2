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
 */
/** @file
 * @brief Declarations of numeric replies and supporting functions.
 * @version $Id$
 */
#ifndef INCLUDED_numeric_h
#define INCLUDED_numeric_h

/** Numeric reply information. */
typedef struct Numeric {
  int         value;  /**< Numeric response. */
  const char* format; /**< Format string to follow :My.Server NNN Dest */
  const char* str;    /**< Text form for numeric. */
} Numeric;

/*
 * Prototypes
 */
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
/*	RPL_MAP		       6	unreal */
/*	RPL_MAPEND	       7	unreal */
#define RPL_SNOMASK            8        /* Undernet extension */
/*       RPL_BOUNCE           10        efnet, IRCnet extension
                                        (server redirect) */
/*      RPL_YOURCOOKIE        14           IRCnet extension */
#define RPL_MAP               15        /* Undernet extension */
#define RPL_MAPMORE           16        /* Undernet extension */
#define RPL_MAPEND            17        /* Undernet extension */
#define RPL_APASSWARN_SET     30	/* Undernet extension */
#define RPL_APASSWARN_SECRET  31	/* Undernet extension */
#define RPL_APASSWARN_CLEAR   32	/* Undernet extension */
/*	RPL_YOURID	      42	IRCnet extension */
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
/*	RPL_STATSOLDNLINE    214    unreal */
#define RPL_STATSNLINE       214 /* unused */
#define RPL_STATSILINE       215
#define RPL_STATSKLINE       216
#define RPL_STATSPLINE       217        /* Undernet extension */
/*      RPL_STATSQLINE       217           Various */
#define RPL_STATSYLINE       218
#define RPL_ENDOFSTATS       219        /* See also RPL_STATSDLINE */
#define RPL_STATSWLINE       220        /* Undernet extension */
/*      RPL_STATSPLINE       220           Hybrid - Because 217 was for
                                           old Q: lines. */
/*      RPL_STATSBLINE       220	   Numerics List: Dalnet,unreal */
#define RPL_UMODEIS          221
/*	RPL_SQLINE_NICK	     222	   Numerics List: Dalnet */
#define RPL_STATSJLINE       222	/* Undernet extension */
/*	RPL_STATSELINE       223	   dalnet */
/*	RPL_STATSGLINE	     223	   unreal */
/*      RPL_STATSFLINE       224           Hybrid extension,Dalnet */
/*	RPL_STATSTLINE	     224	   unreal */
/*      RPL_STATSDLINE       225           Hybrid extension */
/*	RPL_STATSZLINE	     225	   Dalnet
 	RPL_STATSELINE	     225	   unreal
 	RPL_STATSCOUNT	     226	   Dalnet
	RPL_STATSNLINE	     226	   unreal
	RPL_STATSGLINE	     227	   Dalnet 
	RPL_STATSVLINE	     227	   unreal */
#define RPL_STATSALINE       226        /* Hybrid, Undernet */
#define RPL_STATSQLINE       228        /* Undernet extension */

/*      RPL_SERVICEINFO      231	unused */
/*      RPL_ENDOFSERVICES    232	unused */
/*	RPL_RULES	     232	unreal */
/*      RPL_SERVICE          233	unused */
/*      RPL_SERVLIST         234	unused */
/*      RPL_SERVLISTEND      235	unused */

#define RPL_STATSVERBOSE     236        /* Undernet verbose server list */
#define RPL_STATSENGINE      237	/* Undernet engine name */
#define RPL_STATSFLINE       238	/* Undernet feature lines */
/*      RPL_STATSIAUTH       239           IRCnet extension */
/*      RPL_STATSVLINE       240           IRCnet extension */
/*	RPL_STATSXLINE	     240	austnet */
#define RPL_STATSLLINE       241	/* Undernet dynamicly loaded modules */
#define RPL_STATSUPTIME      242
#define RPL_STATSOLINE       243
#define RPL_STATSHLINE       244
/*      RPL_STATSSLINE       245           Reserved / Dalnet / IRCnet / EFnet */
/*	RPL_STATSSPING	     246	   Numerics List: IRCnet */
#define RPL_STATSTLINE       246        /* Undernet extension */
/*	RPL_STATSULINE	     246	Dalnet */
#define RPL_STATSGLINE       247        /* Undernet extension */
/*      RPL_STATSXLINE       247           hybrid extension,PTlink,unreal */
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

/*      RPL_TRACELOG         261	   unused */
#define RPL_TRACEEND	     262	/* efnet/IRCnet */
/*      RPL_LOAD_THROTTLED   263           efnet/hybrid */
/*	RPL_TRYAGAIN	     263	   Numerics List: IRCnet */
/*	RPL_LOAD2HI	     263	   Dalnet */
/*      RPL_CURRENT_LOCAL    265           aircd/efnet/hybrid/dalnet*/
/*      RPL_CURRENT_GLOBAL   266           aircd/efnet/hybrid/dalnet */
/*      RPL_START_NETSTAT    267           aircd */
/*      RPL_NETSTAT          268           aircd */
/*      RPL_END_NETSTAT      269           aircd */
#define RPL_PRIVS            270	/* Undernet extension - privs */
#define RPL_SILELIST         271        /* Undernet extension */
#define RPL_ENDOFSILELIST    272        /* Undernet extension */
/*      RPL_NOTIFY           273           aircd */
/*      RPL_END_NOTIFY       274           aircd */
/*      RPL_STATSDELTA       274           IRCnet extension */
#define RPL_STATSDLINE       275        /* Undernet extension */
#define RPL_STATSRLINE       276        /* Undernet extension */

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

/*      RPL_NONE             300	unused */
#define RPL_AWAY             301
#define RPL_USERHOST         302
#define RPL_ISON             303
/*      RPL_TEXT             304 	unused */
#define RPL_UNAWAY           305
#define RPL_NOWAWAY          306
                                        /* NotAway, aircd */
/*	RPL_WHOISREGNICK     307 	Numeric List: Dalnet */
/*	RPL_SUSERHOST	     307	austnet */
/*      RPL_NOTIFYACTION     308         aircd */
/*	RPL_WHOISADMIN	     308	Numeric List: Dalnet */
/*	RPL_RULESSTART	     308	unreal */
/*      RPL_NICKTRACE        309         aircd */
/*	RPL_WHOISSADMIN	     309	Numeric List: Dalnet */
/*	RPL_ENDOFRULES	     309	unreal */
/*	RPL_WHOISHELPER	     309	austnet */
/*      RPL_WHOISSVCMSG      310         Dalnet */
/*	RPL_WHOISHELPOP	     310	unreal */
/*	RPL_WHOISSERVICE     310	austnet */
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
#define RPL_WHOISWEBIRC      320
/*      RPL_WHOIS_HIDDEN     320         Anothernet +h, ick! */
/*	RPL_WHOISSPECIAL     320	unreal */
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
#define RPL_WHOISACCOUNT     330
#define RPL_NOTOPIC          331
#define RPL_TOPIC            332
#define RPL_TOPICWHOTIME     333        /* Undernet extension */
#define RPL_LISTUSAGE        334        /* Undernet extension */
/*	RPL_COMMANDSYNTAX    334	   Dalnet */
/*	RPL_LISTSYNTAX	     334	   unreal */
#define RPL_INVITELIST       336        /* ircd-hybrid extension */
#define RPL_ENDOFINVITELIST  337        /* ircd-hybrid extension */
/*      RPL_CHANPASSOK       338           IRCnet extension (?)*/
#define	RPL_WHOISACTUALLY    338	/* Undernet extension, dalnet */
/*	RPL_BADCHANPASS	     339           IRCnet extension (?) */
#define RPL_USERIP           340        /* Undernet extension */
#define RPL_INVITING         341
/*      RPL_SUMMONING        342           removed from RFC1459 */

#define RPL_ISSUEDINVITE     345        /* Undernet extension */
#define RPL_INVEXLIST        346        /* Reply to "MODE +I", RFC2812 calls it RPL_INVITELIST */
#define RPL_ENDOFINVEXLIST   347        /* Reply to "MODE +I", RFC2812 calls it RPL_ENDOFINVITELIST */
/*      RPL_EXCEPTLIST       348           IRCnet extension */
/*      RPL_ENDOFEXCEPTLIST  349           IRCnet extension */

#define RPL_VERSION          351
#define RPL_WHOREPLY         352        /* See also RPL_ENDOFWHO */
#define RPL_NAMREPLY         353        /* See also RPL_ENDOFNAMES */
#define RPL_WHOSPCRPL        354        /* Undernet extension,
                                           See also RPL_ENDOFWHO */
#define RPL_DELNAMREPLY      355        /* QuakeNet extension */

/*      RPL_KILLDONE         361	not used */
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
/*      RPL_INFOSTART        373	not used */
#define RPL_ENDOFINFO        374
#define RPL_MOTDSTART        375
#define RPL_ENDOFMOTD        376

/*      RPL_KICKEXPIRED      377   aircd */
/*	RPL_SPAM	     377   austnet */
/*      RPL_BANEXPIRED       378   aircd */
/*      RPL_KICKLINKED       379   aircd */
/*      RPL_BANLINKED        380   aircd */

#define RPL_YOUREOPER        381
#define RPL_REHASHING        382
/*	RPL_YOURSERVICE	     383	   Numeric List: various */
/*      RPL_MYPORTIS         384	not used */
/*      RPL_NOTOPERANYMORE   385        Extension to RFC1459, not used */
/*	RPL_QLIST	     386	unreal */
/*	RPL_ENDOFQLIST	     387	unreal */
/*	RPL_ALIST	     388	unreal */
/*	RPL_ENDOFALIST	     389	unreal */

#define RPL_TIME             391
/*      RPL_START_USERS      392        Dalnet/EFnet/IRCnet */
/*      RPL_USERS            393        Dalnet/EFnet/IRCnet */
/*      RPL_END_USERS        394        Dalnet/EFnet/IRCnet */
/*      RPL_NOUSERS          395        Dalnet/EFnet/IRCnet */
#define RPL_HOSTHIDDEN       396	/* UMODE +x completed succesfuly */

/*
 * Errors are in the range from 400-599 currently and are grouped by what
 * commands they come from.
 */
/*      ERR_FIRSTERROR       400	unused */
#define ERR_NOSUCHNICK       401
#define ERR_NOSUCHSERVER     402
#define ERR_NOSUCHCHANNEL    403
#define ERR_CANNOTSENDTOCHAN 404
#define ERR_TOOMANYCHANNELS  405
#define ERR_WASNOSUCHNICK    406
#define ERR_TOOMANYTARGETS   407
/*      ERR_NOSUCHSERVICE    408  IRCnet */
/*	ERR_NOCOLORSONCHAN   408  Dalnet */
#define ERR_NOORIGIN         409
#define ERR_UNKNOWNCAPCMD    410
#define ERR_NORECIPIENT      411
#define ERR_NOTEXTTOSEND     412
#define ERR_NOTOPLEVEL       413
#define ERR_WILDTOPLEVEL     414
     /* ERR_BADMASK          415           IRCnet extension */
#define ERR_QUERYTOOLONG     416        /* Undernet extension */
     /* ERR_TOOMANYMATCHES   416           IRCnet extension */
#define ERR_INPUTTOOLONG     417
/*      ERR_LENGTHTRUNCATED  419           aircd */

#define ERR_UNKNOWNCOMMAND   421
#define ERR_NOMOTD           422
#define ERR_NOADMININFO      423
/*      ERR_FILEERROR        424           removed from RFC1459 */

/* 	ERR_TOOMANYAWAY	     429	    Dalnet */
#define ERR_NONICKNAMEGIVEN  431
#define ERR_ERRONEUSNICKNAME 432
#define ERR_NICKNAMEINUSE    433
/*      ERR_SERVICENAMEINUSE 434 ? */
/*	ERR_NORULES	     434   unreal */
/*      ERR_SERVICECONFUSED  435 ? */
/*	ERR_BANONCHAN	     435   dalnet */
#define ERR_NICKCOLLISION    436
#define ERR_BANNICKCHANGE    437        /* Undernet extension */
     /* ERR_UNAVAILRESOURCE  437           IRCnet extension */
#define ERR_NICKTOOFAST      438        /* Undernet extension */
     /* ERR_DEAD             438           IRCnet reserved for later use */
#define ERR_TARGETTOOFAST    439        /* Undernet extension */
#define ERR_SERVICESDOWN     440	/* Dalnet,unreal,Undernet */
#define ERR_USERNOTINCHANNEL 441
#define ERR_NOTONCHANNEL     442
#define ERR_USERONCHANNEL    443
/*      ERR_NOLOGIN          444           removed from RFC1459 */
/*      ERR_SUMMONDISABLED   445           removed from RFC1459 */
/*      ERR_USERSDISABLED    446           removed from RFC1459 */
/*	ERR_NONICKCHANGE     447	 unreal */

#define ERR_NOTREGISTERED    451
/*      ERR_IDCOLLISION      452           IRCnet extension ? */
/*      ERR_NICKLOST         453           IRCnet extension ? */

/*	ERR_HOSTILENAME	     455	   unreal */

/*	ERR_NOHIDING	     459	   unreal */
/*	ERR_NOTFORHALFOPS    460	   unreal */

#define ERR_NEEDMOREPARAMS   461
#define ERR_ALREADYREGISTRED 462
#define ERR_NOPERMFORHOST    463
#define ERR_PASSWDMISMATCH   464
#define ERR_YOUREBANNEDCREEP 465
#define ERR_YOUWILLBEBANNED  466
#define ERR_KEYSET           467        /* Undernet extension */
#define ERR_INVALIDUSERNAME  468        /* Undernet extension */
/* 	ERR_ONLYSERVERSCANCHANGE 468	   Dalnet,unreal */
/*	ERR_LINKSET	     469	unreal */
/*	ERR_LINKCHANNEL	     470	unreal */
/*      ERR_KICKEDFROMCHAN   470         aircd */
#define ERR_CHANNELISFULL    471
#define ERR_UNKNOWNMODE      472
#define ERR_INVITEONLYCHAN   473
#define ERR_BANNEDFROMCHAN   474
#define ERR_BADCHANNELKEY    475
#define ERR_BADCHANMASK      476        /* Undernet extension */
#define ERR_NEEDREGGEDNICK   477        /* DalNet&Undernet Extention */
#define ERR_BANLISTFULL      478        /* Undernet extension */
/* 	ERR_LINKFAIL	     479	unreal */

#define ERR_BADCHANNAME      479        /* EFNet extension */
                                        /* 479 Undernet extension badchan */
/*	ERR_CANNOTKNOCK	     480	unreal */
/*	ERR_NOULINE	     480	austnet */
#define ERR_NOPRIVILEGES     481
#define ERR_CHANOPRIVSNEEDED 482
#define ERR_CANTKILLSERVER   483
#define ERR_ISCHANSERVICE    484        /* Undernet extension */
/*	ERR_DESYNC	     484	 Dalnet,PTlink */
/*	ERR_ATTACKDENY	     484	 unreal */
/*	ERR_RESTRICTED	     484	   IRCnet extension */
/*      ERR_UNIQOPRIVSNEEDED 485           IRCnet extension */
/*	ERR_KILLDENY         485	   unreal */
/*	ERR_CANTKICKADMIN    485	   PTlink */
/*	ERR_HTMDISABLED      486	   unreal */
/*      ERR_CHANTOORECENT    487           IRCnet extension (?) */
/*      ERR_TSLESSCHAN       488           IRCnet extension (?) */
#define ERR_VOICENEEDED      489        /* Undernet extension */

#define ERR_NOOPERHOST       491
/*      ERR_NOSERVICEHOST    492 	   IRCnet extension */

#define ERR_NOFEATURE	     493	/* Undernet extension - features */
#define ERR_BADFEATVALUE     494	/* Undernet extension - features */
#define ERR_BADLOGTYPE	     495	/* Undernet extension - features */
#define ERR_BADLOGSYS	     496	/* Undernet extension - features */
#define ERR_BADLOGVALUE	     497	/* Undernet extension - features */

#define ERR_ISOPERLCHAN      498        /* Undernet extension */

#define ERR_UMODEUNKNOWNFLAG 501
#define ERR_USERSDONTMATCH   502
/*      ERR_GHOSTEDCLIENT    503           efnet */
/*	ERR_VWORLDWARN	     503	   austnet */

#define ERR_SILELISTFULL     511        /* Undernet extension */
/*      ERR_NOTIFYFULL       512           aircd */
/*	ERR_TOOMANYWATCH     512           Numeric List: Dalnet */
#define ERR_NOSUCHGLINE      512        /* Undernet extension */
#define ERR_BADPING          513        /* Undernet extension */
/*      ERR_NEEDPONG	     512           Numeric List: Dalnet */
#define ERR_NOSUCHJUPE       514        /* Undernet extension - jupe -Kev */
/*	ERR_TOOMANYDCC	     514	dalnet */
#define ERR_BADEXPIRE        515        /* Undernet extension - jupe -Kev */
#define ERR_DONTCHEAT	     516	/* Undernet extension */
#define ERR_DISABLED	     517	/* Undernet extension -Kev */
/*	ERR_NOINVITE	     518	unreal */
#define ERR_LONGMASK	     518	/* Undernet extension -Kev */
/*	ERR_ADMONLY	     519	unreal */
#define ERR_TOOMANYUSERS     519	/* Undernet extension -Kev */
/*	ERR_OPERONLY	     520	unreal */
#define ERR_MASKTOOWIDE	     520	/* Undernet extension -Kev */
/*      ERR_WHOTRUNC         520        austnet */
/*      ERR_LISTSYNTAX       521        dalnet
	ERR_LISTSYNTAX       521	dalnet
	ERR_WHOSYNTAX	     522        dalnet
	ERR_WHOLIMEXCEED     523	dalnet */
#define ERR_QUARANTINED      524       /* Undernet extension -Vampire */
#define ERR_INVALIDKEY       525        /* Undernet extension */

#define ERR_NOTLOWEROPLEVEL  560	/* Undernet extension */
#define ERR_NOTMANAGER       561	/* Undernet extension */
#define ERR_CHANSECURED      562	/* Undernet extension */
#define ERR_UPASSSET         563	/* Undernet extension */
#define ERR_UPASSNOTSET      564	/* Undernet extension */
/*      ERR_NOMANAGER_LONG   565	no longer used */
#define ERR_NOMANAGER        566	/* Undernet extension */
#define ERR_UPASS_SAME_APASS 567        /* Undernet extension */
#define ERR_LASTERROR        568

/*	RPL_LOGON	     600	dalnet,unreal
	RPL_LOGOFF           601	dalnet,unreal
	RPL_WATCHOFF         602	dalnet,unreal
	RPL_WATCHSTAT        603	dalnet,unreal
	RPL_NOWON            604	dalnet,unreal
	RPL_NOWOFF           605	dalnet,unreal
	RPL_WATCHLIST        606	dalnet,unreal
	RPL_ENDOFWATCHLIST   607	dalnet,unreal

	RPL_MAPMORE          610	unreal

	RPL_MAPMORE          615	PTlink

	RPL_DCCSTATUS        617	dalnet
	RPL_DCCLIST          618	dalnet
	RPL_ENDOFDCCLIST     619	dalnet
	RPL_DCCINFO          620	dalnet

	RPL_DUMPING	     640	unreal
	RPL_DUMPRPL	     641	unreal
	RPL_EODUMP	     642	unreal
*/
#endif /* INCLUDED_numeric_h */
