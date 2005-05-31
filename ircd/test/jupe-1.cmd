define srv localhost:7701

connect cl1 Alex alex %srv% :Test client 1
:cl1 oper oper1 oper1
:cl1 raw :jupe +irc-3.example.net 3600 :Server 3 not welcome here.
:cl1 raw :jupe -irc-3.example.net 3600 :Server 3 not welcome here.
:cl1 raw :jupe +irc-3.example.net * 3600 :Server 3 not welcome here.
:cl1 raw :jupe -irc-3.example.net * 3600 :Server 3 not welcome here.
