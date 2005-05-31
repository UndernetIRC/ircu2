define srv localhost

connect cl1 Alex alex %srv%:7701 :Test client 1
:cl1 oper oper1 oper1
:cl1 oper oper1 oper1
connect cl2 Bubb bubb %srv%:7711 :Test client 2
:cl1 raw :time
:cl2 oper oper3 oper4
:cl1 raw :version
:cl2 oper oldoper wrongpass
:cl2 oper md5oper wrongpass
:cl2 oper cryptoper wrongpass
:cl2 oper oper2 oper2
:cl2 raw :privs Alex Alex
:cl1 wait cl2
:cl1 raw :privs Bubb
:cl1 nick A
:cl1 nick Alexey
:cl1 raw :privmsg :
:cl1 raw :privmsg Alexey :
:cl1 raw :privmsg Bubb :hello Bubb
:cl1 raw :privmsg $*.net :Hello all *.net servers.
:cl1 raw :notice $*.net :Hello all *.net servers.
:cl1 raw :kill Bubb :goodbye Bubb
:cl1 raw :whowas Alex,Bubb 5
