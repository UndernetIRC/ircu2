define srv localhost

connect cl1 Alex alex %srv%:7701 :Test client 1
connect cl2 Bubb bubb %srv%:7711 :Test client 2
:cl1 join #test
:cl1 join #test2
:cl1 mode #test +bb *!*@127.0.0.1 *!*@127.0.0.2
:cl2 wait cl1
:cl2 raw :away :I'm not here, go away.  I'm not here, go away.  I'm not here, go away.  I'm not here, go away.  I'm not here, go away.  I'm not here, go away.  I'm not here, go away.  I'm not here, go away.  I'm not here, go away.  I'm not here, go away.
:cl2 raw :away :I'm not here, go away.
:cl2 join #test,#test3,#test4,+local
:cl1 wait cl2
:cl1 join #test3
:cl1 raw :invite Bubb
:cl1 raw :invite #test
:cl1 invite Bubb #non-existent-channel
:cl1 invite Bubb #test3
:cl1 invite Bubb #test4
:cl1 invite Bubb #test
:cl2 expect *cl1 invite #test
:cl2 mode #test3 +o Alex
:cl2 raw :invite
:cl2 join #test
:cl2 privmsg #test :Hello, *cl1.
:cl2 notice #test :Hello, *cl1 (via notice).
:cl2 notice @#test :Hello, *cl1 (via wallchops).
:cl2 privmsg #test5 :Hello, *cl1.
:cl2 nick Buba
:cl2 mode #test +l 15
:cl1 wait cl2
:cl1 privmsg #test :Hello, *cl2.
:cl1 raw :cprivmsg bubb #test :Hello, bubb.
:cl1 raw :cnotice bubb #test :Hello, bubb.
:cl1 mode #test -b+kv *!*@127.0.0.1 secret Bubb
:cl1 mode #test +b foo!bar@baz
:cl1 mode #test +b
:cl1 mode #test :
:cl1 mode #test
:cl1 raw :names
:cl1 raw :names #test
:cl1 raw :names +local
:cl1 raw :names +local test-2.*
:cl1 raw :who #test %lfuh
:cl2 wait cl1
:cl2 raw :part
:cl2 part #test
:cl2 part #test5
:cl1 wait cl2
:cl2 join #test public
:cl2 join #test secret
:cl1 join 0
:cl1 join #test2
:cl2 wait cl1
:cl2 join #test2
:cl1 wait cl2
:cl1 mode #test2 +smtinrDlAU 15 apples oranges
:cl1 mode #test2
:cl2 wait cl1
:cl2 join #test2 apples
:cl2 privmsg #test2 :Hello, oplevels.
:cl2 mode #test2
:cl2 mode #test2 -io+v Alex Alex
:cl1 wait cl2
:cl1 part #test2
:cl1 join #test2
:cl2 wait cl1
:cl2 mode #test2 -D
:cl2 mode #test +v Alex
:cl1 raw :kick #test bubb
:cl2 raw :squit test-1.*
:cl2 sleep 1
:cl2 raw :connect test-1.*
:cl2 raw :away :
:cl1 wait cl2
