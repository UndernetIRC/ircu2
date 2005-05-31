define srv localhost:7701

connect cl1 Alex alex %srv% :Test client 1
connect cl2 Bubb bubb %srv% :Test client 2
:cl1 raw :help
:cl1 raw :admin
:cl1 raw :admin test-2.*
:cl1 raw :info
:cl1 raw :wallops :HELLO OPERZ!!!
:cl1 wait cl2
:cl1 raw :ison alex,bubb,alex,bubb,alex,bubb
:cl1 raw :who b*b
:cl1 raw :burst the bubble
:cl1 raw :server huh huh i'm a server
:cl1 raw :links
:cl1 raw :map
:cl1 raw :nick
:cl1 raw :nick ~
:cl1 raw :nick -dude-
:cl1 raw :nick alex
:cl1 raw :nick Bubb
:cl1 raw :ping alex test-1.*

:cl1 oper oper1 oper1
:cl1 raw :admin
:cl1 raw :admin test-2.*
:cl1 raw :asll
:cl1 raw :asll test-2.*
:cl1 raw :info
:cl1 raw :info test-2.*
:cl1 raw :who x b*b
:cl1 raw :close
:cl1 raw :map
:cl1 raw :links
:cl1 raw :links test-2.*
:cl1 raw :lusers
:cl1 raw :lusers test-2.*
:cl1 raw :motd
:cl1 raw :motd test-2.*
:cl1 raw :ping alex test-2.*
:cl1 raw :rping test-2.*

:cl2 raw :quit
