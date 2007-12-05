define srv1 localhost:7601
define srv1-name irc.example.net
define cl1-nick Bug1685648
define channel #random-channel

connect cl1 %cl1-nick% buguser %srv1% :Some buggy user
:cl1 join %channel%
:cl1 expect %srv1-name% 366 %channel%
:cl1 quit done
