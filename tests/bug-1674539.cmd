define srv1 127.0.0.1:7611
define srv1-name irc-2.example.net
define srv2 127.0.0.2:7621
define srv2-name irc-3.example.net
define cl1-nick oper1
define cl2-nick oper2
define cl3-nick oper3

# Connect two clients to server 1, one to server 2, and oper them all up.
connect cl1 %cl1-nick% oper %srv1% :Oper 1
connect cl2 %cl2-nick% oper %srv1% :Oper 2
connect cl3 %cl3-nick% oper %srv2% :Oper 3
:cl1 oper oper oper
:cl2 oper oper oper
:cl3 oper oper oper

# Check that we get local privileges properly.
:cl1 wait cl2,cl3
:cl1 raw :privs %cl1-nick%
:cl1 expect %srv1-name% 270 %cl1-nick% :CHAN_LIMIT
:cl1 raw :privs %cl2-nick%
:cl1 expect %srv1-name% 270 %cl2-nick% :CHAN_LIMIT

# Bug 1674539 is that remote /privs do not get any response.
# Testing shows that the problem only shows up with a hub between.
:cl1 raw :privs %cl3-nick%
:cl1 expect %srv2-name% 270 %cl3-nick% :CHAN_LIMIT

# Synchronize everything
sync cl1,cl2,cl3
:cl1 quit done
:cl2 quit done
:cl3 quit done
