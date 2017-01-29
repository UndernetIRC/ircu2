define srv1 localhost:7601
define srv1-name irc.example.net
define cl1-nick Op3rm4n
define channel1 #1234567890123456789012345678901234567890123456789
define channel2 #12345678901234567890123456789012345678901234567890


# Connect a client and try to join the two channels.
# The second channel's name is one character too long, and should be truncated.
connect cl1 %cl1-nick% oper %srv1% :Some Channel Operator
:cl1 join %channel1%
:cl1 join %channel2%
:cl1 expect %srv1-name% 403 %channel2% :No such channel
# Force cl1 to do something else so the expect is checked.
:cl1 part %channel1%
