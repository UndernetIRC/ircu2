define srv1 localhost:7601
define srv1-name irc.example.net
define hidden-srv *.undernet.org
define channel #random-channel
define cl1-nick Ch4n0pm4n
define cl2-nick D00dm4n

# Connect two clients.  Join one to the test channel.
connect cl1 %cl1-nick% op3rm4n %srv1% :Some Chanop
connect cl2 %cl2-nick% d00dm4n %srv1% :Someone Else
:cl1 join %channel%
:cl1 mode %channel% +D
:cl1 expect %cl1-nick% mode %channel% \\+D

# Now join the other client, and let the chanop remove -D.  Both
# should see the channel become +d.
:cl2 wait cl1
:cl2 join %channel%
:cl1 wait cl2
:cl1 mode %channel% -D
:cl1 expect %cl1-nick% mode %channel% -D\\+d
:cl2 expect %cl1-nick% mode %channel% -D\\+d

# Bug 1640796 is that if the chanop sends +D-D, the channel is
# improperly marked -d.  (An empty mode change is also sent to other
# servers.)
:cl1 mode %channel% +D-D
:cl1 mode %channel%
:cl1 expect %srv1-name% 324 %channel% \\+.*d

# Make sure that client 1 does see the -d when client 2 quits
:cl2 wait cl1
:cl1 expect %hidden-srv% mode %channel% -d
:cl2 part %channel%
:cl1 quit done
