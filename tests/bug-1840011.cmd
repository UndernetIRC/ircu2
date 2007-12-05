define srv1 localhost:7601
define srv1-name irc.example.net
define hidden-srv *.undernet.org
define channel #random-channel
define cl1-nick Ch4n0pm4n

# Connect a client and join it to the test channel.
connect cl1 %cl1-nick% op3rm4n %srv1% :Some Chanop
:cl1 join %channel%

# Issue a variety of bans, all of which should be accepted.
:cl1 mode %channel% +b *!*@1.0.0.0/16
:cl1 mode %channel% +b *!*@1.0.0.*
:cl1 mode %channel% +b *!*@*.example.com
:cl1 mode %channel% +b *!foo@*.example.org
:cl1 mode %channel% +b *!*@*.bar.example.*

# Check the modes on the channel.
:cl1 mode %channel% +b
# These regexps make my eyes bleed almost enough to add a load of code to test-driver.pl.
# There's another test-driver problem here, too: one "expect" works fine, but a second
# one never sees the second numeric response from the server.
:cl1 expect %srv1-name% 367 %channel% \\*!\\*@\\*\\.bar\\.example\\.* %cl1-nick% \\d+

# Check that a more-encompassing ban removes the old bans.
:cl1 mode %channel% +b *!*@1.0.*
:cl1 expect %cl1-nick% mode %channel% -bb\\+b \\*!\\*@1\\.0\\.0\\.\\* \\*!\\*@1\\.0\\.0\\.0/16 \\*!\\*@1\\.0\\.\\*

# Check that a narrower ban cannot be added.
# Somewhat sadly, the first command gets no response at all.
:cl1 mode %channel% +b *!*@1.0.0.1
:cl1 mode %channel% +b
:cl1 expect %srv1-name% 367 %channel% \\*!\\*@1\\.0\\.\\* %cl1-nick% \\d+

# Can we remove a broader ban and add a narrow ban at the same time?
# This was the core of the bug report (SF#1840011).
:cl1 mode %channel% -b+b *!*@1.0.* *!*@1.0.0.1
:cl1 expect %cl1-nick% mode %channel% -b\\+b \\*!\\*@1\\.0\\.\\* \\*!\\*@1\\.0\\.0\\.1
:cl1 quit done
