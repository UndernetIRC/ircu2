ircu Test Framework
===================

This directory contains a simple test driver for ircu, supporting
files, and test scripts.  test-driver.pl requires the POE and
POE::Component::IRC modules for Perl; they are available from CPAN.

The test scripts assume that an instance of ircu has been started
using the ircd.conf file in this directory (e.g. by running
"../ircd/ircd -f `pwd`/ircd.conf"), and that IPv4 support is enabled
on the system.

The test-driver.pl script accepts several command-line options:

 -D enables POE::Component::IRC debugging output
 -V enables test-driver.pl debugging output
 -Hipaddr sets the IPv4 address to use for connections to the server
 one or more script names to interpret and execute

The normal output is one dot for each line that is executed.  Using
the -D and -V options generates much more output.

Command Syntax
==============

A test script typically starts with a set of variable definitions for
strings that are used throughout the script or that may be changed to
match changes ircu's configuration file.  These have the syntax:
	define <variable> <replacement text>

A variable is expanded by writing %variablename% in later commands.
If a variable is dereferenced without a definition, the test will
abort.

Following the variable definitions is usually one or more "connect"
statements.  These have the syntax:
	connect <tag> <nickname> <username> <server:port> :<Real Name or GECOS>
This creates a client and starts a connection to an IRC server.  The
tag is used to issue commands for that client in the rest of the file.
The remaining fields have their usual meanings for IRC.

A number of IRC commands are supported natively, including:
	:<tag> join <channel>
	:<tag> mode <nick/channel> [<modes> ...]
	:<tag> nick <nickname>
	:<tag> notice <target> :<text>
	:<tag> oper <name> <password>
	:<tag> part <channel> [:<message>]
	:<tag> privmsg <target> :<text>
	:<tag> quit [:<message>]
	:<tag> raw :<irc line to send>

Other commands are used to implement tests:
	:<tag> expect <irc line contents>
	:<tag> sleep <seconds>
	:<tag> wait <tag2,tag3>

The test commands are discussed at more length below.

expect Syntax
=============

The command to look for data coming from the irc server is "expect":
	:<tag> expect <irc line contents>

The contents are treated as a regular expression and matched against
the start of the line.  If the line from the IRC server began with
':', that is removed before the match is performed.

Because the contents are a regular expression, and because \ is used
as an escape character both in parsing both the script line and the
regular expression, some common things become awkward to match:
	:cl1 mode %channel% +D
	:cl1 expect %cl1-nick% mode %channel% \\+D
or a more drastic example:
	:cl1 mode %channel% +b *!*@*.bar.example.*
	:cl1 mode %channel% +b
	:cl1 expect %srv1-name% 367 %channel% \\*!\\*@\\*\\.bar\\.example\\.* %cl1-nick% \\d+

sleep Syntax
============

The command to make a client stop operating for a fixed period of time
is "sleep":
	:<tag> sleep <seconds>

This will deactivate the identified client for at least <seconds>
seconds (which may be a floating point number).  Other clients will
continue to process commands, but if another command for the
identified client is encountered, it will block execution until the
time expires.

wait Syntax
===========

The command to synchronize one client to another is "wait":
	:<tag> wait <tag2[,tag3...]>

This is syntactic sugar for something like this:
	:<tag> expect <nick2> NOTICE <nick> :SYNC
	:<nick2> notice <nick> :SYNC
	:<tag> expect <nick3> NOTICE <nick> :SYNC
	:<nick3> notice <nick> :SYNC

In other words, the wait command uses in-IRC messages to make sure
that other clients have already executed commands up to a certain
point in the test script.
