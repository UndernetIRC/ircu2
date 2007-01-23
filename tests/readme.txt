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
