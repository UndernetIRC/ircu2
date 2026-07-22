#!/usr/bin/perl
# Stalled inbound P10 server link for the sendq regression test
# (test_server_sendq.py).  Runs INSIDE the ircd container via docker exec so
# the connection crosses the container's loopback only -- Docker Desktop's
# port relay buffers multiple megabytes elastically and would otherwise
# absorb the flood before the ircd's sendq ever grows.
#
# Flow: elicit a pre-registration reply (poisons the cached sendq limit with
# the DEFAULTMAXSENDQLENGTH fallback), complete the P10 handshake, print
# HANDSHAKE-DONE, then stop reading so the ircd's sendq to us fills up.
use strict;
use warnings;
use Socket;

$| = 1;    # autoflush STDOUT so the test sees HANDSHAKE-DONE immediately

my $port = $ARGV[0] || 4410;

socket(my $sock, PF_INET, SOCK_STREAM, getprotobyname('tcp'))
  or die "socket: $!";
# Pin a tiny receive buffer BEFORE connect so the TCP window cannot
# autotune; backpressure then reaches the ircd within a few kilobytes.
setsockopt($sock, SOL_SOCKET, SO_RCVBUF, pack('l', 4096))
  or die "setsockopt: $!";
connect($sock, sockaddr_in($port, inet_aton('127.0.0.1')))
  or die "connect: $!";
{ my $old = select($sock); $| = 1; select($old); }

my $ts = time();
# Unregistered VERSION: the numeric reply goes through the sendq while no
# conf is attached yet, so get_sendq() caches the feature default.
print $sock "VERSION\r\n";
print $sock "PASS :testpass\r\n";
print $sock "SERVER services.test.net 1 $ts $ts J10 AE]]] +s :Stall Test\r\n";

# Read the hub's burst; answer end-of-burst and its ack ("AE" = numeric 4).
my $seen = 0;
while (my $line = <$sock>) {
  if ($line =~ /^\S+ EB\s*$/) { $seen = 1; last; }
}
die "link closed before end of burst\n" unless $seen;
print $sock "AE EB\r\n";
$seen = 0;
while (my $line = <$sock>) {
  if ($line =~ /^\S+ EA\s*$/) { $seen = 1; last; }
}
die "link closed before burst ack\n" unless $seen;
print $sock "AE EA\r\n";

print "HANDSHAKE-DONE\n";

# Stall: never read again.  The test kills this process when it is done.
sleep 120;
