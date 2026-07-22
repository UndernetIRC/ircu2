#!/usr/bin/perl
# IAuth stub for the DNS resolver tests.
#
# Approves every client as soon as its nickname is announced.  Clients
# that connect to the dedicated spoof port (SPOOF_PORT) are IP-rewritten
# with the I command the moment they are introduced (the "C" message),
# i.e. while their forward DNS lookup is still in flight.  This mirrors a
# real spoofing IAuth (WEBIRC/CGIIRC) and exercises the auth->original
# path in auth_dns_callback: the DNS answer that later arrives for the
# client's *original* IP must not be treated as an IP mismatch.
#
# The override must happen at "C" time, not on "n": ircd withholds the
# "n"/"U"/"u" notifications until the initial DNS lookup has finished
# (check_auth_finished bails while AR_DNS_PENDING is set), so an override
# driven by "n" would always land after the DNS answer and never race it.
#
# The override also clears AR_DNS_PENDING, so the client would otherwise
# register (and finish) before the delayed forward DNS answer returns.
# To keep the auth request alive until the answer reaches
# auth_dns_callback, approval (D) for spoofed clients is held for
# HOLD_SECONDS, which must exceed the slow_a A-record delay.
use strict;
use warnings;

$| = 1;

my $SPOOF_IP = "10.99.9.9";
my $SPOOF_PORT = "6672";
my $HOLD_SECONDS = 3;

# R: iauth is required; U: enable Undernet extensions.
print "O RU\n";

my %clients;
my %spoofed;
while (my $line = <STDIN>) {
    $line =~ s/[\r\n]+\z//;
    my @parts = split / /, $line;
    next if @parts < 2;
    my ($cid, $cmd) = @parts[0, 1];
    if ($cmd eq 'C' && @parts >= 6) {
        # "<id> C <remoteip> <remoteport> <localip> <localport>"
        my ($rip, $rport, $lport) = @parts[2, 3, 5];
        $clients{$cid} = [ $rip, $rport ];
        if ($lport eq $SPOOF_PORT) {
            # Rewrite the IP now, before the forward DNS answer returns.
            print "I $cid $rip $rport $SPOOF_IP\n";
            $spoofed{$cid} = 1;
            $clients{$cid} = [ $SPOOF_IP, $rport ];
        }
    }
    elsif ($cmd eq 'n' && exists $clients{$cid}) {
        my ($ip, $port) = @{ $clients{$cid} };
        # Hold spoofed clients so the delayed forward DNS answer reaches
        # auth_dns_callback while the auth request is still pending.
        sleep $HOLD_SECONDS if $spoofed{$cid};
        print "D $cid $ip $port\n";
        delete $clients{$cid};
        delete $spoofed{$cid};
    }
    elsif ($cmd eq 'D') {
        delete $clients{$cid};
        delete $spoofed{$cid};
    }
}
