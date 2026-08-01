#!/usr/bin/perl
# iauth login-on-connect stub for account-based resume tests.
#
# Logs every client into an account named after the username it sends in USER,
# then approves it.  This lets tests give a reconnecting client a verified
# account during registration without SASL/services.  See doc/readme.iauth.
#
# ircd->iauth:  "<id> <cmd> <args>"
# iauth->ircd:  "<cmd> <id> <ip> <port> <args>"   (id/ip/port are verified)
# We reply R (DoneAccount: set account + accept).
use strict;
use warnings;

$| = 1;            # autoflush stdout, or replies never reach the ircd

print "O RU\n";    # R: iauth required; U: Undernet extensions (sends U, n, H).

my (%ip, %port, %account);
while (my $line = <STDIN>) {
    chomp $line;
    my @f = split /\s+/, $line;
    next if @f < 2;
    my ($id, $cmd) = @f[0, 1];

    if ($cmd eq 'C' && @f >= 4) {
        ($ip{$id}, $port{$id}) = ($f[2], $f[3]);  # client ip + port
    } elsif ($cmd eq 'U' && @f >= 3) {
        $account{$id} = $f[2];                    # username -> account
    } elsif ($cmd eq 'n' && defined $ip{$id}) {
        my $acct = $account{$id} // $f[2] // '';  # fall back to the nick
        # Test convention: accounts named "optout*" carry the resume opt-out
        # flag (0x080), standing in for a service-set X_NO_AUTO_RESUME.
        $acct .= ':0:128' if $acct =~ /^optout/i;
        print "R $id $ip{$id} $port{$id} $acct\n";  # log in + accept
    } elsif ($cmd eq 'D') {
        delete $ip{$id}; delete $port{$id}; delete $account{$id};
    }
}
