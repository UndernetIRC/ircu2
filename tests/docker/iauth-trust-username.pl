#! /usr/bin/perl
# IAuth helper: assert a trusted username (iauth "U") with no leading ~.
#
# Used by the Cloudflare/websocket tests to prove that when iauth sets a
# username during auth, ircu does not prepend ~ — even on ports that skip
# the ident query.  This is the opposite of forcing a tilde.
use strict;
use warnings;
use FileHandle;

# Reported via "V"; tests poll STATS iauthconf for it to know the policy
# line below has been processed (both arrive in order on the same pipe).
my $VERSION = "iauth-trust-username";

my %pending;

sub reply {
    my ($msg, $client) = @_;
    return unless defined $msg;
    if (ref $msg eq '') {
        $msg =~ s/^(.) ?/$1 $client->{id} $client->{ip} $client->{port} / if $client;
        print "$msg\n";
    }
}

# Strip an interim ~ that ircu may have already prepended before notifying
# iauth; the trusted name we assert must not keep that marker.
sub trust_user {
    my ($user) = @_;
    $user =~ s/^~//;
    return $user;
}

# Approve only once both USER (trusted reply sent) and NICK are seen, so the
# "U" reply always reaches ircu before "D" regardless of NICK/USER order.
sub maybe_done {
    my ($client) = @_;
    reply("D", $client) if $client->{user} and $client->{nick};
}

autoflush STDOUT 1;
# A: get USER (U) from the client; R: require approval; U: Undernet n/u/H.
print "O ARU\n";
print "V $VERSION\n";

while (<>) {
    s/\r?\n?\r?$//;
    my $client = $pending{my $id = $1} if s/^(\d+) //;

    if (/^C (\S+) (\S+) (.+)$/) {
        $pending{$id} = { id => $id, ip => $1, port => $2 };
    } elsif (/^([DT])/ and $client) {
        delete $pending{$id};
    } elsif (/^U (\S+)/ and $client) {
        # USER notification: reply with a trusted Username (capital U),
        # which sets GotId so registration keeps it without a tilde.
        reply("U " . trust_user($1), $client);
        $client->{user} = 1;
        maybe_done($client);
    } elsif (/^n (.+)$/ and $client) {
        $client->{nick} = 1;
        maybe_done($client);
    }
}
