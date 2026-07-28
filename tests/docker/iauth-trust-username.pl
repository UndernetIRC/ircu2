#! /usr/bin/perl
# IAuth helper: assert a trusted username (iauth "U") with no leading ~.
#
# Used by the Cloudflare/websocket tests to prove that when iauth sets a
# username during auth, ircu does not prepend ~ — even on ports that skip
# the ident query.  This is the opposite of forcing a tilde.
use strict;
use warnings;
use FileHandle;

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

autoflush STDOUT 1;
# A: get USER (U) from the client; R: require approval; U: Undernet n/u/H.
print "O ARU\n";

while (<>) {
    s/\r?\n?\r?$//;
    my $client = $pending{my $id = $1} if s/^(\d+) //;

    if (/^C (\S+) (\S+) (.+)$/) {
        $pending{$id} = { id => $id, ip => $1, port => $2 };
    } elsif (/^([DT])/ and $client) {
        delete $pending{$id};
    } elsif (/^[Uu] (\S+)/ and $client) {
        # Trusted Username (capital U): GotId, no tilde on registration.
        reply("U " . trust_user($1), $client);
    } elsif (/^n (.+)$/ and $client) {
        reply("D", $client);
    }
}
