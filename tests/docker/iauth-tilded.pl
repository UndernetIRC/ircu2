#! /usr/bin/perl
# Minimal IAuth helper for trust-username tests: force ~ prefix on usernames.
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

autoflush STDOUT 1;
print "O ARU\n";

while (<>) {
    s/\r?\n?\r?$//;
    my $client = $pending{my $id = $1} if s/^(\d+) //;

    if (/^C (\S+) (\S+) (.+)$/) {
        $pending{$id} = { id => $id, ip => $1, port => $2 };
    } elsif (/^([DT])/ and $client) {
        delete $pending{$id};
    } elsif (/^u (\S+)/ and $client) {
        my $user = $1;
        $user = "~$user" unless $user =~ /^~/;
        reply("u $user", $client);
    } elsif (/^n (.+)$/ and $client) {
        reply("D", $client);
    }
}
