#! /usr/bin/perl
# IAuth stub for the integration tests (attached to leaf1).
#
# Policy ARUS: the server sends U/P (A), waits for our verdict (R), sends
# n/u/H (U), and uses the asynchronous "? stats2" statistics request (S).
#
# Every client is approved (D) as soon as its nickname arrives.  The stub
# remembers, per nickname, the "U" (USER command) and "u" (confirmed
# username) values the server reported, and exposes them through the
# statistics reply so tests can check what ircd sent (/STATS iauth).
#
# The "? stats2" reply deliberately starts with a fragment terminated by a
# bare carriage return: ircd must log and skip it without desynchronising.
use strict;
use warnings;
use FileHandle;

my %pending;   # id => { id, ip, port, U, u, nick }
my %by_nick;   # nick => summary string
my @order;     # nick insertion order (bounded)
my $config_requests = 0;
my $stats_requests = 0;

sub reply {
    my ($msg, $client) = @_;
    return unless defined $msg;
    $msg =~ s/^(.) ?/$1 $client->{id} $client->{ip} $client->{port} / if $client;
    print "$msg\n";
}

autoflush STDOUT 1;
print "V :iauth-test 1.0\n";
print "O ARUS\n";

while (<>) {
    s/\r?\n?\r?$//;
    my $client;
    if (s/^(-?\d+) //) {
        my $id = $1;
        $client = $pending{$id};
        if (/^C (\S+) (\S+)/) {
            $pending{$id} = { id => $id, ip => $1, port => $2 };
            next;
        }
        if (/^\? config$/) {
            $config_requests++;
            print "a\n";
            print "A * iauth-test :policy=ARUS\n";
            print "A * iauth-test :config-requests=$config_requests\n";
            next;
        } elsif (/^\? stats$/) {
            $stats_requests++;
            print "s\n";
            print "S iauth-test :stats-requests=$stats_requests\n";
            next;
        } elsif (/^\? stats2$/) {
            $stats_requests++;
            # Fragment terminated by a bare CR: must be dropped by ircd.
            print "S iauth-test :garbage-fragment\r";
            print "S iauth-test :stats-requests=$stats_requests\n";
            for my $nick (@order) {
                print "S client :$by_nick{$nick}\n" if exists $by_nick{$nick};
            }
            print "s\n";
            next;
        }
        next unless $client;
        if (/^[DT]$/) {
            delete $pending{$id};
        } elsif (/^U (\S*)/) {
            $client->{U} = $1;
        } elsif (/^u ?(\S*)/) {
            $client->{u} = defined $1 ? $1 : '';
        } elsif (/^n (\S+)/) {
            my $nick = $1;
            $client->{nick} = $nick;
            $by_nick{lc $nick} = sprintf("nick=%s U=%s u=%s", $nick,
                                         $client->{U} // '-', $client->{u} // '-');
            push @order, lc $nick;
            delete $by_nick{shift @order} while @order > 50;
            reply("D", $client);
        }
    }
}
