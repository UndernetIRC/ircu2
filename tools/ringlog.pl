#! /usr/bin/perl -w
#
# Copyright (C) 2002 by Kevin L. Mitchell <klmitch@mit.edu>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# @(#)$Id$
#
# This program is intended to be used in conjunction with ringlog and
# the binutils program addr2line.  The -r option specifies the path to
# the ringlog program; the -a option specifies the path to addr2line.
# (Both of these default to assuming that the programs are in your
# PATH.)  All other options are passed to addr2line, and any other
# arguments are treated as filenames to pass to ringlog.  If no
# filenames are given, the program operates in filter mode, expecting
# to get output from ringlog on its standard input.  In this case,
# ringlog will not be directly executed, but addr2line still will.

use strict;

use Socket;
use IO::Handle;

sub start_addr2line {
    my ($location, @args) = @_;

    unshift(@args, '-f'); # always get functions

    # Get a socket pair
    socketpair(CHILD, PARENT, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
	or die "socketpair: $!";

    CHILD->autoflush(1); # Make sure autoflush is turned on
    PARENT->autoflush(1);

    my $pid;

    # Fork...
    die "cannot fork: $!"
	unless (defined($pid = fork));

    if (!$pid) { # in child
	close(CHILD);
	open(STDIN, "<&PARENT");
	open(STDOUT, ">&PARENT");
	exec($location, @args); # exec!
    }

    # in parent
    close(PARENT);

    return \*CHILD; # Return a filehandle for it
}

sub xlate_addr {
    my ($fh, $addr) = @_;

    # Feed address into addr2line
    print $fh "$addr\n";

    # Get function name, file name, and line number
    my $function = <$fh> || die "Couldn't get function name";
    my $fileline = <$fh> || die "Couldn't get file name or line number";

    # Remove newlines...
    chomp($function, $fileline);

    # If addr2line couldn't translate the address, just return it
    return "[$addr]"
	if ($function eq "??");

    # return function(file:line)[address]
    return "$function($fileline)[$addr]";
}

sub start_ringlog {
    my ($location, @args) = @_;

    # Build a pipe and fork, through the magic of open()
    my $pid = open(RINGLOG, "-|");

    # Make sure we forked!
    die "couldn't fork: $!"
	unless (defined($pid));

    # Execute ringlog...
    exec($location, @args)
	unless ($pid);

    return \*RINGLOG;
}

sub parse_ringlog {
    my ($ringlog, $addr) = @_;
    my $state = "reading";

    while (<$ringlog>) {
	chomp;

	# Beginning of parsable data
	if (/^File.*contents:$/) {
	    $state = "parsing";

	    # Here's actual parsable data, so parse it
	} elsif ($state eq "parsing" && /^\s*\d+/) {
	    s/(0x[a-fA-F0-9]+)/&xlate_addr($addr, $1)/eg;

	    # Switch out of parsing mode
	} else {
	    $state = "reading";
	}

	# Print the final result
	print "$_\n";
    }
}

# get an argument for an option that requires one
sub getarg (\$) {
    my ($iref) = @_;

    $ARGV[$$iref] =~ /^(-.)(.*)/;

    die "Argument for $1 missing"
	unless ((defined($2) && $2 ne "") || @ARGV > $$iref + 1);

    return defined($2) && $2 ne "" ? $2 : $ARGV[++$$iref];
}

my ($ringlog_exe, $addr2line_exe) = ("ringlog", "addr2line");
my (@addr2line_args, @files);

# Deal with arguments; note that we have to deal with -b and -e for
# addr2line.
for (my $i = 0; $i < @ARGV; $i++) {
    if ($ARGV[$i] =~ /^-r/) {
	$ringlog_exe = getarg($i);
    } elsif ($ARGV[$i] =~ /^-a/) {
	$addr2line_exe = getarg($i);
    } elsif ($ARGV[$i] =~ /^-([be])/) {
	push(@addr2line_args, "-$1", getarg($i));
    } elsif ($ARGV[$i] =~ /^-/) {
	push(@addr2line_args, $ARGV[$i]);
    } else {
	push(@files, [ $ARGV[$i], @addr2line_args ]);
	@addr2line_args = ();
    }
}

# Verify that that left us with executable names, at least
die "No ringlog executable"
    unless (defined($ringlog_exe) && $ringlog_exe ne "");
die "No addr2line executable"
    unless (defined($addr2line_exe) && $addr2line_exe ne "");

# Ok, process each file we've been asked to process
foreach my $file (@files) {
    my ($addr2line, $ringlog) =
	(start_addr2line($addr2line_exe, @{$file}[1..$#{$file}]),
	 start_ringlog($ringlog_exe, $file->[0]));

    parse_ringlog($ringlog, $addr2line);

    close($addr2line);
    close($ringlog);
}

# Now if there are still more unprocessed arguments, expect ringlog
# input on stdin...
if (@addr2line_args) {
    my $addr2line = start_addr2line($addr2line_exe, @addr2line_args);

    parse_ringlog(\*STDIN, $addr2line);
    close($addr2line);
}
