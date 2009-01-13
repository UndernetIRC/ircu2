#! /usr/bin/perl -wT

# If you edit this file, please check carefully that the garbage
# collection isn't broken.  POE is sometimes too clever for our good
# in finding references to sessions, and keeps running even after we
# want to stop.

require 5.006;

use warnings;
use strict;
use vars;
use constant DELAY => 2;
use constant EXPECT_TIMEOUT => 15;
use constant RECONNECT_TIMEOUT => 5;
use constant THROTTLED_TIMEOUT => 90;

use FileHandle;
# sub POE::Kernel::ASSERT_DEFAULT () { 1 }
# sub POE::Kernel::TRACE_DEFAULT () { 1 }
use POE v0.35;
use POE::Component::IRC v5.00;

# this defines commands that take "zero time" to execute
# (specifically, those which do not send commands from the issuing
# client to the server)
our $zero_time = {
                  expect => 1,
                  sleep => 1,
                  wait => 1,
                 };

# Create the main session and start POE.
# All the empty anonymous subs are just to make POE:Session::ASSERT_STATES happy.
POE::Session->create(inline_states =>
                     {
                      # POE kernel interaction
                      _start => \&drv_start,
                      _child => sub {},
                      _stop => sub {
                        my $heap = $_[HEAP];
                        print "\nThat's all, folks!";
                        print "(exiting at line $heap->{lineno}: $heap->{line})"
                          if $heap->{line};
                        print "\n";
                      },
                      _default => \&drv_default,
                      # generic utilities or miscellaneous functions
                      heartbeat => \&drv_heartbeat,
                      timeout_expect => \&drv_timeout_expect,
                      reconnect => \&drv_reconnect,
                      enable_client => sub { $_[ARG0]->{ready} = 1; },
                      disable_client => sub { $_[ARG0]->{ready} = 0; },
                      die => sub { $_[KERNEL]->signal($_[SESSION], 'TERM'); },
                      # client-based command issuers
                      cmd_expect => \&cmd_expect,
                      cmd_join => \&cmd_generic,
                      cmd_mode => \&cmd_generic,
                      cmd_nick => \&cmd_generic,
                      cmd_notice => \&cmd_message,
                      cmd_oper => \&cmd_generic,
                      cmd_part => \&cmd_generic,
                      cmd_privmsg => \&cmd_message,
                      cmd_quit => \&cmd_generic,
                      cmd_raw => \&cmd_raw,
                      cmd_sleep => \&cmd_sleep,
                      cmd_wait => \&cmd_wait,
                      # handlers for messages from IRC
                      irc_001 => \&irc_connected, # Welcome to ...
                      irc_snotice => sub {}, # notice from a server (anonymous/our uplink)
                      irc_notice => \&irc_notice, # NOTICE to self or channel
                      irc_msg => \&irc_msg, # PRIVMSG to self
                      irc_public => \&irc_public, # PRIVMSG to channel
                      irc_connected => sub {},
                      irc_ctcp_action => sub {},
                      irc_ctcp_ping => sub {},
                      irc_ctcp_time => sub {},
                      irc_ctcpreply_ping => sub {},
                      irc_ctcpreply_time => sub {},
                      irc_invite => sub {},
                      irc_isupport => sub {},
                      irc_join => sub {},
                      irc_kick => sub {},
                      irc_kill => sub {},
                      irc_mode => \&irc_mode, # MODE change on client or channel
                      irc_nick => sub {},
                      irc_part => sub {},
                      irc_ping => sub {},
                      irc_quit => sub {},
                      irc_registered => sub {},
                      irc_topic => sub {},
                      irc_plugin_add => sub {},
                      irc_error => \&irc_error,
                      irc_disconnected => \&irc_disconnected,
                      irc_socketerr => \&irc_socketerr,
                     },
                     args => [@ARGV]);

$| = 1;
$poe_kernel->run();
exit;

# Core/bookkeeping test driver functions

sub drv_start {
  my ($kernel, $session, $heap) = @_[KERNEL, SESSION, HEAP];

  # initialize heap
  $heap->{clients} = {}; # session details, indexed by (short) session name
  $heap->{sessions} = {}; # session details, indexed by session ref
  $heap->{servers} = {}; # server addresses, indexed by short names
  $heap->{macros} = {}; # macros

  # Parse arguments
  foreach my $arg (@_[ARG0..$#_]) {
    if ($arg =~ /^-D$/) {
      $heap->{irc_debug} = 1;
    } elsif ($arg =~ /^-V$/) {
      $heap->{verbose} = 1;
    } elsif ($arg =~ /^-H(.+)$/) {
      $heap->{local_address} = $1;
    } else {
      die "Extra command-line argument $arg\n" if $heap->{script};
      $heap->{script} = new FileHandle($arg, 'r')
        or die "Unable to open $arg for reading: $!\n";
    }
  }
  die "No test name specified\n" unless $heap->{script};

  # hook in to POE
  $kernel->alias_set('control');
  $kernel->yield('heartbeat');
}

sub drv_heartbeat {
  my ($kernel, $sender, $heap) = @_[KERNEL, SENDER, HEAP];
  my $script = $heap->{script};
  my $used = {};
  my $delay = DELAY;

  while (1) {
    my ($line, $lineno);
    if ($heap->{line}) {
      $line = delete $heap->{line};
    } elsif (defined($line = <$script>)) {
      $heap->{lineno} = $.;
      print "." unless $heap->{irc_debug};
    } else {
      # close all connections
      foreach my $client (values %{$heap->{clients}}) {
        $kernel->call($client->{irc}, 'quit', "I fell off the end of my script");
        $client->{quitting} = 1;
      }
      # unalias the control session
      $kernel->alias_remove('control');
      # die in a few seconds
      $kernel->delay_set('die', 5);
      return;
    }

    chomp $line;
    # ignore comments and blank lines
    next if $line =~ /^\#/ or $line !~ /\S/;

    # expand any macros in the line
    $line =~ s/(?<=[^\\])%(\S+?)%/$heap->{macros}->{$1}
      or die "Use of undefined macro $1 at line $heap->{lineno}\n"/eg;
    # remove any \-escapes
    $line =~ s/\\(.)/$1/g;
    # figure out the type of line
    if ($line =~ /^define (\S+) (.+)$/i) {
      # define a new macro
      $heap->{macros}->{$1} = $2;
    } elsif ($line =~ /^undef (\S+)$/i) {
      # remove the macro
      delete $heap->{macros}->{$1};
    } elsif ($line =~ /^connect (\S+) (\S+) (\S+) (\S+) :(.+)$/i) {
      # connect a new session (named $1) to server $4
      my ($name, $nick, $ident, $server, $userinfo, $port) = ($1, $2, $3, $4, $5, 6667);
      $server = $heap->{servers}->{$server} || $server;
      if ($server =~ /(.+):(\d+)/) {
        $server = $1;
        $port = $2;
      }
      die "Client with nick $nick already exists (line $heap->{lineno})" if $heap->{clients}->{$nick};
      my $alias = "client_$name";
      my $client = {
                    name => $name,
                    nick => $nick,
                    ready => 0,
                    expect => [],
                    expect_alarms => [],
                    params => { Nick     => $nick,
                                Server   => $server,
                                Port     => $port,
                                Username => $ident,
                                Ircname  => $userinfo,
                                Debug    => $heap->{irc_debug},
                              }
                   };
      $client->{params}->{LocalAddr} = $heap->{local_address}
        if $heap->{local_address};
      my $irc = POE::Component::IRC->spawn
        (
         alias => $alias,
         nick => $nick,
        ) or die "Unable to create new user $nick (line $heap->{lineno}): $!";
      $client->{irc} = $irc->session_id();
      $heap->{clients}->{$client->{name}} = $client;
      $heap->{sessions}->{$irc} = $client;
      $kernel->call($client->{irc}, 'register', 'all');
      $kernel->call($client->{irc}, 'connect', $client->{params});
      $used->{$name} = 1;
    } elsif ($line =~ /^sync (.+)$/i) {
      # do multi-way synchronization between every session named in $1
      my @synced = split(/,|\s/, $1);
      # first, check that they exist and are ready
      foreach my $clnt (@synced) {
        die "Unknown session name $clnt (line $heap->{lineno})" unless $heap->{clients}->{$clnt};
        goto REDO unless $heap->{clients}->{$clnt}->{ready};
      }
      # next we actually send the synchronization signals
      foreach my $clnt (@synced) {
        my $client = $heap->{clients}->{$clnt};
        $client->{sync_wait} = [map { $_ eq $clnt ? () : $heap->{clients}->{$_}->{nick} } @synced];
        $kernel->call($client->{irc}, 'notice', $client->{sync_wait}, 'SYNC');
        $kernel->call($sender, 'disable_client', $client);
      }
    } elsif ($line =~ /^:(\S+) (\S+)(.*)$/i) {
      # generic command handler
      my ($names, $cmd, $args) = ($1, lc($2), $3);
      my (@avail, @unavail);
      # figure out whether each listed client is available or not
      foreach my $c (split ',', $names) {
        my $client = $heap->{clients}->{$c};
        if (not $client) {
          print "ERROR: Unknown session name $c (line $heap->{lineno}; ignoring)\n";
        } elsif (($used->{$c} and not $zero_time->{$cmd}) or ($cmd ne 'expect' and not $client->{ready})) {
          push @unavail, $c;
        } else {
          push @avail, $c;
        }
      }
      # redo command with unavailable clients
      if (@unavail) {
        # This will break if the command can cause a redo for
        # available clients.. this should be fixed sometime
        $line = ':'.join(',', @unavail).' '.$cmd.$args;
        $heap->{redo} = 1;
      }
      # do command with available clients
      if (@avail) {
        # split up the argument part of the line
        $args =~ /^((?:(?: [^:])|[^ ])+)?(?: :(.+))?$/;
        $args = [($1 ? split(' ', $1) : ()), ($2 ? $2 : ())];
        # find the client and figure out if we need to wait
        foreach my $c (@avail) {
          my $client = $heap->{clients}->{$c};
          die "Client $c used twice as source (line $heap->{lineno})" if $used->{c} and not $zero_time->{$cmd};
          $kernel->call($sender, 'cmd_' . $cmd, $client, $args);
          $used->{$c} = 1 unless $zero_time->{$cmd};
        }
      }
    } else {
      die "Unrecognized input line $heap->{lineno}: $line";
    }
    if ($heap->{redo}) {
    REDO:
      delete $heap->{redo};
      $heap->{line} = $line;
      last;
    }
  }
  # issue new heartbeat with appropriate delay
  $kernel->delay_set('heartbeat', $delay);
}

sub drv_timeout_expect {
  my ($kernel, $session, $client, $heap) = @_[KERNEL, SESSION, ARG0, HEAP];
  print "\nERROR: Dropping timed-out expectation by $client->{name} (line $heap->{expect_lineno}): ".join(',', @{$client->{expect}->[0]})."\n";
  $client->{expect_alarms}->[0] = undef;
  unexpect($kernel, $session, $client);
}

sub drv_reconnect {
  my ($kernel, $session, $client) = @_[KERNEL, SESSION, ARG0];
  $kernel->call($client->{irc}, 'connect', $client->{params});
}

sub drv_default {
  my ($kernel, $heap, $sender, $session, $state, $args) = @_[KERNEL, HEAP, SENDER, SESSION, ARG0, ARG1];
  if ($state =~ /^irc_(\d\d\d)$/) {
    my $client = $heap->{sessions}->{$sender->get_heap()};
    if (@{$client->{expect}}
        and $args->[0] eq $client->{expect}->[0]->[0]
        and $client->{expect}->[0]->[1] eq "$1") {
      my $expect = $client->{expect}->[0];
      my $mismatch;
      $args = $args->[2]; # ->[1] is the entire string, ->[2] is split
      for (my $x=0; ($x+2<=$#$expect) and ($x<=$#$args) and not $mismatch; $x++) {
        my $expectation = $expect->[$x+2];
        if ($args->[$x] !~ /$expectation/i) {
          $mismatch = 1;
          print "Mismatch in arg $x: $args->[$x] !~ $expectation\n";
        }
      }
      unexpect($kernel, $session, $client) unless $mismatch;
    }
    return undef;
  }
  print "ERROR: Unexpected event $state to test driver (from ".$sender->ID.")\n";
  return undef;
}

# client-based command issuers

sub cmd_message {
  my ($kernel, $heap, $event, $client, $args) = @_[KERNEL, HEAP, STATE, ARG0, ARG1];
  die "Missing arguments" unless $#$args >= 1;
  # translate each target as appropriate (e.g. *sessionname)
  my @targets = split(/,/, $args->[0]);
  foreach my $target (@targets) {
    if ($target =~ /^\*(.+)$/) {
      my $other = $heap->{clients}->{$1} or die "Unknown session name $1 (line $heap->{lineno})\n";
      $target = $other->{nick};
    }
  }
  $kernel->call($client->{irc}, substr($event, 4), \@targets, $args->[1]);
}

sub cmd_generic {
  my ($kernel, $event, $client, $args) = @_[KERNEL, STATE, ARG0, ARG1];
  $kernel->call($client->{irc}, substr($event, 4), @$args);
}

sub cmd_raw {
  my ($kernel, $heap, $client, $args) = @_[KERNEL, HEAP, ARG0, ARG1];
  die "Missing argument" unless $#$args >= 0;
  $kernel->call($client->{irc}, 'sl', $args->[0]);
}

sub cmd_sleep {
  my ($kernel, $session, $heap, $client, $args) = @_[KERNEL, SESSION, HEAP, ARG0, ARG1];
  die "Missing argument" unless $#$args >= 0;
  $kernel->call($session, 'disable_client', $client);
  $kernel->delay_set('enable_client', $args->[0], $client);
}

sub cmd_wait {
  my ($kernel, $session, $heap, $client, $args) = @_[KERNEL, SESSION, HEAP, ARG0, ARG1];
  die "Missing argument" unless $#$args >= 0;
  # if argument was comma-delimited, split it up (space-delimited is split by generic parser)
  $args = [split(/,/, $args->[0])] if $args->[0] =~ /,/;
  # make sure we only wait if all the other clients are ready
  foreach my $other (@$args) {
    if (not $heap->{clients}->{$other}->{ready}) {
      $heap->{redo} = 1;
      return;
    }
  }
  # disable this client, make the others send SYNC to it
  $kernel->call($session, 'disable_client', $client);
  $client->{sync_wait} = [map { $heap->{clients}->{$_}->{nick} } @$args];
  foreach my $other (@$args) {
    die "Cannot wait on self" if $other eq $client->{name};
    $kernel->call($heap->{clients}->{$other}->{irc}, 'notice', $client->{nick}, 'SYNC');
  }
}

sub cmd_expect {
  my ($kernel, $session, $heap, $client, $args) = @_[KERNEL, SESSION, HEAP, ARG0, ARG1];
  die "Missing argument" unless $#$args >= 0;
  $heap->{expect_lineno} = $heap->{lineno};
  push @{$client->{expect}}, $args;
  push @{$client->{expect_alarms}}, $kernel->delay_set('timeout_expect', EXPECT_TIMEOUT, $client);
  $kernel->call($session, 'disable_client', $client);
}

# handlers for messages from IRC

sub unexpect {
  my ($kernel, $session, $client) = @_;
  shift @{$client->{expect}};
  my $alarm_id = shift @{$client->{expect_alarms}};
  $kernel->alarm_remove($alarm_id) if $alarm_id;
  $kernel->call($session, 'enable_client', $client) unless @{$client->{expect}};
}

sub check_expect {
  my ($kernel, $session, $heap, $poe_sender, $sender, $text) = @_[KERNEL, SESSION, HEAP, SENDER, ARG0, ARG1];
  my $client = $heap->{sessions}->{$poe_sender->get_heap()};
  my $expected = $client->{expect}->[0];

  # check sender
  return 0 unless $sender =~ /^:?\Q$expected->[0]\E/i;

  # compare text
  return 0 unless $text =~ /$expected->[2]/i;

  # drop expectation of event
  unexpect($kernel, $session, $client);
}

sub irc_connected {
  my ($kernel, $session, $heap, $sender) = @_[KERNEL, SESSION, HEAP, SENDER];
  my $client = $heap->{sessions}->{$sender->get_heap()};
  print "Client $client->{name} connected to server $_[ARG0]\n"
    if $heap->{verbose};
  $kernel->call($session, 'enable_client', $client);
}

sub handle_irc_disconnect ($$$$$) {
  my ($kernel, $session, $heap, $sender, $client) = @_;
  if ($client->{quitting}) {
    $kernel->call($sender, 'unregister', 'all');
    delete $heap->{sessions}->{$sender->get_heap()};
    delete $heap->{clients}->{$client->{name}};
  } else {
    if ($client->{disconnect_expected}) {
      delete $client->{disconnect_expected};
    } else {
      print "Got unexpected disconnect for $client->{name} (nick $client->{nick})\n";
    }
    $kernel->call($session, 'disable_client', $client);
    $kernel->delay_set('reconnect', $client->{throttled} ? THROTTLED_TIMEOUT : RECONNECT_TIMEOUT, $client);
    delete $client->{throttled};
  }
}

sub irc_disconnected {
  my ($kernel, $session, $heap, $sender, $server) = @_[KERNEL, SESSION, HEAP, SENDER, ARG0];
  my $client = $heap->{sessions}->{$sender->get_heap()};
  print "Client $client->{name} disconnected from server $_[ARG0]\n" if $heap->{verbose};
  handle_irc_disconnect($kernel, $session, $heap, $sender, $client);
}

sub irc_socketerr {
  my ($kernel, $session, $heap, $sender, $msg) = @_[KERNEL, SESSION, HEAP, SENDER, ARG0];
  my $client = $heap->{sessions}->{$sender->get_heap()};
  print "Client $client->{name} (re-)connect error: $_[ARG0]\n";
  handle_irc_disconnect($kernel, $session, $heap, $sender, $client);
}

sub irc_notice {
  my ($kernel, $session, $heap, $sender, $from, $to, $text) = @_[KERNEL, SESSION, HEAP, SENDER, ARG0, ARG1, ARG2];
  my $client = $heap->{sessions}->{$sender->get_heap()};
  if ($client->{sync_wait} and $text eq 'SYNC') {
    $from =~ s/!.+$//;
    my $x;
    # find who sent it..
    for ($x=0; $x<=$#{$client->{sync_wait}}; $x++) {
      last if $from eq $client->{sync_wait}->[$x];
    }
    # exit if we don't expect them
    if ($x>$#{$client->{sync_wait}}) {
      print "Got unexpected SYNC from $from to $client->{name} ($client->{nick})\n";
      return;
    }
    # remove from the list of people we're waiting for
    splice @{$client->{sync_wait}}, $x, 1;
    # re-enable client if we're done waiting
    if ($#{$client->{sync_wait}} == -1) {
      delete $client->{sync_wait};
      $kernel->call($session, 'enable_client', $client);
    }
  } elsif (@{$client->{expect}}
           and $client->{expect}->[0]->[1] =~ /notice/i) {
    check_expect(@_[0..ARG0], $text);
  }
}

sub irc_msg {
  my ($kernel, $session, $heap, $sender, $from, $to, $text) = @_[KERNEL, SESSION, HEAP, SENDER, ARG0, ARG1, ARG2];
  my $client = $heap->{sessions}->{$sender->get_heap()};
  if (@{$client->{expect}}
      and $client->{expect}->[0]->[1] =~ /msg/i) {
    check_expect(@_[0..ARG0], $text);
  }
}

sub irc_public {
  my ($kernel, $session, $heap, $sender, $from, $to, $text) = @_[KERNEL, SESSION, HEAP, SENDER, ARG0, ARG1, ARG2];
  my $client = $heap->{sessions}->{$sender->get_heap()};
  if (@{$client->{expect}}
      and $client->{expect}->[0]->[1] =~ /public/i
      and grep($client->{expect}->[0]->[2], @$to)) {
    splice @{$client->{expect}->[0]}, 2, 1;
    check_expect(@_[0..ARG0], $text);
  }
}

sub irc_mode {
  my ($kernel, $session, $heap, $sender, $from, $to) = @_[KERNEL, SESSION, HEAP, SENDER, ARG0, ARG1];
  my $client = $heap->{sessions}->{$sender->get_heap()};
  if (@{$client->{expect}}
      and $client->{expect}->[0]->[1] =~ /mode/i
      and grep($client->{expect}->[0]->[2], $to)) {
    splice @{$client->{expect}->[0]}, 2, 1;
    splice(@_, ARG1, 1);
    check_expect(@_);
  }
}

sub irc_error {
  my ($kernel, $session, $heap, $sender, $what) = @_[KERNEL, SESSION, HEAP, SENDER, ARG0];
  my $client = $heap->{sessions}->{$sender->get_heap()};
  if (@{$client->{expect}}
      and $client->{expect}->[0]->[1] =~ /error/i) {
    splice @{$client->{expect}->[0]}, 2, 1;
    unexpect($kernel, $session, $client);
    $client->{disconnect_expected} = 1;
  } else {
    print "ERROR: From server to $client->{name}: $what\n";
  }
  $client->{throttled} = 1 if $what =~ /throttled/i;
}
