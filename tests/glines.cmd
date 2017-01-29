define srv1 localhost:7601
define srv1-name irc.example.net
define srv2 localhost:7611
define srv2-name irc-2.example.net
define cl1-nick Op3rm4n
define cl2-nick Monitor

# Connect a client, oper it up and force G-line server notices on (0x8200).
connect cl1 %cl1-nick% oper %srv1% :Some IRC Operator
:cl1 oper oper oper
:cl1 mode %cl1-nick% +s +33280

# Do the same for the second server, for monitoring snotices.
# This is useful while debugging the remote operations in this script.
connect cl2 %cl2-nick% oper %srv2% :Some IRC Operator
:cl2 oper oper oper
:cl2 mode %cl2-nick% +s +33280

# For an operator, the syntax is:
#  GLINE [[!][+|-|>|<]<mask> [<target>] [<expiration> [:<reason>]]]
# By itself, that's 2 * 5 * 3 (target missing/self, other or global)
#  * 3 = 90 possibilities.
#
# In each case, we would want to try it with various combinations:
# - Local gline for <mask> absent or present
# - Global gline for <mask> absent, or present but locally and/or globally activated or deactivated (5 combinations)
# So ten pre-existing states for each syntax variant.
# For sanity's sake, we don't do all 900 combinations.
#
# Perl code to generate a fairly complete list:
# foreach my $operator (split(//, ' +-><')) {
#     foreach my $mask ('test@example.com') {
#         foreach my $target ('', '%srv1-name%', '%srv2-name%', '*') {
#             foreach my $expiration ('', '100000') {
#                 foreach my $reason ('', ':foo') {
#                     my $str = "GLINE ${operator}${mask} ${target} ${expiration} ${reason}";
#                     $str =~ s/ +/ /g;
#                     $str =~ s/ +$//;
#                     print "$str\n";
#                 }
#             }
#         }
#         print "\n";
#     }
# }

# Initial query: verify that our target G-line does not exist.
:cl1 raw :GLINE test@example.com
:cl1 expect %srv1-name% 512 test@example.com :No such gline

# Try a bunch of operations, only one of which should generate an actual G-line.
:cl1 raw :GLINE test@example.com :foo
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
:cl1 raw :GLINE test@example.com 100000
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
:cl1 raw :GLINE test@example.com 100000 :foo
:cl1 expect %srv1-name% 515 foo :Bad expire time
:cl1 raw :GLINE test@example.com %srv1-name%
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
:cl1 raw :GLINE test@example.com %srv1-name% :foo
:cl1 expect %srv1-name% 515 foo :Bad expire time
:cl1 raw :GLINE test@example.com %srv1-name% 100000
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters

# Check that we still have no G-line, and that we create it as expected.
:cl1 raw :GLINE test@example.com
:cl1 expect %srv1-name% 512 test@example.com :No such gline
:cl1 raw :GLINE test@example.com %srv1-name% 100000 :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% adding local GLINE for test@example.com, expiring at \\d+: foo
:cl1 raw :GLINE test@example.com
:cl1 expect %srv1-name% 280 test@example.com \\d+ 0 \\d+ %srv1-name% \\+ :foo
:cl1 expect %srv1-name% 281 :End of G-line List
# Now remove it (and verify removal).
:cl1 raw :GLINE -test@example.com 100000 :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% removing local GLINE for test@example.com
:cl1 raw :GLINE test@example.com
:cl1 expect %srv1-name% 512 test@example.com :No such gline

# Try doing remote operations.
:cl1 raw :GLINE test@example.com %srv2-name%
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
:cl1 raw :GLINE test@example.com %srv2-name% :foo
:cl1 expect %srv1-name% 515 foo :Bad expire time
:cl1 raw :GLINE test@example.com %srv2-name% 100000
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
:cl1 raw :GLINE test@example.com
:cl1 expect %srv1-name% 512 test@example.com :No such gline
:cl1 raw :GLINE test@example.com %srv2-name% 100000 :foo
# No response expected for remote commands; do a remote stats query to check.
:cl1 raw :STATS g %srv2-name%
:cl1 expect %srv2-name% 247 G test@example.com \\d+ 0 \\d+ \\+ :foo
:cl1 expect %srv2-name% 219 g :End of /STATS report
:cl1 raw :GLINE -test@example.com %srv2-name% 100000 :foo
:cl1 raw :STATS g %srv2-name%
:cl1 expect %srv2-name% 219 g :End of /STATS report

# Try doing network-wide operations.
:cl1 raw :GLINE test@example.com *
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
# These should fail because no existing G-line matches.
:cl1 raw :GLINE test@example.com * :foo
:cl1 expect %srv1-name% 515 foo :Bad expire time
:cl1 raw :GLINE test@example.com * 100000
:cl1 expect %srv1-name% 512 test@example.com :No such gline
:cl1 raw :GLINE test@example.com * 100000 :foo
:cl1 expect %srv1-name% 512 test@example.com :No such gline

# Try explicit create/activate operations.
:cl1 raw :GLINE +test@example.com
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
:cl1 raw :GLINE +test@example.com :foo
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
:cl1 raw :GLINE +test@example.com 100000
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
# This next one should create the G-line.
:cl1 raw :GLINE test@example.com
:cl1 expect %srv1-name% 512 test@example.com :No such gline
:cl1 raw :GLINE +test@example.com 100000 :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% adding local GLINE for test@example.com, expiring at \\d+: foo
:cl1 raw :GLINE test@example.com
:cl1 expect %srv1-name% 280 test@example.com \\d+ 0 \\d+ %srv1-name% \\+ :foo
:cl1 expect %srv1-name% 281 :End of G-line List
:cl1 raw :GLINE -test@example.com 100000 :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% removing local GLINE for test@example.com

# Local create/activate operations?
:cl1 raw :GLINE +test@example.com %srv1-name%
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
:cl1 raw :GLINE +test@example.com %srv1-name% :foo
:cl1 expect %srv1-name% 515 .+ :Bad expire time
:cl1 raw :GLINE +test@example.com %srv1-name% 100000
:cl1 expect %srv1-name% 515 .+ :Bad expire time
:cl1 raw :GLINE +test@example.com %srv1-name% 100000 :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% adding local GLINE for test@example.com, expiring at \\d+: foo
:cl1 raw :GLINE test@example.com
:cl1 expect %srv1-name% 280 test@example.com \\d+ 0 \\d+ %srv1-name% \\+ :foo
:cl1 expect %srv1-name% 281 :End of G-line List
:cl1 raw :GLINE -test@example.com 100000 :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% removing local GLINE for test@example.com
:cl1 raw :GLINE +test@example.com %srv1-name% 100000 :foo
:cl1 raw :GLINE -test@example.com 100000 :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% removing local GLINE for test@example.com
:cl1 raw :GLINE +test@example.com %srv1-name% 100000 :foo
:cl1 raw :GLINE -test@example.com %srv1-name% 100000 :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% removing local GLINE for test@example.com

# Remote create/activate operations?
:cl1 raw :GLINE +test@example.com %srv2-name%
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
:cl1 raw :GLINE +test@example.com %srv2-name% :foo
:cl1 expect %srv1-name% 515 .+ :Bad expire time
:cl1 raw :GLINE +test@example.com %srv2-name% 100000
:cl1 expect %srv1-name% 515 .+ :Bad expire time
:cl1 raw :GLINE +test@example.com %srv2-name% 100000 :foo
# No response expected for remote commands; do a remote stats query to check.
:cl1 raw :STATS g %srv2-name%
:cl1 expect %srv2-name% 247 G test@example.com \\d+ 0 \\d+ \\+ :foo
:cl1 expect %srv2-name% 219 g :End of /STATS report
:cl1 raw :GLINE -test@example.com %srv2-name% 100000 :foo
:cl1 raw :STATS g %srv2-name%
:cl1 expect %srv2-name% 219 g :End of /STATS report

# Global create/activate operations?
:cl1 raw :GLINE +test@example.com *
:cl1 expect %srv1-name% 512 test@example.com :No such gline
:cl1 raw :GLINE +test@example.com * :foo
:cl1 expect %srv1-name% 515 .+ :Bad expire time
:cl1 raw :GLINE +test@example.com * 100000
:cl1 expect %srv1-name% 515 .+ :Bad expire time

# Local G-line deactivation?
:cl1 raw :GLINE -test@example.com
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
:cl1 raw :GLINE -test@example.com :foo
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
:cl1 raw :GLINE -test@example.com 100000
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
:cl1 raw :GLINE -test@example.com 100000 :foo
:cl1 expect %srv1-name% 512 test@example.com :No such gline

# .. with a specified server?
:cl1 raw :GLINE -test@example.com %srv1-name%
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
:cl1 raw :GLINE -test@example.com %srv1-name% :foo
:cl1 expect %srv1-name% 515 %srv1-name% :Bad expire time
:cl1 raw :GLINE -test@example.com %srv1-name% 100000
:cl1 expect %srv1-name% 515 %srv1-name% :Bad expire time
:cl1 raw :GLINE -test@example.com %srv1-name% 100000 :foo
:cl1 expect %srv1-name% 512 test@example.com :No such gline
:cl1 raw :GLINE -test@example.com %srv2-name%
:cl1 expect %srv1-name% 461 GLINE :Not enough parameters
:cl1 raw :GLINE -test@example.com %srv2-name% :foo
:cl1 expect %srv1-name% 515 %srv2-name% :Bad expire time
:cl1 raw :GLINE -test@example.com %srv2-name% 100000
:cl1 expect %srv1-name% 515 %srv2-name% :Bad expire time
:cl1 raw :GLINE -test@example.com %srv2-name% 100000 :foo
:cl1 expect %srv2-name% 512 test@example.com :No such gline

# Global deactivations?
:cl1 raw :GLINE -test@example.com *
:cl1 expect %srv1-name% 512 test@example.com :No such gline
:cl1 raw :GLINE -test@example.com * :foo
:cl1 expect %srv1-name% 515 \\* :Bad expire time
:cl1 raw :GLINE -test@example.com * 100000
:cl1 expect %srv1-name% 515 \\* :Bad expire time
:cl1 raw :GLINE -test2@example.com * 100000 :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% adding deactivated global GLINE for test2@example.com

# Now start with the operations that create or need a global G-line.

# Global activations and deactivations?
:cl1 raw :GLINE +test@example.com * 100000 :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% adding global GLINE for test@example.com
:cl1 raw :GLINE test@example.com
:cl1 expect %srv1-name% 280 test@example.com \\d+ \\d+ \\d+ \\* \\+ :foo
:cl1 raw :GLINE test@example.com * 100000
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: changing expiration time to \\d+; and extending record lifetime to \\d+
:cl1 raw :GLINE test@example.com * 100000 :food
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: changing expiration time to \\d+; extending record lifetime to \\d+; and changing reason to "food"
:cl1 raw :GLINE -test@example.com *
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: globally deactivating G-line
:cl1 raw :GLINE -test@example.com * 100000 :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: changing expiration time to \\d+; extending record lifetime to \\d+; and changing reason to "foo"
:cl1 raw :GLINE test@example.com
:cl1 expect %srv1-name% 280 test@example.com \\d+ \\d+ \\d+ \\* - :foo

# Failed local activations and deactivations?
:cl1 raw :GLINE >test@example.com
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: locally activating G-line
:cl1 raw :GLINE <test@example.com
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: locally deactivating G-line
:cl1 raw :GLINE >test@example.com :foo
:cl1 expect %srv1-name% 402 foo :No such server
:cl1 raw :GLINE <test@example.com :foo
:cl1 expect %srv1-name% 402 foo :No such server
:cl1 raw :GLINE >test@example.com 100000
:cl1 expect %srv1-name% 402 100000 :No such server
:cl1 raw :GLINE <test@example.com 100000 :foo
:cl1 expect %srv1-name% 402 100000 :No such server
:cl1 raw :GLINE <test@example.com 100000 :foo
:cl1 expect %srv1-name% 402 100000 :No such server
:cl1 raw :GLINE >test@2.example.com
:cl1 expect %srv1-name% 512 test@2.example.com :No such gline
:cl1 raw :GLINE >test@example.com %srv1-name%

# What about successes for the local server?
# (For simplicity, single-server activations and deactivations are not
# allowed to change any other parameters.)
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: locally activating G-line
:cl1 raw :GLINE <test@example.com %srv1-name%
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: locally deactivating G-line
:cl1 raw :GLINE >test@example.com %srv1-name% :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: locally activating G-line
:cl1 raw :GLINE <test@example.com %srv1-name% :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: locally deactivating G-line
:cl1 raw :GLINE >test@example.com %srv1-name% 100000
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: locally activating G-line
:cl1 raw :GLINE <test@example.com %srv1-name% 100000
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: locally deactivating G-line
:cl1 raw :GLINE >test@example.com %srv1-name% 100000 :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: locally activating G-line
:cl1 raw :GLINE <test@example.com %srv1-name% 100000 :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: locally deactivating G-line
:cl1 raw :GLINE >test@example.com %srv1-name% 100000 :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: locally activating G-line
:cl1 raw :GLINE <test@example.com %srv1-name% 100000 :foo
:cl1 expect %srv1-name% NOTICE :\\*\\*\\* Notice -- %cl1-nick% modifying global GLINE for test@example.com: locally deactivating G-line

# And successful activations/deactiations for a (single) remote server?
# First make sure the global G-line is globally activated.
:cl1 raw :GLINE +test@example.com * 100000 :foo
# Form: "GLINE <gline@mask server.name"
:cl1 raw :STATS g %srv2-name%
:cl1 expect %srv2-name% 247 G test@example.com \\d+ \\d+ \\d+ \\+ :foo
:cl1 expect %srv2-name% 219 g :End of /STATS report
:cl1 raw :GLINE <test@example.com %srv2-name%
:cl1 raw :STATS g %srv2-name%
:cl1 expect %srv2-name% 247 G test@example.com \\d+ \\d+ \\d+ <\\+ :foo
:cl1 expect %srv2-name% 219 g :End of /STATS report
:cl1 raw :GLINE >test@example.com %srv2-name%
:cl1 raw :STATS g %srv2-name%
:cl1 expect %srv2-name% 247 G test@example.com \\d+ \\d+ \\d+ >\\+ :foo
:cl1 expect %srv2-name% 219 g :End of /STATS report
# Form: "GLINE <gline@mask server.name :foo"
:cl1 raw :GLINE <test@example.com %srv2-name% :foo
:cl1 raw :STATS g %srv2-name%
:cl1 expect %srv2-name% 247 G test@example.com \\d+ \\d+ \\d+ <\\+ :foo
:cl1 expect %srv2-name% 219 g :End of /STATS report
:cl1 raw :GLINE >test@example.com %srv2-name% :foo
:cl1 raw :STATS g %srv2-name%
:cl1 expect %srv2-name% 247 G test@example.com \\d+ \\d+ \\d+ >\\+ :foo
:cl1 expect %srv2-name% 219 g :End of /STATS report
# Form: "GLINE <gline@mask server.name 100000"
:cl1 raw :GLINE <test@example.com %srv2-name% 100000
:cl1 raw :STATS g %srv2-name%
:cl1 expect %srv2-name% 247 G test@example.com \\d+ \\d+ \\d+ <\\+ :foo
:cl1 expect %srv2-name% 219 g :End of /STATS report
:cl1 raw :GLINE >test@example.com %srv2-name% 100000
:cl1 raw :STATS g %srv2-name%
:cl1 expect %srv2-name% 247 G test@example.com \\d+ \\d+ \\d+ >\\+ :foo
:cl1 expect %srv2-name% 219 g :End of /STATS report
# Form: "GLINE <gline@mask server.name 100000 :foo"
:cl1 raw :GLINE <test@example.com %srv2-name% 100000 :foo
:cl1 raw :STATS g %srv2-name%
:cl1 expect %srv2-name% 247 G test@example.com \\d+ \\d+ \\d+ <\\+ :foo
:cl1 expect %srv2-name% 219 g :End of /STATS report
:cl1 raw :GLINE >test@example.com %srv2-name% 100000 :foo
:cl1 raw :STATS g %srv2-name%
:cl1 expect %srv2-name% 247 G test@example.com \\d+ \\d+ \\d+ >\\+ :foo
:cl1 expect %srv2-name% 219 g :End of /STATS report

# What about activations/deactivations that might go across the whole network?
# (These are not permitted because "global local [de]activation" does not
# make sense: just globally [de]activate the G-line.)
:cl1 raw :GLINE >test@example.com *
:cl1 expect %srv1-name% 402 \\* :No such server
:cl1 raw :GLINE <test@example.com *
:cl1 expect %srv1-name% 402 \\* :No such server
:cl1 raw :GLINE >test@example.com * :foo
:cl1 expect %srv1-name% 402 \\* :No such server
:cl1 raw :GLINE <test@example.com * :foo
:cl1 expect %srv1-name% 402 \\* :No such server
:cl1 raw :GLINE >test@example.com * 100000
:cl1 expect %srv1-name% 402 \\* :No such server
:cl1 raw :GLINE <test@example.com * 100000
:cl1 expect %srv1-name% 402 \\* :No such server
:cl1 raw :GLINE >test@example.com * 100000 :foo
:cl1 expect %srv1-name% 402 \\* :No such server
:cl1 raw :GLINE <test@example.com * 100000 :foo
:cl1 expect %srv1-name% 402 \\* :No such server
