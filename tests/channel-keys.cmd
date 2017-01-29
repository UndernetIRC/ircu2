define srv1 localhost:7601
define srv1-name irc.example.net
define srv2 localhost:7611
define srv2-name irc-2.example.net
define cl1-nick Op3rm4n
define cl2-nick Monitor
define channel #keytest

# Connect a client to each server, and join them to the same channel.
connect cl1 %cl1-nick% oper %srv1% :Some Channel Operator
connect cl2 %cl2-nick% oper %srv2% :Snoopy
:cl1 join %channel%
sync cl1,cl2
:cl2 join %channel%
sync cl1,cl2

# Set a plain and simple key initially.
:cl1 mode %channel% +k foo
:cl2 expect %cl1-nick% mode %channel% \\+k foo

# Slighly funny quoting here: one : for test-driver.pl and one for quoting.
# The final : makes the key invalid.
:cl1 mode %channel% -k+k foo :::badkey
:cl1 expect %srv1-name% 525 %channel% :Key is not well-formed
:cl2 expect %cl1-nick% mode %channel% -k foo

# Non-ASCII characters should be accepted in the key, and colons after the first character.
:cl1 mode %channel% +k mötör:head
:cl2 expect %cl1-nick% mode %channel% \\+k mötör:head

# We need to have a key, too.
:cl1 mode %channel% -k+k mötör:head
:cl1 expect %srv1-name% 461 MODE \\+k :Not enough parameters

# Are spaces accepted anywhere in the key?
:cl1 mode %channel% +k :: spaced key
:cl1 expect %srv1-name% 525 %channel% :Key is not well-formed

# What about commas?
:cl1 mode %channel% +k foo,bar
:cl1 expect %srv1-name% 525 %channel% :Key is not well-formed

# Is the key too long?
:cl1 mode %channel% +k 123456789012345678901234567890
:cl1 expect %srv1-name% 525 %channel% :Key is not well-formed
