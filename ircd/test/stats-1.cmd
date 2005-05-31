# Connect to server
connect cl1 Alex alex localhost:7701 :Test client 1
:cl1 oper oper1 oper1

# Single letter stats commands
:cl1 raw :stats a
:cl1 raw :stats c
:cl1 raw :stats d
:cl1 raw :stats D
:cl1 raw :stats e
:cl1 raw :stats f
:cl1 raw :stats g
:cl1 raw :stats i
:cl1 raw :stats j
:cl1 raw :stats J
:cl1 raw :stats k
:cl1 raw :stats l
:cl1 raw :stats L
:cl1 raw :stats m
:cl1 raw :stats o
:cl1 raw :stats p
:cl1 raw :stats q
:cl1 raw :stats r
:cl1 raw :stats R
:cl1 raw :stats t
:cl1 raw :stats T
:cl1 raw :stats u
:cl1 raw :stats U
:cl1 raw :stats v
:cl1 raw :stats V
:cl1 raw :stats w
:cl1 raw :stats x
:cl1 raw :stats z
:cl1 raw :stats *

# Remote stats requests
:cl1 raw :stats f test-2.*

# Named stats commands
:cl1 raw :stats nameservers
:cl1 raw :stats connect
:cl1 raw :stats maskrules
:cl1 raw :stats crules
:cl1 raw :stats engine
:cl1 raw :stats features
:cl1 raw :stats glines
:cl1 raw :stats access
:cl1 raw :stats histogram
:cl1 raw :stats jupes
:cl1 raw :stats klines
:cl1 raw :stats links
:cl1 raw :stats modules
:cl1 raw :stats commands
:cl1 raw :stats operators
:cl1 raw :stats ports
:cl1 raw :stats quarantines
:cl1 raw :stats mappings
:cl1 raw :stats usage
:cl1 raw :stats motds
:cl1 raw :stats locals
:cl1 raw :stats uworld
:cl1 raw :stats uptime
:cl1 raw :stats vservers
:cl1 raw :stats vserversmach
:cl1 raw :stats userload
:cl1 raw :stats memusage
:cl1 raw :stats classes
:cl1 raw :stats memory
:cl1 raw :stats help
:cl1 raw :hash
:cl1 raw :rehash m
:cl1 raw :rehash l
:cl1 raw :rehash q
:cl1 raw :rehash
:cl1 nick Alexey

# Varparam stats
:cl1 raw :stats access * 127.0.0.1
:cl1 raw :stats access * *
:cl1 raw :stats klines * *
:cl1 raw :stats klines * *@*
:cl1 raw :stats links * *
:cl1 raw :stats ports * 7700
:cl1 raw :stats quarantines * #frou-frou
:cl1 raw :stats vservers * *.example.net

# Invalid or nonexistent stats requests
:cl1 raw :stats y
:cl1 raw :stats ÿ
:cl1 raw :stats mºDÙ£Ë§
:cl1 raw :stats long_garbage_here_to_hopefully_trigger_the_core_reported_by_dan

# Drop oper status and try a few others
:cl1 mode Alex -o
:cl1 raw :stats k
:cl1 raw :stats k * *
:cl1 raw :stats k * *@*
