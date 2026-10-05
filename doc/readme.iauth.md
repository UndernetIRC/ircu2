# IAuth Protocol

## Overview

The iauth protocol used here is based on the one in irc2.11.1, with
changes to support challenge-response protocols and login-on-connect.
Reference to that version's iauth-internals.txt and source code may be
useful. For clarity, this document uses "server" to refer to any IRC
server implementing this protocol, "ircu" to refer to Undernet ircd,
and "ircd" to refer to IRCnet ircd.

Certain messages are relayed to interested operators. ircu implements
this by using the 131072 (`SNO_AUTH`) server notice mask. ircd
implements this by using the &AUTH local channel.

The implementation lives in `ircd/s_auth.c`.

## Starting iauth

The path to the iauth program is specified in the server configuration
file (the `IAuth` block in `ircd.conf`, see `doc/example.conf`):

```
IAuth {
  program = "../path/to/iauth" "-n" "options go here";
};
```

The server spawns that program when reading the configuration file or
when the previous iauth instance terminates. To protect against a
series of crashes, the server will refuse to restart an iauth instance
that it spawned in the last five seconds. A rehash operation will
clear this behavior. The server and iauth instance communicate over
the iauth instance's stdin and stdout.

Every message from the server to the iauth instance is a single line.
The line starts with an integer client identifier. This may be -1 to
indicate no particular client or a non-negative number to indicate a
client connected to the server.

When the server starts the iauth instance, it sends a line formatted
like `-1 M irc.example.org 20000` to indicate its name and an
exclusive upper bound on valid client identifiers. In that example,
possible client identifiers would be from 0 through 19999 inclusive.
This upper bound is called MAXCONNECTIONS in the server code.

When the iauth instance starts, it sends a V message to indicate its
version.

The server provides `/stats` subcommands that report the iauth
instance's version, configuration and statistics.

Line formats in both directions are IRC-like in format: space
characters separate arguments and a colon at the start of an argument
indicates that the remainder of the line is one argument. To avoid
problems, IPv6 address arguments with a leading colon may have to be
prefixed with a 0 — for example, `::1` sent as `0::1`.

When the iauth instance sends messages that relate to a particular
client, that client is identified by three parameters from the
server's Client Introduction message (`<id>`, `<remoteip>` and
`<remoteport>`). If any of these disagree with the server's current
user tables, it is an error.

## Client states

Each client is conceptually in one of four states: GONE, REGISTER,
HURRY or NORMAL. Each client starts in the GONE state. Certain
messages from the server signal a client's transition from one state
to another, and certain messages from the iauth instance cause a state
transition.

To be pedantic, the REGISTER state is a collection of sub-states since
certain commands must occur at most and/or at least one time during
the REGISTER state. The distinctions between these sub-states are
distracting and not important, so they are described as one state and
the repetition limitations are described for each command.

The rationale for the HURRY state is to give explicit input to the
iauth instance as to when the server believes it has sent the complete
set of data for the client. Rather than defining the complete set of
information in this protocol document, that is left to the server.
ircd does not indicate this state.

## Policies and use cases

The historical application of iauth has been to block users that
appear to be drones early, before they have a chance to disrupt the
network, and without affecting other users on the same host (which
K-lines do). This protocol extends that application by adding the n
server message and by allowing challenge-response exchanges with the
client.

Eventually it would be nice to move the DNS and ident lookups into
iauth, and remove that code from the IRC server. ircd already does
this; since ircu does not, it adds the u server message.

For trusted proxies, this protocol gives the capability for clients
connecting through those proxies to be displayed with their actual
username, IP address and hostname. The same functions allow other
clients to use iauth-assigned spoofs, for example to hide the IP
addresses used by operators.

This protocol allows login-on-connect, for example by clients that
send their account name and password in PASS, through the R iauth
message.

This protocol allows iauth to assign a client to a particular class by
specifying a class name in the D or R iauth message.

### Special port types

For WebIRC and Cloudflare ports the client's real IP address is only
known once the proxy has identified the client (the `WEBIRC` command
or the `CF-Connecting-IP` header). On those connections the Client
Introduction is deferred until the spoofed identity has been applied,
so iauth always sees the client's real address. WebSocket ports send
the introduction once the HTTP upgrade has completed.

## Server messages

### X — Example Message Description

```
Syntax:  <id> X <several> <arguments>
Example: 5 X arguments vary
States:  REGISTER(1), HURRY, NORMAL
Next state: -
```

This is an example message description. Each message is a single
character. The States field indicates which states the message may
occur in and any restrictions on how many times the message may be
sent during those states (restrictions only make sense when Next State
is -). The Next State field indicates which new state is implied by
the message; a hyphen indicates no state change is implied. This is
an example, not a description of the actual X message.

Where ircu behavior is believed to differ from ircd's, a
*Compatibility* note describes ircd's behavior or expectations.

### C — Client Introduction

```
Syntax:  <id> C <remoteip> <remoteport> <localip> <localport>
Example: 5 C 192.168.1.10 23367 192.168.0.1 6667
States:  GONE
Next state: REGISTER
```

Indicates that `<localport>` on `<localip>` accepted a client
connection from `<remoteport>` on `<remoteip>`.

### Z — TLS Certificate Fingerprint

```
Syntax:  <id> Z <fingerprint>
Example: 5 Z 1a2b3c4d5e6f...
States:  REGISTER(1)
Next state: -
```

Indicates the fingerprint of the client certificate the client
presented on a TLS connection. Sent immediately after the Client
Introduction, and only when the client connected over TLS and
presented a certificate.

*Compatibility:* This is an extension in this ircu tree; neither ircd
nor stock ircu send it.

### D — Client Disconnect

```
Syntax:  <id> D
Example: 5 D
States:  REGISTER, HURRY, NORMAL
Next state: GONE
```

Indicates that a client is disconnecting from the server.

### N — Hostname Received

```
Syntax:  <id> N <hostname>
Example: 5 N host-1-10.example.org
States:  REGISTER(1)
Next state: -
```

Indicates that the server received hostname information for a client.
Only one of `N` and `d` is sent.

### d — Hostname Timeout

```
Syntax:  <id> d
Example: 5 d
States:  REGISTER(1)
Next state: -
```

Indicates that the server did not receive hostname information for a
client in a timely fashion. Only one of `N` and `d` is sent.

### P — Client Password

```
Syntax:  <id> P :<password ...>
Example: 5 P :buddha n1rvan4
States:  REGISTER
Next state: -
```

Indicates the client's password information. This may be a
traditional client password, an account and pass phrase pair, or the
response to a challenge (see the iauth C message). This message is
enabled by requesting the A policy.

### U — Client Username

```
Syntax:  <id> U <username> :<userinfo ...>
Example: 5 U buddha :Gautama Siddhartha
States:  REGISTER(1+)
Next state: -
```

Indicates the client's claimed username and "GECOS" information. This
information has not been checked against identd or DNS. This message
is enabled by requesting the A policy.

*Compatibility:* ircd only sends the `<username>` parameter.

### u — Client Username

```
Syntax:  <id> u <username>
Example: 5 u notbuddha
States:  REGISTER(1)
Next state: -
```

Indicates a more reliable username for the client: the identd
response when the lookup succeeded, otherwise the claimed username
with the untrusted-username prefix applied (`~`, or `^` for an
untrusted WEBIRC user when `HIS_WEBIRC` is off).

*Compatibility:* This is an Undernet extension and ircd does not send
it. It is enabled by the iauth instance requesting the U policy.

### A — Client Account

```
Syntax:  <id> A <account>
Example: 5 A buddha
States:  REGISTER
Next state: -
```

Indicates that the client authenticated to an account while still
registering — for example via SASL login-on-connect. Sent when the
account is applied to the client.

*Compatibility:* This is an extension in this ircu tree; neither ircd
nor stock ircu send it.

### c — Capability Negotiation Started

```
Syntax:  <id> c
Example: 5 c
States:  REGISTER
Next state: -
```

Indicates that the client started IRCv3 capability negotiation
(`CAP`). Registration is blocked (the client will not leave the
REGISTER/HURRY states) until negotiation ends.

*Compatibility:* This is an extension in this ircu tree; neither ircd
nor stock ircu send it.

### e — Capability Negotiation Ended

```
Syntax:  <id> e
Example: 5 e
States:  REGISTER
Next state: -
```

Indicates that the client completed capability negotiation (`CAP
END`), unblocking registration.

*Compatibility:* This is an extension in this ircu tree; neither ircd
nor stock ircu send it.

### n — Client Nickname

```
Syntax:  <id> n <nickname>
Example: 5 n Buddha
States:  REGISTER(1+), HURRY
Next state: -
```

Indicates the client's requested nickname.

*Compatibility:* This is an Undernet extension and ircd does not send
it. It is enabled by the iauth instance requesting the U policy.

### H — Hurry Up

```
Syntax:  <id> H
Example: 5 H
States:  REGISTER
Next state: HURRY
```

Indicates that the server is ready to register the client except for
needing a response from the iauth server.

*Compatibility:* This is an Undernet extension and ircd does not send
it. It is enabled by the iauth instance requesting the U policy.

### T — Client Registered

```
Syntax:  <id> T
Example: 5 T
States:  HURRY
Next state: NORMAL
```

Indicates the server got tired of waiting for iauth to finish and the
client is being accepted. This message should never be sent when the
R policy is in effect.

*Compatibility:* ircd allows this message for clients in the REGISTER
state.

### E — Error

```
Syntax:  <id> E <type> :<additional text>
Example: 5 E Gone
```

Indicates that a message received from the iauth instance could not be
rationally interpreted. This may be because the client could not be
found, the client was in an inappropriate state for the message, or
for other reasons. The `<type>` argument specifies the general type
of error and `<additional text>` provides details. `<id>` may be -1.

### M — Server Name and Capacity

```
Syntax:  <id> M <servername> <capacity>
Example: -1 M irc.example.org 20000
States:  GONE(1)
Next state: -
```

Indicates the server's name and upper bound on client identifiers.

*Compatibility:* ircd does not include the `<capacity>` information.
The `<id>` should be ignored: ircd sends 0 and ircu sends -1.

### X — Extension Query Reply

```
Syntax:  <id> X <servername> <routing> :<reply>
Example: -1 X channels.undernet.org 5/127.0.0.1/6667 :OK kev Logged in
```

Used to deliver the reply to an extension query to the iauth instance.
The `<servername>` parameter indicates the origin of the reply. The
`<routing>` parameter is the same as was used in the X message from
the iauth instance, and can be used to pair the reply with the
original request. The `<reply>` parameter contains the text of the
reply.

On the network the query travels as a P10 `XQUERY` with the routing
token prefixed by `iauth:`; the server strips that prefix again before
relaying the reply to the iauth instance (see section 11 of
`doc/p10.md`).

*Compatibility:* This is an Undernet extension and ircd does not send
it.

### x — Extension Query Server Not Linked

```
Syntax:  <id> x <servername> <routing> :Server not online
Example: -1 x channels.undernet.org 5/127.0.0.1/6667 :Server not online
```

Used to indicate to the iauth instance that the server specified in
the X message is not presently linked to the network. This will not
detect the extension query being lost due to a network break, so iauth
instances should further implement a timeout mechanism for extension
queries.

*Compatibility:* This is an Undernet extension and ircd does not send
it.

### ? — Information Request

```
Syntax:  <id> ? <type>
Example: -1 ? config
```

Request that the iauth program send a particular type of information
to the server. The predefined values for `<type>` are:

| Type | Meaning |
|------|---------|
| `config` | iauth should send an `a`, followed by all current `A` lines |
| `stats` | iauth should send an `s`, followed by all current `S` lines |
| `stats2` | iauth should send all current `S` lines, followed by an `s` |

*Compatibility:* This is an Undernet extension and ircd does not send
it.

## IAuth messages

The same example-description conventions apply as for server messages.
If the Notify field says yes, interested operators (with `SNO_AUTH`
set) are notified of the message. An unrecognized command is answered
with `-1 E Garbage`.

### > — Operator Notification

```
Syntax:  > :<message text>
Example: > :Hello Operators!
Notify:  yes
```

Contains a message that the iauth instance wants to send to interested
operators.

### G — Set Debug Level

```
Syntax:  G <level>
Example: G 1
Notify:  yes
```

Sets a debug level for the server's end of the iauth conversation.
When enabled, debug messages should be sent to the same channel
(group, mask, etc) as other iauth notifications. Debug level 0
suppresses iauth-related debug output, and positive integers enable
iauth debugging messages.

### O — Set Policy Options

```
Syntax:  O <options>
Example: O RTAWU
Notify:  yes
```

Sets policy options for the iauth conversation. Old policy options
should be forgotten. Valid policy options are:

| Option | Meaning |
|--------|---------|
| `A` | Send username and password information. This causes the server to send the U and P messages. |
| `R` | Require clients to be approved before registering them. When this policy is in effect, it affects the behavior of a registration timeout; for details, see the documentation for the T server message. |
| `T` | When the R policy is in effect and the iauth service does not respond for a client, this causes the server to count the number of clients refused, to send a warning message to interested operators periodically, and to send the count of rejected users to interested operators when the iauth instance responds again. |
| `U` | Send nickname, confirmed username and hurry information. This causes the server to send the n, u and H messages. |
| `W` | Allow extra time for iauth to respond based on hostname. When this policy is in effect and a DNS message (N or d) is sent for a client, that client's registration timeout is extended or reset. |
| `S` | iauth supports the "? stats2" info request. |

*Compatibility:* The U and A policies are Undernet extensions and are
not recognized by ircd.

### V — iauth Program Version

```
Syntax:  V :<version string>
Example: V :Undernet-iauthu v1.0
Notify:  yes
```

Indicates the iauth program version. This should only be used in
diagnostic messages, and must not change protocol behavior.

### a — Start of new configuration

```
Syntax:  a
Notify:  yes
```

Indicates that a new configuration is being loaded by the iauth
instance. Any cached configuration records should be cleared.

### A — Configuration Information

```
Syntax:  A <hosts?> <module> :<options>
Example: A * rfc931
Notify:  yes
```

Indicates new configuration information.

### s — Start of new statistics

```
Syntax:  s
Notify:  yes
```

Indicates a new set of statistics will be sent. Any cached statistics
records should be cleared. In response to a "? stats2" request,
instead marks the end of a set of statistics.

### S — Statistics Information

```
Syntax:  S <module> :<module information>
Example: S rfc931 connected 0 unix 0 other 0 bad 0 out of 0
Notify:  yes
```

Indicates new or additional statistics information.

### o — Forced Username

```
Syntax:  o <id> <remoteip> <remoteport> <username>
Example: o 5 192.168.1.10 23367 bubba
States:  REGISTER, HURRY
Next state: -
```

Indicates that the username should be used for the specified client
even if the normal sanity-checking would prohibit the username.

### U — Trusted Username

```
Syntax:  U <id> <remoteip> <remoteport> <username>
Example: U 5 192.168.1.10 23367 buddha
States:  REGISTER, HURRY
Next state: -
```

Indicates that the iauth instance believes `<username>` is accurate
for the specified client.

### u — Untrusted Username

```
Syntax:  u <id> <remoteip> <remoteport> <username>
Example: u 5 192.168.1.10 23367 enlightened_one
States:  REGISTER, HURRY
Next state: -
```

Indicates that the iauth instance does not strongly trust `<username>`
to be accurate, but has no more trusted username.

### N — Client Hostname

```
Syntax:  N <id> <remoteip> <remoteport> <hostname>
Example: N 5 192.168.1.10 23367 buddha.example.org
States:  REGISTER, HURRY
Next state: -
```

Indicates that the iauth instance believes the specified client should
use the hostname given.

*Compatibility:* This is an Undernet extension and ircd does not
support this message.

### I — Client IP Address

```
Syntax:  I <id> <currentip> <remoteport> <newip>
Example: I 5 192.168.1.10 23367 127.128.129.130
States:  REGISTER, HURRY
Next state: -
```

Indicates that the iauth instance wants the server to present and
treat the client as using `<newip>`. This means that future iauth
messages relating to the client must use `<newip>` as the `<remoteip>`
parameter.

*Compatibility:* This is an Undernet extension and ircd does not
support this message.

### M — Adjust User Mode

```
Syntax:  M <id> <remoteip> <remoteport> +<mode changes>
Example: M 5 192.168.1.10 23367 +iwg
States:  REGISTER, HURRY
Next state: -
```

Indicates a set of user mode changes to be applied to the client.

*Compatibility:* This is an Undernet extension and ircd does not
support this message.

### C — Challenge User

```
Syntax:  C <id> <remoteip> <remoteport> :<challenge string>
Example: C 5 192.168.1.10 23367 :In which year did Columbus sail the ocean blue?
States:  REGISTER, HURRY
Next state: -
```

Indicates that the challenge string should be sent to the specified
user, for example via `NOTICE AUTH :*** <challenge string>`. The
client responds by sending `PASS :<response>`, which should be relayed
via the P server message. This requires that the A policy be in
effect.

*Compatibility:* This is an Undernet extension and ircd does not
support this message.

### k — Quietly Kill Client

```
Syntax:  k <id> <remoteip> <remoteport> :<reason>
Example: k 5 192.168.1.10 23367 :Open proxy found.
States:  REGISTER, HURRY, NORMAL
Next state: GONE
```

Indicates that the specified client should be disconnected for the
reason given without notifying operators.

*Compatibility:* ircu does not use the same notification mechanism as
ircd, so operators are notified using `SNO_CONNEXIT` anyway.

### K — Kill Client

```
Syntax:  K <id> <remoteip> <remoteport> :<reason>
Example: K 5 192.168.1.10 23367 :We don't like you.
States:  REGISTER, HURRY, NORMAL
Next state: GONE
```

Indicates that the specified client should be disconnected for the
reason given. Operators should be notified.

### d — "Soft" Done Checking

```
Syntax:  d <id> <remoteip> <remoteport>
Example: d 5 192.168.1.10 23367
States:  REGISTER, HURRY
Next state: -
```

Indicates that the iauth instance has no objection to letting the
specified client onto the network, but that some further work is in
process. In particular, an account stamp and/or connection class
might be available later.

*Compatibility:* This is an Undernet extension and ircd does not
support this message.

### D — Done Checking

```
Syntax:  D <id> <remoteip> <remoteport> [class]
Example: D 5 192.168.1.10 23367
States:  REGISTER, HURRY
Next state: NORMAL
```

Indicates that the iauth instance believes the specified client should
be allowed onto the network. If a class parameter is given, the
client should be assigned to that class.

*Compatibility:* Specifying the class is an Undernet extension and
ircd does not support that parameter.

### R — Registered User

```
Syntax:  R <id> <remoteip> <remoteport> <account>[:<id>[:<flags>]] [class]
Example: R 5 192.168.1.10 23367 Buddha:42:0
States:  REGISTER, HURRY
Next state: NORMAL
```

Indicates that the iauth instance believes the specified client should
be allowed onto the network, pre-authenticated to the account listed.
The account may carry a numeric account id and a flag word, separated
by colons, which are stamped onto the client (compare the `ACCOUNT`
message in `doc/p10.md`). If a class parameter is given, the client
should be assigned to that class.

*Compatibility:* This is an Undernet extension and ircd does not
support this message. The account id and flags are extensions in this
ircu tree.

### X — Extension Query

```
Syntax:  X <servername> <routing> :<query>
Example: X channels.undernet.org 5/127.0.0.1/6667 :login kev pass
```

Used by the iauth instance to send an extension query to the server
specified by `<servername>`. The `<routing>` parameter is not
interpreted by the servers; it will be returned unchanged in the
extension query reply message (the X server message) and may be used
to pair the query with its reply. The `<query>` parameter is sent to
`<servername>`.

*Compatibility:* This is an Undernet extension and ircd does not
support this message.
