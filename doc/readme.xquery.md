# Extension queries (XQUERY / XREPLY)

## Overview

The extension query mechanism provides a means by which servers may
send queries to other servers and receive replies. Obviously,
ordinary ircu servers have no need of this mechanism, but it allows
pseudo-server services to communicate with each other. Additionally,
extensions have been made to the iauth protocol (see
`readme.iauth.md`) to allow iauth instances to send and receive
extension queries. This could be used, for instance, to submit client
information for immediate proxy scanning by a centralized service, or
to query a centralized database for log-in parameters.

## Detailed description

The extension query mechanism consists of a pair of commands, the
XQUERY command (token `XQ`) and the XREPLY command (token `XR`).
Servers and IRC operators may send an XQUERY, naming a target service,
an opaque "routing" token, and the query; the target service is
expected to reply with an XREPLY, which will include the routing token
from the query and the service's reply to the query.

The query syntax is:

```
<prefix> XQ <target> <routing> :<query>
```

where `<target>` is the target service's numeric nick, `<routing>` is
the opaque "routing" token, and `<query>` is the query for the service
to act upon. IRC operators may also issue queries, using the XQUERY
command with the same parameters, with `<target>` permitted to be a
server name mask; this is largely intended for debugging purposes.
Ordinary users cannot issue XQUERY commands, in order to encourage use
of the regular PRIVMSG and NOTICE commands.

The reply syntax is:

```
<prefix> XR <target> <routing> :<reply>
```

where `<target>` is the origin of the original query, `<routing>` is
the opaque "routing" token from the query, and `<reply>` is the
service's reply to the query. This command can only be issued by
servers.

Both messages are forwarded hop by hop toward their target. XQUERY
and XREPLY lines never carry an IRCv3 `@time` tag on server links,
because services parse them positionally (see section 13 of
`doc/p10.md`).

## Routing prefixes in use

The routing token was designed so that ircu itself can prepend routing
data to it and dispatch replies to the right subsystem. This server
currently uses three such prefixes (see also section 11 of
`doc/p10.md`):

| Routing prefix | Used by |
|----------------|---------|
| `iauth:<token>` | IAuth extension queries; see below. |
| `sasl:<cookie>` | Client SASL authentication relayed to the network's SASL server; see `readme.sasl.md`. |
| `spam:<token>` | The spamfilter hold queue; see `readme.sline.md`. |

A reply whose routing prefix is not recognized is logged and dropped.

## Use with iauth

Three message extensions have been made to the iauth protocol. An
iauth instance can issue an XQUERY through the use of the `X` client
message with the following syntax:

```
X <servername> <routing> :<query>
```

If `<servername>` is not presently linked to the network, ircu will
respond with an `x` server message, having the following syntax:

```
<id> x <servername> <routing> :Server not online
```

If, on the other hand, `<servername>` names a valid, on-line server,
ircu will prepend `iauth:` to the routing token and forward the query
to that server. If an XREPLY is received from the service, ircu will
strip off the `iauth:` prefix on the routing token and send the reply
to the iauth instance with the `X` server message:

```
<id> X <servername> <routing> :<reply>
```

Having the `iauth:` prefix on the routing token enables other ircu
subsystems that use the extension query mechanism (such as SASL and
the spamfilter, above) to be differentiated from extension queries
originated by iauth.

## Rationale

The extension query mechanism was originated as part of an effort to
establish a reliable login-on-connect system for Undernet. Previous
attempts at such a system required out-of-band parallel connections,
and could possibly result in a compromise of hidden IPs (such as the
IP of X's database server). Further, without extensive extensions to
GNUWorld, certain login restrictions — such as the maximum logged-in
client count — could not be reliably enforced. By providing an
in-band signalling mechanism that iauth can make direct use of, these
problems are eliminated; the only remaining problem is what to do if
iauth is unable to communicate with the login service, which can be
solved through policy decisions and timeouts implemented within the
iauth instance.

The rationale for the opaque "routing" token is to provide pairing
between replies and queries. The lack of such pairing is one of the
shortcomings of the IRC protocol, as specified in RFC 1459; only one
Undernet extension has attempted to provide such a pairing — a
little-used extension to the /WHO command. In an iauth context, such
pairing is critical; otherwise, iauth could potentially apply a reply
to the wrong client. Although the pairing could be part of the query,
it makes sense to make it part of the base protocol message, making it
explicit. This also allows ircu to add routing data to the token,
making it possible for more extensions than just iauth to make use of
extension queries — as the SASL and spamfilter subsystems now do.
