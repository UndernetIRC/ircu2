# Connection rules (CRULEs)

Based on "SmartRoute — Rule based connects" by Tony Vencill (1994);
updated for the current configuration format. The implementation is
in `ircd/crule.c`.

Rule based connects allow an admin to specify under what conditions a
connect should not be allowed. If no rules are specified for a given
Connect block, the connection is allowed under any condition.

A rule may consist of any legal combination of the following functions
and operators.

## Functions

| Function | True if... |
|----------|------------|
| `connected(targetmask)` | a server other than that processing the rule is connected that matches the target mask |
| `directcon(targetmask)` | a server other than that processing the rule is directly connected that matches the target mask |
| `via(viamask, targetmask)` | a server other than that processing the rule matches the target mask and is connected via a directly connected server that matches the via mask |
| `directop()` | an oper is directly connected |

## Operators

| Operator | Meaning |
|----------|---------|
| `!arg` | true if the argument is false |
| `arg1 && arg2` | true if both arguments are true |
| `arg1 \|\| arg2` | true if either argument (or both) is true |

Parentheses `()` are allowed for grouping. Without parentheses, `&&`
takes precedence over `||`, `!` takes precedence over both, and
evaluation is left to right. White space in a rule is ignored.
Invalid characters in a rule lead to the rule being ignored.

## Examples

A simple example of a connect rule might be:

```
connected(*eu.under*)
```

This might be used in a US Undernet server for a Europe Connect block
to ensure that a second Europe link is not allowed if one US-EU link
already exists. (On the Undernet, US server names are
city.state.us.undernet.org and Europe server names are
city.country.eu.undernet.org.)

A more interesting example:

```
connected(*eu.under*) && ( !directcon(*eu.under*) || via(manhat*, *eu.under*) )
```

Imagine the Boston Undernet server uses this rule for its Europe
Connect blocks. This says that a Boston-Europe connect is disallowed
whenever a Europe server is already connected, unless Boston is itself
directly connected to a Europe server and Manhattan is not the one
carrying it. The effect is to allow multiple US-EU links while
attempting to limit them to one server: Boston will not initiate its
first Europe link if another server already links Europe, and prefers
to let Manhattan handle the US-EU link.

An example using `directop()`:

```
connected(*eu.under*) || directop()
```

If this rule is used on Boston for the Paderborn Connect block, it
disallows connects to Paderborn while no other Europe server is
connected and no oper is online on Boston. If the rule is
overrideable (i.e. applies only to autoconnects, see below), it
disallows Boston *auto*connects to Paderborn while a Boston oper is
online, but allows oper-initiated connects to Paderborn under any
circumstance. `directop()` can be used to invoke less preferred
routes only when an oper is not present to handle routing, or
conversely to allow use of less preferable routes only when an oper is
present to monitor their performance.

## Configuration

Rules are configured with CRULE blocks in `ircd.conf` (see
`doc/example.conf`):

```
CRULE
{
 server = "servermask";
 rule = "connectrule";
 # Setting all to yes makes the rule always apply.
 # Otherwise it applies only to autoconnects.
 all = yes;
};
```

A block with `all = yes` applies to all oper- and server-originated
connects as well as autoconnects; without it, the rule applies only to
autoconnects and can therefore be overridden by an oper-initiated
connect. If more than one server mask is present in a single CRULE
block, the rule applies to all the matching servers.

Connects originating from other servers are checked against matching
`all = yes` rules only; autoconnect-only rules are ignored for them,
as it is not clear whether the connection attempt was oper initiated.

(Historical note: in the old flat configuration format these were the
`D:targetmask::rule` and `d:targetmask::rule` lines; `all = yes`
corresponds to the uppercase D form.)

## Viewing rules

To view rules online, `/stats d` (or `/stats maskrules`) shows all
rules, and `/stats D` (or `/stats crules`) shows only those rules
which also affect oper- and server-initiated connects. Both are
subject to the `HIS_STATS_d` feature.

## Processing and storage

The rules are parsed when the configuration file is read and
transformed into a more efficiently computed form; all applicable
rules are then evaluated each time a connect command is given or an
autoconnect is due. If more than one applicable rule is given, only
one need evaluate to true for the connect to be allowed (i.e. the
rules are OR'ed together). Note that conditions that exist when the
connect is initiated might differ from conditions when the link is
established.
