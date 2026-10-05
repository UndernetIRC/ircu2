# JUPE documentation

A jupe forbids a server name on the network: an active jupe causes any
server of that name to be refused at link time and to be squit if it
is introduced behind another link. Jupes are versioned network state:
they are propagated during net bursts and are never deleted, only
deactivated, so that the two sides of a split can reconcile.

## User syntax

For an ordinary user, the syntax is:

```
JUPE [<server>]
```

If `<server>` is given, and if a jupe for that server exists, all the
information about that jupe is displayed. If `<server>` is not given,
all un-expired jupes are displayed.

## Operator syntax

For an operator, the syntax is:

```
JUPE [[+|-]<server> [<target>] <expiration> :<reason>]
```

If `<server>` is not given, or if it is not prefixed by `+` or `-`,
the operation is exactly the same as if it were issued by an ordinary
user. All `+`/`-` forms require the `CONFIG_OPERCMDS` feature to be
enabled, otherwise the command is rejected as disabled.

When the `+` or `-` prefix is used, `<expiration>` and `<reason>` are
required, even if the jupe already exists (they are ignored in that
case; an existing jupe's expiration and reason cannot be changed, only
its activation state). The `<target>` parameter selects the scope:

| Target | Meaning | Privilege |
|--------|---------|-----------|
| omitted | Local jupe on the local server | none checked (see note) |
| a server name | Local jupe on that server; forwarded there if remote | `JUPE` for a remote server, `LOCAL_JUPE` for the local one |
| `*` | Global jupe on the whole network | `JUPE` |

Note the inconsistency in the first row: omitting `<target>` creates
the same local jupe as naming the local server explicitly, but the
explicit form requires the `LOCAL_JUPE` privilege while the implicit
form performs no privilege check (`mo_jupe()` in `ircd/m_jupe.c`).

If `<target>` is `*` and the currently existing jupe is a local jupe,
the local jupe is erased and recreated as a global one with the
parameters given. Otherwise, if the jupe exists (in the requested
scope), a prefix of `+` activates it and a prefix of `-` deactivates
it. If the jupe does not exist, it is created, active or inactive
according to the prefix.

The `<expiration>` parameter is a number of seconds, greater than zero
and not exceeding `JUPE_MAX_EXPIRE` (7 days), for the jupe to exist.
The `<reason>` argument is mandatory and should describe why this
particular jupe was placed.

## Server syntax

For a server, the syntax is (see also section 10.2 of `doc/p10.md`):

```
<prefix> JU <target> [+|-]<server> <expiration> <lastmod> :<reason>
```

The `<target>` may be a server numeric or the character `*` for a
globally scoped jupe; a jupe targeted at another server's numeric is
forwarded to that server unchanged. The `<server>` argument is a
server name, optionally prefixed by `+` (an active jupe) or `-` (an
inactive jupe); a bare server name is treated the same as `-`. The
parameter `<expiration>` is the total number of seconds the jupe is to
live for (again at most 7 days), and `<lastmod>` is used for
versioning. Since jupes are propagated during net bursts, there must
be some way of resolving conflicting states, which is the reason for
this argument, and is also the reason jupes cannot be deleted, only
deactivated. Six parameters are required.

If a jupe is received with a `<target>` of `*`, any jupe of the same
name with local scope is deleted, in preference for the globally
scoped version. If the jupe already exists, the values of `<lastmod>`
are compared: if the received `<lastmod>` is newer, the jupe is
activated or deactivated according to the `<server>` prefix; if it is
equal, the message is a no-op; if it is *older*, the existing (newer)
jupe is resent to the server from which the message was received —
except while that link is bursting, in which case the stale update is
silently ignored. If the jupe does not currently exist, it is created
with the parameters given.
