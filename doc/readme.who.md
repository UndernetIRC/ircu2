# WHO documentation

Originally by Andrea "Nemesi" (02 Jan 1999); revised against the
current implementation in `ircd/m_who.c` and `ircd/whocmds.c`.

Since ircu2.10.02 the WHO command has been extended from what RFC 1459
describes, while keeping backward compatibility. The query format is:

```
WHO <mask1> [<options> [<mask2>]]
```

`<mask2>` is optional; if present it is used for matching and
`<mask1>` is ignored. Since `<mask2>` is the last parameter it *can*
contain a space, which helps when matching a real name, e.g.
`WHO foo %nr :*Black Hacker*`.

Masks and options (and thus all flags) are case-insensitive.

## Mask forms

The mask can have one of two forms:

- **A comma-separated list of elements**: each element is treated as a
  flat channel or nick name and is not matched against the other
  fields. Nicks count toward the output-line limit; channels count
  only if the asker is not on the channel (a `WHO #channel` gives
  unlimited output if you are in there). To force list treatment for
  a single element, add a comma: `WHO #Italia,` or `WHO ,Nemesi`.
  This is the recommended way for clients to fetch a channel's user
  list.

- **A single mask**: the mask is first checked as a full channel or
  nick name, then matched against all selected fields, with duplicate
  removal — a user is reported once even if several fields match.

### IP masks

When matching IP addresses (the `i` match flag), the mask can be:

- An ordinary IRC wildcard mask using `*` and `?`.
- CIDR notation `a.b.c.d/bitcount`, with bitcount from 0 to 32.
  Missing octets default to zero from the right: `194.243/16` is
  taken as `194.243.0.0/16`.
- A trailing-wildcard numeric form: `194.243.*` is equivalent to
  `194.243.0.0/16`.
- An IPv6 address, optionally with `/bitcount` (0 to 128).

CIDR/numeric forms apply only to the IP field; every other field is
matched with the ordinary `*`/`?` wildcard rules (don't expect to
catch a user whose real name is "1.2.3.4" with `WHO 1.2/16 h`).

*Historical note:* the netmask form `a.b.c.d/e.f.g.h` accepted by very
old servers is no longer parsed, and `/32` (an exact address) is now
valid.

## Options

The options parameter has the form:

```
[<flags>][%[<fields>][,<querytype>]]
```

### Field-matching flags

When one of these is specified the field in question is matched
against the mask; otherwise it is not matched.

| Flag | Field matched |
|------|---------------|
| `n` | Nick (in nick!user@host) |
| `u` | Username (in nick!user@host) |
| `h` | Hostname (in nick!user@host) |
| `i` | Numeric IP (the unresolved host) |
| `s` | Server name (the canonical name of the server the user is on) |
| `r` | Info text (formerly "real name") |
| `a` | Account name |

If no field-matching flags are specified, the default is `nuhs`
(nick, username, hostname, server). Note that the info text is *not*
matched by default — ask for it explicitly with `r`.

With the `HIS_WHO_SERVERNAME` feature enabled (the default), non-opers
cannot match on the server field; `s` is silently dropped for them.

For users with hidden hosts, non-opers match only the visible host and
username and can never match the numeric IP; opers additionally match
against the real host and real username.

### Selection flags

Specifying one of these restricts which clients are considered:

| Flag | Effect |
|------|--------|
| `o` | Only IRC operators. Only opers whose status is visible (the `display` privilege) are listed. |
| `d` | Also show join-delayed channel members (channel mode `+D`). |

### Special purpose flags

| Flag | Effect |
|------|--------|
| `x` | Extended visibility for opers: see invisible (+i) users everywhere and, with the `see_chan` privilege, look into secret (+s) and private (+p) channels. Requires oper status *and* the `whox` privilege; otherwise it is silently ignored. Every use is written to the WHO log subsystem (see `doc/readme.log.md`). |

### Output fields

The `%<fields>` part specifies which fields to include in the output:

| Field | Included |
|-------|----------|
| `c` | (First visible) channel name |
| `d` | "Distance" in hops (hop count) |
| `f` | Flags (all of them) |
| `h` | Hostname |
| `i` | IP |
| `l` | Idle time |
| `n` | Nick |
| `r` | Real name |
| `s` | Server name |
| `t` | The querytype in the reply |
| `u` | Username with eventual ~ |
| `a` | Account name (`0` if not authed) |
| `o` | Oplevel (`n/a` for members without ops; the real level is shown only to opers and to chanops of the channel, `999` to everyone else) |

The `,<querytype>` option (up to 3 digits) is echoed in the querytype
field of the output, useful for filtering replies in scripts.

If no `%fields` are specified, the reply is exactly the traditional
numeric 352, same fields, same order. If one or more `%fields` are
specified the reply uses numeric 354 (since an out-of-standard 352
confuses many clients), with only the requested fields present, always
in this order:

```
:server 354 target [querytype] [channel] [user] [IP] [host] [server]
                   [nick] [flags] [hops] [idle] [account] [oplevel]
                   [:realname]
```

The order in which the field letters are given is not significant; the
client has to sort/format the fields by itself.

In the 354 reply the flags field carries the full channel-membership
state: `@` opped, `+` voiced, `!` zombie, `<` join-delayed (the 352
reply keeps the old behavior of showing at most one of them).

### HIS restrictions on output

With the (default-enabled) HIS features, non-opers see censored
values: `HIS_WHO_SERVERNAME` replaces the server name with the
network's HIS server name and zeroes the idle field for other users;
`HIS_WHO_HOPCOUNT` reports hop count `0` for yourself and a flat `3`
for everyone else. Idle time is in any case only known for users
local to the answering server, and umode `+I` (hide idle) zeroes it
for everyone but the user themself and opers.

## Visibility rules

- Users who are `-i` (not invisible) are matched by any `WHO mask`.
  Being on a secret or private channel does not hide a `-i` user
  from a mask query, but such channels are never shown as their
  channel; if no visible channel exists, `*` is shown instead.
- Users who are `+i` are shown only if they share a channel with the
  asker; the first common channel found is shown.
- A full nick given as the mask finds the user even if invisible
  (just as WHOIS would).
- `WHO #channel` on a secret/private channel works only for members —
  or for opers with the `see_chan` privilege using the `x` flag.

## Output limits

The maximum number of reply lines for a mask query is `2048/(n+4)`,
where `n` is the number of fields included in each reply (7 for the
default 352 query):

| Fields returned | Maximum replies |
|-----------------|-----------------|
| 1 | 409 |
| 2 | 341 |
| 3 | 292 |
| 4 | 256 |
| 5 | 227 |
| 6 | 204 |
| 7 | 186 (default query) |
| 8 | 170 |
| 9 | 157 |
| 10 | 146 |

If the limit is reached the reply is truncated and an error numeric is
sent after the "End of WHO" — the "End of WHO" numeric is *always*
sent. A single "End of WHO" is returned even for a comma-separated
list. Opers with the `unlimit_query` privilege get full results
(until they get disconnected by max SendQ exceeded).

Matching against many fields is CPU-expensive, and the default query
matches four of them. When looking for all French users,
`WHO *.fr h` is a lot better than `WHO *.fr` — and it is also what
you actually mean.
