# S-lines (spamfilter)

## Overview

S-lines are network-wide POSIX extended regular expressions used for spam filtering.
A services server publishes patterns with the `SLINE` / `SL` command; every linked ircu stores them and, when a local user’s message matches, can hold delivery while it asks a configured spamfilter service for a decision via `XQUERY` / `XREPLY`.

Unlike G-lines, S-lines do not disconnect clients by themselves.
Private and channel traffic is held for approval; `PART` and `QUIT` reasons that match are suppressed instead.

## Enabling S-lines

S-line checking runs only when **both** are true:

1. Feature `DISABLE_SLINES` is `FALSE` (the default).
2. Netconf key `sline.server` is set to the name of a linked spamfilter / services server.

If either condition fails, matching is skipped.
If a pattern matches but `sline.server` is not currently linked, private/channel paths **fail open** and deliver the message instead of holding it for the full timeout.

Related netconf keys (see `doc/readme.netconf.md`):

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `sline.server` | string | empty | Spamfilter server name (must be linked) |
| `sline.hold_timeout` | integer | `60` | Seconds to wait for an `XREPLY` before timeout |
| `sline.hold_timeout_block` | boolean | `true` | On timeout: block (`true`) or release (`false`) |

## SLINE command (server-to-server)

Long name `SLINE`, P10 token `SL`.
Handled only from servers (`ms_sline`); there is no client `SLINE` command.

```
SL <state> <lastmod> <expire> <types> :<pattern>
```

| Field | Meaning |
| --- | --- |
| `<state>` | `+` active, `-` inactive |
| `<lastmod>` | UNIX timestamp of this change (newer wins; `0` becomes “now”) |
| `<expire>` | UNIX expiry time, or `0` for never |
| `<types>` | One or more type letters (see below) |
| `<pattern>` | POSIX extended regex (`REG_EXTENDED`); max length `SLINELEN` (470) |

Examples:

```
YY SL + 1711200000 0 PC :viagra
YY SL + 1711200100 1711286400 A :(?i)free\s+crypto
YY SL - 1711200200 0 A :oldpattern
```

Identical patterns are updated in place when `lastmod` is newer (state, types, and/or expire).
Stale or no-op updates are ignored.
On server burst, all known S-lines are sent with `sline_burst()`.

Invalid regexes are still stored and burst, but marked invalid (`I` in notices/stats) and never match.

## Message type flags

| Letter | Flag | Applies to |
| --- | --- | --- |
| `A` | all | Private, channel, part, and quit (overrides other letters) |
| `P` | private | `PRIVMSG` / `NOTICE` to users (and related private paths) |
| `C` | channel | Channel `PRIVMSG` / `NOTICE`, `WALLCHOPS`, `WALLVOICES`, channel `TAGMSG` |
| `L` | part | `PART` reasons |
| `Q` | quit | `QUIT` reasons |

Operators (`IsAnOper`) are exempt from all S-line checks.

## Matching behaviour

### Private and channel messages

Checked with `sline_check_privmsg` / `sline_check_chanmsg` on the local server that would deliver the message.

On match:

1. The message is placed on a **hold queue** with a unique token (client gets `FLAG_SPAMHOLD` while referenced).
2. An `XQUERY` is sent to `sline.server`:

```
XQ <spamfilter> spam:<token> :<sender> <target> :<captures>
```

`<target>` is a user (private) or channel (channel).
`<captures>` is space-separated regex capture groups, or the full match if there were no groups (up to 15 capturing groups; see `SLINE_MAX_CAPTURES`).

3. The spamfilter answers with `XREPLY` using the same routing token:

```
XR <origin> spam:<token> :YES
XR <origin> spam:<token> :NO
```

- `YES` — deliver the held message (preserving `PRIVMSG` vs `NOTICE` / wall* semantics, including `echo-message` where applicable).
- `NO` — drop it and send a normal-looking error to the sender (`ERR_NOSUCHNICK` for private, `ERR_CANNOTSENDTOCHAN` for channel).

### Hold timeout

A periodic timer (every 10 seconds) expires holds older than `sline.hold_timeout`.

- If `sline.hold_timeout_block` is true (default): block like `NO`.
- If false: release like `YES`.

Disconnecting clients and destroyed channels clean up their hold-queue entries.

### PART and QUIT

These use a boolean match only (`sline_check_pattern_bool`); there is no hold queue or `XQUERY`.

- Matching `PART` reasons are suppressed (treated like a banned/nopartmsgs part).
- Matching `QUIT` reasons cause a generic “Signed off” exit when the user is on channels that would show the quit text.

## Operator visibility

`/STATS s` or `/STATS slines` (gated by `HIS_STATS_s`) lists active S-lines (`RPL_STATSSLINE` / 240): lastmod, expire, hit count, type string, and pattern.

It also reports whether S-lines are enabled, the configured spamfilter server, hold timeout settings, and counters (hits, held, released, blocked, XREPLY accepted/rejected, timeouts).

Memory use appears under server meminfo reporting (`sline_send_meminfo`).

Oper notices for add/modify use `SNO_GLINE`.

## Implementation notes

- Patterns are compiled once with `regcomp(..., REG_EXTENDED)`.
- Only **active** and **valid** lines for the relevant message type are considered; expired lines are freed when encountered.
- Hold-queue and S-line lists are local state derived from S2S traffic; there is no `ircd.conf` S-line block.
- Extension query details: `doc/readme.xquery`.

## See also

- `include/sline.h`, `ircd/sline.c`, `ircd/m_sline.c`, `ircd/m_xreply.c`
- `doc/readme.netconf.md` (`sline.*` keys)
- `doc/readme.features.md` (`DISABLE_SLINES`, `HIS_STATS_s`)
- `doc/readme.xquery`
- `doc/readme.sasl.md` (uses the same `XQUERY` / `XREPLY` mechanism with `sasl:`)
- `doc/readme.gline` (different mechanism: user bans)
