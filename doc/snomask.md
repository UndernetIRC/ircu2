# SNOMASK - Server Notice Masks

Written by Ghostwolf, 18th June 1997.
Modified with permission by loki, 12th November 1997.

This document gives a brief explanation of the use of server notice masks.
The mask allows clients to specify which types of server notices they will
receive when usermode `+s`. The mask may optionally be omitted, and
reasonable defaults will be used by the server.

Usage:

```
/mode <nick> +s [+/-][mask]
```

The mask is a decimal number given as a separate parameter. A bare
number *replaces* the current mask; a number prefixed with `+` adds
those bits, `-` removes them. Using `-s` inverts the sense of the
prefix (so `/mode <nick> -s +1024` also removes bit 1024). If the
resulting mask is zero, the user drops umode `+s`; `-s` without a mask
clears everything.

## Masks

The authoritative list is in `include/client.h`.

| Mask | Name | Hex value | Description |
|------:|------|-----------|-------------|
| 1 | `SNO_OLDSNO` | 0x1 | unsorted old messages |
| 2 | `SNO_SERVKILL` | 0x2 | server kills (nick collisions) |
| 4 | `SNO_OPERKILL` | 0x4 | oper kills |
| 8 | `SNO_HACK2` | 0x8 | desyncs |
| 16 | `SNO_HACK3` | 0x10 | temporary desyncs |
| 32 | `SNO_UNAUTH` | 0x20 | unauthorized connections |
| 64 | `SNO_TCPCOMMON` | 0x40 | common TCP or socket errors |
| 128 | `SNO_TOOMANY` | 0x80 | too many connections |
| 256 | `SNO_HACK4` | 0x100 | Uworld actions on channels |
| 512 | `SNO_GLINE` | 0x200 | G-lines |
| 1024 | `SNO_NETWORK` | 0x400 | net join/break, etc |
| 2048 | `SNO_IPMISMATCH` | 0x800 | IP mismatches |
| 4096 | `SNO_THROTTLE` | 0x1000 | host throttle add/remove notices |
| 8192 | `SNO_OLDREALOP` | 0x2000 | old oper-only messages |
| 16384 | `SNO_CONNEXIT` | 0x4000 | client connect/exit |
| 32768 | `SNO_AUTO` | 0x8000 | automatic G-lines |
| 65536 | `SNO_DEBUG` | 0x10000 | debugging messages (DEBUGMODE only) |
| 131072 | `SNO_AUTH` | 0x20000 | IAuth notices |

## Defaults

| Situation | Mask |
|-----------|------|
| standard `+s` | `SNO_DEFAULT` = `SNO_NETWORK \| SNO_OPERKILL \| SNO_GLINE` |
| standard `+s` when `+o`/`+O` | `SNO_OPERDEFAULT` = `SNO_DEFAULT \| SNO_HACK2 \| SNO_HACK4 \| SNO_THROTTLE \| SNO_OLDSNO` |
| only opers may set | `SNO_OPER` = `SNO_CONNEXIT \| SNO_OLDREALOP \| SNO_AUTH` |
| maximum for non-opers | `SNO_USER` = everything except `SNO_OPER` |

An explicit mask from a non-opered client is silently ANDed with
`SNO_USER`, so a non-oper may request any notice type *except*
connect/exit, old oper-only messages and IAuth notices. An oper's mask
is capped at `SNO_ALL`. When a user is de-opered (`-o`/`-O`), the
`SNO_OPER` bits are removed from their mask automatically. `SNO_DEBUG`
only exists in servers compiled with DEBUGMODE.

## Examples of usage

To receive only oper kills:

```
/mode <nick> +s 4
```

To receive oper kills and G-lines, add the values (512 + 4 = 516):

```
/mode <nick> +s 516
```

If you are already receiving some notices and you wish to add notices of
net joins/breaks:

```
/mode <nick> +s +1024
```

If you wish to stop receiving net join/break notices, but continue to
receive other notices, either of:

```
/mode <nick> +s -1024
/mode <nick> -s +1024
```

A non-opered user typing `/mode <nick> +s` without a mask gets
`SNO_DEFAULT`: net splits/joins, oper kills and G-lines. An oper doing
the same gets `SNO_OPERDEFAULT`, which adds desync (HACK) notices,
Uworld channel actions, host-throttle notices and the unsorted old
messages.

Only opers can choose to receive the `SNO_OPER` types. Note that
connect/exit notices (`SNO_CONNEXIT`) are only generated at all when
the `CONNEXIT_NOTICES` feature is enabled (default `FALSE`, see
`doc/readme.features.md`).
