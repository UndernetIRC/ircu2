# Client capabilities (`CAP`)

## Overview

ircu supports IRCv3 capability negotiation via the `CAP` command (`ircd/m_cap.c`, `include/capab.h`).
Clients can list, request, and clear capabilities before or after registration.
During registration on user or WebSocket ports, `CAP LS` / `CAP REQ` suspends auth until `CAP END`.

Most capabilities are gated by a matching `CAP_*` feature (default `TRUE`).
Setting a feature to `FALSE` removes the capability from `LS`/`REQ` (see `doc/readme.features.md`).
`sasl` is special: it also depends on netconf and link state (see `doc/readme.sasl.md`).

## Subcommands

| Subcommand | Role |
| --- | --- |
| `CAP LS [302]` | List available capabilities. With `302` or higher, mark the client as IRCv3.2 (`FLAG_CAP302`), auto-enable sticky `cap-notify`, and include `name=value` for caps that have a value |
| `CAP LIST` | List capabilities the client currently has enabled |
| `CAP REQ :…` | Request enabling or disabling caps (`-cap` to clear). Success → `CAP ACK`; any failure → `CAP NAK` for the whole request string |
| `CAP END` | Finish CAP negotiation during registration (`auth_cap_done`) |
| `CAP NEW` / `CAP DEL` | Server→client only (clients do not send these). Used when availability changes for clients with `cap-notify` |

`ACK` and `NAK` from clients are accepted as no-ops (protocol compatibility).

Unavailable or feature-disabled caps are omitted from `LS` and cannot be `REQ`uest’d.
`CAPFL_PROHIBIT` / sticky flags also cause `NAK` (for example clearing sticky `cap-notify` on a 302 client).

## IRCv3.2 notes

- `CAP LS 302` sets `FLAG_CAP302` and enables `cap-notify` without listing it in `LS` (`CAPFL_HIDDEN_302`).
- `cap-notify` is sticky for 302 clients (`CAPFL_STICKY_302`): it cannot be cleared with `CAP REQ -cap-notify`.
- Dynamic availability changes call `cap_update_availability()`, which sends `CAP NEW` or `CAP DEL` to clients that have `cap-notify` (typically after SASL becomes available or disappears).

## Supported capabilities

| Capability | Feature | Notes |
| --- | --- | --- |
| `account-notify` | `CAP_ACCOUNTNOTIFY` | Account login notices |
| `away-notify` | `CAP_AWAYNOTIFY` | Away state changes |
| `chghost` | `CAP_CHGHOST` | Hidden host / trusted username changes |
| `echo-message` | `CAP_ECHOMESSAGE` | Echo of the client’s own messages |
| `extended-join` | `CAP_EXTJOIN` | Extended `JOIN` with account / realname |
| `invite-notify` | `CAP_INVITENOTIFY` | Invite notifications |
| `userhost-in-names` | `CAP_UHNAMES` | `user@host` in `NAMES` |
| `message-tags` | `CAP_MESSAGE_TAGS` | Client message tags; see tags section below |
| `server-time` | `CAP_SERVER_TIME` | `@time=` on delivered messages |
| `account-tag` | `CAP_ACCOUNT_TAG` | `@account=` on messages from logged-in users |
| `cap-notify` | *(none)* | Auto for `LS 302`; hidden from 302 `LS`; sticky |
| `sasl` | `CAP_SASL` | Starts unavailable until netconf + linked service; CAP value = mechanism list. See `doc/readme.sasl.md` |

## Message tags

With `message-tags` (and related caps), clients may send and receive IRCv3 message tags.

- Server tags such as `time` and `account` are produced for clients that negotiated `server-time` / `account-tag` (or `message-tags` as applicable).
- Client-only tags (keys beginning with `+`) are filtered by feature `CLIENTTAGDENY` (ISUPPORT `CLIENTTAGDENY=…`). Default `"*"` denies all client-only tags; see `doc/readme.features.md`.
- S2S tag federation is controlled by `NETWORK_FEATURES` and `@time=` invention/forwarding by `NETWORK_TIME`.

Implementation: `ircd/msg_tag.c`.

## See also

- `include/capab.h`, `ircd/m_cap.c`
- `doc/readme.features.md` (`CAP_*`, `CLIENTTAGDENY`, `NETWORK_FEATURES`, `NETWORK_TIME`)
- `doc/readme.sasl.md`
- IRCv3 capability negotiation: https://ircv3.net/specs/extensions/capability-negotiation
