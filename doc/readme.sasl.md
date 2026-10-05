# SASL authentication

## Overview

ircu implements IRCv3 SASL by advertising the `sasl` capability and handling client `AUTHENTICATE` messages.
Authentication itself is performed by an external login / services server over `XQUERY` / `XREPLY` (routing prefix `sasl:`).
ircu tracks per-client sessions (cookie, timeout) and applies success/failure replies to the client.

SASL can run during registration (before the client is a user) or after registration.
During registration, a successful `OK` reply can set account information on the auth request; when registration finishes the client is introduced with umode `+r` and that account.
After registration, account assignment is expected via the usual account (`AC`) path (or the client may already have been introduced with `+r` / account from earlier SASL); ircu still sends `RPL_LOGGEDIN` / `RPL_SASLSUCCESS` on success.

## Enabling SASL

SASL is offered to clients only when **all** of the following hold:

1. Feature `CAP_SASL` is `TRUE` (default).
2. Netconf `sasl.server` is set and that server is currently linked.
3. Netconf `sasl.mechanisms` is non-empty.

`sasl_available()` encodes (2) and (3).
The CAP starts as unavailable (`CAPFL_UNAVAILABLE`) and is toggled with `sasl_check_capability()` on netconf changes and after netjoins/netsplits (`END_OF_BURST` / server exit).

When `sasl.mechanisms` changes, its value is also set as the IRCv3 CAP value for `sasl` (mechanism list advertised to CAP LS 302 clients).

Related netconf keys (see `doc/readme.netconf.md`):

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `sasl.server` | string | empty | Login / SASL service server name (must be linked) |
| `sasl.mechanisms` | string | empty | Comma-separated mechanism names (also CAP value) |
| `sasl.timeout` | integer | `30` | Seconds before an in-progress session fails |

## Client flow (`AUTHENTICATE`)

Command name `AUTHENTICATE` (same long name and token).
Handled for local clients that have negotiated `CAP_SASL` (`m_sasl`).

| Client sends | Behaviour |
| --- | --- |
| `AUTHENTICATE <mechanism>` | Start a session if none is active; mechanism must appear in `sasl.mechanisms` |
| `AUTHENTICATE <payload>` | Continuation while a session cookie is set (base64 / `+` as usual for IRCv3) |
| `AUTHENTICATE *` | Abort; clears session and sends `ERR_SASLABORTED` (906) |

Constraints and errors:

- Without `CAP_SASL`, `AUTHENTICATE` is ignored (no reply).
- Already authenticated (`FLAG_SASL` or `FLAG_ACCOUNT`) → `ERR_SASLALREADY` (907).
- SASL unavailable / service disconnected → `ERR_SASLFAIL` (904) with a disconnect notice.
- Parameter longer than 400 characters → `ERR_SASLTOOLONG` (905).
- Unknown mechanism → `RPL_SASLMECHS` (908) listing `sasl.mechanisms`.

On a successful start, ircu assigns a non-zero session cookie, stores it in a cookie→client hash, and starts a relative timeout of `sasl.timeout` seconds.
Timeout sends `ERR_SASLFAIL` (“Authentication timed out”) and clears the session.

## Service protocol (`XQUERY` / `XREPLY`)

General extension-query syntax is documented in `doc/readme.xquery`.
SASL uses routing tokens of the form `sasl:<cookie>`.

### Initial query (unregistered client)

```
XQ <sasl.server> sasl:<cookie> :SASL <ip> <fingerprint|_> <mechanism>
```

`<fingerprint>` is the client TLS fingerprint, or `_` if none.

### Initial query (already registered user)

```
XQ <sasl.server> sasl:<cookie> :SASL <numnick> <mechanism>
```

### Continuation

```
XQ <sasl.server> sasl:<cookie> :SASL <payload>
```

### Replies (to the originating server)

```
XR <origin> sasl:<cookie> :SASL <client-payload>
XR <origin> sasl:<cookie> :OK [<account>[:<id>[:<flags>]]]
XR <origin> sasl:<cookie> :NO <reason>
```

| Reply | Effect |
| --- | --- |
| `SASL …` | Forwarded to the client as `AUTHENTICATE <…>` (text after the `SASL ` prefix) |
| `OK` / `OK <account_info>` | Success: stop timeout, clear session, set `FLAG_SASL`, send `RPL_SASLSUCCESS` (903). For unregistered clients, `account_info` is parsed as `account[:id[:flags]]` via `auth_set_account`, and the user is later introduced with `+r` and that account. For registered clients, send `RPL_LOGGEDIN` (900); services should set or confirm account with `AC` if needed. Bare `OK` with no account string does not set account fields. |
| `NO <reason>` | Failure: `ERR_SASLFAIL` with `<reason>`, clear session |

## Operator visibility

`/STATS S` or `/STATS sasl` (gated by `HIS_STATS_S`) reports whether SASL is available, the configured server, mechanisms, timeout, and success/failure counters.

## Implementation notes

- Cookie allocation uses a local ticker (skips 0); sessions are hashed for `XREPLY` lookup.
- Disconnect clears any outstanding SASL session for the client.
- `CAP_SASL` only gates advertising/requesting the capability; netconf still controls real availability.
- Client-facing SASL numerics are in the 900–908 range (`include/numeric.h`).

## See also

- `include/sasl.h`, `ircd/sasl.c`, `ircd/m_sasl.c`, `ircd/m_xreply.c`
- `doc/readme.netconf.md` (`sasl.*` keys)
- `doc/readme.features.md` (`CAP_SASL`, `HIS_STATS_S`)
- `doc/readme.xquery`
- IRCv3 SASL specs: https://ircv3.net/specs/extensions/sasl-3.1 and https://ircv3.net/specs/extensions/sasl-3.2
- `doc/readme.cap.md` (capability negotiation)
