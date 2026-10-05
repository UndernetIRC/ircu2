# Network configuration (netconf)

## Overview

The netconf subsystem provides dynamic, network-wide configuration.
A service (or other server) can set, update, or delete options that are stored on every server and propagated over server links.
This avoids editing `ircd.conf` Feature blocks on each server for settings that must stay in sync network-wide (for example SASL and S-line / spamfilter).

## Key concepts

- **Network-wide store:** Key/value entries live in a linked list on each server and are burst to newly linked peers.
- **Dynamic updates:** Entries can change at runtime without reloading local configuration files.
- **Timestamps:** Each entry carries a UNIX timestamp; only a newer timestamp is accepted, so stale updates cannot overwrite fresher data.
- **Typed accessors:** Known keys are exposed through the `NetConf` enum and `netconf_int` / `netconf_bool` / `netconf_str`, with compiled-in defaults when unset.
- **Callbacks:** Built-in code can register a prefix callback (for example `sasl.`) to react when matching keys change.
- **Server-to-server only:** The `CONFIG` / `CF` command is handled on server links (`ms_config`); clients do not set netconf.

## How it works

Services send a `CONFIG` message (P10 token `CF`) with a timestamp, key, and optional value:

- If the value is omitted or empty and the timestamp is newer, the key is deleted.
- If the key is new, or exists with an older timestamp, the value is created or updated.
- Accepted changes are forwarded to other servers and may generate operator notices (`SNO_NETWORK`).
- On server burst, `config_burst()` sends all current entries to the new peer.

## Known keys

These keys are defined in `include/ircd_netconf.h` / `ircd/ircd_netconf.c`.
Arbitrary keys may still be stored via `CF`, but only the keys below have typed accessors and defaults.

### SASL

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `sasl.server` | string | empty | Nick/name of the SASL service server |
| `sasl.mechanisms` | string | empty | Comma-separated mechanism list (also used as the IRCv3 `sasl` CAP value) |
| `sasl.timeout` | integer | `30` | SASL session timeout in seconds |

`ircd/sasl.c` registers a `sasl.` callback on init.
When `sasl.mechanisms` changes it updates the CAP value; capability availability is recomputed when SASL-related keys change.

### S-line (spamfilter)

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `sline.server` | string | empty | Nick/name of the spamfilter service server |
| `sline.hold_timeout` | integer | `60` | Hold-entry lifetime in seconds |
| `sline.hold_timeout_block` | boolean | `true` | If true, expire held matches as blocks; see `ircd/sline.c` |

S-lines also require the `DISABLE_SLINES` feature to be `FALSE`.
Boolean netconf values accept `true` / `1` / `yes` (case-insensitive comparison as implemented).

## CF message syntax

Long name `CONFIG`, P10 token `CF`:

```
CF <timestamp> <key> [:<value>]
```

- `<timestamp>`: UNIX time (seconds since epoch)
- `<key>`: configuration key (for example `sasl.mechanisms`)
- `<value>`: value to set; omit (or send empty) to delete when the timestamp is newer

Examples (P10 with source numnick):

```
YY CF 1711200000 sasl.mechanisms :PLAIN,EXTERNAL,SCRAM-SHA-256
YY CF 1711201234 sasl.mechanisms
YY CF 1711202000 sline.server :spamfilter.example.net
YY CF 1711202001 sline.hold_timeout :120
YY CF 1711202002 sline.hold_timeout_block :yes
```

No matching `ircd.conf` Feature entries are required for these keys; they are purely network state.

## Operator visibility

Oper `/STATS C`, `/STATS config`, or `/STATS netconf` lists current entries as timestamp, key, and value.
Access is gated like other oper stats (`HIS_STATS_C`).
This is distinct from `/STATS c` (connect blocks); both letters are case-sensitive in stats.

## Accessing options in code

```c
enum NetConf {
  NETCONF_SASL_SERVER,
  NETCONF_SASL_MECHANISMS,
  NETCONF_SASL_TIMEOUT,
  NETCONF_SLINE_SERVER,
  NETCONF_SLINE_HOLD_TIMEOUT,
  NETCONF_SLINE_HOLD_TIMEOUT_BLOCK,
  NETCONF_LAST_NC
};
```

Typed getters (use the default from `netconf_descs` when the key is unset):

- `int netconf_int(enum NetConf key);`
- `int netconf_bool(enum NetConf key);`
- `const char *netconf_str(enum NetConf key);`

```c
int timeout = netconf_int(NETCONF_SASL_TIMEOUT);
const char *mechs = netconf_str(NETCONF_SASL_MECHANISMS);
```

Add new well-known options by extending the `NetConf` enum and the `netconf_descs[]` table in `ircd/ircd_netconf.c`.

## API summary

- `int config_set(const char *key, const char *value, time_t timestamp);`
  - Create, update, or delete a key.
  - Returns `CONFIG_REJECTED` (-1), `CONFIG_CREATED` (0), `CONFIG_TIMESTAMP` (1), `CONFIG_CHANGED` (2), or `CONFIG_DELETED` (3).
- `const char *config_get(const char *key);`
  - Raw value, or `NULL` if unset (no default applied).
- `void config_register_callback(const char *key_prefix, config_callback_f callback);`
  - Invoke `callback(key, old_value, new_value)` when a matching key changes (`new_value` is `NULL` on delete).
- `void config_unregister_callback(const char *key_prefix);`
- `void config_burst(struct Client *cptr);`
  - Send all entries to a linking server.
- `void config_stats(struct Client *sptr, const struct StatDesc *sd, char *param);`
  - Implement `/STATS C` / `config` / `netconf`.

## Callback example (in-tree)

`sasl_init()` registers for the `sasl.` prefix:

```c
static void sasl_config_callback(const char *key, const char *old_value,
                                 const char *new_value)
{
  if (ircd_strcmp(key, "sasl.mechanisms") == 0)
    cap_set_value(E_CAP_SASL, new_value);
  sasl_check_capability();
}

void sasl_init(void)
{
  config_register_callback("sasl.", sasl_config_callback);
}
```

## Setting and reading values

From privileged server-side code:

```c
#include <time.h>

time_t now = time(NULL);
config_set("sasl.mechanisms", "PLAIN,EXTERNAL", now);
```

Reading without defaults:

```c
const char *mechs = config_get("sasl.mechanisms");
if (mechs)
  /* use mechs */;
```

Prefer `netconf_str` / `netconf_int` / `netconf_bool` for known keys so defaults apply.

## Benefits

- One place to push service settings to the whole network
- Less config drift between servers
- Timestamp ordering avoids clobbering newer state during netsplits/rejoins

## See also

- `include/ircd_netconf.h`
- `ircd/ircd_netconf.c`
- `ircd/m_config.c`
- `ircd/sasl.c`
- `ircd/sline.c`
- `doc/readme.sasl.md`
- `doc/readme.sline.md`
- `doc/readme.features.md` (`DISABLE_SLINES`, `HIS_STATS_C`, `CAP_SASL`)
