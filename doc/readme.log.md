# Logging

Older versions of ircd had no consistent way of logging various
actions. Some things, such as G-lines, were written out to log files
with names compiled into the server. Others could only be logged
through syslog. Some required that their log files exist beforehand.
Starting with u2.10.11, this situation changed dramatically.

All logging in the server is unified through a single logging
subsystem. The log messages may be sent to a given file, to syslog,
or even to online operators — or any combination of these three
methods. This file describes the configuration of the logging
subsystem, implemented in `ircd/ircd_log.c`.

All logs are classified by a "subsystem" and a "level." The subsystem
is a major classification; each subsystem may be configured
individually. The level classification is used to indicate how
important the message is; subsystems may be configured to omit log
messages with less than a certain importance — not unlike syslog.

## Levels

Levels are used to classify the importance of various log messages.
The most important level is CRIT; the least important is DEBUG. Each
level maps to a corresponding syslog priority, and some also force
generation of certain types of server notices.

| Level | Used for | Syslog priority | Server notices |
|-------|----------|-----------------|----------------|
| CRIT | Very critical notifications, such as server termination | CRIT | `OLDSNO` mask |
| ERROR | Important error conditions | ERR | |
| WARNING | Warnings about certain conditions | WARNING | |
| NOTICE | Important information | NOTICE | |
| TRACE | Tracing the operation of the server | INFO | |
| INFO | Unimportant but potentially useful information | INFO | |
| DEBUG | Debugging information | DEBUG | `DEBUG` mask |

## Subsystems

All of the subsystems are listed below, along with their default
logging configuration. There are no default log files to log to, and
the default logging level is INFO (unless the server is compiled with
debugging enabled) — this means that only notices of importance INFO
or higher will be logged.

| Subsystem | Used for | Default destination |
|-----------|----------|---------------------|
| SYSTEM | Information that affects the server as a whole | nowhere |
| CONFIG | Information concerning the configuration file | default syslog facility and the `OLDSNO` server notice mask |
| OPERMODE | Usage of /OPMODE and /CLEARMODE | `HACK4` server notice mask |
| GLINE | Usage of /GLINE, particularly BADCHANs | `GLINE` server notice mask |
| JUPE | Usage of /JUPE | `NETWORK` server notice mask |
| WHO | Usage of the extended features of /WHO (/WHOX) | nowhere |
| NETWORK | Net junctions and net breaks | `NETWORK` server notice mask |
| OPERKILL | Usage of /KILL by IRC operators | nowhere |
| SERVKILL | Usage of /KILL by other servers | nowhere |
| USER | User sign-ons and sign-offs | nowhere |
| OPER | Usage of /OPER, either successfully or unsuccessfully | `OLDREALOP` server notice mask |
| RESOLVER | Error messages or other conditions from the resolver and authentication system | nowhere |
| SOCKET | Problems with sockets | nowhere |
| IAUTH | Connects, disconnects and errors for the IAuth authorization mechanism | `NETWORK` server notice mask |
| DEBUG | Only when debugging is enabled | the console or the debug log file compiled into the server, plus the `DEBUG` server notice mask. This is the only subsystem with a default log file. |

## Configuration

The true power of the logging subsystem comes from its extremely
flexible configuration. The default server facility can be
configured, as can the facility for each individual subsystem
described above. Moreover, administrators can configure the server to
log to specific files, send selected log messages to operators
subscribed to any server notice mask, and even change the default log
level for each subsystem.

The logging subsystem has a set of tables mapping names to the
numerical values used internally. Subsystems, levels, syslog
facilities, and server notice masks are all configured using strings.
These tables even include special strings, such as "DEFAULT" and
"NONE."

### Default syslog facility

The IRC server has a default facility that it uses when sending log
messages to syslog. The default facility may be overridden for each
individual subsystem, but the default itself can be changed with an
appropriate Feature entry in the configuration file. The facility
normally defaults to "USER," but may be configured to be any of AUTH,
CRON, DAEMON, LOCAL0 through LOCAL7, LPR, MAIL, NEWS, USER, or UUCP.
Some systems also have the AUTHPRIV facility. To configure this
default, add a Feature line to the configuration file:

```
"LOG" = "<facility>";
```

### Log files

Each subsystem may be configured to send its log messages to any
single log file:

```
"LOG" = "<subsys>" "FILE" "<file>";
```

`<subsys>` is one of the subsystem names described above, and
`<file>` is a file name for the log file. The file name may be
relative to the server's data directory ("DPATH"), or it may be an
absolute path name. Note that if you're using chroot, absolute path
names are relative to the server's root directory.

### Logging to syslog

By default, except for the CONFIG subsystem, no logs are sent to
syslog. This can be overridden with:

```
"LOG" = "<subsys>" "FACILITY" "<facility>";
```

`<facility>` must be one of the facility strings mentioned under
"Default syslog facility." The facility string may also be "NONE," to
turn off syslog for that subsystem, and "DEFAULT," to use the server's
default facility. Please don't confuse a DEFAULT facility with the
default for a particular subsystem; only the CONFIG subsystem defaults
to DEFAULT, whereas all the rest default to NONE.

### Logging via server notices

Log messages can be sent to online IRC operators. Many subsystems
actually default to this behavior, in fact. For security, log
messages containing IP addresses or other extremely sensitive data
will never be sent via server notices, but all others can be sent to a
specific server notice mask. (For more information about server
notice masks, please see `doc/snomask.md`.) The available mask names
are OLDSNO, SERVKILL, OPERKILL, HACK2, HACK3, UNAUTH, TCPCOMMON,
TOOMANY, HACK4, GLINE, NETWORK, IPMISMATCH, THROTTLE, OLDREALOP,
CONNEXIT, DEBUG, and AUTH. The special mask name "NONE" inhibits
sending of server notices for a particular subsystem:

```
"LOG" = "<subsys>" "SNOMASK" "<mask>";
```

### Setting the minimum logging level

The minimum log level for a particular subsystem may be set with:

```
"LOG" = "<subsys>" "LEVEL" "<level>";
```

`<level>` is one of the level names described above.
