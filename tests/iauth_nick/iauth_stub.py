#!/usr/bin/env python3
"""IAuth stub for nickname assignment tests.

Logs every line from the ircd to the file given as argv[1].  Client
nicknames drive stub behaviour:

  testnick      -> force nick to "Guest001", then approve (used with/without SASL)
  tmpuser       -> force nick to "finaluser", then approve
  set_<nick>    -> force nick to <nick>, then approve
  bad_<nick>    -> try invalid nick, then on E retry with "recovered", D
  collide       -> force "taken"; on E InUse retry with "freenick", D
  stuckbad      -> force invalid nick and D without retry (should not 001)

All other clients are approved on "n" without changing their nick.

For testnick, f is always sent before D so registration cannot finish on
the client's requested nick.  SASL success (A) is independent and may
arrive before or after n; the stub does not wait for it.
"""

import sys


def main():
    logf = open(sys.argv[1], "a", buffering=1)

    def out(line):
        # Prefix outgoing replies so tests can assert f-before-D ordering.
        logf.write("> " + line + "\n")
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    # R: iauth is required; U: enable Undernet extensions (U/u/n/H/T).
    out("O RU")

    clients = {}
    # cid -> ("bad"|"collide", ip, port)
    awaiting_retry = {}

    for line in sys.stdin:
        line = line.rstrip("\r\n")
        logf.write(line + "\n")
        parts = line.split(" ")
        if len(parts) < 2:
            continue
        cid, cmd = parts[0], parts[1]
        if cmd == "C" and len(parts) >= 4:
            clients[cid] = (parts[2], parts[3])
        elif cmd == "n" and cid in clients:
            ip, port = clients[cid]
            nick = parts[2] if len(parts) >= 3 else ""
            if nick == "testnick":
                # Reject requested nick by forcing Guest001 before Done.
                out(f"f {cid} {ip} {port} Guest001")
                out(f"D {cid} {ip} {port}")
                clients.pop(cid, None)
            elif nick == "tmpuser":
                out(f"f {cid} {ip} {port} finaluser")
                out(f"D {cid} {ip} {port}")
                clients.pop(cid, None)
            elif nick.startswith("set_"):
                out(f"f {cid} {ip} {port} {nick[4:]}")
                out(f"D {cid} {ip} {port}")
                clients.pop(cid, None)
            elif nick.startswith("bad_"):
                out(f"f {cid} {ip} {port} {nick[4:]}")
                awaiting_retry[cid] = ("bad", ip, port)
            elif nick == "stuckbad":
                out(f"f {cid} {ip} {port} -invalid")
                out(f"D {cid} {ip} {port}")
                clients.pop(cid, None)
            elif nick == "collide":
                out(f"f {cid} {ip} {port} taken")
                awaiting_retry[cid] = ("collide", ip, port)
            else:
                out(f"D {cid} {ip} {port}")
                clients.pop(cid, None)
        elif cmd == "E" and cid in awaiting_retry:
            kind, ip, port = awaiting_retry.pop(cid)
            if kind == "bad":
                out(f"f {cid} {ip} {port} recovered")
            else:
                out(f"f {cid} {ip} {port} freenick")
            out(f"D {cid} {ip} {port}")
            clients.pop(cid, None)
        elif cmd == "D":
            clients.pop(cid, None)
            awaiting_retry.pop(cid, None)


if __name__ == "__main__":
    main()
