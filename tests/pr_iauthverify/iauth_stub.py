#!/usr/bin/env python3
"""IAuth stub for testing the ircd->iauth message stream.

Logs every line received from the ircd to the file given as argv[1]
and approves every client as soon as its nickname is announced.
"""

import sys


def main():
    logf = open(sys.argv[1], "a", buffering=1)

    def out(line):
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    # R: iauth is required; U: enable Undernet extensions (U/u/n/H/T).
    out("O RU")

    clients = {}
    for line in sys.stdin:
        line = line.rstrip("\r\n")
        logf.write(line + "\n")
        parts = line.split(" ")
        if len(parts) < 2:
            continue
        cid, cmd = parts[0], parts[1]
        if cmd == "C" and len(parts) >= 4:
            # "<id> C <ip> <port> ..." -- new client
            clients[cid] = (parts[2], parts[3])
        elif cmd == "n" and cid in clients:
            # Nickname announced: approve the client.
            ip, port = clients[cid]
            out(f"D {cid} {ip} {port}")
        elif cmd == "D":
            clients.pop(cid, None)


if __name__ == "__main__":
    main()
