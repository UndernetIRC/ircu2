"""Entry point for running BogusTLSServer inside a container.

Prints one JSON object per line on stdout so the test on the host can
follow what happened through `docker logs`:

  {"event": "listening", "port": N}
  {"event": "accepted"}
  {"event": "raw", "hex": "..."}     bytes received on the wire (silent /
                                     garbage / truncated modes)
  {"event": "line", "text": "..."}   decrypted application-data line
                                     (complete mode)
  {"event": "done"}
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys

from tls.bogus_peer import BogusTLSServer


def emit(**kw) -> None:
    sys.stdout.write(json.dumps(kw) + "\n")
    sys.stdout.flush()


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True)
    ap.add_argument("--port", type=int, default=4500)
    ap.add_argument("--truncate", type=int, default=200)
    ap.add_argument("--cert", default="tlspeer")
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--pre-delay", type=float, default=0.0)
    ap.add_argument("--chunk", type=int, default=0)
    ap.add_argument("--chunk-delay", type=float, default=0.0)
    args = ap.parse_args()

    # Each scenario replaces the container at the same address; announce the
    # new MAC so the hub's neighbour cache does not point at the old one.
    try:
        ip = subprocess.run(["hostname", "-i"], capture_output=True, text=True, timeout=5).stdout.split()[0]
        subprocess.run(["arping", "-c", "2", "-U", "-I", "eth0", ip], capture_output=True, timeout=10)
    except Exception:
        pass

    srv = BogusTLSServer(args.mode, cert=args.cert, truncate=args.truncate,
                         delay=args.delay, pre_delay=args.pre_delay,
                         chunk=args.chunk, chunk_delay=args.chunk_delay)
    srv.server = await asyncio.start_server(srv._handle, "0.0.0.0", args.port)
    srv.port = args.port
    emit(event="listening", port=args.port)

    async def report() -> None:
        raw_sent = 0
        lines_sent = 0
        accepted_sent = False
        while True:
            await asyncio.sleep(0.2)
            if srv.accepted.is_set() and not accepted_sent:
                accepted_sent = True
                emit(event="accepted")
            if len(srv.received_raw) > raw_sent:
                emit(event="raw", hex=bytes(srv.received_raw[raw_sent:]).hex())
                raw_sent = len(srv.received_raw)
            while lines_sent < len(srv.app_lines):
                emit(event="line", text=srv.app_lines[lines_sent])
                lines_sent += 1
            if srv.done.is_set():
                emit(event="done")
                return

    await report()
    # Keep serving (ircd may reconnect) until the container is removed.
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
