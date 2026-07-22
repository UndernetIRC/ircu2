#!/usr/bin/env python3
"""Minimal DNS server for ircu resolver integration tests.

Serves scripted UDP/TCP responses for client auth lookups and exposes a
small HTTP control API on port 8053 for pytest to switch scenarios.
"""

from __future__ import annotations

import asyncio
import os
import struct
from enum import Enum

T_A = 1
T_PTR = 12
T_AAAA = 28
C_IN = 1

DNS_PORT = 53
HTTP_PORT = 8053

CLIENT_IPV4 = os.environ.get("CLIENT_IPV4", "10.55.0.1")
AAAA_TARGET = os.environ.get("AAAA_TARGET", "fdaa:1:1::42")


class Scenario(str, Enum):
    OK_UDP = "ok_udp"
    TC_TCP = "tc_tcp"
    TC_TCP_FAIL = "tc_tcp_fail"
    MISMATCH = "mismatch"
    TC_HOLD = "tc_hold"
    TC_AAAA = "tc_aaaa"
    TC_AAAA_EMPTY = "tc_aaaa_empty"


class State:
    def __init__(self) -> None:
        self.scenario = Scenario.OK_UDP
        self.client_ipv4: str | None = None
        self.udp_queries = 0
        self.tcp_sessions = 0
        self.tcp_queries = 0
        self.tcp_aaaa_queries = 0
        self.a_fallback_queries = 0
        self.hold_tcp = False


STATE = State()


def ptr_to_ipv4(name: str) -> str | None:
    labels = name.rstrip(".").lower().split(".")
    if len(labels) < 3 or labels[-2:] != ["in-addr", "arpa"]:
        return None
    octets = labels[:-2]
    if len(octets) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in octets):
        return None
    return ".".join(reversed(octets))


def client_ipv4() -> str:
    return STATE.client_ipv4 or CLIENT_IPV4


def scenario_forward_ipv4() -> str:
    if STATE.scenario == Scenario.MISMATCH:
        parts = client_ipv4().split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.99"
    return client_ipv4()


def ipv4_to_ptr(ip: str) -> str:
    a, b, c, d = ip.split(".")
    return f"{d}.{c}.{b}.{a}.in-addr.arpa"


def scenario_ptr_name() -> str:
    return {
        Scenario.OK_UDP: "client.ok.test",
        Scenario.TC_TCP: "client.tc.test",
        Scenario.TC_TCP_FAIL: "client.tcfail.test",
        Scenario.MISMATCH: "client.bad.test",
        Scenario.TC_HOLD: "client.hold.test",
        Scenario.TC_AAAA: "client.ok.test",
        Scenario.TC_AAAA_EMPTY: "client.ok.test",
    }[STATE.scenario]


def encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        out.append(len(label))
        out.extend(label.encode("ascii"))
    out.append(0)
    return bytes(out)


def parse_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = offset
    while True:
        if offset >= len(packet):
            break
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:
            if offset + 1 >= len(packet):
                break
            ptr = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                end = offset + 2
            offset = ptr
            jumped = True
            continue
        offset += 1
        labels.append(packet[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), (end if jumped else offset)


def ipv4_to_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def ipv6_to_bytes(ip: str) -> bytes:
    import ipaddress

    return ipaddress.ip_address(ip).packed


def build_rr(name: str, rtype: int, rdata: bytes, ttl: int = 60) -> bytes:
    rr = encode_name(name)
    rr += struct.pack("!HHI", rtype, C_IN, ttl)
    rr += struct.pack("!H", len(rdata))
    rr += rdata
    return rr


def question_section(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    qdcount = struct.unpack("!H", query[4:6])[0]
    offset = 12
    start = offset
    for _ in range(qdcount):
        _, offset = parse_name(query, offset)
        offset += 4
    return query[start:offset]


def build_response(
    query: bytes,
    answers: list[bytes],
    *,
    tc: bool = False,
    rcode: int = 0,
) -> bytes:
    if len(query) < 12:
        return b""
    qdcount = struct.unpack("!H", query[4:6])[0]
    flags = 0x8400 | (rcode & 0xF)
    if tc:
        flags |= 0x0200
    header = query[:2] + struct.pack("!H", flags)
    header += struct.pack("!HHHH", qdcount, len(answers), 0, 0)
    return header + question_section(query) + b"".join(answers)


def answer_for_query(query: bytes, qname: str, qtype: int, transport: str) -> bytes | None:
    host = scenario_ptr_name()
    qname_norm = qname.rstrip(".").lower()

    if qtype == T_PTR:
        observed = ptr_to_ipv4(qname_norm)
        if observed is not None:
            STATE.client_ipv4 = observed
            return build_response(
                query,
                [build_rr(qname_norm, T_PTR, encode_name(host))],
                tc=False,
            )

    if qtype == T_A and qname_norm == host:
        if transport == "udp" and STATE.scenario in (
            Scenario.TC_TCP,
            Scenario.TC_TCP_FAIL,
            Scenario.TC_HOLD,
        ):
            return build_response(query, [], tc=True)
        if transport == "tcp":
            return build_response(
                query,
                [build_rr(host, T_A, ipv4_to_bytes(scenario_forward_ipv4()))],
                tc=False,
            )
        return build_response(
            query,
            [build_rr(host, T_A, ipv4_to_bytes(scenario_forward_ipv4()))],
            tc=False,
        )

    if qtype == T_AAAA and qname_norm in ("aaaa.tc.test", "aaaa.empty.test"):
        if transport == "udp" and STATE.scenario in (
            Scenario.TC_AAAA,
            Scenario.TC_AAAA_EMPTY,
        ):
            return build_response(query, [], tc=True)
        if transport == "tcp":
            STATE.tcp_aaaa_queries += 1
            if STATE.scenario == Scenario.TC_AAAA_EMPTY:
                # Complete, authoritative "no AAAA records" answer.
                return build_response(query, [], tc=False)
            return build_response(
                query,
                [build_rr(qname_norm, T_AAAA, ipv6_to_bytes(AAAA_TARGET))],
                tc=False,
            )

    if qtype == T_A and qname_norm in ("aaaa.tc.test", "aaaa.empty.test"):
        STATE.a_fallback_queries += 1
        return build_response(
            query,
            [build_rr(qname_norm, T_A, ipv4_to_bytes("10.55.0.99"))],
            tc=False,
        )

    return build_response(query, [], rcode=3)


def handle_query(query: bytes, transport: str) -> bytes | None:
    if len(query) < 12:
        return None
    qdcount = struct.unpack("!H", query[4:6])[0]
    if qdcount != 1:
        return build_response(query, [], rcode=1)
    offset = 12
    qname, offset = parse_name(query, offset)
    if offset + 4 > len(query):
        return build_response(query, [], rcode=1)
    qtype, qclass = struct.unpack("!HH", query[offset : offset + 4])
    if qclass != C_IN:
        return build_response(query, [], rcode=2)
    return answer_for_query(query, qname, qtype, transport)


class UDPProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        STATE.udp_queries += 1
        response = handle_query(data, "udp")
        if response:
            self.transport.sendto(response, addr)


async def tcp_client_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    STATE.tcp_sessions += 1
    try:
        if STATE.scenario == Scenario.TC_TCP_FAIL:
            return
        len_bytes = await reader.readexactly(2)
        msg_len = struct.unpack("!H", len_bytes)[0]
        query = await reader.readexactly(msg_len)
        STATE.tcp_queries += 1
        if STATE.scenario == Scenario.TC_HOLD and STATE.hold_tcp:
            await asyncio.sleep(3600)
            return
        response = handle_query(query, "tcp")
        if not response:
            return
        writer.write(struct.pack("!H", len(response)) + response)
        await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        return
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        request_line = (await reader.readline()).decode("ascii", "replace").strip()
        if not request_line:
            return
        parts = request_line.split()
        method = parts[0]
        path = parts[1] if len(parts) > 1 else "/"
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break

        body = b""
        status = "200 OK"
        if method == "GET" and path == "/stats":
            body = (
                f'{{"scenario":"{STATE.scenario.value}","client_ipv4":"{client_ipv4()}",'
                f'"observed_client_ipv4":"{STATE.client_ipv4 or ""}",'
                f'"udp_queries":{STATE.udp_queries},'
                f'"tcp_sessions":{STATE.tcp_sessions},"tcp_queries":{STATE.tcp_queries},'
                f'"tcp_aaaa_queries":{STATE.tcp_aaaa_queries},'
                f'"a_fallback_queries":{STATE.a_fallback_queries}}}\n'
            ).encode()
        elif method == "POST" and path.startswith("/scenario/"):
            name = path.split("/", 2)[2]
            STATE.scenario = Scenario(name)
            STATE.hold_tcp = STATE.scenario == Scenario.TC_HOLD
            body = b'{"ok":true}\n'
        elif method == "POST" and path == "/reset":
            STATE.udp_queries = 0
            STATE.tcp_sessions = 0
            STATE.tcp_queries = 0
            STATE.tcp_aaaa_queries = 0
            STATE.a_fallback_queries = 0
            STATE.client_ipv4 = None
            STATE.hold_tcp = STATE.scenario == Scenario.TC_HOLD
            body = b'{"ok":true}\n'
        else:
            status = "404 Not Found"
            body = b'{"error":"not found"}\n'

        response = (
            f"HTTP/1.1 {status}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode() + body
        writer.write(response)
        await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def main() -> None:
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(UDPProtocol, local_addr=("0.0.0.0", DNS_PORT))
    tcp_server = await asyncio.start_server(tcp_client_handler, "0.0.0.0", DNS_PORT)
    http_server = await asyncio.start_server(handle_http, "0.0.0.0", HTTP_PORT)
    print(
        f"dns_test_server: CLIENT_IPV4={CLIENT_IPV4} AAAA_TARGET={AAAA_TARGET}",
        flush=True,
    )
    async with tcp_server, http_server:
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
