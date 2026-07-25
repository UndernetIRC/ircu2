"""CAP command stress and concurrency tests."""

from __future__ import annotations

import asyncio

import pytest

from irc_client import IRCClient

pytestmark = pytest.mark.single_server

STANDARD_CAPS = [
    "account-notify",
    "away-notify",
    "chghost",
    "echo-message",
    "extended-join",
    "invite-notify",
    "userhost-in-names",
    "message-tags",
    "server-time",
    "account-tag",
]


async def _collect_cap_ls(client: IRCClient, timeout: float = 8.0) -> list[str]:
    tokens: list[str] = []
    while True:
        msg = await client.wait_for("CAP", timeout=timeout)
        assert msg.params[1] == "LS", msg.raw
        tokens.extend(msg.params[-1].split())
        if len(msg.params) < 4 or msg.params[2] != "*":
            return tokens


async def _rapid_req_list(host: str, port: int, nick: str, rounds: int = 40) -> None:
    """Stress REQ/LIST after registration (avoids CAP-pending auth timeouts)."""
    from cap_helpers import make_cap_client

    client = await make_cap_client(host, port, nick, caps=["account-notify"])
    try:
        await client.send("CAP LS 302")
        offered = {
            t.split("=", 1)[0] for t in await _collect_cap_ls(client)
        }
        want = [c for c in STANDARD_CAPS if c in offered]
        assert want, f"No standard caps offered: {offered}"
        subset = want[:3]

        for i in range(rounds):
            if i % 2 == 0:
                await client.send(f"CAP REQ :{' '.join(subset)}")
            else:
                await client.send(f"CAP REQ :-{subset[0]}")
            msg = await client.wait_for("CAP", timeout=5.0)
            assert msg.params[1] in ("ACK", "NAK"), msg.raw
            if i % 7 == 0:
                await client.send("CAP LIST")
                listing = await client.wait_for("CAP", timeout=5.0)
                assert listing.params[1] == "LIST"
            await asyncio.sleep(0.03)

        await client.send("PING :cap-rapid-done")
        pong = await client.wait_for("PONG", timeout=5.0)
        assert "cap-rapid-done" in (pong.params[-1] if pong.params else "")
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()


async def test_rapid_cap_ls_req_list_cycle(ircd_hub):
    """Many post-registration REQ/LIST cycles must not desync or crash."""
    await _rapid_req_list(ircd_hub["host"], ircd_hub["port"], "caprapid1", rounds=40)


async def test_concurrent_cap_negotiations(ircd_hub):
    """Dozens of clients negotiating CAP in parallel must all register."""
    hub = ircd_hub
    n = 25

    async def one(i: int) -> None:
        client = IRCClient()
        await client.connect(hub["host"], hub["port"])
        try:
            await client.send("CAP LS 302")
            await _collect_cap_ls(client)
            subset = STANDARD_CAPS[i % len(STANDARD_CAPS) :][:4] or STANDARD_CAPS[:2]
            await client.send(f"CAP REQ :{' '.join(subset)}")
            ack = await client.wait_for("CAP", timeout=8.0)
            assert ack.params[1] == "ACK", ack.raw
            await client.send("CAP END")
            nick = f"capc{i:02d}"
            await client.send(f"NICK {nick}")
            await client.send(f"USER u{i} 0 * :c{i}")
            await client.wait_for("001", timeout=20.0)
        finally:
            try:
                await client.send("QUIT :done")
            except Exception:
                pass
            await client.disconnect()

    await asyncio.gather(*(one(i) for i in range(n)))


async def test_oversized_req_line_with_junk_caps(ircd_hub):
    """Long REQ packed with junk names must NAK without hanging."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await _collect_cap_ls(client)
        # Stay under ~512 IRC line length while packing many unknown tokens
        junk = " ".join(f"fc{i}" for i in range(40))
        line = f"CAP REQ :account-notify {junk}"
        assert len(line) < 500, len(line)
        await client.send(line)
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "NAK"
        await client.send("CAP REQ :account-notify")
        ack = await client.wait_for("CAP", timeout=5.0)
        assert ack.params[1] == "ACK"
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_burst_cap_ls_without_end_then_recover(ircd_hub):
    """Burst CAP LS while pending; CAP END must still complete registration.

    Interleave send/drain so CLIENT_FLOOD (default 1024) does not kill the
    connection when replies are large.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        drained = 0
        for _ in range(20):
            await client.send("CAP LS 302")
            msg = await client.wait_for("CAP", timeout=5.0)
            # Drain continuation lines if any
            while msg.params[1] == "LS" and len(msg.params) >= 4 and msg.params[2] == "*":
                msg = await client.wait_for("CAP", timeout=5.0)
            assert msg.params[1] == "LS", msg.raw
            drained += 1
            await asyncio.sleep(0.01)
        assert drained == 20

        await client.send("NICK capflood1")
        await client.send("USER flood 0 * :flood")
        await client.send("CAP END")
        await client.wait_for("001", timeout=15.0)
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_all_standard_caps_ack_in_one_req(ircd_hub):
    """Requesting every always-on CAP in one REQ should ACK the full set."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        offered = {
            t.split("=", 1)[0] for t in await _collect_cap_ls(client)
        }
        want = [c for c in STANDARD_CAPS if c in offered]
        assert want, f"No standard caps offered: {offered}"
        await client.send(f"CAP REQ :{' '.join(want)}")
        ack = await client.wait_for("CAP", timeout=5.0)
        assert ack.params[1] == "ACK"
        got = set(ack.params[-1].split())
        assert set(want) <= got, f"ACK missing caps: want={want} got={got}"

        await client.send("CAP LIST")
        listing = await client.wait_for("CAP", timeout=5.0)
        listed = set(listing.params[-1].split())
        assert set(want) <= listed
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_interleaved_commands_during_negotiation(ircd_hub):
    """Unregistered PING (451) interleaved with CAP traffic must still round-trip."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.send("PING :mid-ls")
        saw_ls = False
        saw_451 = False
        deadline = asyncio.get_running_loop().time() + 8.0
        while (not saw_ls or not saw_451) and asyncio.get_running_loop().time() < deadline:
            msg = await client.recv(timeout=3.0)
            if msg.command == "CAP" and msg.params[1] == "LS":
                if len(msg.params) < 4 or msg.params[2] != "*":
                    saw_ls = True
            if msg.command == "451":
                saw_451 = True
        assert saw_ls and saw_451, f"saw_ls={saw_ls} saw_451={saw_451}"

        await client.send("CAP REQ :message-tags")
        await client.send("PING :mid-req")
        saw_ack = saw_451 = False
        deadline = asyncio.get_running_loop().time() + 8.0
        while (not saw_ack or not saw_451) and asyncio.get_running_loop().time() < deadline:
            msg = await client.recv(timeout=3.0)
            if msg.command == "CAP" and msg.params[1] in ("ACK", "NAK"):
                saw_ack = True
            if msg.command == "451":
                saw_451 = True
        assert saw_ack and saw_451, f"saw_ack={saw_ack} saw_451={saw_451}"
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()
