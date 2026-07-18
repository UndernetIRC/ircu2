"""Edge cases for PR #69: throttle exemption must track /rehash class changes.

Finding (#2 in review): the exemption is derived from GetMaxFlood(cptr), which
caches its result in cli_max_flood the first time it is resolved (at connect) and
is never reset on /rehash (only on /OPER, ircd/m_oper.c:198). The in-code comment
at ircd/s_bsd.c claims the flag is "re-checked each read so it tracks class
changes", but because the underlying GetMaxFlood value is frozen in the cache, an
already-connected client keeps FLAG_EXEMPT_THROTTLE even after an admin rehashes
its class's maxflood back down to the CLIENT_FLOOD default.

Operational impact: an operator cannot revoke throttle exemption from a live,
abusive client without disconnecting it. The fix invalidates the cached per-client
maxflood in rehash() so the exemption (and the recvQ ceiling, which shares the
cache) re-resolves from the updated class on the next read.

This test connects an Exempt-class client, confirms it is exempt, then lowers the
Exempt class maxflood to the default and /rehashes leaf1, and asserts the same
connected client is now throttled.

Requires modifying the running leaf1 config in-container and rehashing, so it is a
multi_server test that mutates and then restores shared state.
"""

import asyncio
import os
import subprocess

import pytest

from irc_client import IRCClient

pytestmark = pytest.mark.multi_server

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LEAF1_SERVICE = "ircd-leaf1"
LEAF1_CONF = "/opt/ircu/lib/ircd.conf"

# Mirror the constants from test_fix.py: a burst large enough that a throttled
# sender provably cannot deliver it all within the window, but an exempt one can.
BURST = 15
FAST_WINDOW = 4.0


def _exec_in_leaf1(*cmd):
    """Run a command inside the running leaf1 container."""
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", LEAF1_SERVICE, *cmd],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=REPO_ROOT,
        env=os.environ.copy(),
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"docker compose exec {' '.join(cmd)} failed:\n{result.stderr}"
        )
    return result


def _set_exempt_maxflood(value):
    """Rewrite the Exempt class maxflood in leaf1's on-disk config."""
    # The Exempt class is the only block with a maxflood line in this config.
    _exec_in_leaf1(
        "sed", "-i",
        f"s/maxflood = [0-9]*;/maxflood = {value};/",
        LEAF1_CONF,
    )


async def make_client_on(server, nick, port=None):
    client = IRCClient()
    await client.connect(server["host"], port or server["port"])
    await client.register(nick, "testuser", "Test User")
    return client


async def burst_privmsgs(sender, target_nick, count):
    for i in range(count):
        await sender.send(f"PRIVMSG {target_nick} :flood {i}")


async def count_privmsgs_within(recipient, sender_nick, expected, window):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + window
    count = 0
    while count < expected:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            msg = await recipient.recv(timeout=remaining)
        except (asyncio.TimeoutError, ConnectionError):
            break
        if (
            msg.command == "PRIVMSG"
            and msg.prefix
            and msg.prefix.split("!", 1)[0] == sender_nick
        ):
            count += 1
    return count


async def rehash_leaf1(oper):
    """OPER up on leaf1 and issue REHASH; wait for the rehash to be acknowledged."""
    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=5.0)  # RPL_YOUREOPER
    await oper.send("REHASH")
    await oper.wait_for("382", timeout=5.0)  # RPL_REHASHING
    # Give the daemon a beat to finish re-reading the config and invalidating caches.
    await asyncio.sleep(1.0)


async def cleanup(*clients):
    for client in clients:
        try:
            await client.send("QUIT :cleanup")
        except Exception:
            pass
        await client.disconnect()


async def test_rehash_revokes_exemption(ircd_network):
    """Lowering a class's maxflood via /rehash must throttle its live clients.

    Before the fix the connected client keeps its cached (exempt) maxflood after
    rehash, so it is still not throttled -> the final assertion fails.
    """
    leaf = ircd_network["leaf1"]
    recipient = await make_client_on(leaf, "rcpt69r")
    sender = await make_client_on(leaf, "exsnd69r", port=leaf["exempt_port"])
    oper = await make_client_on(leaf, "op69r")
    restored = False
    try:
        # Baseline: the sender is in the Exempt class, so the whole burst lands.
        await burst_privmsgs(sender, "rcpt69r", BURST)
        got = await count_privmsgs_within(recipient, "exsnd69r", BURST, FAST_WINDOW)
        assert got == BURST, (
            f"precondition failed: exempt sender should deliver all {BURST}, got {got}"
        )

        # Revoke the exemption: drop the Exempt class maxflood to the default and rehash.
        _set_exempt_maxflood(1024)
        await rehash_leaf1(oper)

        # The same, still-connected sender must now be throttled.
        await burst_privmsgs(sender, "rcpt69r", BURST)
        got = await count_privmsgs_within(recipient, "exsnd69r", BURST, FAST_WINDOW)
        assert got < BURST, (
            f"after /rehash lowering maxflood, sender should be throttled but "
            f"recipient got all {got}/{BURST} within {FAST_WINDOW}s "
            f"(exemption not re-resolved from the updated class)"
        )
    finally:
        # Restore the config so other tests in the session see the Exempt class again.
        try:
            _set_exempt_maxflood(262144)
            await rehash_leaf1(oper)
            restored = True
        except Exception:
            pass
        await cleanup(recipient, sender, oper)
        assert restored, "failed to restore leaf1 Exempt-class maxflood after test"
