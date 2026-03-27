"""pytest fixtures for ircu2 integration testing."""

import os
import subprocess
import time

import pytest
import pytest_asyncio

from irc_client import IRCClient

# docker-compose.yml and Dockerfile live in the repo root (parent of tests/)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def wait_for_port(host: str, port: int, timeout: float = 30.0):
    """Block until a TCP port is accepting connections."""
    import socket

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except (ConnectionRefusedError, OSError):
            time.sleep(0.5)
    raise TimeoutError(f"Port {host}:{port} not ready after {timeout}s")


def docker_compose(*args, check=True):
    """Run a docker compose command from the repo root."""
    result = subprocess.run(
        ["docker", "compose"] + list(args),
        capture_output=True,
        text=True,
        timeout=600,
        cwd=REPO_ROOT,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"docker compose {' '.join(args)} failed:\n{result.stderr}"
        )
    return result


HUB = {"host": "127.0.0.1", "port": 6667, "server_port": 4400, "name": "hub.test.net"}
LEAF1 = {"host": "127.0.0.1", "port": 6668, "server_port": 4401, "name": "leaf1.test.net"}
LEAF2 = {"host": "127.0.0.1", "port": 6669, "server_port": 4402, "name": "leaf2.test.net"}


def _start_services(*services):
    """Stop any running containers, rebuild, and start fresh."""
    docker_compose("down", check=False)
    args = ["up", "--build", "--force-recreate", "-d"]
    args.extend(services)
    docker_compose(*args)


@pytest.fixture(scope="session")
def ircd_hub():
    """Start the hub ircd container. Session-scoped — shared across all tests.

    Always rebuilds the image from the current working tree to ensure
    the test runs against the checked-out code.
    """
    _start_services("ircd-hub")
    try:
        wait_for_port(HUB["host"], HUB["port"])
        yield HUB
    finally:
        docker_compose("down", check=False)


@pytest.fixture(scope="session")
def ircd_network():
    """Start all three ircd containers (hub + 2 leaves). Session-scoped.

    Always rebuilds from the current working tree.
    """
    _start_services()
    try:
        for server in (HUB, LEAF1, LEAF2):
            wait_for_port(server["host"], server["port"])
        # Wait for servers to link
        time.sleep(3)
        yield {"hub": HUB, "leaf1": LEAF1, "leaf2": LEAF2}
    finally:
        docker_compose("down", check=False)


@pytest_asyncio.fixture
async def make_client(ircd_hub):
    """Factory fixture that creates connected and registered IRC clients.

    Usage:
        client = await make_client("mynick")
        # or with custom server:
        client = await make_client("mynick", host="127.0.0.1", port=6668)
    """
    clients: list[IRCClient] = []

    async def _make(
        nick: str,
        username: str = "testuser",
        realname: str = "Test User",
        host: str | None = None,
        port: int | None = None,
    ) -> IRCClient:
        client = IRCClient()
        await client.connect(host or ircd_hub["host"], port or ircd_hub["port"])
        await client.register(nick, username, realname)
        clients.append(client)
        return client

    yield _make

    for client in clients:
        try:
            await client.send("QUIT :test cleanup")
        except Exception:
            pass
        await client.disconnect()
