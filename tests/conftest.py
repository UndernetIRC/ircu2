"""pytest fixtures for ircu2 integration testing."""

import os
import subprocess
import time

import pytest
import pytest_asyncio

from debug_support import (
    compose_env,
    debug_mode,
    format_failure_report,
    prepare_debug_session,
    snapshot_failure_artifacts,
)
from irc_client import IRCClient

# docker-compose.yml and Dockerfile live in the repo root (parent of tests/)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HUB = {"host": "127.0.0.1", "port": 6667, "server_port": 4400, "name": "hub.test.net"}
LEAF1 = {"host": "127.0.0.1", "port": 6668, "server_port": 4401, "name": "leaf1.test.net", "exempt_port": 6690}
LEAF2 = {"host": "127.0.0.1", "port": 6669, "server_port": 4402, "name": "leaf2.test.net"}

TLS_HUB = {
    "host": "127.0.0.1",
    "port": 16677,
    "tls_port": 16697,
    "tls_port_alt": 16698,
    "wss_port": 16700,
    "wss_cf_port": 16701,
    "server_port": 14440,
    "server_tls_ca_port": 14441,
    "name": "tls-hub.test.net",
}
TLS_LEAF = {
    "host": "127.0.0.1",
    "port": 16678,
    "tls_port": 16680,
    "server_port": 14411,
    "server_tls_ca_port": 14412,
    "name": "tls-leaf.test.net",
}

DNS_HUB = {
    "host": "127.0.0.1",
    "port": 6671,
    "name": "dns-hub.test.net",
    "dns_control_port": 8053,
}


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


def wait_for_hub_ports(host: str | None = None):
    """Wait until the test hub IRC and WebSocket ports accept connections."""
    host = host or HUB["host"]
    wait_for_port(host, HUB["port"])
    wait_for_port(host, 7000)
    wait_for_port(host, 7001)
    # Ident lookups during registration can take several seconds on a cold start.
    time.sleep(2)


def docker_compose(*args, check=True):
    """Run a docker compose command from the repo root."""
    result = subprocess.run(
        ["docker", "compose"] + list(args),
        capture_output=True,
        text=True,
        timeout=600,
        cwd=REPO_ROOT,
        env=compose_env(),
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"docker compose {' '.join(args)} failed:\n{result.stderr}"
        )
    return result


LIMITS = {
    "host": "127.0.0.1",
    "port": 6670,
    "server_port": 4410,
    "name": "limits.test.net",
}


def _start_services(*services):
    """Stop any running containers, rebuild, and start fresh."""
    prepare_debug_session()
    docker_compose("down", check=False)
    args = ["up", "--build", "--force-recreate", "-d"]
    args.extend(services)
    docker_compose(*args)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """On test failure, snapshot docker/gdb/valgrind output into debug-output/."""
    outcome = yield
    report = outcome.get_result()
    if report.when != "call" or not report.failed:
        return
    snapshot = snapshot_failure_artifacts(item.nodeid)
    extra = format_failure_report(snapshot)
    if extra:
        report.longrepr = f"{report.longrepr}{extra}"


def pytest_report_header(config):
    mode = debug_mode()
    if mode:
        return [f"ircd debug mode: IRCD_DEBUG={mode}"]
    return []


@pytest.fixture(scope="session")
def ircd_hub():
    """Start the hub ircd container. Session-scoped — shared across all tests.

    Always rebuilds the image from the current working tree to ensure
    the test runs against the checked-out code.
    """
    _start_services("ircd-hub")
    try:
        wait_for_hub_ports(HUB["host"])
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


@pytest.fixture(scope="session")
def ircd_tls_network():
    """Start TLS-enabled hub and leaf containers. Session-scoped."""
    docker_compose("down", check=False)
    _start_services("ircd-tls-hub", "ircd-tls-leaf")
    try:
        wait_for_port(TLS_HUB["host"], TLS_HUB["port"])
        wait_for_port(TLS_HUB["host"], TLS_HUB["tls_port"])
        wait_for_port(TLS_HUB["host"], TLS_HUB["wss_port"])
        wait_for_port(TLS_HUB["host"], TLS_HUB["server_port"])
        wait_for_port(TLS_LEAF["host"], TLS_LEAF["server_port"])
        # Allow autoconnect TLS links hub <-> tls-leaf
        time.sleep(20)
        yield {"hub": TLS_HUB, "leaf": TLS_LEAF}
    finally:
        docker_compose("down", check=False)


@pytest.fixture(scope="session")
def ircd_limits():
    """Start the dedicated limits-test ircd with a volume-mounted config."""
    _start_services("ircd-limits")
    try:
        wait_for_port(LIMITS["host"], LIMITS["port"])
        # Ident lookups during registration can take a moment on cold start.
        time.sleep(2)
        yield LIMITS
    finally:
        docker_compose("down", check=False)


@pytest.fixture(scope="session")
def limits_config_snapshot():
    """Pristine limits config text, restored into the container at session end."""
    from class_limits.helpers import read_config, restore_config

    snapshot = read_config()
    yield snapshot
    try:
        restore_config(snapshot)
    except Exception:
        pass  # container may already be gone at session teardown


@pytest_asyncio.fixture
async def limits_oper(ircd_limits):
    """Connected global operator on the limits test server."""
    from class_limits.helpers import make_oper

    oper = await make_oper(ircd_limits)
    yield oper
    try:
        await oper.send("QUIT :test cleanup")
    except Exception:
        pass
    await oper.disconnect()


@pytest_asyncio.fixture
async def limits_services(ircd_limits):
    """UWorld-capable P10 services server for remote oper tests."""
    from p10_server import P10Server

    srv = P10Server(
        name="services.test.net",
        numeric=4,
        password="testpass",
    )
    await srv.connect(ircd_limits["host"], ircd_limits["server_port"])
    await srv.handshake()
    yield srv
    await srv.disconnect()


@pytest_asyncio.fixture
async def make_limits_client(ircd_limits):
    """Factory for registered clients on the limits test server."""
    clients: list[IRCClient] = []

    async def _make(
        nick: str,
        username: str = "testuser",
        realname: str = "Test User",
    ) -> IRCClient:
        client = IRCClient()
        await client.connect(ircd_limits["host"], ircd_limits["port"])
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


def _start_dns_services(*ircd_services: str):
    """Start test-dns and selected ircd DNS test containers."""
    from pr81_dns_tcp.helpers import reset_stats, set_scenario, wait_for_dns_control

    prepare_debug_session()
    docker_compose("down", "--remove-orphans", check=False)
    docker_compose("up", "--build", "--force-recreate", "-d", "test-dns")
    wait_for_dns_control()
    set_scenario("ok_udp")
    reset_stats()
    docker_compose("up", "--build", "--force-recreate", "-d", *ircd_services)


@pytest.fixture(scope="session")
def ircd_dns_hub():
    """Start test-dns and the DNS-enabled hub for resolver integration tests."""
    from pr81_dns_tcp.helpers import reset_stats, set_scenario, wait_for_dns_control

    _start_dns_services("ircd-dns-hub")
    try:
        wait_for_dns_control()
        wait_for_port(DNS_HUB["host"], DNS_HUB["port"])
        time.sleep(2)
        set_scenario("ok_udp")
        reset_stats()
        yield DNS_HUB
    finally:
        docker_compose("down", "--remove-orphans", check=False)


@pytest.fixture
def dns_control():
    """Switch DNS server scenario and reset per-test counters."""
    from pr81_dns_tcp.helpers import reset_stats, set_scenario

    def _set(name: str) -> None:
        set_scenario(name)
        reset_stats()

    return _set


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
