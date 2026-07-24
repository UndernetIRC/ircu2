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
from p10_server import P10Server

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
    "spoof_port": 6672,
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


# ---------------------------------------------------------------------------
# Docker topology management
#
# All docker fixtures share one compose project, and every topology start is
# destructive: _start_services() begins with `docker compose down`, so
# bringing up one topology kills the containers of every other. Plain
# session-scoped fixtures therefore break as soon as topologies interleave —
# a cached fixture would describe containers that a later fixture's setup
# already tore down.
#
# Topology state is managed explicitly instead:
#   * the ircd_* fixtures below only return connection info (host/port dicts)
#   * the autouse _ircd_topology fixture inspects which ircd_* fixtures a
#     test (transitively) uses and (re)starts the matching topology, but only
#     when the currently running topology does not satisfy it
#   * pytest_collection_modifyitems groups tests by topology so each
#     topology normally goes through a single up/down cycle per run
#
# Correctness never depends on test/collection order; grouping is purely a
# docker-cycle optimization.
# ---------------------------------------------------------------------------


def _wait_tls_hub_ports():
    wait_for_port(TLS_HUB["host"], TLS_HUB["port"])
    wait_for_port(TLS_HUB["host"], TLS_HUB["tls_port"])
    wait_for_port(TLS_HUB["host"], TLS_HUB["wss_port"])
    wait_for_port(TLS_HUB["host"], TLS_HUB["server_port"])


def _start_topology_hub():
    _start_services("ircd-hub")
    wait_for_hub_ports(HUB["host"])


def _start_topology_network():
    _start_services()
    for server in (HUB, LEAF1, LEAF2):
        wait_for_port(server["host"], server["port"])
    # Wait for servers to link
    time.sleep(3)


def _start_topology_tls_network():
    _start_services("ircd-tls-hub", "ircd-tls-leaf")
    _wait_tls_hub_ports()
    wait_for_port(TLS_LEAF["host"], TLS_LEAF["server_port"])
    # Allow autoconnect TLS links hub <-> tls-leaf
    time.sleep(20)


def _start_topology_tls_hub():
    _start_services("ircd-tls-hub")
    _wait_tls_hub_ports()
    # Ident lookups during registration can take a moment on cold start.
    time.sleep(2)


def _start_topology_limits():
    _start_services("ircd-limits")
    wait_for_port(LIMITS["host"], LIMITS["port"])
    # Ident lookups during registration can take a moment on cold start.
    time.sleep(2)


def _start_topology_dns():
    from pr81_dns_tcp.helpers import reset_stats, set_scenario, wait_for_dns_control

    _start_dns_services("ircd-dns-hub")
    wait_for_dns_control()
    wait_for_port(DNS_HUB["host"], DNS_HUB["port"])
    time.sleep(2)
    set_scenario("ok_udp")
    reset_stats()


_TOPOLOGIES = {
    "hub": _start_topology_hub,
    "network": _start_topology_network,
    "tls_network": _start_topology_tls_network,
    "tls_hub": _start_topology_tls_hub,
    "limits": _start_topology_limits,
    "dns": _start_topology_dns,
}

# A running topology satisfies a required one iff listed here. "network"
# is a superset of "hub" (same hub service plus the leaves); everything
# else is mutually exclusive. Note that "tls_hub" is NOT satisfied by
# "tls_network": standalone secure-path tests require a hub that no leaf
# has ever linked to.
_SATISFIED_BY = {
    "hub": {"hub", "network"},
    "network": {"network"},
    "tls_network": {"tls_network"},
    "tls_hub": {"tls_hub"},
    "limits": {"limits"},
    "dns": {"dns"},
}

_FIXTURE_TOPOLOGY = {
    "ircd_hub": "hub",
    "ircd_network": "network",
    "ircd_tls_network": "tls_network",
    "ircd_tls_hub": "tls_hub",
    "ircd_limits": "limits",
    "ircd_dns_hub": "dns",
}

# Collection order: tests with no docker dependency first, then one
# contiguous block per topology. "network" runs before "hub" so hub-only
# tests reuse the already-running network (see _SATISFIED_BY).
_TOPOLOGY_ORDER = ["network", "hub", "limits", "dns", "tls_network", "tls_hub"]

_active_topology = None


def _required_topology(fixturenames):
    """Topology a test needs, derived from its (transitive) fixture closure."""
    required = {
        _FIXTURE_TOPOLOGY[name]
        for name in fixturenames
        if name in _FIXTURE_TOPOLOGY
    }
    if "network" in required:
        required.discard("hub")
    if len(required) > 1:
        raise RuntimeError(
            "test requires mutually exclusive docker topologies: "
            f"{sorted(required)}"
        )
    return required.pop() if required else None


def _ensure_topology(name):
    global _active_topology
    if _active_topology in _SATISFIED_BY[name]:
        return
    # The starter begins by tearing everything down; forget the old
    # topology first so a failed start is not mistaken for it still
    # running when the next test retries.
    _active_topology = None
    _TOPOLOGIES[name]()
    _active_topology = name


@pytest.fixture(autouse=True)
def _ircd_topology(request):
    """Bring up the docker topology the current test needs.

    Autouse and function-scoped, so it runs before the test's other
    function-scoped fixtures (make_client, limits_oper, ...) connect to
    the server — even right after a topology switch.
    """
    required = _required_topology(request.fixturenames)
    if required:
        _ensure_topology(required)


@pytest.fixture(scope="session", autouse=True)
def _docker_teardown():
    """Tear all containers down once at the end of the session."""
    yield
    if _active_topology is not None:
        docker_compose("down", "--remove-orphans", check=False)


def pytest_collection_modifyitems(config, items):
    """Group tests into one contiguous block per docker topology.

    Correctness does not depend on this (_ircd_topology restarts topologies
    on demand), but grouping keeps each topology to a single docker
    up/down cycle per run. The sort is stable: relative order within a
    topology group is unchanged.
    """
    def sort_key(item):
        try:
            required = _required_topology(getattr(item, "fixturenames", ()))
        except RuntimeError:
            # Impossible topology mix: let _ircd_topology fail the test
            # with a clear message instead of aborting collection.
            return len(_TOPOLOGY_ORDER) + 1
        if required is None:
            return 0
        return 1 + _TOPOLOGY_ORDER.index(required)

    items.sort(key=sort_key)


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
    """Connection info for the hub ircd.

    The container lifecycle is handled by _ircd_topology, which always
    rebuilds the image from the current working tree.
    """
    return HUB


@pytest.fixture(scope="session")
def ircd_network():
    """Connection info for all three ircd containers (hub + 2 leaves)."""
    return {"hub": HUB, "leaf1": LEAF1, "leaf2": LEAF2}


@pytest.fixture(scope="session")
def ircd_tls_hub():
    """Connection info for the standalone TLS hub — no peer server ever links.

    Use this for standalone secure-path coverage: compute_secure_path_groups()
    must run at boot, because link/SQUIT never fires on a lone server.
    _ircd_topology guarantees a fresh hub that no leaf has connected to.
    """
    return TLS_HUB


@pytest.fixture(scope="session")
def ircd_tls_network():
    """Connection info for the TLS-enabled hub and leaf containers."""
    return {"hub": TLS_HUB, "leaf": TLS_LEAF}


@pytest.fixture(scope="session")
def ircd_limits():
    """Connection info for the dedicated limits-test ircd."""
    return LIMITS


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
    """Connection info for test-dns and the DNS-enabled hub."""
    return DNS_HUB


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


@pytest_asyncio.fixture
async def ulined_server(ircd_hub):
    """A U:lined P10 server linked to the hub.

    U:lined as "services.test.net", matching the UWorld block in ircd-hub.conf,
    so it can send traffic that only a U:lined server may, e.g. ACCOUNT.
    """
    srv = P10Server(name="services.test.net", numeric=4, password="testpass")
    await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
    await srv.handshake()
    yield srv
    await srv.disconnect()
