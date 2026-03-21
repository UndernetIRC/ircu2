# ircu2 Test Harness

Python-based integration test suite for ircu2 using Docker and pytest.

## Prerequisites

- Docker and Docker Compose
- Python 3.10+
- [uv](https://docs.astral.sh/uv/)

## Setup

```bash
uv sync
```

## Running Tests

```bash
# All tests (starts Docker containers automatically)
uv run pytest tests/

# Specific PR tests
uv run pytest tests/pr59_part_messages/
uv run pytest tests/pr61_uhnames/

# Only unit tests (no Docker needed)
uv run pytest tests/test_irc_client.py

# By marker
uv run pytest -m single_server    # tests needing only the hub
uv run pytest -m multi_server     # tests needing hub + 2 leaves

# Verbose with output
uv run pytest tests/ -v -s --timeout=60
```

## Test Organization

Each PR has its own directory under `tests/`:

```
tests/
  irc_client.py          # Async IRC client for client-level testing
  p10_server.py          # Fake P10 server for server-to-server testing
  conftest.py            # pytest fixtures (ircd_hub, ircd_network, make_client)
  pr59_part_messages/
    test_fix.py          # TDD: reproduces the exact bug the PR fixes
    test_edge_cases.py   # Adversarial: tries to break the implementation
  pr61_uhnames/
    test_fix.py
    test_edge_cases.py
  pr62_remote_x/
    test_fix.py          # S2S tests using P10Server for OPMODE +x and ACCOUNT
    test_edge_cases.py
```

- **test_fix.py** — focused tests that reproduce the bug or verify the feature claimed by the PR. These fail on the base branch and pass with the PR applied.
- **test_edge_cases.py** — adversarial tests that exercise boundary conditions, invalid inputs, and feature interactions. Tests that depend on the PR feature use `pytest.skip()` when it's not available.

## Docker Topology

Three ircd servers form a test network:

| Service    | Server Name    | Client Port | Server Port | Numeric |
|------------|----------------|-------------|-------------|---------|
| ircd-hub   | hub.test.net   | 6667        | 4400        | 1       |
| ircd-leaf1 | leaf1.test.net | 6668        | 4401        | 2       |
| ircd-leaf2 | leaf2.test.net | 6669        | 4402        | 3       |

The hub is a HUB server. Leaves autoconnect to the hub. All servers have `NODNS` enabled for fast client registration.

Operator credentials: name `testoper`, password `operpass`.

The hub also has Connect blocks for two external test servers used by the P10 test harness:

| Server              | Numeric | U:lined | Purpose                          |
|---------------------|---------|---------|----------------------------------|
| services.test.net   | 4       | Yes     | Fake services for S2S testing    |
| notulined.test.net  | 5       | No      | Non-U:lined server for rejection tests |

Configs are baked into the Docker images (in `tests/docker/`), not volume-mounted.

## IRC Client API

`tests/irc_client.py` provides `IRCClient` — a minimal async IRC client:

```python
from tests.irc_client import IRCClient

client = IRCClient()
await client.connect("127.0.0.1", 6667)
await client.register("nick", "user", "Real Name")

# CAP negotiation (must be called BEFORE register)
acked = await client.negotiate_cap(["userhost-in-names"])

# Send raw IRC commands
await client.send("JOIN #channel")

# Wait for a specific server response
msg = await client.wait_for("366")  # RPL_ENDOFNAMES

# Collect messages until a terminator
msgs = await client.collect_until("366")

# Send and wait for response
msg = await client.send_and_expect("NAMES #channel", "366")
```

`Message` is a namedtuple: `Message(prefix, command, params)`.

## P10 Server API

`tests/p10_server.py` provides `P10Server` — a fake IRC server that connects to ircd on its server port and speaks the P10 protocol. This enables testing server-to-server behavior (OPMODE, ACCOUNT, etc.) that can't be triggered from client connections.

```python
from tests.p10_server import P10Server

srv = P10Server("services.test.net", numeric=4, password="testpass")
await srv.connect("127.0.0.1", 4400)
await srv.handshake()

# Wait for a user to appear (registered after handshake)
numnick = await srv.wait_for_user("somenick")

# Send S2S commands
await srv.send_account(numnick, "AccountName")
await srv.send_opmode(numnick, "+x")

# Read server responses
await srv.drain_messages()

await srv.disconnect()
```

The P10 server handles the full handshake (PASS, SERVER, burst, EB/EA), auto-responds to PINGs, and tracks users by parsing NICK messages. It requires a matching Connect block in the hub config.

## pytest Fixtures

- **`ircd_hub`** (session) — starts the hub container, yields connection info
- **`ircd_network`** (session) — starts all 3 containers, waits for linking
- **`make_client`** (function) — factory for connected+registered IRC clients:
  ```python
  client = await make_client("mynick")
  client = await make_client("mynick", host="127.0.0.1", port=6668)
  ```

## Writing Tests for a New PR

1. Create `tests/pr<N>_<short_name>/`
2. Add `__init__.py`
3. Write `test_fix.py` — reproduce the bug/feature
4. Write `test_edge_cases.py` — try to break it
5. Use `@pytest.mark.single_server` or `@pytest.mark.multi_server`
6. For S2S protocol tests, use `P10Server` to connect as a fake server
7. Use the `/ircu2-test` Claude skill for automated test generation

## Troubleshooting

```bash
# View server logs
docker compose logs ircd-hub
docker compose logs ircd-leaf1

# Rebuild containers (after code changes)
docker compose build --no-cache

# Manual connection for debugging
docker compose up -d ircd-hub
nc 127.0.0.1 6667

# Stop everything
docker compose down
```
