# ircu2 Test Harness

Python-based integration test suite for ircu2 using Docker and pytest.

## Prerequisites

- Docker and Docker Compose
- Python 3.10+
- [uv](https://docs.astral.sh/uv/)

## Setup

```bash
cd tests
uv sync
```

## Running Tests

All commands are run from the `tests/` directory:

```bash
cd tests

# All tests (starts Docker containers automatically)
uv run pytest

# Specific PR tests
uv run pytest pr59_part_messages/
uv run pytest pr61_uhnames/

# Only unit tests (no Docker needed)
uv run pytest test_irc_client.py

# By marker
uv run pytest -m single_server    # tests needing only the hub
uv run pytest -m multi_server     # tests needing hub + 2 leaves
uv run pytest -m tls              # TLS trust / verification tests (hub + TLS leaf)
uv run pytest -m tls_single       # standalone TLS hub (no peer server ever links)
uv run pytest -m nf_compat        # A(prod)-B(NF=FALSE)-C topology

# TLS suite only
uv run pytest tls/ -v

# NETWORK_FEATURES rolling-upgrade compat (downloads prod release on first build)
uv run pytest pr_network_features_compat/ -v

All docker topologies (hub-only, full network, TLS, limits, DNS, standalone
TLS hub) share one compose project and are mutually exclusive. `conftest.py`
manages them explicitly: an autouse fixture starts the topology each test
needs and tests are grouped by topology at collection time, so any selection
(`-m`, `-k`, paths) is safe — mixing topologies in one run just costs extra
docker restarts.

## TLS integration tests (`tls/`)

Dedicated Docker services `ircd-tls-hub` and `ircd-tls-leaf` exercise per-block
TLS settings with a private test PKI under `tests/docker/certs/`.

| Test area | What it covers |
|-----------|----------------|
| Client TLS | Plain and TLS user registration on hub/leaf |
| Plaintext rejection | Non-TLS connect to TLS-only ports |
| Inbound S2S fingerprint | Accept matching cert; reject mismatch/self-signed |
| Inbound S2S CA verify | Accept CA-signed peer cert; reject self-signed/rogue CA |
| Outbound S2S | Hub→leaf (fingerprint), leaf→hub (CA + verifypeer) |

Regenerate certificates with `tests/docker/generate-certs.sh` after changing
the PKI. Host ports use the `166xx`/`144xx` range to avoid clashing with
standard IRC ports.

**Note:** Docker images are built with OpenSSL (`--with-tls=openssl`). TLS
listener ports in the test configs set `tls systemca = no` so each port gets
its own listener TLS context at config parse time.

# Verbose with output
uv run pytest -v -s --timeout=60
```

## Test Organization

Each PR has its own directory:

```
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
    test_fix.py              # S2S tests using P10Server for OPMODE +x and ACCOUNT
    test_edge_cases.py
    test_privilege_check.py  # U:line privilege tiers (CONF_UWORLD vs CONF_UWORLD_OPER)
    test_umode_ordering.py   # send_umode_out() / hide_hostmask() ordering
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

| ircd-tls-hub  | tls-hub.test.net  | 16677 / 16697 | 14440 / 14441 | 10        |
| ircd-tls-leaf | tls-leaf.test.net | 16678 / 16680 | 14411 / 14412 | 11        |

The TLS containers use certificates under `tests/docker/certs/` (regenerate
with `tests/docker/generate-certs.sh`). Host port 14411 maps to leaf S2S
port 4401; 14412 maps to 4402.

The hub is a HUB server. Leaves autoconnect to the hub. All servers have `NODNS` enabled for fast client registration.

Operator credentials: name `testoper`, password `operpass`.

The hub also has Connect blocks for two external test servers used by the P10 test harness:

| Server              | Numeric | U:lined     | Purpose                              |
|---------------------|---------|-------------|--------------------------------------|
| services.test.net   | 4       | Yes (oper)  | Fake services for S2S testing        |
| notulined.test.net  | 5       | No          | Non-U:lined server for rejection tests |
| uworldonly.test.net | 6       | Yes (no oper) | U:lined without CONF_UWORLD_OPER   |

Configs are baked into the Docker images (in `docker/`), not volume-mounted.

### NETWORK_FEATURES compat topology (`pr_network_features_compat/`)

Rolling-upgrade guard tests use a dedicated A—B—C chain.  **A** is built from
the current [UndernetIRC/ircu2 release](https://github.com/UndernetIRC/ircu2/releases)
(`Dockerfile` target `runtime-release`, default tag `u2.10.12.19`).  **B** and
**C** are built from the working tree.

| Service   | Server Name      | Binary   | NETWORK_FEATURES | Client | S2S  | IP         |
|-----------|------------------|----------|------------------|--------|------|------------|
| ircd-nf-a | a.prod.test.net  | release  | n/a (prod)       | 6671   | 4420 | 10.55.0.40 |
| ircd-nf-b | b.test.net       | tree     | FALSE            | 6672   | 4421 | 10.55.0.41 |
| ircd-nf-c | c.test.net       | tree     | TRUE (also HUB)  | 6673   | 4422 | 10.55.0.42 |

Services (`P10Server`, numeric 4) attach to **C** (C sets `HUB` so it can
accept that server link).  Assertions check that remote `OPMODE +x`,
already-authed `ACCOUNT` flag updates, and `+z` TLS fingerprint tokens on
NICK/umode bursts never reach **A** (prod would `protocol_violation` on a
second ACCOUNT).  A P10 spy on **B** (`spy.test.net`) observes B's
re-burst wire.  Override the release with `IRCD_RELEASE_TAG=...`.

## IRC Client API

`irc_client.py` provides `IRCClient` — a minimal async IRC client:

```python
from irc_client import IRCClient

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

`p10_server.py` provides `P10Server` — a fake IRC server that connects to ircd on its server port and speaks the P10 protocol. This enables testing server-to-server behavior (OPMODE, ACCOUNT, etc.) that can't be triggered from client connections.

```python
from p10_server import P10Server

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

1. Create `pr<N>_<short_name>/`
2. Add `__init__.py`
3. Write `test_fix.py` — reproduce the bug/feature
4. Write `test_edge_cases.py` — try to break it
5. Use `@pytest.mark.single_server` or `@pytest.mark.multi_server`
6. For S2S protocol tests, use `P10Server` to connect as a fake server
7. Use the `/ircu2-test` Claude skill for automated test generation

## Troubleshooting

Docker commands must be run from the repo root (where `docker-compose.yml` lives):

```bash
cd ..  # back to repo root

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
