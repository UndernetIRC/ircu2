# ircu2 Test Harness

Python-based integration test suite for ircu2 using Docker and pytest.

## Prerequisites

- Docker and Docker Compose
- Python 3.10+
- pip

## Setup

```bash
pip install -r tests/requirements.txt
```

## Running Tests

```bash
# All tests (starts Docker containers automatically)
pytest tests/

# Specific PR tests
pytest tests/pr59_part_messages/
pytest tests/pr61_uhnames/

# Only unit tests (no Docker needed)
pytest tests/test_irc_client.py

# By marker
pytest -m single_server    # tests needing only the hub
pytest -m multi_server     # tests needing hub + 2 leaves

# Verbose with output
pytest tests/ -v -s --timeout=60
```

## Test Organization

Each PR has its own directory under `tests/`:

```
tests/
  pr59_part_messages/
    test_fix.py          # TDD: reproduces the exact bug the PR fixes
    test_edge_cases.py   # Adversarial: tries to break the implementation
  pr61_uhnames/
    test_fix.py
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
6. Use the `/ircu2-test` Claude skill for automated test generation

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
