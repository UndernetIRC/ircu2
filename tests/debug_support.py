"""Debug helpers for ircu2 integration tests.

Two complementary toolkits:

1. **Failure capture** (``IRCD_DEBUG=gdb|valgrind``, ``IRCD_SANITIZE=address``):
   snapshot docker/gdb/valgrind/asan artifacts into ``tests/debug-output/``
   when a test fails. Wired from ``conftest.py``.

2. **Live DEBUGMODE introspection** (requires ircd started with ``-x 8``):
   read ``ircd.log`` / ``docker logs``, or subscribe an oper to SNO_DEBUG
   snotices (``MODE nick +s 65536``) and wait for matching lines.

Usage::

    IRCD_DEBUG=gdb pytest test_websocket_stress.py -k parallel -v
    IRCD_DEBUG=valgrind pytest ...
    IRCD_SANITIZE=address pytest ...

Flood-limit introspection example (from ``s_bsd.c``)::

    DEBUG [DEBUG]: dbuf: 4095 maxfl: 4096
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from irc_client import IRCClient, Message

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DEBUG_DIR = REPO_ROOT / "tests" / "debug-output"
FAILURES_DIR = DEFAULT_DEBUG_DIR / "failures"

HUB_CONTAINER = "ircu-hub"
HUB_IMAGE = "ircu2-ircd-hub"

DEBUG_LOG_NAMES = (
    "gdb.log",
    "valgrind.log",
    "valgrind-stdout.log",
    "valgrind-meta.log",
    "ircd.log",
)

# SNO_DEBUG from include/client.h
SNO_DEBUG = 65536

# Common locations for the DEBUGMODE log file inside test containers.
DEBUG_LOG_PATHS = (
    "/opt/ircu/ircd.log",
    "/opt/ircu/lib/ircd.log",
)

# Service name (docker-compose) -> container_name mapping.
SERVICE_CONTAINERS: dict[str, str] = {
    "ircd-hub": "ircu-hub",
    "ircd-leaf1": "ircu-leaf1",
    "ircd-leaf2": "ircu-leaf2",
    "ircd-tls-hub": "ircu-tls-hub",
    "ircd-tls-leaf": "ircu-tls-leaf",
    "ircd-limits": "ircu-limits",
}

DEBUG_LINE_RE = re.compile(r"DEBUG \[(\w+)\]: (.+)$")
DBUF_MAXFL_RE = re.compile(r"dbuf:\s*(\d+)\s+maxfl:\s*(\d+)")


# ---------------------------------------------------------------------------
# Failure capture (IRCD_DEBUG / IRCD_SANITIZE)
# ---------------------------------------------------------------------------


def debug_mode() -> str | None:
    """Return gdb, valgrind, or None when running ircd normally."""
    mode = os.environ.get("IRCD_DEBUG", "").strip().lower()
    return mode or None


def debug_output_dir() -> Path:
    raw = os.environ.get("IRCD_DEBUG_DIR")
    path = Path(raw) if raw else DEFAULT_DEBUG_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def compose_env() -> dict[str, str]:
    """Environment passed to docker compose from pytest."""
    env = os.environ.copy()
    env.setdefault("IRCD_DEBUG", debug_mode() or "")
    env.setdefault("IRCD_DEBUG_DIR", str(debug_output_dir()))
    env.setdefault("IRCD_SANITIZE", os.environ.get("IRCD_SANITIZE", ""))
    return env


def _find_latest_core() -> Path | None:
    cores = sorted(
        debug_output_dir().glob("core.*"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return cores[0] if cores else None


def analyze_core_postmortem(core: Path, dest: Path) -> str:
    """Run gdb on a core file from the test image; save and return backtrace."""
    out_path = dest / "core-backtrace.txt"
    mount = f"{debug_output_dir()}:/opt/ircu/debug:ro"
    core_in_container = f"/opt/ircu/debug/{core.name}"
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            mount,
            "--entrypoint",
            "gdb",
            HUB_IMAGE,
            "-batch",
            "-ex",
            "set pagination off",
            "-ex",
            "thread apply all bt full",
            "-ex",
            "quit",
            "/opt/ircu/bin/ircd",
            core_in_container,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=REPO_ROOT,
    )
    text = (result.stdout or "") + (result.stderr or "")
    out_path.write_text(text, encoding="utf-8")
    shutil.copy2(core, dest / core.name)
    return text


def container_state(container: str = HUB_CONTAINER) -> str:
    result = subprocess.run(
        [
            "docker",
            "inspect",
            "-f",
            "{{.State.Status}} exit={{.State.ExitCode}}",
            container,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        return f"missing ({result.stderr.strip() or 'not found'})"
    return result.stdout.strip()


def docker_logs(container: str = HUB_CONTAINER, tail: int = 500) -> str:
    result = subprocess.run(
        ["docker", "logs", "--tail", str(tail), container],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        return result.stderr.strip() or f"docker logs failed for {container}"
    return result.stdout + result.stderr


def _crash_exit(state: str) -> bool:
    return any(code in state for code in ("139", "134", "133"))


def _copy_debug_files(dest: Path) -> list[str]:
    copied: list[str] = []
    src = debug_output_dir()
    if debug_mode():
        for name in DEBUG_LOG_NAMES:
            path = src / name
            if path.is_file() and path.stat().st_size > 0:
                shutil.copy2(path, dest / name)
                copied.append(name)
    return copied


def _copy_asan_logs(dest: Path) -> list[str]:
    """Copy AddressSanitizer reports written under debug-output/asan.*."""
    copied: list[str] = []
    if not os.environ.get("IRCD_SANITIZE", "").strip():
        return copied
    src = debug_output_dir()
    for path in sorted(src.glob("asan.*")):
        if path.is_file() and path.stat().st_size > 0:
            shutil.copy2(path, dest / path.name)
            copied.append(path.name)
    return copied


def snapshot_failure_artifacts(test_nodeid: str) -> Path | None:
    """Save hub logs and debug files for a failed test; return snapshot dir."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_name = test_nodeid.replace("/", "_").replace("::", "__")
    dest = FAILURES_DIR / f"{safe_name}__{stamp}"
    dest.mkdir(parents=True, exist_ok=True)

    state = container_state()
    (dest / "container-state.txt").write_text(state + "\n", encoding="utf-8")

    logs = docker_logs()
    (dest / "docker-logs.txt").write_text(logs, encoding="utf-8")

    copied = _copy_debug_files(dest)
    copied.extend(_copy_asan_logs(dest))

    if _crash_exit(state):
        core = _find_latest_core()
        if core is not None:
            try:
                analyze_core_postmortem(core, dest)
                copied.append(core.name)
                copied.append("core-backtrace.txt")
            except (OSError, subprocess.TimeoutExpired) as exc:
                (dest / "core-backtrace.txt").write_text(
                    f"core analysis failed: {exc}\n", encoding="utf-8"
                )

    readme_lines = [
        f"test: {test_nodeid}",
        f"IRCD_DEBUG: {debug_mode() or '(unset)'}",
        f"IRCD_SANITIZE: {os.environ.get('IRCD_SANITIZE') or '(unset)'}",
        f"hub state: {state}",
        f"artifacts: {', '.join(copied) if copied else '(none)'}",
        "",
        "Re-run with AddressSanitizer stack trace:",
        "  IRCD_SANITIZE=address pytest tests/test_websocket_stress.py -k <name> -v",
        "",
        "Re-run under gdb (live; may perturb timing):",
        "  IRCD_DEBUG=gdb pytest tests/test_websocket_stress.py -k <name> -v",
        "",
        "Re-run under valgrind:",
        "  IRCD_DEBUG=valgrind pytest tests/test_websocket_stress.py -k <name> -v",
    ]
    (dest / "README.txt").write_text("\n".join(readme_lines) + "\n", encoding="utf-8")

    return dest


def format_failure_report(snapshot_dir: Path | None) -> str:
    if snapshot_dir is None:
        return ""

    lines = [
        "",
        "=" * 72,
        "ircd debug snapshot",
        f"  directory: {snapshot_dir}",
        f"  hub state: {container_state()}",
    ]

    for name in DEBUG_LOG_NAMES:
        path = snapshot_dir / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        tail = text[-12000:] if len(text) > 12000 else text
        lines.extend(
            [
                "",
                f"--- {name} (last {len(tail)} chars) ---",
                tail.rstrip(),
            ]
        )

    docker_path = snapshot_dir / "docker-logs.txt"
    if docker_path.is_file():
        text = docker_path.read_text(encoding="utf-8", errors="replace")
        tail = text[-8000:] if len(text) > 8000 else text
        lines.extend(["", f"--- docker-logs.txt (last {len(tail)} chars) ---", tail.rstrip()])

    for path in sorted(snapshot_dir.glob("asan.*")):
        text = path.read_text(encoding="utf-8", errors="replace")
        tail = text[-16000:] if len(text) > 16000 else text
        lines.extend(["", f"--- {path.name} ---", tail.rstrip()])

    core_path = snapshot_dir / "core-backtrace.txt"
    if core_path.is_file():
        text = core_path.read_text(encoding="utf-8", errors="replace")
        tail = text[-16000:] if len(text) > 16000 else text
        lines.extend(["", f"--- core-backtrace.txt (last {len(tail)} chars) ---", tail.rstrip()])

    lines.append("=" * 72)
    return "\n".join(lines)


def prepare_debug_session() -> None:
    """Prepare debug-output for a fresh pytest session."""
    out = debug_output_dir()
    out.mkdir(parents=True, exist_ok=True)
    out.chmod(0o777)
    for path in out.glob("core.*"):
        path.unlink(missing_ok=True)
    for path in out.glob("asan.*"):
        path.unlink(missing_ok=True)
    if debug_mode():
        for name in DEBUG_LOG_NAMES:
            path = out / name
            if path.is_file():
                path.unlink()


# ---------------------------------------------------------------------------
# Live DEBUGMODE introspection (log file / docker logs / snotices)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DebugLine:
    """One parsed DEBUG log or snotice line."""

    level: str
    message: str
    raw: str


@dataclass(frozen=True)
class DbufMaxfl:
    """Parsed ``dbuf: N maxfl: M`` flood-limit debug snapshot."""

    dbuf: int
    maxfl: int
    raw: str


def resolve_container(service_or_container: str) -> str:
    """Map a docker-compose service name to its container_name."""
    return SERVICE_CONTAINERS.get(service_or_container, service_or_container)


def docker_exec(
    container: str,
    *args: str,
    check: bool = True,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    """Run a command inside a test container."""
    result = subprocess.run(
        ["docker", "exec", resolve_container(container), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=REPO_ROOT,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"docker exec {container!r} {' '.join(args)!r} failed "
            f"(exit {result.returncode}): {result.stderr.strip()}"
        )
    return result


def fetch_debug_log(
    container: str,
    *,
    tail: int | None = None,
    paths: tuple[str, ...] = DEBUG_LOG_PATHS,
) -> str:
    """Read DEBUGMODE output from a running container.

    Tries the on-disk log file first (``LPATH``, usually ``/opt/ircu/ircd.log``).
    Falls back to ``docker logs`` when no file is present — in the test
    containers debug is often mirrored to stderr instead of a file.

    Requires the container to be started with ``-x 8`` (or higher).
    """
    name = resolve_container(container)
    for path in paths:
        probe = subprocess.run(
            ["docker", "exec", name, "test", "-r", path],
            capture_output=True,
            text=True,
            timeout=10.0,
        )
        if probe.returncode != 0:
            continue
        cmd = ["docker", "exec", name]
        if tail is not None:
            cmd.extend(["tail", "-n", str(tail), path])
        else:
            cmd.extend(["cat", path])
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30.0, cwd=REPO_ROOT
        )
        if result.returncode == 0:
            return result.stdout

    # Fallback: docker logs (debug is dup2'd to stderr in daemon mode).
    cmd = ["docker", "logs", name]
    if tail is not None:
        cmd = ["docker", "logs", "--tail", str(tail), name]
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30.0, cwd=REPO_ROOT
    )
    log_text = (result.stdout or "") + (result.stderr or "")
    if result.returncode == 0 and log_text.strip():
        return log_text
    raise FileNotFoundError(
        f"No debug output found for container {name!r} "
        f"(tried {', '.join(paths)} and docker logs). "
        "Start ircd with -x 8 to enable DEBUG_DEBUG logging."
    )


def parse_debug_lines(text: str, *, pattern: str | None = None) -> list[DebugLine]:
    """Extract ``DEBUG [LEVEL]: message`` lines from log text or IRC notices."""
    regex = re.compile(pattern) if pattern else None
    lines: list[DebugLine] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # Strip IRC notice wrapper if present.
        notice_idx = line.find("*** Notice -- ")
        if notice_idx >= 0:
            line = line[notice_idx + len("*** Notice -- ") :]
        # Strip log timestamp prefix: [YYYY-MM-DD HH:MM:SS]
        if line.startswith("["):
            bracket = line.find("]")
            if bracket > 0:
                line = line[bracket + 1 :].strip()
        match = DEBUG_LINE_RE.search(line)
        if not match:
            continue
        level, message = match.groups()
        if regex and not regex.search(message):
            continue
        lines.append(DebugLine(level=level, message=message, raw=raw_line))
    return lines


def parse_dbuf_maxfl(text: str) -> list[DbufMaxfl]:
    """Return all ``dbuf: N maxfl: M`` snapshots found in *text*."""
    results: list[DbufMaxfl] = []
    seen: set[tuple[int, int]] = set()
    for raw_line in text.splitlines():
        for match in DBUF_MAXFL_RE.finditer(raw_line):
            dbuf, maxfl = int(match.group(1)), int(match.group(2))
            key = (dbuf, maxfl)
            if key in seen:
                continue
            seen.add(key)
            results.append(DbufMaxfl(dbuf=dbuf, maxfl=maxfl, raw=raw_line.strip()))
    return results


def grep_debug_log(
    container: str,
    pattern: str,
    *,
    tail: int | None = 500,
) -> list[DebugLine]:
    """Fetch the container debug log and return lines matching *pattern*."""
    log = fetch_debug_log(container, tail=tail)
    return parse_debug_lines(log, pattern=pattern)


async def enable_debug_snotices(client: IRCClient) -> None:
    """Subscribe an oper to DEBUG snotices (SNO_DEBUG / 65536).

    The snomask value must be a separate MODE parameter after ``+s``
    (``MODE nick +s 65536``), matching ircu's parv[3] parsing.
    """
    if not client.nick:
        raise ValueError("client must be registered before enabling debug snotices")
    await client.send(f"MODE {client.nick} +s {SNO_DEBUG}")
    # Drain RPL_SNOMASK (008) if the server sends it.
    try:
        msg = await client.wait_for("008", timeout=2.0)
        if msg.params and int(msg.params[1]) != SNO_DEBUG:
            raise ValueError(f"Unexpected snomask: {msg}")
    except asyncio.TimeoutError:
        pass


def _notice_debug_text(msg: Message) -> str | None:
    """Return the debug payload from a server-notice NOTICE, if any."""
    if msg.command != "NOTICE" or not msg.params:
        return None
    text = msg.params[-1]
    if "*** Notice -- " in text:
        text = text.split("*** Notice -- ", 1)[1]
    if "DEBUG [" not in text:
        return None
    return text


async def collect_debug_snotices(
    client: IRCClient,
    *,
    pattern: str | None = None,
    timeout: float = 2.0,
    drain_first: bool = True,
) -> list[DebugLine]:
    """Collect DEBUG snotices already in the client's receive buffer/stream.

    Call ``enable_debug_snotices()`` first.  This function reads until
    *timeout* seconds elapse without a new matching notice.
    """
    regex = re.compile(pattern) if pattern else None
    collected: list[DebugLine] = []

    if drain_first:
        # Brief pause so notices triggered just before this call can arrive.
        await asyncio.sleep(0.05)

    idle_deadline = asyncio.get_running_loop().time() + timeout
    while True:
        remaining = idle_deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            break
        try:
            msg = await client.recv(timeout=min(remaining, 0.25))
        except asyncio.TimeoutError:
            continue
        payload = _notice_debug_text(msg)
        if payload is None:
            continue
        parsed = parse_debug_lines(payload)
        for entry in parsed:
            if regex and not regex.search(entry.message):
                continue
            collected.append(entry)
            idle_deadline = asyncio.get_running_loop().time() + timeout
    return collected


async def wait_for_debug_snotice(
    client: IRCClient,
    pattern: str,
    *,
    timeout: float = 5.0,
) -> DebugLine:
    """Wait until a DEBUG snotice matching *pattern* is received."""
    regex = re.compile(pattern)
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise asyncio.TimeoutError(
                f"Timed out waiting for DEBUG snotice matching /{pattern}/"
            )
        try:
            msg = await client.recv(timeout=min(remaining, 0.5))
        except asyncio.TimeoutError:
            continue
        payload = _notice_debug_text(msg)
        if payload is None:
            continue
        for entry in parse_debug_lines(payload):
            if regex.search(entry.message):
                return entry


async def wait_for_dbuf_maxfl_snotice(
    client: IRCClient,
    *,
    min_dbuf: int = 1,
    timeout: float = 5.0,
) -> DbufMaxfl:
    """Wait for a flood-limit debug line and return the parsed values."""
    entry = await wait_for_debug_snotice(client, r"dbuf:\s*\d+\s+maxfl:\s*\d+", timeout=timeout)
    snapshots = parse_dbuf_maxfl(entry.message)
    if not snapshots:
        snapshots = parse_dbuf_maxfl(entry.raw)
    if not snapshots:
        raise ValueError(f"Could not parse dbuf/maxfl from: {entry.message!r}")
    snap = snapshots[-1]
    if snap.dbuf < min_dbuf:
        raise AssertionError(
            f"Expected dbuf >= {min_dbuf}, got dbuf={snap.dbuf} maxfl={snap.maxfl}"
        )
    return snap
