"""Capture ircd container debug output when integration tests fail.

Usage (from tests/ or repo root):

  IRCD_DEBUG=gdb pytest test_websocket_stress.py -k parallel -v
  IRCD_DEBUG=valgrind pytest test_websocket_stress.py -k parallel -v
  IRCD_SANITIZE=address pytest test_websocket_stress.py -k parallel -v

Core dumps (exit 139) are written to tests/debug-output/ and analyzed with
post-mortem gdb automatically on test failure.

Logs land in tests/debug-output/ (live) and tests/debug-output/failures/
(per failed test). Failed runs also append a summary to the pytest report.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

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
