"""Test PKI paths and helpers for TLS integration tests."""

from __future__ import annotations

import ssl
from pathlib import Path

CERT_DIR = Path(__file__).resolve().parent / "docker" / "certs"


def _read_fingerprints() -> dict[str, str]:
    fps: dict[str, str] = {}
    path = CERT_DIR / "fingerprints.txt"
    for line in path.read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fps[key.strip()] = value.strip()
    return fps


FINGERPRINTS = _read_fingerprints()


def cert_path(name: str) -> Path:
    """Return path to a PEM certificate (e.g. 'hub' -> hub.pem)."""
    return CERT_DIR / f"{name}.pem"


def key_path(name: str) -> Path:
    """Return path to a PEM private key."""
    return CERT_DIR / f"{name}.key"


def client_ssl_context(
    *,
    ca: str | None = None,
    cert: str | None = None,
    verify: bool = False,
) -> ssl.SSLContext:
    """Build an SSL context for test clients."""
    if verify and ca:
        ctx = ssl.create_default_context(cafile=str(cert_path(ca)))
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if cert:
        ctx.load_cert_chain(certfile=str(cert_path(cert)), keyfile=str(key_path(cert)))
    return ctx


def fingerprint(name: str) -> str:
    """Return the SHA-256 fingerprint (lowercase hex) for a generated cert."""
    return FINGERPRINTS[name]
