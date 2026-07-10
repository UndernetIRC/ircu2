"""Unit tests for TLS test certificate helpers."""

from pathlib import Path

from tls_certs import CERT_DIR, FINGERPRINTS, cert_path, fingerprint, key_path


def test_cert_files_exist():
    for name in (
        "ca", "hub", "leaf", "tlspeer", "tlspeer-ca",
        "selfsigned", "expired", "rogue",
    ):
        assert cert_path(name).is_file(), f"missing {name}.pem"
        assert key_path(name).is_file(), f"missing {name}.key"


def test_fingerprints_are_sha256_hex():
    for name, fp in FINGERPRINTS.items():
        assert len(fp) == 64, name
        assert fp == fp.lower()
        int(fp, 16)


def test_fingerprints_match_openssl_labels():
    assert fingerprint("hub") == FINGERPRINTS["hub"]
    assert fingerprint("leaf") == FINGERPRINTS["leaf"]


def test_fingerprints_file_matches_cert_dir():
  assert (CERT_DIR / "fingerprints.txt").is_file()
