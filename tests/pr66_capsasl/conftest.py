"""Fixtures shared by the pr66_capsasl tests."""

import pytest

from p10_server import P10Server


SASL_NETCONF_KEYS = ("sasl.server", "sasl.mechanisms", "sasl.timeout")


@pytest.fixture
async def reset_sasl_netconf(ircd_hub):
    """Delete the sasl.* network config a test set via CF once it is done.

    Netconf persists network-wide, so a leftover sasl.server would make
    sasl appear for any later test that links a matching fake server.
    Links its own server (not services.test.net, which a failed test may
    still hold) and sends an empty CF value, which deletes the key.
    """
    yield
    srv = P10Server(name="uworldonly.test.net", numeric=61, password="testpass")
    await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
    try:
        await srv.handshake()
        for key in SASL_NETCONF_KEYS:
            await srv.send_config(key, "")
    finally:
        await srv.disconnect()
