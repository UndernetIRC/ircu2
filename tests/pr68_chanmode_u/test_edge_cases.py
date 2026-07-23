"""Edge cases for channel mode +u: permissions."""

import pytest

pytestmark = pytest.mark.single_server


async def chan_modes(client, channel):
    msg = await client.send_and_expect(f"MODE {channel}", "324")
    return next((p for p in msg.params if p.startswith("+")), "")


async def test_nonop_cannot_set_u(make_client):
    """A non-op cannot set +u."""
    op = await make_client("op68perm")
    await op.send("JOIN #pr68perm")
    await op.wait_for("366")

    user = await make_client("usr68perm")
    await user.send("JOIN #pr68perm")
    await user.wait_for("366")

    msg = await user.send_and_expect("MODE #pr68perm +u", "482")  # ERR_CHANOPRIVSNEEDED
    assert msg.command == "482"
    assert "u" not in await chan_modes(op, "#pr68perm")
