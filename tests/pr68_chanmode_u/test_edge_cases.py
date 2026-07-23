"""Edge cases for channel mode +u: permissions."""

import pytest

pytestmark = pytest.mark.single_server


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
    assert "u" not in await op.chan_modes("#pr68perm")


async def test_old_chanmode_P_is_unknown(make_client):
    """The old +P letter is gone: setting it returns ERR_UNKNOWNMODE."""
    op = await make_client("op68oldP")
    await op.send("JOIN #pr68oldp")
    await op.wait_for("366")

    msg = await op.send_and_expect("MODE #pr68oldp +P", "472")  # ERR_UNKNOWNMODE
    assert msg.command == "472"
    assert "P" not in await op.chan_modes("#pr68oldp")
