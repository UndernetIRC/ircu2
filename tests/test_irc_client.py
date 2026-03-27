"""Unit tests for the IRC message parser."""

from irc_client import Message, parse_message


def test_parse_server_welcome():
    """Parse a standard server welcome message."""
    msg = parse_message(":server 001 nick :Welcome to the IRC Network")
    assert msg == Message(
        prefix="server",
        command="001",
        params=["nick", "Welcome to the IRC Network"],
    )


def test_parse_ping():
    """Parse a PING with no prefix."""
    msg = parse_message("PING :12345")
    assert msg == Message(prefix=None, command="PING", params=["12345"])


def test_parse_privmsg():
    """Parse a PRIVMSG with full prefix and trailing text."""
    msg = parse_message(":nick!user@host PRIVMSG #channel :hello world")
    assert msg == Message(
        prefix="nick!user@host",
        command="PRIVMSG",
        params=["#channel", "hello world"],
    )


def test_parse_names_reply():
    """Parse a 353 (RPL_NAMREPLY) with channel names."""
    msg = parse_message(":server 353 nick = #channel :@op +voice user")
    assert msg == Message(
        prefix="server",
        command="353",
        params=["nick", "=", "#channel", "@op +voice user"],
    )


def test_parse_empty_trailing():
    """Parse a message with an empty trailing parameter."""
    msg = parse_message(":server PART #channel :")
    assert msg == Message(
        prefix="server",
        command="PART",
        params=["#channel", ""],
    )


def test_parse_no_params():
    """Parse a command with no parameters."""
    msg = parse_message("QUIT")
    assert msg == Message(prefix=None, command="QUIT", params=[])


def test_parse_no_trailing():
    """Parse a message with params but no trailing."""
    msg = parse_message(":nick MODE #channel +o otheruser")
    assert msg == Message(
        prefix="nick",
        command="MODE",
        params=["#channel", "+o", "otheruser"],
    )


def test_parse_only_trailing():
    """Parse a message with only a trailing parameter."""
    msg = parse_message(":server ERROR :Closing Link")
    assert msg == Message(
        prefix="server",
        command="ERROR",
        params=["Closing Link"],
    )


def test_parse_colon_in_trailing():
    """Parse a message where the trailing contains colons."""
    msg = parse_message(":server 001 nick :Welcome to IRC: the network")
    assert msg == Message(
        prefix="server",
        command="001",
        params=["nick", "Welcome to IRC: the network"],
    )
