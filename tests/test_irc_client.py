"""Unit tests for the IRC message parser."""

from irc_client import Message, parse_message


def _msg(line: str, **kwargs) -> Message:
    """Build expected Message with default empty tags and raw=line."""
    defaults = dict(prefix=None, command="", params=[], tags="", raw=line)
    defaults.update(kwargs)
    return Message(**defaults)


def test_parse_server_welcome():
    """Parse a standard server welcome message."""
    line = ":server 001 nick :Welcome to the IRC Network"
    msg = parse_message(line)
    assert msg == _msg(
        line,
        prefix="server",
        command="001",
        params=["nick", "Welcome to the IRC Network"],
    )


def test_parse_ping():
    """Parse a PING with no prefix."""
    line = "PING :12345"
    msg = parse_message(line)
    assert msg == _msg(line, command="PING", params=["12345"])


def test_parse_privmsg():
    """Parse a PRIVMSG with full prefix and trailing text."""
    line = ":nick!user@host PRIVMSG #channel :hello world"
    msg = parse_message(line)
    assert msg == _msg(
        line,
        prefix="nick!user@host",
        command="PRIVMSG",
        params=["#channel", "hello world"],
    )


def test_parse_names_reply():
    """Parse a 353 (RPL_NAMREPLY) with channel names."""
    line = ":server 353 nick = #channel :@op +voice user"
    msg = parse_message(line)
    assert msg == _msg(
        line,
        prefix="server",
        command="353",
        params=["nick", "=", "#channel", "@op +voice user"],
    )


def test_parse_empty_trailing():
    """Parse a message with an empty trailing parameter."""
    line = ":server PART #channel :"
    msg = parse_message(line)
    assert msg == _msg(
        line,
        prefix="server",
        command="PART",
        params=["#channel", ""],
    )


def test_parse_no_params():
    """Parse a command with no parameters."""
    line = "QUIT"
    msg = parse_message(line)
    assert msg == _msg(line, command="QUIT")


def test_parse_no_trailing():
    """Parse a message with params but no trailing."""
    line = ":nick MODE #channel +o otheruser"
    msg = parse_message(line)
    assert msg == _msg(
        line,
        prefix="nick",
        command="MODE",
        params=["#channel", "+o", "otheruser"],
    )


def test_parse_only_trailing():
    """Parse a message with only a trailing parameter."""
    line = ":server ERROR :Closing Link"
    msg = parse_message(line)
    assert msg == _msg(
        line,
        prefix="server",
        command="ERROR",
        params=["Closing Link"],
    )


def test_parse_colon_in_trailing():
    """Parse a message where the trailing contains colons."""
    line = ":server 001 nick :Welcome to IRC: the network"
    msg = parse_message(line)
    assert msg == _msg(
        line,
        prefix="server",
        command="001",
        params=["nick", "Welcome to IRC: the network"],
    )


def test_parse_message_tags():
    """Parse IRCv3 message-tags before the prefix."""
    line = "@time=2020-01-15T12:34:56.789Z :nick!u@h PRIVMSG #chan :hi"
    msg = parse_message(line)
    assert msg == _msg(
        line,
        tags="time=2020-01-15T12:34:56.789Z",
        prefix="nick!u@h",
        command="PRIVMSG",
        params=["#chan", "hi"],
    )
