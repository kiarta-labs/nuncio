"""stdout delivery adapter — the zero-config default so a fresh install
delivers somewhere visible."""
import io

from nuncio.delivery.stdout import Stdout


def test_send_always_succeeds_and_writes_to_stream():
    stream = io.StringIO()
    s = Stdout(stream=stream)
    assert s.send("My Title", "the body text", "critical") is True
    out = stream.getvalue()
    assert "My Title" in out
    assert "critical" in out
    assert "the body text" in out


def test_defaults_to_sys_stdout(capsys):
    s = Stdout()
    s.send("T", "B")
    captured = capsys.readouterr()
    assert "T" in captured.out
    assert "B" in captured.out


def test_stdout_is_not_durable():
    # Stdout always returns True (diagnostic sink) -- it must be flagged
    # non-durable so a stdout success alone can never mask a real channel's
    # failure when fanned out alongside it (see Fanout/Dispatch's
    # durable-aware success rule).
    assert Stdout.durable is False
