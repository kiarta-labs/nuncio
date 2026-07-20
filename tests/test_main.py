"""`python -m nuncio` entry-point wiring: build_app() -> serve(), and the
ConfigError -> stderr + exit(1) fatal-startup path. `serve()` itself
(ThreadingHTTPServer.serve_forever) is monkeypatched out here -- it's
already exercised as a real server in test_app.py's
test_serve_starts_a_server_and_accepts_a_request; this module is purely
about main()'s own glue.
"""
import pytest

from nuncio import __main__ as main_mod
from nuncio.config import ConfigError


class _FakeSettings:
    NUNCIO_BIND = "127.0.0.1"
    NUNCIO_PORT = 8095


def test_main_wires_build_app_into_serve(monkeypatch):
    calls = []
    fake_app = object()

    monkeypatch.setattr(main_mod, "build_app", lambda: (fake_app, _FakeSettings()))
    monkeypatch.setattr(main_mod, "serve", lambda app, bind, port: calls.append((app, bind, port)))

    main_mod.main()

    assert calls == [(fake_app, "127.0.0.1", 8095)]


def test_main_exits_nonzero_on_config_error(monkeypatch, capsys):
    def boom():
        raise ConfigError("NUNCIO_LLM_URL is required")

    monkeypatch.setattr(main_mod, "build_app", boom)
    monkeypatch.setattr(main_mod, "serve", lambda *a, **k: pytest.fail("serve() must not run after a ConfigError"))

    with pytest.raises(SystemExit) as exc:
        main_mod.main()

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "config error" in captured.err
    assert "NUNCIO_LLM_URL is required" in captured.err
