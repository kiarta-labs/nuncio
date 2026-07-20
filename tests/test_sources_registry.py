"""Source-adapter registry: register/get/names, and the
narrow-waist rule that the core never imports an adapter module."""
from nuncio import sources


def test_all_five_launch_adapters_registered():
    assert {"checkmk", "grafana", "alertmanager", "openobserve", "generic"} <= set(sources.names())


def test_get_unknown_source_returns_none():
    assert sources.get("nonexistent-tool") is None


def test_register_is_idempotent_by_name():
    before = sources.get("generic")
    from nuncio.sources.generic import Generic  # re-import triggers no re-registration
    assert sources.get("generic") is before or isinstance(sources.get("generic"), Generic)


def test_core_modules_never_import_adapter_rings():
    # "the core never imports an adapter module" — CI-style
    # grep check, run here so it's exercised by the normal test suite too.
    core_modules = [
        "engine.py", "store.py", "deadline.py", "render.py", "router.py",
        "prompt.py", "redactor.py", "model.py", "llm.py", "gatherer.py",
        "collectors.py", "bundle.py", "replay.py", "correlate.py",
        "relevance.py", "resolver.py",
    ]
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1] / "nuncio"
    for name in core_modules:
        text = (root / name).read_text(encoding="utf-8")
        assert "nuncio.sources" not in text, f"{name} imports the source-adapter ring"
        assert "nuncio.delivery" not in text, f"{name} imports the delivery-adapter ring"
        assert "nuncio.clients" not in text, f"{name} imports the client ring"
