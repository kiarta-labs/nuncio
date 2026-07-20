"""Context gatherer — category-based collector selection, concurrent
execution with a total timeout, degrade-on-slow, bundle assembly."""
import time
from nuncio.gatherer import Gatherer, categorize
from nuncio.collectors import UNAVAIL


def test_categorize_hardware_kernel():
    assert categorize({"host": "host01", "output": "general protection fault (GPF) escalation"}) == "hardware"


def test_categorize_storage_mount():
    assert categorize({"service": "sonarr", "output": "CIFS mount not present at boot"}) == "storage"


def test_categorize_defaults_to_container_when_service_present():
    assert categorize({"host": "host01", "service": "infisical-postgres", "output": "down"}) == "container"


def test_gather_runs_selected_collectors_and_assembles():
    collectors = {
        "recent_logs": lambda a, k, n: "## Recent logs\nlog line",
        "container_state": lambda a, k, n: "## Container state\nrestarting",
        "correlated": lambda a, k, n: "## Correlated\ngpf storm",
        "metrics": lambda a, k, n: "## Metrics\nx",
        "kernel": lambda a, k, n: "## Kernel\ny",
    }
    g = Gatherer(collectors, timeout_s=2.0)
    bundle = g.gather({"service": "sonarr", "output": "container Created"}, "k1", now=1000.0)
    assert "## Container state" in bundle  # container category -> logs+state+correlated
    assert "## Correlated" in bundle


def test_slow_collector_degrades_to_unavailable():
    def slow(a, k, n):
        time.sleep(3)
        return "## Recent logs\ntoo late"
    collectors = {
        "recent_logs": slow,
        "container_state": lambda a, k, n: "## Container state\nok",
        "correlated": lambda a, k, n: "## Correlated\nok",
    }
    g = Gatherer(collectors, timeout_s=0.3)
    t0 = time.time()
    bundle = g.gather({"service": "sonarr"}, "k1", now=1000.0)
    assert time.time() - t0 < 1.5           # bounded by the timeout, not the 3s sleep
    assert UNAVAIL.format("recent_logs") in bundle
    assert "## Container state" in bundle    # the fast ones still made it


def test_raising_collector_degrades():
    def boom(a, k, n):
        raise RuntimeError("collector broke")
    collectors = {"correlated": boom, "container_state": lambda a, k, n: "## State\nok"}
    g = Gatherer(collectors, timeout_s=1.0)
    bundle = g.gather({"service": "x"}, "k1", now=1.0)
    assert UNAVAIL.format("correlated") in bundle


# --- word-boundary categorization (no substring false positives) ---

def test_smartgallery_not_miscategorized_as_hardware():
    # 'smart' is a substring of smartgallery -> must NOT become 'hardware'
    assert categorize({"service": "smartgallery", "output": "container unhealthy"}) == "container"


def test_portainer_not_miscategorized_as_network():
    # 'port' is a substring of portainer -> must NOT become 'network'
    assert categorize({"service": "portainer", "output": "restart loop"}) == "container"


def test_real_ap_hostname_is_network():
    assert categorize({"host": "drawing-ap", "output": "radio DFS event"}) == "network"


def test_real_hardware_still_detected():
    assert categorize({"host": "host01", "output": "machine check exception (MCE)"}) == "hardware"


# --- gather is bounded / degrades under saturation, accepts explicit timeout ---

# --- weighted multi-signal categorization ---

from nuncio.gatherer import score_categories


def test_score_categories_returns_all_scores():
    scores = score_categories({"service": "sonarr",
                               "output": "CIFS mount not present at boot"})
    assert scores["storage"] > scores["container"] > 0
    assert scores["hardware"] == 0


def test_mixed_container_storage_alert_gets_union_of_collectors():
    # Both container AND storage signals -> logs + state + metrics all selected.
    collectors = {n: (lambda a, k, t: "x") for n in
                  ("recent_logs", "container_state", "metrics", "kernel", "correlated")}
    g = Gatherer(collectors)
    names = g.select({"service": "sonarr",
                      "output": "Docker container sonarr restarting: CIFS mount /downloads lost"})
    assert {"recent_logs", "container_state", "metrics", "correlated"} <= set(names)


def test_single_signal_alert_stays_narrow():
    collectors = {n: (lambda a, k, t: "x") for n in
                  ("recent_logs", "container_state", "metrics", "kernel", "correlated")}
    g = Gatherer(collectors)
    names = g.select({"service": "infisical-postgres", "output": "down"})
    assert "kernel" not in names and "metrics" not in names  # no hw/storage signal


def test_weak_secondary_signal_below_threshold_not_added():
    # one weak storage word must not drag in the storage collector set
    collectors = {n: (lambda a, k, t: "x") for n in
                  ("recent_logs", "container_state", "metrics", "kernel", "correlated")}
    g = Gatherer(collectors)
    names = g.select({"service": "paperless", "output": "docker container unhealthy, check filesystem later"})
    assert "container_state" in names
    assert "metrics" not in names  # single weak storage hit stays secondary-excluded


def test_hardware_plus_storage_mixed():
    collectors = {n: (lambda a, k, t: "x") for n in
                  ("recent_logs", "container_state", "metrics", "kernel", "correlated")}
    g = Gatherer(collectors)
    names = g.select({"host": "host01",
                      "output": "XFS filesystem error after NVMe SMART warning, kernel I/O errors"})
    assert "kernel" in names and "metrics" in names and "recent_logs" in names


def test_categorize_still_returns_single_top_category():
    # backward-compatible surface: categorize() = argmax of score_categories()
    assert categorize({"service": "sonarr",
                       "output": "Docker container restarting: CIFS mount lost"}) in ("container", "storage")


def test_gather_accepts_explicit_timeout():
    slow = lambda a, k, n: (time.sleep(2), "## Logs\nx")[1]
    g = Gatherer({"recent_logs": slow, "correlated": lambda a, k, n: "## Corr\nok",
                  "container_state": lambda a, k, n: "## State\nok"}, timeout_s=5.0)
    t0 = time.time()
    bundle = g.gather({"service": "x"}, "k", now=1.0, timeout=0.3)  # explicit tighter bound
    assert time.time() - t0 < 1.5
    assert UNAVAIL.format("recent_logs") in bundle


# --- B3: return_sections ---

def test_gather_return_sections_shape():
    collectors = {
        "recent_logs": lambda a, k, n: "## Recent logs\nline",
        "container_state": lambda a, k, n: "## Container state\nok",
        "correlated": lambda a, k, n: "## Correlated\nok",
        "recurrence": lambda a, k, n: "## Recurrence\n(first occurrence in 2h)",
    }
    g = Gatherer(collectors, timeout_s=2.0)
    bundle, sections = g.gather({"service": "sonarr", "output": "container Created"},
                                "k1", now=1000.0, return_sections=True)
    assert isinstance(bundle, str) and "## Container state" in bundle
    assert isinstance(sections, dict)
    assert sections["container_state"] == "## Container state\nok"
    assert sections["recurrence"] == "## Recurrence\n(first occurrence in 2h)"
    assert "## Container state" in bundle  # bundle still assembled as before


def test_gather_default_return_unchanged():
    collectors = {"correlated": lambda a, k, n: "## Correlated\nok"}
    g = Gatherer(collectors, timeout_s=2.0)
    result = g.gather({"service": "x"}, "k1", now=1.0)
    assert isinstance(result, str)  # not a tuple -- byte-identical default behavior


def test_gather_return_sections_empty_names():
    g = Gatherer({}, timeout_s=2.0)
    bundle, sections = g.gather({"service": "x"}, "k1", now=1.0, return_sections=True)
    assert bundle == ""
    assert sections == {}


def test_recurrence_in_every_category_collector_list():
    from nuncio.gatherer import _CATEGORY_COLLECTORS
    for cat, names in _CATEGORY_COLLECTORS.items():
        assert "recurrence" in names, f"{cat} missing recurrence"


# --- Phase B: profile="full" + per-name degrade to the standard closure ---

def test_full_profile_uses_the_deep_closure_when_present():
    collectors = {
        "recent_logs": lambda a, k, n: "## Recent logs\nSTANDARD",
        "container_state": lambda a, k, n: "## Container state\nok",
        "correlated": lambda a, k, n: "## Correlated\nok",
    }
    full_collectors = {"recent_logs": lambda a, k, n: "## Recent logs\nDEEP"}
    g = Gatherer(collectors, timeout_s=2.0, full_collectors=full_collectors)
    bundle = g.gather({"service": "sonarr", "output": "container Created"}, "k1", now=1000.0,
                       profile="full")
    assert "DEEP" in bundle
    assert "STANDARD" not in bundle


def test_full_profile_degrades_per_name_to_standard_closure_when_missing():
    collectors = {
        "recent_logs": lambda a, k, n: "## Recent logs\nSTANDARD",
        "container_state": lambda a, k, n: "## Container state\nok",
        "correlated": lambda a, k, n: "## Correlated\nok",
    }
    # full_collectors has NO 'recent_logs' entry -- must still be gathered,
    # via the standard closure, not silently dropped.
    full_collectors = {"container_state": lambda a, k, n: "## Container state\nDEEP"}
    g = Gatherer(collectors, timeout_s=2.0, full_collectors=full_collectors)
    bundle = g.gather({"service": "sonarr", "output": "container Created"}, "k1", now=1000.0,
                       profile="full")
    assert "STANDARD" in bundle    # degraded, not dropped
    assert "DEEP" in bundle        # the collector that DOES have a deep variant used it


def test_low_profile_default_ignores_full_collectors():
    collectors = {"correlated": lambda a, k, n: "## Correlated\nSTANDARD"}
    full_collectors = {"correlated": lambda a, k, n: "## Correlated\nDEEP"}
    g = Gatherer(collectors, timeout_s=2.0, full_collectors=full_collectors)
    bundle = g.gather({"service": "x"}, "k1", now=1.0)  # profile defaults to "low"
    assert "STANDARD" in bundle
    assert "DEEP" not in bundle


def test_select_full_profile_includes_names_only_in_full_collectors():
    collectors = {"container_state": lambda a, k, n: "x", "correlated": lambda a, k, n: "x"}
    full_collectors = {"recent_logs": lambda a, k, n: "x"}
    g = Gatherer(collectors, full_collectors=full_collectors)
    names_low = g.select({"service": "sonarr", "output": "container Created"}, profile="low")
    names_full = g.select({"service": "sonarr", "output": "container Created"}, profile="full")
    assert "recent_logs" not in names_low
    assert "recent_logs" in names_full
