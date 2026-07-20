"""Provider-agnostic plane router.

Encodes the privacy invariant: alert content always goes to the private plane
(any OpenAI-compatible endpoint the operator configures); the knowledge plane
(a second, optional, typically-hosted endpoint) is reachable ONLY through a
fixed classification table and ONLY when explicitly enabled. There is
deliberately no method that maps arbitrary/alert text to a knowledge-plane
alias — the only knowledge-plane-bound string is a table VALUE, keyed by a
known class name (allowlist by construction).
"""

# Built-in, identifier-free classification table — one entry per built-in
# category (see nuncio.model.categorize: hardware/storage/network/container/
# generic). Without this, an operator who enables the knowledge plane but
# hasn't authored their own NUNCIO_CONFIG classification_table would get a
# classification table that defaults to `{}` — enabling the plane would then
# do NOTHING (every route_knowledge() call returns None, a silent no-op).
# nuncio.config.build_router() merges this UNDER any operator-supplied table
# (`{**DEFAULT_CLASSIFICATION_TABLE, **operator_table}`) so an operator can
# override any individual entry, but never has to author one just to get a
# working default. Every string here is deliberately generic and
# identifier-free — an operator-authored override MUST keep that property
# too (see the anonymisation notice wherever this table is documented).
DEFAULT_CLASSIFICATION_TABLE = {
    "hardware": "a server reporting hardware-level faults such as memory errors, CPU faults, disk I/O errors, "
                "or sensor/temperature problems",
    "storage": "a host or service running out of disk space, or a filesystem/volume reporting errors or "
               "degraded performance",
    "network": "a network interface, link, or connectivity problem such as reduced link speed, packet loss, "
               "or an unreachable host or port",
    "container": "a containerized service that is crashing, restarting repeatedly, failing its healthcheck, "
                 "or exiting unexpectedly",
    "generic": "a monitored infrastructure service reporting a failure or degraded state",
}


class Router:
    def __init__(self, private_alias, knowledge_alias, classification_table,
                 knowledge_enabled=False, knowledge_redundant_with_private=False):
        self.private_alias = private_alias
        self.knowledge_alias = knowledge_alias
        self.classification_table = dict(classification_table)
        self.knowledge_enabled = knowledge_enabled
        # Phase C redundancy-skip signal (see nuncio.config.build_router):
        # True when the knowledge plane's effective endpoint+model is
        # identical to the private plane's -- computed once at construction
        # time from settings, never from per-alert data. Consumed by
        # Engine._garnish_with_knowledge, combined THERE with the per-alert
        # depth (full vs. low), since depth is threaded per-alert while this
        # is a static, boot/settings-time fact.
        self.knowledge_redundant_with_private = knowledge_redundant_with_private

    def route_alert(self):
        """All real alert enrichment → private plane. Never the knowledge plane."""
        return self.private_alias

    def route_knowledge(self, alert_class):
        """Return (knowledge_alias, generic_prompt) or None.

        Only fires when the knowledge plane is enabled AND `alert_class` is a
        known key in the classification table. The returned prompt is the
        table's generic, identifier-free string — never the caller's text — so
        raw alert content can never reach the knowledge plane through this path.
        """
        if not self.knowledge_enabled:
            return None
        generic = self.classification_table.get(alert_class)
        if generic is None:
            return None
        return (self.knowledge_alias, generic)
