"""stdout delivery adapter — the zero-config default (`NUNCIO_DELIVERY=stdout`)
so a fresh install delivers *somewhere visible* with NO configuration at
all."""
import sys

from nuncio.delivery import DeliveryAdapter, register


@register
class Stdout(DeliveryAdapter):
    name = "stdout"
    # Always-True diagnostic sink -- a stdout success must never, on its
    # own, mark an alert delivered when a real (durable) channel is also
    # configured and failed. See Fanout/Dispatch's durable-aware success
    # rule in nuncio/delivery/__init__.py.
    durable = False

    def __init__(self, cfg=None, stream=None):
        self._stream = stream or sys.stdout

    def send(self, title, body, severity="unknown", **kw):
        print(f"=== {title} [{severity}] ===", file=self._stream)
        print(body, file=self._stream)
        print("=" * 40, file=self._stream)
        self._stream.flush()
        return True
