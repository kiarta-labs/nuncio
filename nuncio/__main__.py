"""`python -m nuncio` entry point. This module and `nuncio/config.py` are the
ONLY two places allowed to read `os.environ`."""
import sys

from nuncio.config import ConfigError, build_app
from nuncio.server import serve


def main():
    try:
        app, settings = build_app()
    except ConfigError as e:
        print(f"nuncio: config error: {e}", file=sys.stderr)
        raise SystemExit(1)
    serve(app, settings.NUNCIO_BIND, settings.NUNCIO_PORT)


if __name__ == "__main__":  # pragma: no cover -- process entry guard, main() itself is tested directly
    main()
