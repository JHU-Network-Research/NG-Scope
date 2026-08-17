"""Persisted GUI state: ~/.config/ngscope-gui/state.json.

Holds the whole config model plus the choices that are not part of the ngscope config at
all -- output directory, binary override, console preferences, window size -- so reopening
the app lands exactly where the last session left off.
"""

import json
import os
import tempfile
from pathlib import Path

from . import schema

APP_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "ngscope-gui"
STATE_PATH = APP_DIR / "state.json"


def default_state():
    return {
        "schema_version": schema.STATE_VERSION,
        "config": schema.default_config(),
        "out_dir": str(Path.home() / "ngscope_out"),
        "binary": "",
        "active_cell": 0,
        "console": {"autoscroll": True, "wrap": False},
        "window": {"width": 1440, "height": 920},
    }


def _merge(base, saved):
    """Shallow-merge saved values over defaults, one level deep, so a state file written
    by an older build gains new keys instead of losing the whole session."""
    for key, value in (saved or {}).items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            base[key] = _merge(dict(base[key]), value)
        else:
            base[key] = value
    return base


def load():
    state = default_state()
    try:
        saved = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return state
    except (OSError, json.JSONDecodeError):
        # A corrupt state file must not stop the app from opening.
        return state

    if saved.get("schema_version") != schema.STATE_VERSION:
        # Layout changed incompatibly; keep only what is safe to carry over.
        carried = {k: saved[k] for k in ("out_dir", "binary", "window") if k in saved}
        return _merge(state, carried)

    return _merge(state, saved)


def save(state):
    """Atomic write -- the app saves on every change, and a truncated file on a crash
    would lose the session."""
    APP_DIR.mkdir(parents=True, exist_ok=True)
    state = dict(state or {})
    state["schema_version"] = schema.STATE_VERSION

    fd, tmp = tempfile.mkstemp(dir=str(APP_DIR), prefix=".state-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)
        os.replace(tmp, STATE_PATH)
    except OSError:
        Path(tmp).unlink(missing_ok=True)
        raise
    return str(STATE_PATH)
