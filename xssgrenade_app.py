# -*- coding: utf-8 -*-
"""
XSS Grenade — single-exe launcher (PyInstaller entry point).

Runs the GUI as the main program. Kept deliberately thin: it imports the GUI
module NORMALLY (so xss_grenade_gui.__file__ resolves to the bundle's extraction
dir), which makes every runtime path-based load — the engine xss_grenade.py, the
_*.py modules, dom_hooks_v6.js, payloads.txt — resolve correctly inside the
frozen onefile bundle without touching any existing source.
"""
import os
import sys


def _bundle_dir():
    # PyInstaller onefile extracts everything to sys._MEIPASS at runtime.
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def _prepare_frozen_env():
    if not getattr(sys, "frozen", False):
        return
    base = _bundle_dir()
    # ensure the bundled source modules + data files are importable / findable
    if base not in sys.path:
        sys.path.insert(0, base)
    # use the machine's installed Playwright browsers if present (headless verify);
    # harmless if absent — the engine already degrades gracefully without them.
    if "PLAYWRIGHT_BROWSERS_PATH" not in os.environ:
        local = os.environ.get("LOCALAPPDATA", "")
        cand = os.path.join(local, "ms-playwright") if local else ""
        if cand and os.path.isdir(cand):
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = cand


def main():
    _prepare_frozen_env()
    import xss_grenade_gui
    xss_grenade_gui.main()


if __name__ == "__main__":
    main()
