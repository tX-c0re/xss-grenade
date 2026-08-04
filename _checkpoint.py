"""
_checkpoint.py — Resume/checkpoint for long XSS Grenade scans (v10.16).

Design goals (timeless, robust):
  • Phase-level granularity. We checkpoint AFTER each expensive phase
    completes (crawl, seed, etc.), recording which phases are done and
    their reusable outputs (crawled pages, param URLs, confirmed findings).
    On resume we skip completed phases and restore their outputs.
  • Atomic writes. Write to a temp file then os.replace() — a crash
    mid-write never corrupts the checkpoint. Last good state always intact.
  • Scan fingerprinting. A checkpoint only resumes the SAME scan: same
    target + same scan-defining config. If the user changes payloads,
    depth, scope, etc., the fingerprint changes and we start fresh (a stale
    resume would silently produce wrong/partial results).
  • Versioned + self-describing. SCHEMA_VERSION guards against loading a
    checkpoint written by an incompatible future/older format. Unknown =
    ignore and start fresh rather than crash or mis-resume.
  • Forward-compatible. State is a plain JSON dict; new phases/fields can
    be added without breaking old readers (they ignore unknown keys).

Public API:
    make_fingerprint(target, config_dict) -> str
    CheckpointManager(path, fingerprint, enabled=True)
        .load() -> dict | None           # returns saved state if compatible
        .is_phase_done(name) -> bool
        .get_phase_output(name, default)  # restore a completed phase's output
        .mark_phase_done(name, output=None)  # record completion + save
        .update(**fields)                # merge extra state + save
        .save()                          # force atomic write
        .clear()                         # delete checkpoint (scan finished OK)
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from typing import Any, Dict, List, Optional


SCHEMA_VERSION = 1


def make_fingerprint(target: str, config: Dict[str, Any]) -> str:
    """Stable fingerprint of a scan's identity. Two scans with the same
    fingerprint are 'the same scan' and may resume each other; different
    fingerprints must not (would produce wrong results).

    We hash the target plus the SCAN-DEFINING config keys. We deliberately
    EXCLUDE runtime-only / cosmetic keys (workers, verbose, report paths,
    tor settings) — changing thread count shouldn't invalidate a resume,
    but changing payloads or crawl depth should.
    """
    # Scan-defining keys: anything that changes WHAT gets tested or found.
    defining_keys = (
        "payloads", "limit_urls", "limit_payloads", "early_exit",
        "marker_enabled", "marker_param", "follow_redirects", "crawl_depth",
        "crawl_max_pages", "enable_post_scan", "enable_json_scan",
        "enable_header_scan", "enable_context_scan", "enable_stored_scan",
        "enable_path_scan", "enable_cookie_scan", "ssrf_scan_enabled",
        "cors_scan_enabled", "xssi_scan_enabled", "crlf_scan_enabled",
        "destructive_enabled", "static_js", "param_wordlist",
    )
    h = hashlib.sha256()
    h.update(("target=" + (target or "")).encode("utf-8", "replace"))
    for k in defining_keys:
        if k not in config:
            continue
        v = config[k]
        # Normalize lists (payloads) deterministically by length+sample —
        # full payload list can be huge; its identity is captured by a
        # content hash so reordering or edits invalidate the fingerprint.
        if isinstance(v, (list, tuple)):
            inner = hashlib.sha256()
            for item in v:
                inner.update(str(item).encode("utf-8", "replace"))
                inner.update(b"\x00")
            v_repr = f"list[{len(v)}]:{inner.hexdigest()[:16]}"
        else:
            v_repr = repr(v)
        h.update(f"|{k}={v_repr}".encode("utf-8", "replace"))
    return h.hexdigest()[:32]


class CheckpointManager:
    """Manages a single scan's checkpoint file.

    Usage in run_scan:
        ck = CheckpointManager(path, fingerprint, enabled=resume_flag)
        resumed = ck.load()  # None if no/incompatible/different-scan ckpt

        if ck.is_phase_done("crawl"):
            pages = ck.get_phase_output("crawl", {}).get("pages", [])
            param_urls = ck.get_phase_output("crawl", {}).get("param_urls", [])
        else:
            ... do crawl ...
            ck.mark_phase_done("crawl", {"pages": pages,
                                         "param_urls": param_urls})
        ...
        ck.clear()  # scan finished cleanly — remove checkpoint
    """

    def __init__(self, path: Optional[str], fingerprint: str,
                 enabled: bool = True):
        self.path = path
        self.fingerprint = fingerprint
        self.enabled = bool(enabled and path)
        self._state: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "fingerprint": fingerprint,
            "created_at": time.time(),
            "updated_at": time.time(),
            "phases_done": [],         # ordered list of completed phase names
            "phase_outputs": {},       # name -> reusable output dict
            "findings": [],            # confirmed findings restored on resume
            "extra": {},               # misc forward-compatible state
        }
        self._loaded_from_disk = False

    # ── Load ──────────────────────────────────────────────────────────────
    def load(self) -> Optional[Dict[str, Any]]:
        """Load checkpoint if it exists AND is compatible AND matches this
        scan's fingerprint. Returns the state dict on successful resume,
        else None (caller starts fresh). Never raises on a bad file —
        a corrupt/incompatible checkpoint just means 'start fresh'.
        """
        if not self.enabled or not self.path or not os.path.exists(self.path):
            return None
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError, ValueError):
            # Corrupt or unreadable — ignore, start fresh.
            return None

        # Schema gate — unknown version → don't risk mis-resuming.
        if data.get("schema_version") != SCHEMA_VERSION:
            return None
        # Fingerprint gate — different scan → must not resume.
        if data.get("fingerprint") != self.fingerprint:
            return None

        # Merge defensively (preserve defaults for any missing keys).
        for k in ("phases_done", "phase_outputs", "findings", "extra",
                  "created_at"):
            if k in data:
                self._state[k] = data[k]
        self._loaded_from_disk = True
        return self._state

    @property
    def resumed(self) -> bool:
        return self._loaded_from_disk

    # ── Query ─────────────────────────────────────────────────────────────
    def is_phase_done(self, name: str) -> bool:
        return name in self._state.get("phases_done", [])

    def get_phase_output(self, name: str, default: Any = None) -> Any:
        return self._state.get("phase_outputs", {}).get(name, default)

    def get_findings(self) -> List[dict]:
        return list(self._state.get("findings", []))

    # ── Mutate + persist ──────────────────────────────────────────────────
    def mark_phase_done(self, name: str,
                        output: Optional[dict] = None) -> None:
        if name not in self._state["phases_done"]:
            self._state["phases_done"].append(name)
        if output is not None:
            self._state["phase_outputs"][name] = output
        self.save()

    def set_findings(self, findings: List[dict]) -> None:
        # Store a shallow copy so later mutation doesn't change the snapshot.
        self._state["findings"] = list(findings)

    def update(self, **fields: Any) -> None:
        self._state["extra"].update(fields)
        self.save()

    def save(self) -> None:
        """Atomic write: temp file in same dir, then os.replace().
        Same-dir temp guarantees replace() is atomic (same filesystem).
        Silent on failure — a checkpoint we can't write must never crash
        the scan that's running fine.
        """
        if not self.enabled or not self.path:
            return
        self._state["updated_at"] = time.time()
        try:
            d = os.path.dirname(os.path.abspath(self.path)) or "."
            os.makedirs(d, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".xsgckpt_", dir=d)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(self._state, f, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())  # durability before rename
                os.replace(tmp, self.path)  # atomic on same fs
            finally:
                if os.path.exists(tmp):
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
        except OSError:
            pass  # best-effort; don't break the scan

    def clear(self) -> None:
        """Remove the checkpoint — call when the scan finishes cleanly so a
        future run of the same scan starts fresh rather than 'resuming' a
        completed scan.
        """
        if not self.path:
            return
        try:
            if os.path.exists(self.path):
                os.unlink(self.path)
        except OSError:
            pass


def summarize_checkpoint(path: str) -> Optional[Dict[str, Any]]:
    """Read-only peek at a checkpoint for CLI/GUI display ('what would
    resume?'). Returns a small summary dict or None."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError, ValueError):
        return None
    return {
        "schema_version": data.get("schema_version"),
        "fingerprint": data.get("fingerprint"),
        "phases_done": data.get("phases_done", []),
        "findings_count": len(data.get("findings", [])),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
    }
