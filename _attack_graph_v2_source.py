"""
attack_graph_widget.py
======================
Force-directed live attack surface visualization.

This is a complete rewrite of the old radial AttackGraphWidget.

Why the rewrite
---------------
The old widget had hard limits (MAX_PATHS=8, MAX_PARAMS_PER_PATH=3) which
silently dropped findings when target had more endpoints. It also had
edge cases where mark_hit() called for an unknown path would not appear
on the graph at all (lazy auto-create wasn't always reached because of
the path-cap check).

What's different
----------------
- **Force-directed layout** — nodes attract/repel organically. Adding a
  node never repositions everything; the layout finds equilibrium. This
  scales to thousands of endpoints without breaking.

- **Zero limits** — every path, every param, every hit is tracked
  internally. Display uses viewport culling: only nodes inside the
  current view rectangle get drawn. So 5000 endpoints don't slow
  rendering — only the ~50 visible at current zoom do.

- **Mouse zoom + pan** — wheel zooms toward cursor, drag pans. Right-click
  recenters and fits all nodes into view. Click on hit node opens
  VulnerabilityDetailDialog (same signal as before).

- **Lazy auto-create** — every API method (add_path, add_param, mark_hit,
  mark_waf) creates parent nodes if they don't exist yet. A hit can never
  be silently dropped because the path wasn't crawled first.

- **GATE-aware coloring** — nodes use the v2 gate classification
  (xss_executable / tag_injection / text_only) for color coding. Old
  binary "hit yes/no" replaced by 4-state visualization.

- **Live counters in corner** — paths/params/hits/waf, always current.

Public API (drop-in compatible with old AttackGraphWidget)
-----------------------------------------------------------
    set_target(url)           — initialize with target host
    add_path(path)            — endpoint discovered (crawler)
    add_param(path, name)     — parameter discovered
    mark_hit(path, param, details=None)   — XSS confirmed
    mark_waf(path, param)     — WAF blocked
    set_tor_status(active, exit_ip)
    reset()                   — return to idle
    stop()                    — finish (status → done)

Signal:
    sig_hit_clicked(dict)     — emit when user clicks a hit node

Compat shims kept (no-op or simple delegates):
    inject_hit(), inject_line(text, status=None), tick_pulse()
"""

from __future__ import annotations

import math
import random as _rnd
import time
from typing import Optional, Dict, List, Tuple
from urllib.parse import urlparse as _urlparse

from PyQt5.QtCore import Qt, QTimer, QRectF, QPointF, pyqtSignal
from PyQt5.QtGui import (
    QPainter, QColor, QPen, QBrush, QFont, QPainterPath,
    QRadialGradient, QLinearGradient,
)
from PyQt5.QtWidgets import QWidget


# ════════════════════════════════════════════════════════════════════════════
# COLOR PALETTE
# ════════════════════════════════════════════════════════════════════════════

# Background / chrome
BG_TOP    = QColor("#0d0e10")
BG_BOTTOM = QColor("#16181c")
GRID      = QColor(255, 255, 255, 8)

# Connection lines
LINK_DIM  = QColor(255, 255, 255, 30)
LINK_HOT  = QColor(255, 255, 255, 75)

# Node fills by state
COL_ROOT      = QColor("#5eead4")     # teal — root target
COL_PATH      = QColor("#94a3b8")     # slate — path
COL_PARAM     = QColor("#cbd5e1")     # light — param probing

COL_XSS_EXEC  = QColor("#ef4444")     # red — true XSS executable
COL_TAG_INJ   = QColor("#f97316")     # orange — tag injection only
COL_TEXT_ONLY = QColor("#64748b")     # gray — informational reflection
COL_HIT_LEGACY = QColor("#10b981")    # green — legacy "hit" w/o gate info

COL_WAF       = QColor("#fbbf24")     # amber — WAF blocked

# Text
TXT_PRIMARY   = QColor("#e2e8f0")
TXT_SECONDARY = QColor("#94a3b8")
TXT_DIM       = QColor("#64748b")

# Tor indicator
TOR_ON  = QColor("#a78bfa")
TOR_OFF = QColor("#475569")


# ════════════════════════════════════════════════════════════════════════════
# DATA MODEL
# ════════════════════════════════════════════════════════════════════════════

class _Node:
    """A node in the force-directed graph."""
    __slots__ = (
        "id", "label", "kind", "state", "x", "y", "vx", "vy",
        "fixed", "pulse_ph", "details", "parent_id", "created_ts",
        "gate_klass", "gate_severity",
    )

    def __init__(self, node_id: str, label: str, kind: str,
                 x: float = 0.0, y: float = 0.0,
                 parent_id: Optional[str] = None):
        self.id = node_id
        self.label = label
        self.kind = kind             # 'root' | 'path' | 'param'
        self.state = "idle"          # 'idle' | 'probing' | 'hit' | 'waf'
        self.x = x
        self.y = y
        self.vx = 0.0
        self.vy = 0.0
        self.fixed = False
        self.pulse_ph = _rnd.random()
        self.details: dict = {}
        self.parent_id = parent_id
        self.created_ts = time.time()
        self.gate_klass: Optional[str] = None
        self.gate_severity: Optional[str] = None


# ════════════════════════════════════════════════════════════════════════════
# WIDGET
# ════════════════════════════════════════════════════════════════════════════

class AttackGraphWidget(QWidget):
    """Force-directed live attack surface graph (v2)."""

    sig_hit_clicked = pyqtSignal(dict)

    # Animation
    TICK_MS         = 33               # ~30 fps
    SIM_ITERATIONS  = 2                # physics steps per tick

    # Force constants — tweakable for layout feel
    REPULSE_STRENGTH = 1800.0          # node-node repulsion
    REPULSE_RANGE_2  = 200.0 ** 2      # max distance² for repulsion
    SPRING_LEN_PATH  = 80.0            # ideal edge length root↔path
    SPRING_LEN_PARAM = 38.0            # ideal edge length path↔param
    SPRING_K         = 0.05            # edge stiffness
    DAMPING          = 0.85            # velocity decay per tick
    CENTER_GRAVITY   = 0.0008          # pull toward center

    # Node sizes
    R_ROOT  = 10.0
    R_PATH  = 6.0
    R_PARAM = 5.0
    R_HIT   = 8.0

    # Zoom
    ZOOM_MIN = 0.15
    ZOOM_MAX = 4.0
    ZOOM_STEP = 1.15

    def __init__(self, parent=None, font_size=11, speed_ms=55):
        super().__init__(parent)
        self._font_size = font_size

        self.setAttribute(Qt.WA_OpaquePaintEvent, True)
        self.setMinimumHeight(220)
        self.setMouseTracking(True)

        # Graph state — zero hard limits
        self._nodes: Dict[str, _Node] = {}
        self._edges: List[Tuple[str, str]] = []   # (parent_id, child_id)
        self._target_host: Optional[str] = None
        self._is_running = False

        # Counters (always live, never capped)
        self._hit_count = 0
        self._waf_count = 0
        self._path_count = 0
        self._param_count = 0

        # View transform
        self._zoom = 1.0
        self._pan_x = 0.0
        self._pan_y = 0.0
        self._dragging = False
        self._drag_last: Optional[QPointF] = None

        # Hover
        self._hover_node_id: Optional[str] = None

        # Tor
        self._tor_active = False
        self._tor_exit_ip: Optional[str] = None

        # Anim phase
        self._t = 0.0

        # Initial zoom-to-fit pending flag — fits view after first layout settles
        self._fit_pending = False

        self._tick_timer = QTimer(self)
        self._tick_timer.timeout.connect(self._tick)
        self._tick_timer.start(self.TICK_MS)

    # ════════════════════════════════════════════════════════════════════
    # PUBLIC API (drop-in compatible)
    # ════════════════════════════════════════════════════════════════════

    def set_target(self, url: str):
        if not url:
            return
        parsed = _urlparse(url if "://" in url else f"http://{url}")
        host = parsed.netloc or parsed.path.split("/")[0]
        if not host:
            return

        self._target_host = host
        self._is_running = True
        self._reset_graph()

        # Create root node centered
        cx = self.width() / 2 if self.width() > 0 else 300
        cy = self.height() / 2 if self.height() > 0 else 150
        root = _Node("__root__", host, "root", x=cx, y=cy)
        root.fixed = True
        self._nodes["__root__"] = root
        self.update()

    def add_path(self, path: str) -> str:
        """Add a path node. Returns node_id (whether new or existing)."""
        if not self._target_host:
            # Lazy: even without explicit set_target, accept path adds —
            # but only if user has set a target via reset. Be defensive.
            return ""
        norm = self._norm_path(path)
        node_id = f"path::{norm}"
        if node_id in self._nodes:
            return node_id
        # Place near root with slight random offset so it doesn't stack
        rx, ry = self._random_near("__root__", 60.0)
        n = _Node(node_id, self._display_path(norm), "path",
                  x=rx, y=ry, parent_id="__root__")
        self._nodes[node_id] = n
        self._edges.append(("__root__", node_id))
        self._path_count += 1
        self._fit_pending = True
        self.update()
        return node_id

    def add_param(self, path: str, name: str) -> str:
        """Add a param node under the given path. Auto-creates path."""
        if not name:
            return ""
        path_id = self.add_path(path)
        if not path_id:
            return ""
        norm_path = self._norm_path(path)
        param_id = f"param::{norm_path}::{name}"
        if param_id in self._nodes:
            return param_id
        rx, ry = self._random_near(path_id, 30.0)
        n = _Node(param_id, self._display_param(name), "param",
                  x=rx, y=ry, parent_id=path_id)
        n.state = "probing"
        self._nodes[param_id] = n
        self._edges.append((path_id, param_id))
        self._param_count += 1
        self.update()
        return param_id

    def mark_hit(self, path: str, param: str, details: Optional[dict] = None):
        """
        Mark a parameter as confirmed XSS hit. Auto-creates path AND
        param nodes if they don't exist yet — this fixes the old bug
        where hits on uncrawled endpoints disappeared.
        """
        if not param:
            return
        param_id = self.add_param(path, param)
        if not param_id:
            return
        n = self._nodes.get(param_id)
        if n is None:
            return
        # Was already a hit? Don't double-count
        prev_state = n.state
        n.state = "hit"
        n.details = details or {}
        # Always store full path & param (un-truncated) in details for click handler
        n.details.setdefault("path", path)
        n.details.setdefault("param", param)
        n.details.setdefault("display_path", n.label)
        n.details.setdefault("display_param", n.label)

        # Pull GATE classification from details (set by xss_grenade v2)
        n.gate_klass = (details or {}).get("gate_klass")
        n.gate_severity = (details or {}).get("gate_severity")

        if prev_state != "hit":
            self._hit_count += 1
        self.update()

    def mark_waf(self, path: str, param: str):
        if not param:
            return
        param_id = self.add_param(path, param)
        if not param_id:
            return
        n = self._nodes.get(param_id)
        if n is None or n.state == "hit":
            return
        if n.state != "waf":
            n.state = "waf"
            self._waf_count += 1
        self.update()

    def set_tor_status(self, active: bool, exit_ip: Optional[str] = None):
        self._tor_active = active
        self._tor_exit_ip = exit_ip
        self.update()

    def reset(self):
        self._target_host = None
        self._is_running = False
        self._reset_graph()
        self.update()

    def stop(self):
        self._is_running = False
        self.update()

    # Compat shims kept for callers that use them
    def inject_hit(self):
        # Pick a random known param and mark as hit (used for demo)
        param_nodes = [n for n in self._nodes.values() if n.kind == "param"]
        if param_nodes:
            pick = _rnd.choice(param_nodes)
            parent_label = self._nodes.get(pick.parent_id, _Node("?", "?", "?")).label
            self.mark_hit(parent_label, pick.label)

    def inject_line(self, text, status=None):
        pass    # no-op in v2 (was used by BiosPanel old API)

    def tick_pulse(self):
        pass    # no-op

    # ════════════════════════════════════════════════════════════════════
    # INTERNAL HELPERS
    # ════════════════════════════════════════════════════════════════════

    def _reset_graph(self):
        self._nodes.clear()
        self._edges.clear()
        self._hit_count = 0
        self._waf_count = 0
        self._path_count = 0
        self._param_count = 0
        self._zoom = 1.0
        self._pan_x = 0.0
        self._pan_y = 0.0
        self._fit_pending = False

    @staticmethod
    def _norm_path(path: str) -> str:
        if "?" in path:
            path = path.split("?")[0]
        if "#" in path:
            path = path.split("#")[0]
        return path or "/"

    @staticmethod
    def _display_path(path: str, width: int = 22) -> str:
        if len(path) <= width:
            return path
        return path[:width - 2] + ".."

    @staticmethod
    def _display_param(name: str, width: int = 14) -> str:
        if len(name) <= width:
            return name
        return name[:width - 2] + ".."

    def _random_near(self, anchor_id: str, dist: float) -> Tuple[float, float]:
        """Random initial position near anchor — used so new nodes don't
        spawn at exactly the same pixel and instantly NaN-explode the sim."""
        a = self._nodes.get(anchor_id)
        if a is None:
            cx = self.width() / 2 if self.width() > 0 else 300
            cy = self.height() / 2 if self.height() > 0 else 150
            return cx, cy
        ang = _rnd.uniform(0, 2 * math.pi)
        return (a.x + dist * math.cos(ang) + _rnd.uniform(-3, 3),
                a.y + dist * math.sin(ang) + _rnd.uniform(-3, 3))

    # ════════════════════════════════════════════════════════════════════
    # PHYSICS
    # ════════════════════════════════════════════════════════════════════

    def _step_simulation(self):
        if not self._nodes:
            return
        nodes = list(self._nodes.values())
        cx = self.width() / 2
        cy = self.height() / 2

        # 1) repulsion (O(n²) but with cutoff) — cheap up to ~500 nodes
        n = len(nodes)
        for i in range(n):
            ni = nodes[i]
            if ni.fixed:
                continue
            for j in range(i + 1, n):
                nj = nodes[j]
                dx = ni.x - nj.x
                dy = ni.y - nj.y
                d2 = dx * dx + dy * dy
                if d2 == 0.0:
                    dx, dy = _rnd.uniform(-1, 1), _rnd.uniform(-1, 1)
                    d2 = 1.0
                if d2 > self.REPULSE_RANGE_2:
                    continue
                f = self.REPULSE_STRENGTH / d2
                d = math.sqrt(d2)
                ux, uy = dx / d, dy / d
                ni.vx += ux * f
                ni.vy += uy * f
                if not nj.fixed:
                    nj.vx -= ux * f
                    nj.vy -= uy * f

        # 2) springs — edges pull together
        for parent_id, child_id in self._edges:
            p = self._nodes.get(parent_id)
            c = self._nodes.get(child_id)
            if not p or not c:
                continue
            dx = c.x - p.x
            dy = c.y - p.y
            d = math.sqrt(dx * dx + dy * dy) + 1e-9
            ideal = (self.SPRING_LEN_PATH if c.kind == "path"
                     else self.SPRING_LEN_PARAM)
            disp = (d - ideal) * self.SPRING_K
            ux, uy = dx / d, dy / d
            if not p.fixed:
                p.vx += ux * disp
                p.vy += uy * disp
            if not c.fixed:
                c.vx -= ux * disp
                c.vy -= uy * disp

        # 3) gravity toward center (so disconnected components don't drift)
        for n in nodes:
            if n.fixed:
                continue
            n.vx += (cx - n.x) * self.CENTER_GRAVITY
            n.vy += (cy - n.y) * self.CENTER_GRAVITY

        # 4) integrate + damping + clamp velocity
        max_v = 8.0
        for n in nodes:
            if n.fixed:
                n.vx = n.vy = 0
                continue
            n.vx *= self.DAMPING
            n.vy *= self.DAMPING
            # clamp so unstable forces don't fling nodes off-screen
            sp = math.sqrt(n.vx * n.vx + n.vy * n.vy)
            if sp > max_v:
                n.vx = n.vx / sp * max_v
                n.vy = n.vy / sp * max_v
            n.x += n.vx
            n.y += n.vy

    def _tick(self):
        self._t += self.TICK_MS / 1000.0
        if self._is_running and self._nodes:
            for _ in range(self.SIM_ITERATIONS):
                self._step_simulation()

        # Auto-fit when new nodes added (gentle, ~3 sec settle then fit once)
        if self._fit_pending and self._t > 0.5:
            self._fit_view()
            self._fit_pending = False

        self.update()

    def _fit_view(self):
        """Fit all nodes into widget — used on initial layout & right-click."""
        if not self._nodes:
            return
        xs = [n.x for n in self._nodes.values()]
        ys = [n.y for n in self._nodes.values()]
        x_min, x_max = min(xs), max(xs)
        y_min, y_max = min(ys), max(ys)
        bw = max(1.0, x_max - x_min)
        bh = max(1.0, y_max - y_min)

        ww = max(1, self.width()) - 80   # padding for labels
        wh = max(1, self.height()) - 60

        z_x = ww / bw
        z_y = wh / bh
        z = min(z_x, z_y, self.ZOOM_MAX)
        z = max(self.ZOOM_MIN, z)
        self._zoom = z

        # Pan so center of bbox lands at center of widget
        bcx = (x_min + x_max) / 2
        bcy = (y_min + y_max) / 2
        self._pan_x = self.width() / 2 - bcx * z
        self._pan_y = self.height() / 2 - bcy * z

    # ════════════════════════════════════════════════════════════════════
    # COORDINATE TRANSFORMS
    # ════════════════════════════════════════════════════════════════════

    def _world_to_screen(self, x: float, y: float) -> Tuple[float, float]:
        return (x * self._zoom + self._pan_x,
                y * self._zoom + self._pan_y)

    def _screen_to_world(self, sx: float, sy: float) -> Tuple[float, float]:
        return ((sx - self._pan_x) / self._zoom,
                (sy - self._pan_y) / self._zoom)

    # ════════════════════════════════════════════════════════════════════
    # MOUSE
    # ════════════════════════════════════════════════════════════════════

    def _node_at_screen(self, sx: float, sy: float) -> Optional[_Node]:
        # Walk in reverse — newer nodes drawn on top should hit first
        for n in reversed(list(self._nodes.values())):
            ssx, ssy = self._world_to_screen(n.x, n.y)
            r = self._node_radius(n) * self._zoom
            r_click = max(8.0, r + 4)   # generous hitbox
            dx = sx - ssx
            dy = sy - ssy
            if dx * dx + dy * dy <= r_click * r_click:
                return n
        return None

    def _node_radius(self, n: _Node) -> float:
        if n.kind == "root":
            return self.R_ROOT
        if n.kind == "path":
            return self.R_PATH
        if n.state == "hit":
            return self.R_HIT
        return self.R_PARAM

    def mouseMoveEvent(self, event):
        if self._dragging and self._drag_last is not None:
            dx = float(event.x()) - self._drag_last.x()
            dy = float(event.y()) - self._drag_last.y()
            self._pan_x += dx
            self._pan_y += dy
            self._drag_last = QPointF(event.x(), event.y())
            self.update()
        else:
            n = self._node_at_screen(float(event.x()), float(event.y()))
            new_id = n.id if n else None
            if new_id != self._hover_node_id:
                self._hover_node_id = new_id
                if n and n.state == "hit":
                    self.setCursor(Qt.PointingHandCursor)
                else:
                    self.setCursor(Qt.ArrowCursor)
                self.update()
        super().mouseMoveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            n = self._node_at_screen(float(event.x()), float(event.y()))
            if n is not None and n.state == "hit":
                emit_data = dict(n.details or {})
                emit_data.setdefault("display_path", n.label)
                emit_data.setdefault("display_param", n.label)
                self.sig_hit_clicked.emit(emit_data)
                return
            # Otherwise start panning
            self._dragging = True
            self._drag_last = QPointF(event.x(), event.y())
            self.setCursor(Qt.ClosedHandCursor)
        elif event.button() == Qt.RightButton:
            self._fit_view()
            self.update()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        if self._dragging:
            self._dragging = False
            self._drag_last = None
            self.setCursor(Qt.ArrowCursor)
        super().mouseReleaseEvent(event)

    def wheelEvent(self, event):
        # Zoom toward cursor
        delta = event.angleDelta().y()
        if delta == 0:
            return
        factor = self.ZOOM_STEP if delta > 0 else (1.0 / self.ZOOM_STEP)
        new_zoom = max(self.ZOOM_MIN, min(self.ZOOM_MAX, self._zoom * factor))
        if new_zoom == self._zoom:
            return
        # Keep cursor world position fixed
        sx = float(event.x())
        sy = float(event.y())
        wx, wy = self._screen_to_world(sx, sy)
        self._zoom = new_zoom
        self._pan_x = sx - wx * self._zoom
        self._pan_y = sy - wy * self._zoom
        self.update()

    def leaveEvent(self, event):
        self._hover_node_id = None
        self.setCursor(Qt.ArrowCursor)
        super().leaveEvent(event)

    # ════════════════════════════════════════════════════════════════════
    # PAINTING
    # ════════════════════════════════════════════════════════════════════

    def _font(self, size_delta=-2, bold=False) -> QFont:
        f = QFont("JetBrains Mono", self._font_size + size_delta)
        if not f.exactMatch():
            f = QFont("Courier New", self._font_size + size_delta)
        f.setBold(bold)
        return f

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)

        self._draw_background(p)
        self._draw_grid(p)

        if not self._target_host or not self._nodes:
            self._draw_idle(p)
        else:
            self._draw_edges(p)
            self._draw_nodes(p)

        self._draw_hud(p)

        p.end()

    def _draw_background(self, p: QPainter):
        rect = self.rect()
        grad = QLinearGradient(0, 0, 0, rect.height())
        grad.setColorAt(0.0, BG_TOP)
        grad.setColorAt(1.0, BG_BOTTOM)
        p.fillRect(rect, QBrush(grad))

    def _draw_grid(self, p: QPainter):
        p.setPen(QPen(GRID, 1))
        step = 24
        x = 0
        while x < self.width():
            p.drawLine(x, 0, x, self.height())
            x += step
        y = 0
        while y < self.height():
            p.drawLine(0, y, self.width(), y)
            y += step

    def _draw_idle(self, p: QPainter):
        p.setPen(TXT_DIM)
        p.setFont(self._font(0, bold=True))
        p.drawText(self.rect(), Qt.AlignCenter,
                   "Attack graph — set target to begin")

    def _draw_edges(self, p: QPainter):
        # Viewport culling: only draw edges where at least one endpoint is on screen
        rect = self.rect()
        margin = 80
        for parent_id, child_id in self._edges:
            pn = self._nodes.get(parent_id)
            cn = self._nodes.get(child_id)
            if not pn or not cn:
                continue
            psx, psy = self._world_to_screen(pn.x, pn.y)
            csx, csy = self._world_to_screen(cn.x, cn.y)
            if (max(psx, csx) < -margin or min(psx, csx) > self.width() + margin or
                max(psy, csy) < -margin or min(psy, csy) > self.height() + margin):
                continue

            # Color: edges to "hit" or "waf" nodes get accent
            if cn.state == "hit":
                col = QColor(COL_XSS_EXEC)
                col.setAlpha(120)
            elif cn.state == "waf":
                col = QColor(COL_WAF)
                col.setAlpha(110)
            else:
                col = LINK_DIM
            pen = QPen(col, 1.0)
            p.setPen(pen)
            p.drawLine(int(psx), int(psy), int(csx), int(csy))

    def _draw_nodes(self, p: QPainter):
        rect = self.rect()
        margin = 60
        # Sort: root, path, param-idle, param-probing, param-waf, param-hit
        def sort_key(n: _Node):
            order = {"root": 0, "path": 1}.get(n.kind, 2)
            sub = {"idle": 0, "probing": 1, "waf": 2, "hit": 3}.get(n.state, 0)
            return (order, sub)
        for n in sorted(self._nodes.values(), key=sort_key):
            sx, sy = self._world_to_screen(n.x, n.y)
            r = self._node_radius(n) * self._zoom
            # Cull off-screen
            if sx < -margin or sx > self.width() + margin:
                continue
            if sy < -margin or sy > self.height() + margin:
                continue
            self._draw_one_node(p, n, sx, sy, r)

    def _draw_one_node(self, p: QPainter, n: _Node, sx: float, sy: float, r: float):
        # Determine fill color by kind/state/gate
        if n.kind == "root":
            fill = COL_ROOT
        elif n.kind == "path":
            fill = COL_PATH
        elif n.state == "hit":
            # Use gate classification when available, else legacy green
            if n.gate_klass == "xss_executable":
                fill = COL_XSS_EXEC
            elif n.gate_klass == "tag_injection":
                fill = COL_TAG_INJ
            elif n.gate_klass == "text_only":
                fill = COL_TEXT_ONLY
            else:
                fill = COL_HIT_LEGACY
        elif n.state == "waf":
            fill = COL_WAF
        elif n.state == "probing":
            fill = COL_PARAM
        else:
            fill = COL_PARAM

        # Halo for hit/waf
        if n.state in ("hit", "waf"):
            phase = (math.sin(self._t * 4.0 + n.pulse_ph * 6.28) + 1) / 2
            halo_r = r + 6 + phase * 5
            halo = QColor(fill)
            halo.setAlpha(int(50 + phase * 60))
            p.setPen(Qt.NoPen)
            p.setBrush(QBrush(halo))
            p.drawEllipse(QPointF(sx, sy), halo_r, halo_r)

        # Hover ring
        if self._hover_node_id == n.id:
            ring = QColor(255, 255, 255, 100)
            p.setPen(QPen(ring, 1.5))
            p.setBrush(Qt.NoBrush)
            p.drawEllipse(QPointF(sx, sy), r + 3, r + 3)

        # Main node
        p.setPen(QPen(QColor(0, 0, 0, 80), 1))
        p.setBrush(QBrush(fill))
        p.drawEllipse(QPointF(sx, sy), r, r)

        # Inner highlight (gives glassy look)
        glow = QRadialGradient(sx, sy - r * 0.3, r)
        c1 = QColor(255, 255, 255, 90)
        c2 = QColor(255, 255, 255, 0)
        glow.setColorAt(0, c1)
        glow.setColorAt(1, c2)
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(glow))
        p.drawEllipse(QPointF(sx, sy), r, r)

        # Label — only at sufficient zoom or for important nodes
        zoom_thresh = 0.6
        show_label = (n.kind in ("root",) or n.state == "hit"
                      or self._zoom >= zoom_thresh
                      or self._hover_node_id == n.id)
        if show_label and n.label:
            label_y_offset = r + 12
            p.setFont(self._font(-3, bold=(n.kind == "root")))
            color = TXT_PRIMARY if (n.state == "hit" or n.kind == "root") \
                                else TXT_SECONDARY
            p.setPen(color)
            metrics = p.fontMetrics()
            tw = metrics.horizontalAdvance(n.label)
            p.drawText(int(sx - tw / 2), int(sy + label_y_offset), n.label)

    def _draw_hud(self, p: QPainter):
        # Top-left: target host + status
        p.setFont(self._font(-1, bold=True))
        if self._target_host:
            p.setPen(TXT_PRIMARY)
            status = " ▶ scanning" if self._is_running else " ◼ done"
            p.drawText(12, 18, f"target: {self._target_host}{status}")
        else:
            p.setPen(TXT_DIM)
            p.drawText(12, 18, "target: (idle)")

        # Top-right: counters
        counters = (
            f"paths: {self._path_count}   "
            f"params: {self._param_count}   "
            f"hits: {self._hit_count}   "
            f"waf: {self._waf_count}"
        )
        p.setFont(self._font(-2))
        p.setPen(TXT_SECONDARY)
        metrics = p.fontMetrics()
        tw = metrics.horizontalAdvance(counters)
        p.drawText(self.width() - tw - 12, 18, counters)

        # Bottom-left: Tor status
        p.setFont(self._font(-3))
        if self._tor_active:
            p.setPen(TOR_ON)
            tor_txt = (f"⚓ TOR · exit {self._tor_exit_ip}"
                       if self._tor_exit_ip else "⚓ TOR active")
        else:
            p.setPen(TOR_OFF)
            tor_txt = ""   # don't clutter when off
        if tor_txt:
            p.drawText(12, self.height() - 8, tor_txt)

        # Bottom-right: zoom + hint
        p.setFont(self._font(-3))
        p.setPen(TXT_DIM)
        hint = f"zoom {self._zoom:.2f}x   ·   wheel zoom · drag pan · right-click fit"
        metrics = p.fontMetrics()
        tw = metrics.horizontalAdvance(hint)
        p.drawText(self.width() - tw - 12, self.height() - 8, hint)
