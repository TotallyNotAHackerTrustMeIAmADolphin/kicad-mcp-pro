"""KiCad 10 IPC action: native wx companion for the active PCB Editor.

KiCad launches this file in its managed Python environment, which includes
wxPython on the supported KiCad desktop runtime. No PCB mutations occur here.
"""

from __future__ import annotations

import sys
import threading
import webbrowser

try:
    import wx
except ImportError:
    print(
        "KiCad MCP Pro Companion requires KiCad's wxPython-enabled desktop runtime.",
        file=sys.stderr,
    )
    raise SystemExit(1) from None

from companion_core import (
    BoardSummary,
    backend_status,
    board_summary,
    dashboard_url,
    repair_ipc_dependencies,
    sync_board_context,
)

BACKGROUND = "#101720"
PANEL = "#192432"
FOREGROUND = "#e9eff8"
SECONDARY = "#9cb0c6"
ACCENT = "#8ec5fc"
CONNECTED = "#62ddb4"


def _text(
    parent: wx.Window,
    value: str,
    *,
    size: int = 10,
    color: str = FOREGROUND,
    bold: bool = False,
) -> wx.StaticText:
    item = wx.StaticText(parent, label=value)
    font = item.GetFont()
    font.SetPointSize(size)
    if bold:
        font.SetWeight(wx.FONTWEIGHT_BOLD)
    item.SetFont(font)
    item.SetForegroundColour(wx.Colour(color))
    return item


def _card(parent: wx.Panel, title: str) -> tuple[wx.Panel, wx.BoxSizer]:
    outer = wx.Panel(parent)
    outer.SetBackgroundColour(wx.Colour(PANEL))
    content = wx.BoxSizer(wx.VERTICAL)
    heading = _text(outer, title, size=10, color=ACCENT, bold=True)
    content.Add(heading, 0, wx.BOTTOM, 10)
    outer.SetSizer(content)
    return outer, content


class CompanionFrame(wx.Frame):
    """Portable modeless KiCad companion; intentionally read-only."""

    def __init__(self) -> None:
        super().__init__(
            None,
            title="KiCad MCP Pro · Companion",
            size=(585, 650),
            style=wx.DEFAULT_FRAME_STYLE,
        )
        self.SetMinSize((520, 575))
        self.SetBackgroundColour(wx.Colour(BACKGROUND))
        self.board: BoardSummary | None = None
        self.ready = False

        panel = wx.Panel(self)
        panel.SetBackgroundColour(wx.Colour(BACKGROUND))
        layout = wx.BoxSizer(wx.VERTICAL)

        layout.Add(_text(panel, "KiCad MCP Pro", size=20, bold=True), 0, wx.BOTTOM, 4)
        layout.Add(
            _text(panel, "PCB Editor companion  ·  read-only preview", color=SECONDARY),
            0,
            wx.BOTTOM,
            21,
        )

        board_panel, board_content = _card(panel, "ACTIVE PCB")
        self.board_label = _text(board_panel, "Connecting to KiCad…", size=13, bold=True)
        board_content.Add(self.board_label, 0, wx.BOTTOM, 8)
        self.board_details = _text(
            board_panel, "Footprints  ·  Nets  ·  Selection", color=SECONDARY
        )
        board_content.Add(self.board_details, 0)
        layout.Add(board_panel, 0, wx.EXPAND | wx.BOTTOM, 14)

        service_panel, service_content = _card(panel, "ENGINEERING SERVICE")
        self.service_label = _text(service_panel, "Checking local backend…", color=SECONDARY)
        service_content.Add(self.service_label, 0)
        layout.Add(service_panel, 0, wx.EXPAND | wx.BOTTOM, 14)

        tools_panel, tools_content = _card(panel, "WORKSPACE")
        tools_content.Add(
            _text(
                tools_panel,
                "Continue in the installed MCP Pro dashboard for engineering tools.",
                color=SECONDARY,
            ),
            0,
            wx.BOTTOM,
            12,
        )
        actions = wx.BoxSizer(wx.HORIZONTAL)
        self.dashboard_btn = wx.Button(tools_panel, label="Open dashboard")
        self.review_btn = wx.Button(tools_panel, label="Review tools")
        actions.Add(self.dashboard_btn, 0, wx.RIGHT, 10)
        actions.Add(self.review_btn, 0)
        tools_content.Add(actions, 0)
        layout.Add(tools_panel, 0, wx.EXPAND | wx.BOTTOM, 14)

        self.refresh_btn = wx.Button(panel, label="Refresh KiCad and backend status")
        self.sync_btn = wx.Button(panel, label="Sync active PCB context to MCP Pro")
        self.repair_btn = wx.Button(panel, label="Repair KiCad IPC dependencies")
        layout.Add(self.refresh_btn, 0, wx.EXPAND | wx.BOTTOM, 10)
        layout.Add(self.sync_btn, 0, wx.EXPAND | wx.BOTTOM, 10)
        layout.Add(self.repair_btn, 0, wx.EXPAND | wx.BOTTOM, 12)
        self.repair_btn.Hide()
        layout.Add(
            _text(
                panel,
                "Context sync is user-initiated. No changes are applied to the PCB.",
                color=SECONDARY,
            ),
            0,
            wx.TOP,
            3,
        )

        panel.SetSizer(layout)
        outer = wx.BoxSizer(wx.VERTICAL)
        outer.Add(panel, 1, wx.EXPAND | wx.ALL, 23)
        self.SetSizer(outer)

        self.dashboard_btn.Bind(wx.EVT_BUTTON, lambda _event: self.open_dashboard())
        self.review_btn.Bind(wx.EVT_BUTTON, lambda _event: self.open_dashboard("#tools-catalog"))
        self.refresh_btn.Bind(wx.EVT_BUTTON, lambda _event: self.refresh())
        self.sync_btn.Bind(wx.EVT_BUTTON, self.sync_context)
        self.repair_btn.Bind(wx.EVT_BUTTON, self.repair_dependencies)
        self.Centre()
        wx.CallAfter(self.refresh)

    def refresh(self) -> None:
        try:
            summary = board_summary()
        except ModuleNotFoundError as exc:
            self.board = None
            self.board_label.SetLabel("KiCad IPC dependencies incomplete")
            self.board_details.SetLabel(f"Missing Python module: {exc.name or 'unknown'}")
            self.repair_btn.Show()
            self.board_label.SetForegroundColour(wx.Colour(SECONDARY))
        except Exception:
            self.board = None
            self.repair_btn.Hide()
            self.board_label.SetLabel("KiCad PCB context unavailable")
            self.board_details.SetLabel("Open a saved PCB and enable KiCad's IPC API.")
            self.board_label.SetForegroundColour(wx.Colour(SECONDARY))
        else:
            self.repair_btn.Hide()
            self.board = summary
            self.board_label.SetLabel(summary.name or "Untitled PCB")
            self.board_details.SetLabel(
                f"{summary.project}  ·  {summary.footprints} footprints  ·  "
                f"{summary.nets} nets  ·  {summary.selected} selected"
            )
            self.board_label.SetForegroundColour(wx.Colour(FOREGROUND))

        self.ready, status = backend_status()
        self.service_label.SetLabel(status)
        self.service_label.SetForegroundColour(wx.Colour(CONNECTED if self.ready else SECONDARY))
        self.dashboard_btn.Enable(self.ready)
        self.review_btn.Enable(self.ready)
        self.sync_btn.Enable(self.ready and self.board is not None)
        self.Layout()

    def open_dashboard(self, fragment: str = "") -> None:
        if not self.ready:
            return
        try:
            url = dashboard_url(fragment)
        except ValueError:
            self.service_label.SetLabel("Dashboard URL must use loopback.")
            return
        webbrowser.open(url)

    def repair_dependencies(self, _event: wx.CommandEvent) -> None:
        confirmation = wx.MessageBox(
            "Download and install missing Python packages into KiCad's private "
            "plugin environment? This does not change system Python. "
            "An internet connection may be required.",
            "Repair KiCad MCP Pro IPC dependencies",
            wx.YES_NO | wx.ICON_QUESTION,
        )
        if confirmation != wx.YES:
            return
        self.repair_btn.Enable(False)
        self.service_label.SetLabel("Repairing KiCad IPC dependencies…")

        def worker() -> None:
            try:
                repair_ipc_dependencies()
            except RuntimeError:
                wx.CallAfter(
                    self._repair_done,
                    "Repair failed; check network access and plugin logs.",
                    False,
                )
            else:
                wx.CallAfter(self._repair_done, "Dependencies installed.", True)

        threading.Thread(target=worker, daemon=True, name="kicad-mcp-ipc-repair").start()

    def _repair_done(self, message: str, success: bool) -> None:
        self.repair_btn.Enable(True)
        self.service_label.SetLabel(message)
        if success:
            self.refresh()

    def sync_context(self, _event: wx.CommandEvent) -> None:
        if not self.ready or self.board is None:
            return
        snapshot = self.board
        self.sync_btn.Enable(False)
        self.service_label.SetLabel("Syncing context…")

        def worker() -> None:
            try:
                sync_board_context(snapshot)
            except Exception:
                wx.CallAfter(self._sync_done, "Context sync failed; check backend access.", False)
            else:
                wx.CallAfter(self._sync_done, "PCB context synced.", True)

        threading.Thread(target=worker, daemon=True, name="kicad-mcp-context-sync").start()

    def _sync_done(self, message: str, success: bool) -> None:
        self.service_label.SetLabel(message)
        self.service_label.SetForegroundColour(wx.Colour(CONNECTED if success else SECONDARY))
        self.sync_btn.Enable(self.ready and self.board is not None)


def main() -> int:
    app = wx.App(redirect=False)
    frame = CompanionFrame()
    frame.Show()
    app.MainLoop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
