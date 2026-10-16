"""Headless wx interaction contracts for the KiCad IPC Companion.

wxPython is supplied by KiCad's runtime. CI does not have to install a desktop
environment or mutate KiCad: these tests exercise GUI actions with wx fakes.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "packages" / "kicad-plugin"


@pytest.fixture
def ui(monkeypatch: pytest.MonkeyPatch) -> tuple[types.ModuleType, types.ModuleType]:
    class FakeFrame:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.calls = Mock()

        def __getattr__(self, name: str) -> Mock:
            return getattr(self.calls, name)

    wx = types.ModuleType("wx")
    wx.Frame = FakeFrame
    wx.Panel = Mock(side_effect=lambda *a, **k: Mock())
    wx.BoxSizer = Mock(side_effect=lambda *a, **k: Mock())
    wx.StaticText = Mock(side_effect=lambda *a, **k: Mock())
    wx.Button = Mock(side_effect=lambda *a, **k: Mock())
    wx.Colour = lambda value: value
    wx.App = Mock()
    wx.CallAfter = lambda callback, *args: callback(*args)
    wx.MessageBox = Mock()
    for name in ("VERTICAL", "HORIZONTAL", "EXPAND", "BOTTOM", "ALL", "TOP", "RIGHT"):
        setattr(wx, name, 0)
    wx.DEFAULT_FRAME_STYLE = 0
    wx.FONTWEIGHT_BOLD = 700
    wx.EVT_BUTTON = 100
    wx.YES = 1
    wx.NO = 0
    wx.YES_NO = 2
    wx.ICON_QUESTION = 4
    wx.MessageBox.return_value = wx.NO

    monkeypatch.syspath_prepend(str(PLUGIN))
    monkeypatch.setitem(sys.modules, "wx", wx)
    spec = importlib.util.spec_from_file_location(
        "_test_native_companion_window", PLUGIN / "companion.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, wx


def _ready(ui: tuple[types.ModuleType, types.ModuleType], monkeypatch: pytest.MonkeyPatch):
    module, _wx = ui
    monkeypatch.setattr(
        module,
        "board_summary",
        lambda: module.BoardSummary("test.kicad_pcb", "test", 7, 11, 2),
    )
    monkeypatch.setattr(module, "backend_status", lambda: (True, "Connected"))
    return module.CompanionFrame()


def test_window_shows_board_and_enables_read_only_actions(
    ui: tuple[types.ModuleType, types.ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    frame = _ready(ui, monkeypatch)
    assert frame.board is not None
    assert frame.board.footprints == 7
    assert frame.ready
    frame.board_label.SetLabel.assert_called_with("test.kicad_pcb")
    frame.board_details.SetLabel.assert_called_with(
        "test  ·  7 footprints  ·  11 nets  ·  2 selected"
    )
    frame.dashboard_btn.Enable.assert_called_with(True)
    frame.review_btn.Enable.assert_called_with(True)
    frame.sync_btn.Enable.assert_called_with(True)
    frame.repair_btn.Hide.assert_called()


def test_missing_board_disables_context_sync(
    ui: tuple[types.ModuleType, types.ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    module, _wx = ui

    def offline() -> object:
        raise OSError("Board is closed")

    monkeypatch.setattr(module, "board_summary", offline)
    monkeypatch.setattr(module, "backend_status", lambda: (False, "Not connected"))
    frame = module.CompanionFrame()
    assert frame.board is None
    assert not frame.ready
    frame.board_label.SetLabel.assert_called_with("KiCad PCB context unavailable")
    frame.dashboard_btn.Enable.assert_called_with(False)
    frame.sync_btn.Enable.assert_called_with(False)


def test_missing_ipc_dependency_offers_repair(
    ui: tuple[types.ModuleType, types.ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    module, _wx = ui

    def missing() -> object:
        raise ModuleNotFoundError("Missing dependency", name="google")

    monkeypatch.setattr(module, "board_summary", missing)
    monkeypatch.setattr(module, "backend_status", lambda: (False, "Not connected"))
    frame = module.CompanionFrame()
    frame.board_label.SetLabel.assert_called_with("KiCad IPC dependencies incomplete")
    frame.board_details.SetLabel.assert_called_with("Missing Python module: google")
    frame.repair_btn.Show.assert_called()


def test_dashboard_and_review_actions_use_loopback_only(
    ui: tuple[types.ModuleType, types.ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    module, _wx = ui
    frame = _ready(ui, monkeypatch)
    browser = Mock()
    urls = Mock(side_effect=lambda part="": "http://127.0.0.1:3334/ui" + part)
    monkeypatch.setattr(module.webbrowser, "open", browser)
    monkeypatch.setattr(module, "dashboard_url", urls)
    frame.open_dashboard()
    frame.open_dashboard("#tools-catalog")
    assert browser.call_count == 2
    urls.assert_any_call("#tools-catalog")
    browser.assert_any_call("http://127.0.0.1:3334/ui#tools-catalog")


def test_unsafe_dashboard_url_never_opens_browser(
    ui: tuple[types.ModuleType, types.ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    module, _wx = ui
    frame = _ready(ui, monkeypatch)
    monkeypatch.setattr(module, "dashboard_url", Mock(side_effect=ValueError("Not loopback")))
    browser = Mock()
    monkeypatch.setattr(module.webbrowser, "open", browser)
    frame.open_dashboard()
    browser.assert_not_called()
    frame.service_label.SetLabel.assert_called_with("Dashboard URL must use loopback.")


def test_context_sync_success_and_failure(
    ui: tuple[types.ModuleType, types.ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    module, _wx = ui
    frame = _ready(ui, monkeypatch)

    class ImmediateThread:
        def __init__(self, *, target: Callable[[], None], **_kwargs: object) -> None:
            self.target = target

        def start(self) -> None:
            self.target()

    monkeypatch.setattr(module, "threading", types.SimpleNamespace(Thread=ImmediateThread))
    sync = Mock()
    monkeypatch.setattr(module, "sync_board_context", sync)
    frame.sync_context(None)
    sync.assert_called_once_with(frame.board)
    frame.service_label.SetLabel.assert_called_with("PCB context synced.")

    sync.side_effect = OSError("backend disconnected")
    frame.sync_context(None)
    frame.service_label.SetLabel.assert_called_with("Context sync failed; check backend access.")


def test_repair_requires_confirmation_and_reports_completion(
    ui: tuple[types.ModuleType, types.ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    module, wx = ui
    frame = _ready(ui, monkeypatch)

    class ImmediateThread:
        def __init__(self, *, target: Callable[[], None], **_kwargs: object) -> None:
            self.target = target

        def start(self) -> None:
            self.target()

    monkeypatch.setattr(module, "threading", types.SimpleNamespace(Thread=ImmediateThread))
    repair = Mock()
    monkeypatch.setattr(module, "repair_ipc_dependencies", repair)
    frame.repair_dependencies(None)
    repair.assert_not_called()

    wx.MessageBox.return_value = wx.YES
    frame.repair_dependencies(None)
    repair.assert_called_once_with()

    repair.side_effect = RuntimeError("No connection")
    frame.repair_dependencies(None)
    frame.service_label.SetLabel.assert_called_with(
        "Repair failed; check network access and plugin logs."
    )


def test_entrypoint_runs_wx_mainloop(
    ui: tuple[types.ModuleType, types.ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    module, wx = ui
    monkeypatch.setattr(module, "board_summary", lambda: module.BoardSummary("", "", 0, 0, 0))
    monkeypatch.setattr(module, "backend_status", lambda: (False, "No backend"))
    assert module.main() == 0
    wx.App.assert_called_once_with(redirect=False)
    wx.App.return_value.MainLoop.assert_called_once_with()
