"""Read-only evidence about copper-zone fill for the PCB quality gate.

Nothing here writes a board file. ``scan_zone_fill`` inspects the saved board text and
``drc_outcome_changes`` compares two DRC JSON reports, so a caller can tell whether the
fill stored in the board still matches what KiCad would compute.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field

from .drc_report import Report, report_entries

_ZONE_START = re.compile(r"\(zone(?=[\s)])")
_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|[()]')
_NAME = re.compile(r'\((?:net_name|net)\s+"((?:\\.|[^"\\])*)"\)')
_LAYERS = re.compile(r"\((?:layers|layer)((?:\s+\"(?:\\.|[^\"\\])*+\")++)\s*\)")
_LAYER_NAME = re.compile(r'"((?:\\.|[^"\\])*)"')
_FILL_ENABLED = re.compile(r"\(fill\s+yes[\s)]")

_COMPARED_KEYS = ("violations", "unconnected_items")


@dataclass(frozen=True, slots=True)
class ZoneFillScan:
    """Result of inspecting every copper zone in a saved board."""

    copper_zones: int = 0
    unfilled: list[str] = field(default_factory=list)


def _zone_blocks(text: str) -> Iterator[str]:
    for start in _ZONE_START.finditer(text):
        depth = 0
        for token in _TOKEN.finditer(text, start.start()):
            if token.group() == "(":
                depth += 1
            elif token.group() == ")":
                depth -= 1
                if depth == 0:
                    yield text[start.start() : token.end()]
                    break


def _is_copper(layer: str) -> bool:
    return layer.endswith(".Cu")


def scan_zone_fill(board_text: str) -> ZoneFillScan:
    """Find copper zones that carry no stored fill.

    Rule areas (keepouts) and zones on non-copper layers are not copper pours and are
    skipped. A copper zone counts as filled when it has at least one ``filled_polygon``.
    """
    copper = 0
    unfilled: list[str] = []
    for block in _zone_blocks(board_text):
        layers_match = _LAYERS.search(block)
        if layers_match is None or "(keepout" in block:
            continue
        layers = _LAYER_NAME.findall(layers_match.group(1))
        if not any(_is_copper(layer) for layer in layers):
            continue
        copper += 1
        if "(filled_polygon" in block:
            continue
        name_match = _NAME.search(block)
        name = name_match.group(1) if name_match and name_match.group(1) else "(no net)"
        reason = "no stored fill" if _FILL_ENABLED.search(block) else "fill disabled"
        unfilled.append(f"zone on net {name} ({', '.join(layers)}): {reason}")
    return ZoneFillScan(copper_zones=copper, unfilled=unfilled)


def _signature(report: Report, key: str) -> Counter[tuple[str, tuple[str, ...]]]:
    signature: Counter[tuple[str, tuple[str, ...]]] = Counter()
    for entry in report_entries(report, key):
        items = entry.get("items")
        descriptions = (
            sorted(str(item.get("description", "")) for item in items if isinstance(item, dict))
            if isinstance(items, list)
            else []
        )
        signature[(str(entry.get("type", "")), tuple(descriptions))] += 1
    return signature


def drc_outcome_changes(stored: Report, refilled: Report) -> list[str]:
    """Describe how a fresh refill changes the DRC result compared with the stored fill."""
    changes: list[str] = []
    for key in _COMPARED_KEYS:
        before = _signature(stored, key)
        after = _signature(refilled, key)
        if before == after:
            continue
        gone = sum((before - after).values())
        new = sum((after - before).values())
        changes.append(
            f"{key} {sum(before.values())} -> {sum(after.values())} "
            f"({gone} no longer reported, {new} newly reported)"
        )
    return changes
