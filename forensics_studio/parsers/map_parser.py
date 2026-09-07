from __future__ import annotations

import re
from pathlib import Path

from forensics_studio.models.types import MapFileEntry
from forensics_studio.parsers.base import BaseMapParser


class GenericMapParser(BaseMapParser):
    """Parse common map formats used by SquashFS tooling.

    Supported line styles:
    1) pipe-delimited: path|size|fragment|blocks(comma-separated)
    2) whitespace key-value: path=<p> size=<n> fragment=<id> blocks=<1,2>
    3) csv-like with commas and no headers: path,size,fragment,blocks
    """

    _ws_pattern = re.compile(
        r"path=(?P<path>\S+)\s+size=(?P<size>\d+)\s+fragment=(?P<fragment>\S+)"
        r"(?:\s+blocks=(?P<blocks>[0-9,]+))?"
        r"(?:\s+start_offset=(?P<start_offset>\d+))?"
        r"(?:\s+extents=(?P<extents>[0-9\-;]+))?"
    )
    _fragment_table_pattern = re.compile(
        r"^<fragment-(?P<fragment_id>\d+)>\s+(?P<offset>\d+)\s+(?P<size>\d+)$"
    )

    def __init__(self) -> None:
        self.last_diagnostics: dict[str, object] = {}

    def parse(self, input_path: Path) -> list[MapFileEntry]:
        records: list[MapFileEntry] = []
        total_lines = 0
        fragment_rows = 0
        file_rows = 0
        dropped_rows = 0
        first_file_row_line: int | None = None
        drop_reasons: dict[str, int] = {}

        with input_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                total_lines += 1
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue

                parsed, reason = self._parse_line(raw)
                if parsed is not None:
                    parsed.source_file = str(input_path)
                    parsed.source_line = line_number
                    records.append(parsed)
                    if parsed.row_type == "fragment":
                        fragment_rows += 1
                    elif parsed.row_type == "file":
                        file_rows += 1
                        if first_file_row_line is None:
                            first_file_row_line = line_number
                else:
                    dropped_rows += 1
                    key = reason or "unrecognized"
                    drop_reasons[key] = drop_reasons.get(key, 0) + 1

        self.last_diagnostics = {
            "source_file": str(input_path),
            "total_lines": total_lines,
            "fragment_rows": fragment_rows,
            "file_rows": file_rows,
            "dropped_rows": dropped_rows,
            "drop_reasons": drop_reasons,
            "transition_line": first_file_row_line,
        }

        return records

    def _parse_line(self, raw: str) -> tuple[MapFileEntry | None, str | None]:
        fragment_match = self._fragment_table_pattern.match(raw)
        if fragment_match:
            fragment_id = fragment_match.group("fragment_id")
            offset = int(fragment_match.group("offset"))
            size = int(fragment_match.group("size"))
            return MapFileEntry(
                path=f"fragment::{fragment_id}",
                size=size,
                fragment_id=fragment_id,
                blocks=[],
                start_offset=offset,
                extent_ranges=[(offset, offset + size)],
                parser_rule="fragment_table",
                is_synthetic=True,
                entry_kind="fragment",
                row_type="fragment",
            ), None

        if (not raw.startswith("<fragment-")) and (" " in raw) and ("path=" not in raw):
            parts = raw.split()
            if len(parts) < 2:
                return None, "file_row_missing_offset"
            if not parts[1].isdigit():
                return None, "file_row_invalid_offset"

            start_offset = int(parts[1])
            blocks: list[int] = []
            for token in parts[2:]:
                if token.isdigit():
                    blocks.append(int(token))
                else:
                    return None, "file_row_non_numeric_block"

            # For this map type, block descriptors are the only per-file size-like signal.
            derived_size = sum(blocks) if blocks else 0
            return MapFileEntry(
                path=parts[0],
                size=derived_size,
                fragment_id=None,
                blocks=blocks,
                start_offset=start_offset,
                extent_ranges=[],
                parser_rule="ws_file_row",
                is_synthetic=False,
                entry_kind="file",
                row_type="file",
            ), None

        if "|" in raw:
            parts = [part.strip() for part in raw.split("|")]
            if len(parts) < 3:
                return None, "pipe_too_few_fields"
            blocks = self._parse_blocks(parts[3] if len(parts) > 3 else "")
            start_offset = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else None
            extents = self._parse_extents(parts[5] if len(parts) > 5 else "")
            return MapFileEntry(
                path=parts[0],
                size=int(parts[1]),
                fragment_id=str(parts[2]),
                blocks=blocks,
                start_offset=start_offset,
                extent_ranges=extents,
                parser_rule="pipe_delimited",
                is_synthetic=False,
                entry_kind="file",
                row_type="file",
            ), None

        if "," in raw and "path=" not in raw:
            parts = [part.strip() for part in raw.split(",")]
            if len(parts) < 3:
                return None, "csv_too_few_fields"
            blocks = self._parse_blocks(parts[3] if len(parts) > 3 else "")
            start_offset = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else None
            extents = self._parse_extents(parts[5] if len(parts) > 5 else "")
            return MapFileEntry(
                path=parts[0],
                size=int(parts[1]),
                fragment_id=str(parts[2]),
                blocks=blocks,
                start_offset=start_offset,
                extent_ranges=extents,
                parser_rule="csv_no_header",
                is_synthetic=False,
                entry_kind="file",
                row_type="file",
            ), None

        match = self._ws_pattern.match(raw)
        if match:
            blocks = self._parse_blocks(match.group("blocks") or "")
            start_offset = int(match.group("start_offset")) if match.group("start_offset") else None
            extents = self._parse_extents(match.group("extents") or "")
            return MapFileEntry(
                path=match.group("path"),
                size=int(match.group("size")),
                fragment_id=match.group("fragment"),
                blocks=blocks,
                start_offset=start_offset,
                extent_ranges=extents,
                parser_rule="kv_whitespace",
                is_synthetic=False,
                entry_kind="file",
                row_type="file",
            ), None

        return None, "unrecognized"

    @staticmethod
    def _parse_blocks(raw_blocks: str) -> list[int]:
        if not raw_blocks:
            return []
        values: list[int] = []
        for token in raw_blocks.split(","):
            token = token.strip()
            if token.isdigit():
                values.append(int(token))
        return values

    @staticmethod
    def _parse_extents(raw_extents: str) -> list[tuple[int, int]]:
        if not raw_extents:
            return []
        extents: list[tuple[int, int]] = []
        for token in raw_extents.split(";"):
            token = token.strip()
            if "-" not in token:
                continue
            parts = token.split("-", 1)
            if parts[0].isdigit() and parts[1].isdigit():
                start = int(parts[0])
                end = int(parts[1])
                if end > start:
                    extents.append((start, end))
        return extents
