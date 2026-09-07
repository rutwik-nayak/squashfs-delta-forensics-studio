from __future__ import annotations

import re
from pathlib import Path

from forensics_studio.extractors.base import BaseExtractor
from forensics_studio.models.canonical import (
    BlockDescriptor,
    CanonicalFile,
    CanonicalFragment,
    CanonicalImageModel,
)

# Fragment table row pattern: <fragment-0> 18134666 27659
_FRAGMENT_TABLE_PATTERN = re.compile(
    r"^<fragment-(?P<fragment_id>\d+)>\s+(?P<offset>\d+)\s+(?P<size>\d+)$"
)

# File row patterns (from GenericMapParser):
# 1) pipe-delimited: path|size|fragment|blocks
# 2) whitespace key-value: path=<p> size=<n> fragment=<id> blocks=<1,2>
# 3) csv-like: path,size,fragment,blocks
# 4) whitespace file row: <path> <start_offset> <block_desc_0> <block_desc_1> ...
_WS_PATTERN = re.compile(
    r"path=(?P<path>\S+)\s+size=(?P<size>\d+)\s+fragment=(?P<fragment>\S+)"
    r"(?:\s+blocks=(?P<blocks>[0-9,]+))?"
    r"(?:\s+start_offset=(?P<start_offset>\d+))?"
    r"(?:\s+extents=(?P<extents>[0-9\-;]+))?"
)


class UnsquashfsMapAdapter(BaseExtractor):
    """Adapt unsquashfs map files into the canonical image model.

    This adapter provides backward compatibility for existing map files.
    It converts map rows into CanonicalFile and CanonicalFragment entries.

    Note: Map files do not contain authoritative file->fragment membership.
    The adapter sets fragment_id on file entries when the map provides it
    (e.g., pipe-delimited format), but the membership is not authoritative
    in the same way as direct SquashFS inode/fragment-table extraction.
    """

    def __init__(self) -> None:
        self.last_diagnostics: dict[str, object] = {}

    def extract(self, source_path: Path) -> CanonicalImageModel:
        """Extract a canonical image model from an unsquashfs map file.

        Args:
            source_path: Path to the map file.

        Returns:
            A CanonicalImageModel with files and fragments adapted from the map.
        """
        files: list[CanonicalFile] = []
        fragments: list[CanonicalFragment] = []
        total_lines = 0
        file_rows = 0
        fragment_rows = 0
        dropped_rows = 0
        drop_reasons: dict[str, int] = {}

        with source_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                total_lines += 1
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue

                fragment_match = _FRAGMENT_TABLE_PATTERN.match(raw)
                if fragment_match:
                    fragment_id = fragment_match.group("fragment_id")
                    offset = int(fragment_match.group("offset"))
                    size = int(fragment_match.group("size"))
                    fragments.append(
                        CanonicalFragment(
                            fragment_id=fragment_id,
                            start_offset=offset,
                            compressed_size=size,
                            uncompressed_size=size,
                        )
                    )
                    fragment_rows += 1
                    continue

                parsed_file = self._parse_file_row(raw)
                if parsed_file is not None:
                    files.append(parsed_file)
                    file_rows += 1
                else:
                    dropped_rows += 1
                    key = "unrecognized"
                    drop_reasons[key] = drop_reasons.get(key, 0) + 1

        diagnostics = {
            "source_file": str(source_path),
            "source_type": "unsquashfs_map",
            "total_lines": total_lines,
            "file_rows": file_rows,
            "fragment_rows": fragment_rows,
            "dropped_rows": dropped_rows,
            "drop_reasons": drop_reasons,
            "files_with_fragment_membership": sum(1 for f in files if f.fragment_id is not None),
        }
        self.last_diagnostics = diagnostics

        return CanonicalImageModel(
            image_path=str(source_path),
            source_type="unsquashfs_map",
            files=files,
            fragments=fragments,
            superblock={},
            extraction_diagnostics=diagnostics,
        )

    def _parse_file_row(self, raw: str) -> CanonicalFile | None:
        """Parse a single file row from the map into a CanonicalFile."""
        # Pipe-delimited: path|size|fragment|blocks
        if "|" in raw:
            parts = [part.strip() for part in raw.split("|")]
            if len(parts) < 3:
                return None
            path = parts[0]
            size = int(parts[1]) if parts[1].isdigit() else 0
            fragment_id = parts[2] if parts[2] and parts[2] != "N/A" else None
            blocks = self._parse_blocks(parts[3] if len(parts) > 3 else "")
            start_offset = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else None
            return self._build_canonical_file(
                path=path,
                size=size,
                fragment_id=fragment_id,
                blocks=blocks,
                start_offset=start_offset,
            )

        # CSV-like: path,size,fragment,blocks
        if "," in raw and "path=" not in raw:
            parts = [part.strip() for part in raw.split(",")]
            if len(parts) < 3:
                return None
            path = parts[0]
            size = int(parts[1]) if parts[1].isdigit() else 0
            fragment_id = parts[2] if parts[2] and parts[2] != "N/A" else None
            blocks = self._parse_blocks(parts[3] if len(parts) > 3 else "")
            start_offset = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else None
            return self._build_canonical_file(
                path=path,
                size=size,
                fragment_id=fragment_id,
                blocks=blocks,
                start_offset=start_offset,
            )

        # Whitespace key-value: path=<p> size=<n> fragment=<id> blocks=<1,2>
        match = _WS_PATTERN.match(raw)
        if match:
            path = match.group("path")
            size = int(match.group("size"))
            fragment_id = match.group("fragment")
            blocks = self._parse_blocks(match.group("blocks") or "")
            start_offset = int(match.group("start_offset")) if match.group("start_offset") else None
            return self._build_canonical_file(
                path=path,
                size=size,
                fragment_id=fragment_id,
                blocks=blocks,
                start_offset=start_offset,
            )

        # Whitespace file row: <path> <start_offset> <block_desc_0> <block_desc_1> ...
        if " " in raw and "path=" not in raw and not raw.startswith("<fragment-"):
            parts = raw.split()
            if len(parts) < 2:
                return None
            if not parts[1].isdigit():
                return None
            path = parts[0]
            start_offset = int(parts[1])
            blocks: list[int] = []
            for token in parts[2:]:
                if token.isdigit():
                    blocks.append(int(token))
                else:
                    return None
            derived_size = sum(blocks) if blocks else 0
            return self._build_canonical_file(
                path=path,
                size=derived_size,
                fragment_id=None,
                blocks=blocks,
                start_offset=start_offset,
            )

        return None

    @staticmethod
    def _build_canonical_file(
        path: str,
        size: int,
        fragment_id: str | None,
        blocks: list[int],
        start_offset: int | None,
    ) -> CanonicalFile:
        """Build a CanonicalFile from parsed map row fields."""
        block_list: list[BlockDescriptor] = []
        current_offset = start_offset or 0
        for idx, block_size in enumerate(blocks):
            block_list.append(
                BlockDescriptor(
                    block_index=idx,
                    start_offset=current_offset,
                    compressed_size=block_size,
                    uncompressed_size=block_size,
                    is_compressed=True,
                )
            )
            current_offset += block_size

        return CanonicalFile(
            path=path,
            inode_number=0,  # not available from map
            size=size,
            fragment_id=fragment_id,
            fragment_offset=None,  # not available from map
            block_list=block_list,
            start_offset=start_offset,
            metadata={"source": "unsquashfs_map"},
        )

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