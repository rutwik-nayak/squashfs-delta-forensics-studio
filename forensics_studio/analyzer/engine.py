from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any

from forensics_studio.models.canonical import (
    CanonicalFile,
    CanonicalFragment,
    CanonicalImageModel,
)
from forensics_studio.models.types import (
    AnalysisResult,
    BlastRadius,
    FileRecord,
    FragmentMovement,
    FragmentRecord,
    MapFileEntry,
    ReuseOpportunity,
    RootCauseRecord,
)
from forensics_studio.parsers.registry import ParserRegistry


class ForensicsAnalyzer:
    def __init__(self, registry: ParserRegistry | None = None) -> None:
        self.registry = registry or ParserRegistry()

    def analyze(
        self,
        old_model: CanonicalImageModel,
        new_model: CanonicalImageModel,
        old_fragment_path: Path | None = None,
        new_fragment_path: Path | None = None,
    ) -> AnalysisResult:
        """Analyze the delta between two canonical image models.

        The engine operates exclusively on the canonical model and never
        sees raw source formats (map files, image binaries, etc.).

        Args:
            old_model: Canonical model of the old (baseline) image.
            new_model: Canonical model of the new (target) image.
            old_fragment_path: Deprecated; kept for API compatibility.
            new_fragment_path: Deprecated; kept for API compatibility.

        Returns:
            An AnalysisResult with file/fragment deltas, movement, and
            reuse analytics.
        """
        del old_fragment_path, new_fragment_path

        # Convert canonical models to internal analysis records.
        old_entries = self._canonical_to_entries(old_model)
        new_entries = self._canonical_to_entries(new_model)

        old_diag = old_model.extraction_diagnostics
        new_diag = new_model.extraction_diagnostics

        old_file_rows, old_fragment_rows = self._split_entries(old_entries)
        new_file_rows, new_fragment_rows = self._split_entries(new_entries)

        has_real_file_paths = bool(old_file_rows or new_file_rows)
        has_fragment_rows = bool(old_fragment_rows or new_fragment_rows)
        has_fragment_membership = self._has_fragment_membership(old_model, new_model)
        source_type = self._source_type(old_model, new_model)
        confidence_level = self._confidence_level(
            has_real_file_paths, has_fragment_rows, has_fragment_membership, source_type
        )

        files = self._analyze_files_independent(old_file_rows, new_file_rows, confidence_level)
        root_causes = self._root_causes(files)
        fragments = self._analyze_fragments_independent(old_fragment_rows, new_fragment_rows)
        movement_graph = self._fragment_movement_graph(fragments)
        blast_radius: list[BlastRadius] = []
        reuse_opportunities = self._reuse_opportunities(files)
        heatmap_data = self._heatmap_data(files, fragments, movement_graph)

        parser_validation = self._build_parser_validation(
            old_file_rows=old_file_rows,
            new_file_rows=new_file_rows,
            old_fragment_rows=old_fragment_rows,
            new_fragment_rows=new_fragment_rows,
            old_entries=old_entries,
            new_entries=new_entries,
            old_diag=old_diag,
            new_diag=new_diag,
            confidence_level=confidence_level,
        )

        offset_analysis = self._offset_analysis(files, fragments)
        relationship_graph = self._relationship_graph(old_entries, new_entries, confidence_level)
        debug_dataset = self._debug_dataset(parser_validation, relationship_graph, offset_analysis)

        summary = self._summary(files, fragments, reuse_opportunities)
        summary["has_real_file_paths"] = has_real_file_paths
        summary["has_fragment_membership"] = has_fragment_membership
        summary["analysis_mode"] = "canonical_model"
        summary["source_type"] = source_type
        if has_fragment_membership:
            summary["fragment_membership_message"] = "Available: direct file->fragment membership from SquashFS extraction"
            summary["membership_status"] = "present_in_canonical_model"
        else:
            summary["fragment_membership_message"] = "Unavailable: source does not include direct file->fragment membership"
            summary["membership_status"] = "not_present_in_source"

        warnings = self._detect_warnings(
            files=files,
            fragments=fragments,
            old_diag=old_diag,
            new_diag=new_diag,
            has_real_file_paths=has_real_file_paths,
        )
        executive_summary = self._executive_summary(files, fragments, blast_radius, reuse_opportunities, summary)

        return AnalysisResult(
            summary=summary,
            files=files,
            fragments=fragments,
            movement_graph=movement_graph,
            blast_radius=blast_radius,
            reuse_opportunities=reuse_opportunities,
            root_causes=root_causes,
            heatmap_data=heatmap_data,
            executive_summary=executive_summary,
            parser_validation=parser_validation,
            data_confidence={
                "level": confidence_level,
                "has_real_file_paths": has_real_file_paths,
                "has_fragment_membership": has_fragment_membership,
                "synthetic_only": False,
                "membership_status": summary["membership_status"],
                "source_type": source_type,
            },
            relationship_graph=relationship_graph,
            debug_dataset=debug_dataset,
            warnings=warnings,
            offset_analysis=offset_analysis,
        )

    @staticmethod
    def _canonical_to_entries(model: CanonicalImageModel) -> list[MapFileEntry]:
        """Convert a canonical image model to internal MapFileEntry records.

        This is the single conversion point between the canonical model and
        the internal analysis representation. The engine operates on the
        canonical model exclusively; this conversion is an internal detail.
        """
        entries: list[MapFileEntry] = []

        # Convert fragments first so file entries can reference them.
        for frag in model.fragments:
            entries.append(
                MapFileEntry(
                    path=f"fragment::{frag.fragment_id}",
                    size=frag.compressed_size,
                    fragment_id=frag.fragment_id,
                    blocks=[],
                    start_offset=frag.start_offset,
                    extent_ranges=[(frag.start_offset, frag.start_offset + frag.compressed_size)],
                    source_file=model.image_path,
                    source_line=0,
                    parser_rule=f"canonical:{model.source_type}:fragment",
                    is_synthetic=False,
                    entry_kind="fragment",
                    row_type="fragment",
                )
            )

        # Convert files.
        for file_row in model.files:
            blocks = [block.compressed_size for block in file_row.block_list]
            entries.append(
                MapFileEntry(
                    path=file_row.path,
                    size=file_row.size,
                    fragment_id=file_row.fragment_id,
                    blocks=blocks,
                    start_offset=file_row.start_offset,
                    extent_ranges=[],
                    source_file=model.image_path,
                    source_line=0,
                    parser_rule=f"canonical:{model.source_type}:file",
                    is_synthetic=False,
                    entry_kind="file",
                    row_type="file",
                )
            )

        return entries

    @staticmethod
    def _has_fragment_membership(
        old_model: CanonicalImageModel,
        new_model: CanonicalImageModel,
    ) -> bool:
        """Determine whether the canonical models provide file->fragment membership."""
        for model in (old_model, new_model):
            if model.source_type == "squashfs_image":
                if any(f.fragment_id is not None for f in model.files):
                    return True
        return False

    @staticmethod
    def _source_type(
        old_model: CanonicalImageModel,
        new_model: CanonicalImageModel,
    ) -> str:
        """Determine the effective source type for confidence scoring."""
        types = {old_model.source_type, new_model.source_type}
        if "squashfs_image" in types:
            return "squashfs_image"
        if "unsquashfs_map" in types:
            return "unsquashfs_map"
        return "unknown"

    @staticmethod
    def _split_entries(entries: list[MapFileEntry]) -> tuple[list[MapFileEntry], list[MapFileEntry]]:
        files = [row for row in entries if row.row_type == "file"]
        fragments = [row for row in entries if row.row_type == "fragment"]
        return files, fragments

    @staticmethod
    def _confidence_level(
        has_real_file_paths: bool,
        has_fragment_rows: bool,
        has_fragment_membership: bool = False,
        source_type: str = "unknown",
    ) -> str:
        """Compute the data confidence level.

        HIGH: Direct file->fragment membership from SquashFS image extraction.
        MEDIUM: File rows and fragment rows present as independent datasets.
        LOW: Only one dataset present or weak source.
        """
        if has_fragment_membership and source_type == "squashfs_image":
            return "HIGH"
        if has_real_file_paths and has_fragment_rows:
            return "MEDIUM"
        if has_real_file_paths or has_fragment_rows:
            return "LOW"
        return "LOW"

    def _analyze_files_independent(
        self,
        old_file_rows: list[MapFileEntry],
        new_file_rows: list[MapFileEntry],
        confidence_level: str,
    ) -> list[FileRecord]:
        old_by_path = {row.path: row for row in old_file_rows}
        new_by_path = {row.path: row for row in new_file_rows}
        all_paths = sorted(set(old_by_path.keys()) | set(new_by_path.keys()))

        out: list[FileRecord] = []
        for path in all_paths:
            old_row = old_by_path.get(path)
            new_row = new_by_path.get(path)

            old_start = old_row.start_offset if old_row else None
            new_start = new_row.start_offset if new_row else None
            old_blocks = old_row.blocks if old_row else []
            new_blocks = new_row.blocks if new_row else []

            status = self._classify_file_status(old_row, new_row)
            same_size = bool(old_row and new_row and old_row.size == new_row.size)
            same_fragment = False

            block_churn = self._block_chain_churn(old_blocks, new_blocks)
            offset_delta = abs((new_start or 0) - (old_start or 0)) if old_row and new_row else 0
            impact_score = self._impact_score(status, offset_delta, block_churn)
            reuse_score = self._reuse_score(status, same_size, old_blocks, new_blocks)
            root_cause, root_conf = self._classify_root_cause(status, old_start, new_start, old_blocks, new_blocks)

            out.append(
                FileRecord(
                    path=path,
                    old_size=old_row.size if old_row else None,
                    new_size=new_row.size if new_row else None,
                    old_fragment=None,
                    new_fragment=None,
                    old_blocks=old_blocks,
                    new_blocks=new_blocks,
                    same_size=same_size,
                    same_fragment=same_fragment,
                    status=status,
                    impact_score=impact_score,
                    reuse_score=reuse_score,
                    directly_changed=status != "unchanged",
                    root_cause=root_cause,
                    root_cause_confidence=root_conf,
                    neighbors_old=[],
                    neighbors_new=[],
                    data_confidence=confidence_level,
                    source_old_file=old_row.source_file if old_row else None,
                    source_old_line=old_row.source_line if old_row else None,
                    source_old_rule=old_row.parser_rule if old_row else None,
                    source_new_file=new_row.source_file if new_row else None,
                    source_new_line=new_row.source_line if new_row else None,
                    source_new_rule=new_row.parser_rule if new_row else None,
                    synthetic=False,
                    old_start_offset=old_start,
                    new_start_offset=new_start,
                )
            )

        return out

    @staticmethod
    def _classify_file_status(old_row: MapFileEntry | None, new_row: MapFileEntry | None) -> str:
        if old_row and new_row:
            same_start = old_row.start_offset == new_row.start_offset
            same_blocks = old_row.blocks == new_row.blocks
            if same_start and same_blocks:
                return "unchanged"
            if (not same_start) and same_blocks:
                return "moved"
            return "modified"
        if old_row and not new_row:
            return "deleted"
        return "added"

    @staticmethod
    def _block_chain_churn(old_blocks: list[int], new_blocks: list[int]) -> float:
        if not old_blocks and not new_blocks:
            return 0.0
        old_set = set(old_blocks)
        new_set = set(new_blocks)
        union = len(old_set | new_set)
        if union == 0:
            return 0.0
        symmetric = len(old_set ^ new_set)
        return round(symmetric / union, 4)

    @staticmethod
    def _impact_score(status: str, offset_delta: int, block_churn: float) -> float:
        if status == "unchanged":
            return 0.0
        base = 20.0
        if status in {"added", "deleted"}:
            base += 30.0
        if status == "moved":
            base += 10.0
        if status == "modified":
            base += 20.0

        offset_component = min(30.0, offset_delta / 500000.0)
        churn_component = min(20.0, block_churn * 100.0)
        return round(min(100.0, base + offset_component + churn_component), 2)

    @staticmethod
    def _reuse_score(status: str, same_size: bool, old_blocks: list[int], new_blocks: list[int]) -> float:
        if status == "unchanged":
            return 100.0
        if status in {"added", "deleted"}:
            return 0.0
        churn = ForensicsAnalyzer._block_chain_churn(old_blocks, new_blocks)
        score = 80.0 - (churn * 60.0)
        if not same_size:
            score -= 10.0
        return round(max(0.0, min(100.0, score)), 2)

    @staticmethod
    def _classify_root_cause(
        status: str,
        old_start: int | None,
        new_start: int | None,
        old_blocks: list[int],
        new_blocks: list[int],
    ) -> tuple[str, float]:
        if status == "unchanged":
            return "No change", 1.0
        if status == "added":
            return "Added file row", 0.99
        if status == "deleted":
            return "Deleted file row", 0.99

        offset_changed = old_start != new_start
        blocks_changed = old_blocks != new_blocks

        if offset_changed and blocks_changed:
            return "Offset and block chain changed", 0.93
        if offset_changed:
            return "Layout offset shift", 0.95
        return "Block chain changed", 0.92

    @staticmethod
    def _root_causes(files: list[FileRecord]) -> list[RootCauseRecord]:
        return [
            RootCauseRecord(
                file_path=row.path,
                category=row.root_cause,
                confidence=row.root_cause_confidence,
                details=f"status={row.status}; old_start={row.old_start_offset}; new_start={row.new_start_offset}; blocks_old={len(row.old_blocks)}; blocks_new={len(row.new_blocks)}",
            )
            for row in files
        ]

    def _analyze_fragments_independent(
        self,
        old_fragment_rows: list[MapFileEntry],
        new_fragment_rows: list[MapFileEntry],
    ) -> list[FragmentRecord]:
        old_by_id = {row.fragment_id: row for row in old_fragment_rows if row.fragment_id is not None}
        new_by_id = {row.fragment_id: row for row in new_fragment_rows if row.fragment_id is not None}
        all_fragment_ids = sorted(set(old_by_id.keys()) | set(new_by_id.keys()), key=lambda v: int(v) if str(v).isdigit() else str(v))

        out: list[FragmentRecord] = []
        for fragment_id in all_fragment_ids:
            old_row = old_by_id.get(fragment_id)
            new_row = new_by_id.get(fragment_id)

            old_range = self._entry_range(old_row)
            new_range = self._entry_range(new_row)
            status = self._fragment_status(old_row, new_row)
            churn_ratio = self._fragment_churn_ratio(old_row, new_row)
            reuse_score = round((1.0 - churn_ratio) * 100.0, 2)

            out.append(
                FragmentRecord(
                    fragment_id=str(fragment_id),
                    file_count=0,
                    old_file_list=[],
                    new_file_list=[],
                    added_files=[],
                    removed_files=[],
                    retained_files=[],
                    compressed_size_old=old_row.size if old_row else None,
                    compressed_size_new=new_row.size if new_row else None,
                    status=status,
                    change_reason=self._fragment_change_reason(status, old_row, new_row),
                    reuse_score=max(0.0, reuse_score),
                    churn_ratio=churn_ratio,
                    membership_available=False,
                    membership_message="Unavailable: not present in source map",
                    old_offset_range=self._range_to_text(old_range),
                    new_offset_range=self._range_to_text(new_range),
                    overlapping_files_old=[],
                    overlapping_files_new=[],
                    overlap_confidence_score=0.0,
                    inference_method="Not Present In Source Map",
                )
            )

        return out

    @staticmethod
    def _entry_range(row: MapFileEntry | None) -> tuple[int, int] | None:
        if row is None or row.start_offset is None:
            return None
        end = row.start_offset + max(row.size, 0)
        if end <= row.start_offset:
            return None
        return (row.start_offset, end)

    @staticmethod
    def _fragment_status(old_row: MapFileEntry | None, new_row: MapFileEntry | None) -> str:
        if old_row and new_row:
            if old_row.start_offset == new_row.start_offset and old_row.size == new_row.size:
                return "unchanged"
            return "modified"
        if old_row and not new_row:
            return "removed"
        return "added"

    @staticmethod
    def _fragment_churn_ratio(old_row: MapFileEntry | None, new_row: MapFileEntry | None) -> float:
        if old_row and new_row:
            old_size = max(old_row.size, 1)
            new_size = max(new_row.size, 1)
            size_delta = abs(new_row.size - old_row.size) / max(old_size, new_size)
            offset_delta = 0.0 if old_row.start_offset == new_row.start_offset else 1.0
            return round(min(1.0, (size_delta * 0.7) + (offset_delta * 0.3)), 4)
        return 1.0

    @staticmethod
    def _fragment_change_reason(status: str, old_row: MapFileEntry | None, new_row: MapFileEntry | None) -> str:
        if status == "unchanged":
            return "No fragment offset/size change"
        if status == "added":
            return "Fragment introduced in new map"
        if status == "removed":
            return "Fragment removed from new map"
        if old_row and new_row and old_row.start_offset != new_row.start_offset:
            return "Fragment start offset changed"
        return "Fragment size changed"

    def _fragment_movement_graph(self, fragments: list[FragmentRecord]) -> list[FragmentMovement]:
        rows: list[FragmentMovement] = []
        for row in fragments:
            if row.status != "modified":
                continue

            old_start = self._extract_range_start(row.old_offset_range)
            new_start = self._extract_range_start(row.new_offset_range)
            if old_start is None or new_start is None:
                continue

            start_delta = new_start - old_start
            rows.append(
                FragmentMovement(
                    old_fragment=row.fragment_id,
                    new_fragment=row.fragment_id,
                    moved_files=[f"start_delta={start_delta}"],
                    movement_ratio=1.0,
                )
            )

        rows.sort(key=lambda item: abs(int(item.moved_files[0].split("=")[1])) if item.moved_files else 0, reverse=True)
        return rows

    @staticmethod
    def _extract_range_start(range_text: str | None) -> int | None:
        if not range_text or "-" not in range_text:
            return None
        start, _ = range_text.split("-", 1)
        return int(start) if start.isdigit() else None

    @staticmethod
    def _reuse_opportunities(files: list[FileRecord]) -> list[ReuseOpportunity]:
        candidates: list[ReuseOpportunity] = []
        for row in files:
            if row.status not in {"moved", "modified"}:
                continue
            if row.old_blocks == row.new_blocks and row.old_blocks:
                file_size = row.new_size or row.old_size or 0
                importance = min(100.0, 50.0 + file_size / 8192.0 + row.impact_score * 0.3)
                candidates.append(
                    ReuseOpportunity(
                        file_path=row.path,
                        old_fragment="N/A",
                        new_fragment="N/A",
                        file_size=file_size,
                        importance_score=round(importance, 2),
                        reason="Block chain stable while layout changed",
                    )
                )

        candidates.sort(key=lambda item: item.importance_score, reverse=True)
        return candidates

    @staticmethod
    def _heatmap_data(
        files: list[FileRecord],
        fragments: list[FragmentRecord],
        movement_graph: list[FragmentMovement],
    ) -> dict[str, Any]:
        fragment_churn = [
            {"fragment": row.fragment_id, "churn_ratio": row.churn_ratio, "reuse_score": row.reuse_score}
            for row in fragments
        ]

        movement = [
            {
                "old_fragment": row.old_fragment,
                "new_fragment": row.new_fragment,
                "moved_count": len(row.moved_files),
                "movement_ratio": row.movement_ratio,
            }
            for row in movement_graph
        ]

        impact = [
            {
                "path": row.path,
                "impact_score": row.impact_score,
                "reuse_score": row.reuse_score,
                "status": row.status,
            }
            for row in files
        ]

        reuse = [
            {
                "path": row.path,
                "same_size": row.same_size,
                "same_fragment": row.same_fragment,
                "reuse_score": row.reuse_score,
            }
            for row in files
        ]

        return {
            "fragment_churn": fragment_churn,
            "movement": movement,
            "impact": impact,
            "reuse": reuse,
        }

    def _build_parser_validation(
        self,
        old_file_rows: list[MapFileEntry],
        new_file_rows: list[MapFileEntry],
        old_fragment_rows: list[MapFileEntry],
        new_fragment_rows: list[MapFileEntry],
        old_entries: list[MapFileEntry],
        new_entries: list[MapFileEntry],
        old_diag: dict[str, Any],
        new_diag: dict[str, Any],
        confidence_level: str,
    ) -> dict[str, Any]:
        old_by_path = {row.path: row for row in old_file_rows}
        new_by_path = {row.path: row for row in new_file_rows}
        all_paths = sorted(set(old_by_path.keys()) | set(new_by_path.keys()))

        parsed_files: list[dict[str, Any]] = []
        for path in all_paths:
            old_row = old_by_path.get(path)
            new_row = new_by_path.get(path)
            parsed_files.append(
                {
                    "path": path,
                    "old_fragment": None,
                    "new_fragment": None,
                    "source_old": {
                        "file": old_row.source_file if old_row else None,
                        "line": old_row.source_line if old_row else None,
                        "rule": old_row.parser_rule if old_row else None,
                    },
                    "source_new": {
                        "file": new_row.source_file if new_row else None,
                        "line": new_row.source_line if new_row else None,
                        "rule": new_row.parser_rule if new_row else None,
                    },
                    "confidence": confidence_level,
                    "old_start_offset": old_row.start_offset if old_row else None,
                    "new_start_offset": new_row.start_offset if new_row else None,
                    "old_blocks": old_row.blocks if old_row else [],
                    "new_blocks": new_row.blocks if new_row else [],
                    "old_extents": old_row.extent_ranges if old_row else [],
                    "new_extents": new_row.extent_ranges if new_row else [],
                    "membership_status": "not_present_in_source_map",
                }
            )

        old_by_fragment = {row.fragment_id: row for row in old_fragment_rows if row.fragment_id is not None}
        new_by_fragment = {row.fragment_id: row for row in new_fragment_rows if row.fragment_id is not None}
        fragment_ids = sorted(set(old_by_fragment.keys()) | set(new_by_fragment.keys()), key=lambda v: int(v) if str(v).isdigit() else str(v))
        parsed_fragments = []
        for fragment_id in fragment_ids:
            old_row = old_by_fragment.get(fragment_id)
            new_row = new_by_fragment.get(fragment_id)
            parsed_fragments.append(
                {
                    "fragment_id": fragment_id,
                    "old_members": [],
                    "new_members": [],
                    "membership_available": False,
                    "membership_message": "Unavailable: not present in source map",
                    "old_start_offset": old_row.start_offset if old_row else None,
                    "new_start_offset": new_row.start_offset if new_row else None,
                    "old_size": old_row.size if old_row else None,
                    "new_size": new_row.size if new_row else None,
                }
            )

        source_records = [
            {
                "dataset": "old",
                "row_type": row.row_type,
                "path": row.path,
                "fragment_id": row.fragment_id,
                "size": row.size,
                "blocks": row.blocks,
                "start_offset": row.start_offset,
                "extent_ranges": row.extent_ranges,
                "source_file": row.source_file,
                "source_line": row.source_line,
                "parser_rule": row.parser_rule,
                "synthetic": row.is_synthetic,
            }
            for row in old_entries
        ] + [
            {
                "dataset": "new",
                "row_type": row.row_type,
                "path": row.path,
                "fragment_id": row.fragment_id,
                "size": row.size,
                "blocks": row.blocks,
                "start_offset": row.start_offset,
                "extent_ranges": row.extent_ranges,
                "source_file": row.source_file,
                "source_line": row.source_line,
                "parser_rule": row.parser_rule,
                "synthetic": row.is_synthetic,
            }
            for row in new_entries
        ]

        parser_assumptions = [
            "File rows and fragment rows are treated as independent datasets.",
            "File->fragment membership is unavailable and not inferred from offsets.",
            "File analytics use start offsets and block descriptor chains only.",
            "Fragment analytics use fragment offsets and fragment sizes only.",
        ]

        return {
            "parsed_files": parsed_files,
            "parsed_fragments": parsed_fragments,
            "source_records": source_records,
            "parser_assumptions": parser_assumptions,
            "confidence_level": confidence_level,
            "parser_diagnostics": {
                "old": old_diag,
                "new": new_diag,
            },
        }

    def _relationship_graph(
        self,
        old_entries: list[MapFileEntry],
        new_entries: list[MapFileEntry],
        confidence_level: str,
    ) -> dict[str, Any]:
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []

        def upsert_node(node_id: str, node_type: str, label: str, row: MapFileEntry, dataset: str) -> None:
            if node_id in nodes:
                return
            nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "label": label,
                "dataset": dataset,
                "source_file": row.source_file,
                "source_line": row.source_line,
                "parser_rule": row.parser_rule,
                "confidence": "LOW" if row.is_synthetic else confidence_level,
            }

        def register(rows: list[MapFileEntry], dataset: str) -> None:
            for row in rows:
                if row.row_type == "file":
                    file_id = f"FILE::{dataset}::{row.path}"
                    upsert_node(file_id, "FILE", row.path, row, dataset)
                    for idx, block in enumerate(row.blocks):
                        block_id = f"BLOCK::{dataset}::{row.path}::{idx}::{block}"
                        upsert_node(block_id, "BLOCK", str(block), row, dataset)
                        edges.append(
                            {
                                "from": file_id,
                                "to": block_id,
                                "relation": "FILE_TO_BLOCK_DESCRIPTOR",
                                "source_file": row.source_file,
                                "source_line": row.source_line,
                                "parser_rule": row.parser_rule,
                            }
                        )
                elif row.row_type == "fragment":
                    fragment_id = row.fragment_id if row.fragment_id is not None else "unknown"
                    frag_node = f"FRAGMENT::{dataset}::{fragment_id}"
                    upsert_node(frag_node, "FRAGMENT", str(fragment_id), row, dataset)
                    if row.start_offset is not None:
                        range_id = f"RANGE::{dataset}::{fragment_id}::{row.start_offset}:{row.size}"
                        upsert_node(range_id, "EXTENT", f"{row.start_offset}-{row.start_offset + row.size}", row, dataset)
                        edges.append(
                            {
                                "from": frag_node,
                                "to": range_id,
                                "relation": "FRAGMENT_TO_RANGE",
                                "source_file": row.source_file,
                                "source_line": row.source_line,
                                "parser_rule": row.parser_rule,
                            }
                        )

        register(old_entries, "old")
        register(new_entries, "new")
        return {"nodes": list(nodes.values()), "edges": edges}

    @staticmethod
    def _debug_dataset(
        parser_validation: dict[str, Any],
        relationship_graph: dict[str, Any],
        offset_analysis: dict[str, Any],
    ) -> dict[str, Any]:
        nodes = relationship_graph.get("nodes", [])
        edges = relationship_graph.get("edges", [])
        blocks = [row for row in nodes if row.get("type") == "BLOCK"]
        extents = [row for row in nodes if row.get("type") == "EXTENT"]
        return {
            "files": parser_validation.get("parsed_files", []),
            "fragments": parser_validation.get("parsed_fragments", []),
            "blocks": blocks,
            "extents": extents,
            "relationships": edges,
            "source_records": parser_validation.get("source_records", []),
            "parser_assumptions": parser_validation.get("parser_assumptions", []),
            "offset_analysis": offset_analysis,
            "parser_diagnostics": parser_validation.get("parser_diagnostics", {}),
        }

    def _offset_analysis(self, files: list[FileRecord], fragments: list[FragmentRecord]) -> dict[str, Any]:
        file_comparison_rows: list[dict[str, Any]] = []
        movement_rows: list[dict[str, Any]] = []

        for row in files:
            old_start = row.old_start_offset
            new_start = row.new_start_offset
            start_delta = None
            if old_start is not None and new_start is not None:
                start_delta = new_start - old_start

            file_comparison_rows.append(
                {
                    "path": row.path,
                    "status": row.status,
                    "old_start_offset": old_start,
                    "new_start_offset": new_start,
                    "offset_delta": start_delta,
                    "old_block_count": len(row.old_blocks),
                    "new_block_count": len(row.new_blocks),
                    "block_chain_churn": self._block_chain_churn(row.old_blocks, row.new_blocks),
                }
            )

            if start_delta is not None:
                movement_rows.append(
                    {
                        "fragment_id": row.path,
                        "old_start": old_start,
                        "new_start": new_start,
                        "start_delta": start_delta,
                    }
                )

        movement_rows.sort(key=lambda item: abs(item["start_delta"]), reverse=True)

        fragment_diff_rows: list[dict[str, Any]] = []
        timeline_old: list[dict[str, Any]] = []
        timeline_new: list[dict[str, Any]] = []

        for row in fragments:
            old_start = self._extract_range_start(row.old_offset_range)
            new_start = self._extract_range_start(row.new_offset_range)
            old_end = self._extract_range_end(row.old_offset_range)
            new_end = self._extract_range_end(row.new_offset_range)

            if old_start is not None and old_end is not None:
                timeline_old.append(
                    {
                        "fragment_id": row.fragment_id,
                        "start": old_start,
                        "end": old_end,
                        "size": old_end - old_start,
                        "image": "old",
                    }
                )
            if new_start is not None and new_end is not None:
                timeline_new.append(
                    {
                        "fragment_id": row.fragment_id,
                        "start": new_start,
                        "end": new_end,
                        "size": new_end - new_start,
                        "image": "new",
                    }
                )

            start_delta = None
            if old_start is not None and new_start is not None:
                start_delta = new_start - old_start

            size_delta = None
            if row.compressed_size_old is not None and row.compressed_size_new is not None:
                size_delta = row.compressed_size_new - row.compressed_size_old

            fragment_diff_rows.append(
                {
                    "fragment_id": row.fragment_id,
                    "old_range": row.old_offset_range,
                    "new_range": row.new_offset_range,
                    "start_delta": start_delta,
                    "size_delta": size_delta,
                    "confidence": 1.0,
                    "inference_method": "Direct Fragment Row",
                }
            )

        timeline_old.sort(key=lambda item: item["start"])
        timeline_new.sort(key=lambda item: item["start"])

        cascades = self._largest_offset_cascades(file_comparison_rows)
        downstream = self._downstream_sources(file_comparison_rows)

        absolute_shifts = [abs(item["start_delta"]) for item in movement_rows]
        image_shift = {
            "total_fragments_compared": len(fragment_diff_rows),
            "shifted_fragments": sum(1 for row in fragment_diff_rows if row.get("start_delta") not in (None, 0)),
            "max_positive_shift": max((row["start_delta"] for row in fragment_diff_rows if row.get("start_delta") is not None), default=0),
            "max_negative_shift": min((row["start_delta"] for row in fragment_diff_rows if row.get("start_delta") is not None), default=0),
            "avg_absolute_shift": round(sum(absolute_shifts) / len(absolute_shifts), 3) if absolute_shifts else 0.0,
            "median_absolute_shift": round(sorted(absolute_shifts)[len(absolute_shifts) // 2], 3) if absolute_shifts else 0.0,
        }

        return {
            "storage_timeline": {"old": timeline_old, "new": timeline_new},
            "offset_movement": movement_rows,
            "fragment_offset_diff": fragment_diff_rows,
            "image_shift_analysis": image_shift,
            "largest_offset_cascades": cascades,
            "downstream_movement_sources": downstream,
            "file_start_offset_comparison": file_comparison_rows,
            "file_block_chain_comparison": [
                {
                    "path": row["path"],
                    "old_block_count": row["old_block_count"],
                    "new_block_count": row["new_block_count"],
                    "block_chain_churn": row["block_chain_churn"],
                }
                for row in file_comparison_rows
            ],
            "file_layout_churn": {
                "total_files": len(file_comparison_rows),
                "changed_files": sum(1 for row in file_comparison_rows if row["status"] != "unchanged"),
                "moved_files": sum(1 for row in file_comparison_rows if row["status"] == "moved"),
                "modified_files": sum(1 for row in file_comparison_rows if row["status"] == "modified"),
            },
        }

    @staticmethod
    def _extract_range_end(range_text: str | None) -> int | None:
        if not range_text or "-" not in range_text:
            return None
        _, end = range_text.split("-", 1)
        return int(end) if end.isdigit() else None

    @staticmethod
    def _largest_offset_cascades(file_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        sortable = [row for row in file_rows if row.get("offset_delta") not in (None, 0)]
        sortable.sort(key=lambda row: abs(row.get("offset_delta") or 0), reverse=True)
        cascades: list[dict[str, Any]] = []
        for idx, row in enumerate(sortable[:20], start=1):
            cascades.append(
                {
                    "fragments": [row["path"]],
                    "cascade_length": 1,
                    "total_shift_magnitude": abs(row.get("offset_delta") or 0),
                    "first_fragment": row["path"],
                    "last_fragment": row["path"],
                    "rank": idx,
                }
            )
        return cascades

    @staticmethod
    def _downstream_sources(file_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        ranked = sorted(
            file_rows,
            key=lambda row: (abs(row.get("offset_delta") or 0), row.get("block_chain_churn") or 0.0),
            reverse=True,
        )
        return [
            {
                "source": row["path"],
                "source_type": "file",
                "estimated_downstream_shift": abs(row.get("offset_delta") or 0),
                "note": "Derived from direct file-row start offset/block chain comparison.",
            }
            for row in ranked[:20]
        ]

    @staticmethod
    def _detect_warnings(
        files: list[FileRecord],
        fragments: list[FragmentRecord],
        old_diag: dict[str, Any],
        new_diag: dict[str, Any],
        has_real_file_paths: bool,
    ) -> list[str]:
        warnings: list[str] = []

        if not has_real_file_paths:
            warnings.append("No real file rows found in input sources.")
        if not fragments:
            warnings.append("No fragment rows found in input sources.")

        # Check if membership is available from the canonical model.
        membership_available = any(
            row.membership_available for row in fragments
        )
        if not membership_available:
            warnings.append("File->fragment membership is unavailable and is not inferred from source data.")

        for label, diag in (("old", old_diag), ("new", new_diag)):
            dropped = int(diag.get("dropped_rows", 0)) if isinstance(diag, dict) else 0
            if dropped > 0:
                warnings.append(f"Extractor dropped {dropped} rows in {label} source. Inspect extraction_diagnostics for reasons.")

        return warnings

    @staticmethod
    def _summary(
        files: list[FileRecord],
        fragments: list[FragmentRecord],
        reuse_opportunities: list[ReuseOpportunity],
    ) -> dict[str, Any]:
        status_counts = defaultdict(int)
        for row in files:
            status_counts[row.status] += 1

        total_fragments = len(fragments)
        changed_fragments = sum(1 for row in fragments if row.status != "unchanged")
        reuse_ratio = 0.0
        if total_fragments:
            reuse_ratio = round((total_fragments - changed_fragments) / total_fragments, 4)

        potential_reuse_loss = round(sum(100.0 - row.reuse_score for row in files) / max(len(files), 1), 2)

        return {
            "total_files": len(files),
            "unchanged_files": status_counts["unchanged"],
            "modified_files": status_counts["modified"],
            "moved_files": status_counts["moved"],
            "added_files": status_counts["added"],
            "deleted_files": status_counts["deleted"],
            "total_fragments": total_fragments,
            "changed_fragments": changed_fragments,
            "fragment_reuse_ratio": reuse_ratio,
            "potential_reuse_loss": potential_reuse_loss,
            "reuse_candidates": len(reuse_opportunities),
        }

    @staticmethod
    def _executive_summary(
        files: list[FileRecord],
        fragments: list[FragmentRecord],
        blast_radius: list[BlastRadius],
        reuse_opportunities: list[ReuseOpportunity],
        summary: dict[str, Any],
    ) -> dict[str, Any]:
        top_disruptive_files = [
            {"path": row.path, "impact_score": row.impact_score, "status": row.status}
            for row in sorted(files, key=lambda item: item.impact_score, reverse=True)[:20]
        ]

        top_changed_fragments = [
            {
                "fragment_id": row.fragment_id,
                "churn_ratio": row.churn_ratio,
                "status": row.status,
                "reuse_score": row.reuse_score,
            }
            for row in sorted(fragments, key=lambda item: item.churn_ratio, reverse=True)[:20]
        ]

        largest_blast = asdict(blast_radius[0]) if blast_radius else None

        return {
            "totals": summary,
            "top_20_most_disruptive_files": top_disruptive_files,
            "top_20_most_changed_fragments": top_changed_fragments,
            "largest_blast_radius": largest_blast,
            "estimated_reuse_loss": summary["potential_reuse_loss"],
            "top_reuse_opportunities": [asdict(row) for row in reuse_opportunities[:20]],
        }

    @staticmethod
    def _range_to_text(rng: tuple[int, int] | None) -> str | None:
        if rng is None:
            return None
        return f"{rng[0]}-{rng[1]}"
