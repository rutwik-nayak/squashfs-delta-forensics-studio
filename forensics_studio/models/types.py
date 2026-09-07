from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class MapFileEntry:
    path: str
    size: int
    fragment_id: str | None
    blocks: list[int] = field(default_factory=list)
    start_offset: int | None = None
    extent_ranges: list[tuple[int, int]] = field(default_factory=list)
    source_file: str = ""
    source_line: int = 0
    parser_rule: str = ""
    is_synthetic: bool = False
    entry_kind: str = "file"
    row_type: str = "file"


@dataclass(slots=True)
class FileRecord:
    path: str
    old_size: int | None
    new_size: int | None
    old_fragment: str | None
    new_fragment: str | None
    old_blocks: list[int]
    new_blocks: list[int]
    same_size: bool
    same_fragment: bool
    status: str
    impact_score: float
    reuse_score: float
    directly_changed: bool
    root_cause: str
    root_cause_confidence: float
    neighbors_old: list[str]
    neighbors_new: list[str]
    data_confidence: str
    source_old_file: str | None
    source_old_line: int | None
    source_old_rule: str | None
    source_new_file: str | None
    source_new_line: int | None
    source_new_rule: str | None
    synthetic: bool
    old_start_offset: int | None = None
    new_start_offset: int | None = None


@dataclass(slots=True)
class FragmentRecord:
    fragment_id: str
    file_count: int
    old_file_list: list[str]
    new_file_list: list[str]
    added_files: list[str]
    removed_files: list[str]
    retained_files: list[str]
    compressed_size_old: int | None
    compressed_size_new: int | None
    status: str
    change_reason: str
    reuse_score: float
    churn_ratio: float
    membership_available: bool
    membership_message: str
    old_offset_range: str | None
    new_offset_range: str | None
    overlapping_files_old: list[str]
    overlapping_files_new: list[str]
    overlap_confidence_score: float
    inference_method: str


@dataclass(slots=True)
class FragmentMovement:
    old_fragment: str
    new_fragment: str
    moved_files: list[str]
    movement_ratio: float


@dataclass(slots=True)
class BlastRadius:
    source_file: str
    impacted_fragments: list[str]
    impacted_files: list[str]
    estimated_reuse_loss: float
    impact_score: float


@dataclass(slots=True)
class RootCauseRecord:
    file_path: str
    category: str
    confidence: float
    details: str


@dataclass(slots=True)
class ReuseOpportunity:
    file_path: str
    old_fragment: str
    new_fragment: str
    file_size: int
    importance_score: float
    reason: str


@dataclass(slots=True)
class AnalysisResult:
    summary: dict[str, Any]
    files: list[FileRecord]
    fragments: list[FragmentRecord]
    movement_graph: list[FragmentMovement]
    blast_radius: list[BlastRadius]
    reuse_opportunities: list[ReuseOpportunity]
    root_causes: list[RootCauseRecord]
    heatmap_data: dict[str, Any]
    executive_summary: dict[str, Any]
    parser_validation: dict[str, Any]
    data_confidence: dict[str, Any]
    relationship_graph: dict[str, Any]
    debug_dataset: dict[str, Any]
    warnings: list[str]
    offset_analysis: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "files": [asdict(row) for row in self.files],
            "fragments": [asdict(row) for row in self.fragments],
            "movement_graph": [asdict(row) for row in self.movement_graph],
            "blast_radius": [asdict(row) for row in self.blast_radius],
            "reuse_opportunities": [asdict(row) for row in self.reuse_opportunities],
            "root_causes": [asdict(row) for row in self.root_causes],
            "heatmap_data": self.heatmap_data,
            "executive_summary": self.executive_summary,
            "parser_validation": self.parser_validation,
            "data_confidence": self.data_confidence,
            "relationship_graph": self.relationship_graph,
            "debug_dataset": self.debug_dataset,
            "warnings": self.warnings,
            "offset_analysis": self.offset_analysis,
        }
