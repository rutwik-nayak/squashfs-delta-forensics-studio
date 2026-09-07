from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class BlockDescriptor:
    """A single compressed block descriptor within a file's block list.

    Attributes:
        block_index: Zero-based index of the block within the file.
        start_offset: Absolute offset of the block in the SquashFS image.
        compressed_size: Size of the compressed block data in bytes.
        uncompressed_size: Size of the block after decompression.
        is_compressed: Whether the block is stored compressed (True) or raw (False).
    """

    block_index: int
    start_offset: int
    compressed_size: int
    uncompressed_size: int
    is_compressed: bool = True


@dataclass(slots=True)
class CanonicalFile:
    """A regular file extracted from a metadata source.

    This is the source-agnostic representation of a file. It carries the
    authoritative file->fragment relationship when available (from direct
    SquashFS inode/fragment-table extraction) and the authoritative block
    list.

    Attributes:
        path: Absolute path of the file within the image.
        inode_number: Inode number from the SquashFS inode table.
        size: Uncompressed file size in bytes.
        fragment_id: Fragment ID if the file tail is stored in a fragment,
            otherwise None.
        fragment_offset: Offset of the file tail within the fragment, or None.
        block_list: Ordered list of BlockDescriptor entries for the file.
        start_offset: Absolute offset of the first block in the image, or None
            if the file has no blocks (e.g., empty file).
        metadata: Source-specific extra metadata (e.g., mode, uid, gid, mtime).
    """

    path: str
    inode_number: int
    size: int
    fragment_id: str | None = None
    fragment_offset: int | None = None
    block_list: list[BlockDescriptor] = field(default_factory=list)
    start_offset: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CanonicalFragment:
    """A fragment entry from the SquashFS fragment table.

    Attributes:
        fragment_id: Fragment identifier (e.g., "0", "1", ...).
        start_offset: Absolute offset of the fragment in the image.
        compressed_size: Compressed size of the fragment data in bytes.
        uncompressed_size: Uncompressed size of the fragment data in bytes.
        files: List of file paths whose tails are stored in this fragment.
            This is the authoritative file->fragment membership.
        metadata: Source-specific extra metadata. For SquashFS image
            extraction, this includes the SHA256 content hash of the
            fragment data (key "sha256") when hashing is enabled.
    """

    fragment_id: str
    start_offset: int
    compressed_size: int
    uncompressed_size: int
    files: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CanonicalImageModel:
    """Canonical, source-agnostic model of a SquashFS image.

    This is the single contract that the analysis engine consumes. It is
    produced by metadata extractors (SquashFS image extractor, unsquashfs
    map adapter, future sources) and is independent of any specific input
    format.

    Attributes:
        image_path: Path of the source image or map file.
        source_type: Type of the source that produced this model. One of
            "squashfs_image", "unsquashfs_map", or a future source type.
        files: List of CanonicalFile entries.
        fragments: List of CanonicalFragment entries.
        superblock: SquashFS superblock metadata (block size, inode table
            start, fragment table start, etc.) when available.
        extraction_diagnostics: Diagnostics from the extraction process
            (e.g., rows parsed, rows dropped, warnings).
    """

    image_path: str
    source_type: str
    files: list[CanonicalFile] = field(default_factory=list)
    fragments: list[CanonicalFragment] = field(default_factory=list)
    superblock: dict[str, Any] = field(default_factory=dict)
    extraction_diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "image_path": self.image_path,
            "source_type": self.source_type,
            "files": [asdict(row) for row in self.files],
            "fragments": [asdict(row) for row in self.fragments],
            "superblock": self.superblock,
            "extraction_diagnostics": self.extraction_diagnostics,
        }