from __future__ import annotations

from pathlib import Path

from forensics_studio.extractors.base import BaseExtractor
from forensics_studio.extractors.squashfs_image import SquashfsImageExtractor
from forensics_studio.extractors.unsquashfs_map import UnsquashfsMapAdapter

# SquashFS magic number: "hsqs" little-endian
SQUASHFS_MAGIC = 0x73717368


class ExtractorRegistry:
    """Resolver for metadata extractors by source type/path.

    The registry determines the appropriate extractor based on the
    source file. SquashFS images are detected by their magic number
    and are the preferred source because they provide authoritative
    file->fragment relationships. Map files are adapted via the
    UnsquashfsMapAdapter for backward compatibility.
    """

    def get_extractor(self, source_path: Path) -> BaseExtractor:
        """Resolve the appropriate extractor for the given source path.

        Args:
            source_path: Path to the source image or map file.

        Returns:
            A BaseExtractor implementation.

        Raises:
            ValueError: If the source type cannot be determined.
        """
        if self._is_squashfs_image(source_path):
            return SquashfsImageExtractor()
        return UnsquashfsMapAdapter()

    @staticmethod
    def _is_squashfs_image(source_path: Path) -> bool:
        """Detect whether the file is a SquashFS image by its magic number.

        Reads only the first 4 bytes of the file to check for the SquashFS
        magic number (0x73717368, "hsqs" little-endian).
        """
        try:
            with source_path.open("rb") as handle:
                raw = handle.read(4)
            if len(raw) < 4:
                return False
            import struct

            magic = struct.unpack("<I", raw)[0]
            return magic == SQUASHFS_MAGIC
        except (OSError, ValueError):
            return False