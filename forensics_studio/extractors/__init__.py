"""Metadata extraction layer that produces canonical image models.

The extraction layer consumes various source formats (SquashFS images,
unsquashfs maps, future metadata sources) and emits a canonical
CanonicalImageModel that the analysis engine consumes exclusively.
"""

from forensics_studio.extractors.base import BaseExtractor
from forensics_studio.extractors.registry import ExtractorRegistry
from forensics_studio.extractors.squashfs_image import SquashfsImageExtractor
from forensics_studio.extractors.unsquashfs_map import UnsquashfsMapAdapter

__all__ = [
    "BaseExtractor",
    "ExtractorRegistry",
    "SquashfsImageExtractor",
    "UnsquashfsMapAdapter",
]