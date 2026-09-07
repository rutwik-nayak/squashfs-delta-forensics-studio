from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from forensics_studio.models.canonical import CanonicalImageModel


class BaseExtractor(ABC):
    """Abstract extractor that produces a canonical image model.

    Implementations consume a specific source format (SquashFS image,
    unsquashfs map, future metadata sources) and emit a source-agnostic
    CanonicalImageModel. The analysis engine operates exclusively on the
    canonical model and never sees the raw source format.
    """

    @abstractmethod
    def extract(self, source_path: Path) -> CanonicalImageModel:
        """Extract a canonical image model from the given source.

        Args:
            source_path: Path to the source image or map file.

        Returns:
            A CanonicalImageModel populated with files, fragments, and
            authoritative file->fragment relationships when available.
        """
        raise NotImplementedError