from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from forensics_studio.models.types import MapFileEntry


class BaseMapParser(ABC):
    """Abstract parser for map-like file to fragment relationships."""

    @abstractmethod
    def parse(self, input_path: Path) -> list[MapFileEntry]:
        raise NotImplementedError


class BaseFragmentMetadataParser(ABC):
    """Abstract parser for fragment metadata dumps."""

    @abstractmethod
    def parse(self, input_path: Path) -> dict[str, dict[str, Any]]:
        raise NotImplementedError
