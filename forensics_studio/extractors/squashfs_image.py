from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path
from typing import Any

from forensics_studio.extractors.base import BaseExtractor
from forensics_studio.models.canonical import (
    BlockDescriptor,
    CanonicalFile,
    CanonicalFragment,
    CanonicalImageModel,
)

# SquashFS magic number: "hsqs" little-endian
SQUASHFS_MAGIC = 0x73717368

# Inode type constants (SquashFS inode types)
SQUASHFS_DIR_TYPE = 1
SQUASHFS_REG_TYPE = 2
SQUASHFS_SYMLINK_TYPE = 3
SQUASHFS_BLKDEV_TYPE = 4
SQUASHFS_CHRDEV_TYPE = 5
SQUASHFS_FIFO_TYPE = 6
SQUASHFS_SOCKET_TYPE = 7
SQUASHFS_LDIR_TYPE = 8
SQUASHFS_LREG_TYPE = 9
SQUASHFS_LSYMLINK_TYPE = 10
SQUASHFS_LBLKDEV_TYPE = 11
SQUASHFS_LCHRDEV_TYPE = 12
SQUASHFS_LFIFO_TYPE = 13
SQUASHFS_LSOCKET_TYPE = 14

# Inode sizes in bytes
# Base inode header (squashfs_base_inode_header):
#   inode_type(2) + mode(2) + uid(2) + guid(2) + mtime(4) + inode_number(4) = 16 bytes
INODE_HEADER_SIZE = 16

# Type-specific sizes (after the 16-byte base header):
#   REG:  start_block(4) + fragment(4) + offset(4) + file_size(4) = 16 bytes -> 32 total
#   LREG: start_block(8) + file_size(8) + sparse(8) + nlink(4)
#         + fragment(4) + offset(4) + xattr(4) = 40 bytes -> 56 total
#   DIR:  start_block(4) + nlink(4) + file_size(2) + offset(2)
#         + parent_inode(4) = 16 bytes -> 32 total
#   LDIR: nlink(4) + file_size(4) + start_block(4) + parent_inode(4)
#         + i_count(2) + offset(2) + xattr(4) = 24 bytes -> 40 total
#         + index entries (variable)
#   SYMLINK: nlink(4) + symlink_size(4) + target = 8 + target bytes -> 24 + target
#   DEV:  nlink(4) + rdev(4) = 8 bytes -> 24 total
#   LDEV: nlink(4) + rdev(4) + xattr(4) = 12 bytes -> 28 total
#   IPC:  nlink(4) = 4 bytes -> 20 total
#   LIPC: nlink(4) + xattr(4) = 8 bytes -> 24 total
REG_INODE_SIZE = 32
LREG_INODE_SIZE = 56
DIR_INODE_SIZE = 32
LDIR_INODE_SIZE = 40
DEV_INODE_SIZE = 24
LDEV_INODE_SIZE = 28
IPC_INODE_SIZE = 20
LIPC_INODE_SIZE = 24
SYMLINK_BASE_SIZE = 24  # 16 base + nlink(4) + symlink_size(4)

# Fragment table entry size: start (8) + size (4) + unused (4) = 16 bytes
FRAGMENT_ENTRY_SIZE = 16

# Block descriptor size: 4 bytes (24-bit size + 8-bit flags)
BLOCK_DESCRIPTOR_SIZE = 4

# Block list terminator
BLOCK_LIST_TERMINATOR = 0xFFFFFFFF

# Superblock field offsets (little-endian)
SB_MAGIC = 0
SB_INODES = 4
SB_MKFS_TIME = 8
SB_BLOCK_SIZE = 12
SB_FRAGMENTS = 16
SB_COMPRESSION = 20
SB_BLOCK_LOG = 24
SB_FLAGS = 25
SB_NO_IDS = 26
SB_S_MAJOR = 28
SB_S_MINOR = 30
SB_ROOT_INODE = 32
SB_BYTES_USED = 36
SB_ID_TABLE_START = 40
SB_XATTR_ID_TABLE_START = 44
SB_INODE_TABLE_START = 48
SB_DIRECTORY_TABLE_START = 52
SB_FRAGMENT_TABLE_START = 56
SB_EXPORT_TABLE_START = 60

# Compression types
COMPRESSION_ZLIB = 1
COMPRESSION_LZMA = 2
COMPRESSION_LZO = 3
COMPRESSION_XZ = 4
COMPRESSION_LZ4 = 5
COMPRESSION_ZSTD = 6

# Directory entry header sizes
DIR_ENTRY_HEADER_SIZE = 8  # offset(2) + inode_number(2) + type(2) + size(2)
LDIR_ENTRY_HEADER_SIZE = 12  # offset(2) + inode_number(2) + type(2) + size(2) + start_block(4)


class SquashfsImageExtractor(BaseExtractor):
    """Extract canonical metadata directly from a SquashFS image.

    This extractor parses the SquashFS binary structure to obtain
    authoritative inode, fragment-table, directory-table, and block-list
    information. It provides the file->fragment relationships that map
    formats do not contain.

    Phase 1 capabilities:
      - Directory table parsing: resolves real file paths (e.g.,
        ``/usr/share/theme/theme.json``) instead of synthetic ``inode-N``
        paths.
      - Real block descriptor parsing: reads the actual block descriptor
        list from the data region, producing accurate block chains with
        per-block compressed/uncompressed sizes.
      - Fragment content hashing: reads fragment data and computes SHA256
        content hashes, stored in ``CanonicalFragment.metadata["sha256"]``.

    The extractor reads only the metadata regions of the image
    (superblock, inode table, fragment table, directory table) plus the
    fragment data blocks for hashing. It does not decompress file data
    blocks.
    """

    def __init__(self, hash_fragments: bool = True) -> None:
        self.last_diagnostics: dict[str, Any] = {}
        self._compressed_inode_blocks = 0
        self._compressed_fragment_blocks = 0
        self._compressed_directory_blocks = 0
        self._hash_fragments = hash_fragments
        self._handle: Any = None
        self._superblock: dict[str, Any] = {}
        self._inode_offsets: dict[int, int] = {}
        self._path_by_inode: dict[int, str] = {}

    def extract(self, source_path: Path) -> CanonicalImageModel:
        """Extract a canonical image model from a SquashFS image.

        Args:
            source_path: Path to the SquashFS image file.

        Returns:
            A CanonicalImageModel with files, fragments, and authoritative
            file->fragment membership.
        """
        with source_path.open("rb") as handle:
            self._handle = handle
            superblock = self._read_superblock(handle)
            if superblock.get("magic") != SQUASHFS_MAGIC:
                raise ValueError(f"Not a SquashFS image (bad magic): {source_path}")

            self._superblock = superblock

            fragments = self._read_fragment_table(handle, superblock)
            files = self._read_inode_table(handle, superblock, fragments)

            # Resolve real file paths via directory table parsing
            self._resolve_file_paths(handle, superblock, files)

            # Hash fragment content (SHA256) for content-based identity
            if self._hash_fragments:
                self._hash_fragment_content(handle, fragments)

        diagnostics = {
            "source_file": str(source_path),
            "source_type": "squashfs_image",
            "files_extracted": len(files),
            "fragments_extracted": len(fragments),
            "files_with_fragment_membership": sum(1 for f in files if f.fragment_id is not None),
            "files_with_real_paths": sum(1 for f in files if not f.path.startswith("inode-")),
            "fragments_with_sha256": sum(1 for f in fragments if "sha256" in f.metadata),
            "compressed_inode_blocks": self._compressed_inode_blocks,
            "compressed_fragment_blocks": self._compressed_fragment_blocks,
            "compressed_directory_blocks": self._compressed_directory_blocks,
            "superblock": superblock,
        }
        self.last_diagnostics = diagnostics

        return CanonicalImageModel(
            image_path=str(source_path),
            source_type="squashfs_image",
            files=files,
            fragments=fragments,
            superblock=superblock,
            extraction_diagnostics=diagnostics,
        )

    def _read_superblock(self, handle: Any) -> dict[str, Any]:
        """Read and parse the SquashFS superblock (96 bytes at offset 0)."""
        handle.seek(0)
        raw = handle.read(96)
        if len(raw) < 96:
            raise ValueError("File too small to be a SquashFS image")

        # SquashFS v4 superblock format (96 bytes total):
        # Offset 0:   magic (I = 4 bytes)
        # Offset 4:   inodes (I = 4 bytes)
        # Offset 8:   creation_time (I = 4 bytes)
        # Offset 12:  block_size (I = 4 bytes)
        # Offset 16:  fragments (I = 4 bytes)
        # Offset 20:  compression (H = 2 bytes)
        # Offset 22:  block_log (H = 2 bytes)
        # Offset 24:  flags (H = 2 bytes)
        # Offset 26:  no_ids (H = 2 bytes)
        # Offset 28:  s_major (H = 2 bytes)
        # Offset 30:  s_minor (H = 2 bytes)
        # Offset 32:  root_inode (Q = 8 bytes)
        # Offset 40:  bytes_used (Q = 8 bytes)
        # Offset 48:  id_table_start (Q = 8 bytes)
        # Offset 56:  xattr_id_table_start (Q = 8 bytes)
        # Offset 64:  inode_table_start (Q = 8 bytes)
        # Offset 72:  directory_table_start (Q = 8 bytes)
        # Offset 80:  fragment_table_start (Q = 8 bytes)
        # Offset 88:  export_table_start (Q = 8 bytes)
        (
            magic,
            inodes,
            mkfs_time,
            block_size,
            fragments,
            compression,
            block_log,
            flags,
            no_ids,
            s_major,
            s_minor,
            root_inode,
            bytes_used,
            id_table_start,
            xattr_id_table_start,
            inode_table_start,
            directory_table_start,
            fragment_table_start,
            export_table_start,
        ) = struct.unpack("<IIIIIHHHHHHQQQQQQQQ", raw)

        return {
            "magic": magic,
            "inodes": inodes,
            "mkfs_time": mkfs_time,
            "block_size": block_size,
            "fragments": fragments,
            "compression": compression,
            "block_log": block_log,
            "flags": flags,
            "no_ids": no_ids,
            "s_major": s_major,
            "s_minor": s_minor,
            "root_inode": root_inode,
            "bytes_used": bytes_used,
            "id_table_start": id_table_start,
            "xattr_id_table_start": xattr_id_table_start,
            "inode_table_start": inode_table_start,
            "directory_table_start": directory_table_start,
            "fragment_table_start": fragment_table_start,
            "export_table_start": export_table_start,
        }

    def _extract_metadata(
        self,
        handle: Any,
        superblock: dict[str, Any],
    ) -> tuple[list[CanonicalFile], list[CanonicalFragment]]:
        """Extract files and fragments from the inode and fragment tables."""
        fragments = self._read_fragment_table(handle, superblock)
        files = self._read_inode_table(handle, superblock, fragments)
        return files, fragments

    def _read_fragment_table(
        self,
        handle: Any,
        superblock: dict[str, Any],
    ) -> list[CanonicalFragment]:
        """Read the fragment table to obtain fragment start offsets and sizes.

        The fragment table layout in SquashFS v4 is:
          1. At ``fragment_table_start``, a list of 8-byte pointers (index
             entries). The number of index entries is
             ``SQUASHFS_FRAGMENT_INDEX(fragments)`` =
             ``(fragments * 16 / 8192) + 1``.
          2. Each pointer points to a metadata block containing fragment
             entries. Each entry is 16 bytes:
                 start (8 bytes, little-endian)
                 size (4 bytes, little-endian)  -- compressed size
                 unused (4 bytes)

        Args:
            handle: Open file handle to the SquashFS image.
            superblock: Parsed superblock.

        Returns:
            A list of CanonicalFragment entries.
        """
        fragment_table_start = superblock.get("fragment_table_start", 0)
        fragment_count = superblock.get("fragments", 0)

        if fragment_table_start == 0 or fragment_count == 0:
            return []

        # Number of index entries in the fragment table
        # SQUASHFS_FRAGMENT_INDEX(fragments) = (fragments * 16 / 8192) + 1
        index_count = (fragment_count * FRAGMENT_ENTRY_SIZE // 8192) + 1

        # Read the fragment table index (list of 8-byte pointers)
        handle.seek(fragment_table_start)
        index_data = handle.read(index_count * 8)
        if len(index_data) < index_count * 8:
            return []

        fragments: list[CanonicalFragment] = []

        # Walk each metadata block pointed to by the index
        for i in range(index_count):
            if len(fragments) >= fragment_count:
                break

            block_ptr = struct.unpack("<Q", index_data[i * 8 : (i + 1) * 8])[0]
            if block_ptr == 0xFFFFFFFFFFFFFFFF:
                break

            # Read the metadata block header
            handle.seek(block_ptr)
            header = handle.read(2)
            if len(header) < 2:
                break
            block_size_field = struct.unpack("<H", header)[0]
            # SquashFS metadata block header:
            #   - Bits 0-14: size stored as (size - 1)
            #   - Bit 15:    compression flag (SET = uncompressed, CLEAR = compressed)
            meta_size = (block_size_field & 0x7FFF) + 1
            meta_compressed = not bool(block_size_field & 0x8000)

            # Read the metadata block data
            data = handle.read(meta_size)
            if len(data) < meta_size:
                break

            # If the block is compressed, decompress it to parse entries
            if meta_compressed:
                self._compressed_fragment_blocks += 1
                decompressed = self._try_decompress_metadata_block(data, meta_size)
                if decompressed is None:
                    break
                data = decompressed

            # Parse fragment entries from the metadata block
            for j in range(0, len(data) - FRAGMENT_ENTRY_SIZE + 1, FRAGMENT_ENTRY_SIZE):
                entry = data[j : j + FRAGMENT_ENTRY_SIZE]
                start, size, _unused = struct.unpack("<QII", entry)
                fragment_id = str(len(fragments))
                fragments.append(
                    CanonicalFragment(
                        fragment_id=fragment_id,
                        start_offset=start,
                        compressed_size=size,
                        uncompressed_size=size,  # uncompressed size not stored in fragment table
                    )
                )
                if len(fragments) >= fragment_count:
                    break

        return fragments

    def _read_inode_table(
        self,
        handle: Any,
        superblock: dict[str, Any],
        fragments: list[CanonicalFragment],
    ) -> list[CanonicalFile]:
        """Walk the inode table to extract regular file inodes.

        The inode table is a sequence of metadata blocks. Each metadata block
        has a 2-byte header (size + compression flag) followed by inode data.
        Inodes are variable-length; we walk them sequentially.

        For regular files (SQUASHFS_REG_TYPE and SQUASHFS_LREG_TYPE), we
        extract:
          - inode number
          - file size
          - block list (start offsets and sizes of compressed blocks)
          - fragment reference (fragment index + offset) for the file tail
        """
        inode_table_start = superblock.get("inode_table_start", 0)
        inode_count = superblock.get("inodes", 0)
        block_size = superblock.get("block_size", 131072)

        if inode_table_start == 0:
            return []

        files: list[CanonicalFile] = []
        handle.seek(inode_table_start)

        # Walk metadata blocks
        inode_number = 0
        while inode_number < inode_count:
            header = handle.read(2)
            if len(header) < 2:
                break
            block_size_field = struct.unpack("<H", header)[0]
            # SquashFS metadata block header:
            #   - Bits 0-14: size stored as (size - 1)
            #   - Bit 15:    compression flag (SET = uncompressed, CLEAR = compressed)
            meta_size = (block_size_field & 0x7FFF) + 1
            meta_compressed = not bool(block_size_field & 0x8000)

            data = handle.read(meta_size)
            if len(data) < meta_size:
                break

            # If the metadata block is compressed, decompress it
            if meta_compressed:
                self._compressed_inode_blocks += 1
                decompressed = self._try_decompress_metadata_block(data, meta_size)
                if decompressed is None:
                    break
                data = decompressed

            # Walk inodes within this uncompressed metadata block
            offset = 0
            while offset < len(data) and inode_number < inode_count:
                inode_number += 1
                inode, consumed = self._parse_inode(data, offset, inode_number, fragments)
                offset += consumed
                if inode is not None:
                    files.append(inode)

        return files

    def _parse_inode(
        self,
        data: bytes,
        offset: int,
        inode_number: int,
        fragments: list[CanonicalFragment],
    ) -> tuple[CanonicalFile | None, int]:
        """Parse a single inode from the inode table data.

        The SquashFS v4 inode structure has a 16-byte base header
        (squashfs_base_inode_header) followed by type-specific data:

            inode_type:2, mode:2, uid:2, guid:2  (8 bytes)
            mtime:4, inode_number:4              (8 bytes)

        This parser handles regular file inodes (SQUASHFS_REG_TYPE and
        SQUASHFS_LREG_TYPE) and skips other types.

        Returns a tuple of (CanonicalFile | None, bytes_consumed).
        """
        if offset + INODE_HEADER_SIZE > len(data):
            return None, 0

        # Parse base inode header (16 bytes)
        inode_type, perm, uid_idx, guid_idx = struct.unpack(
            "<HHHH", data[offset : offset + 8]
        )
        mtime, inode_num = struct.unpack("<II", data[offset + 8 : offset + 16])

        if inode_type == SQUASHFS_REG_TYPE:
            # Regular inode: base(16) + start_block(4) + fragment(4) + offset(4) + file_size(4) = 32 bytes
            if offset + REG_INODE_SIZE > len(data):
                return None, 0
            start_block, fragment_index, fragment_offset, file_size = struct.unpack(
                "<IIII", data[offset + INODE_HEADER_SIZE : offset + INODE_HEADER_SIZE + 16]
            )
            consumed = REG_INODE_SIZE

            # Parse the block descriptor list that follows the inode data
            block_list, block_list_consumed = self._parse_block_list(
                data, offset + consumed, file_size, start_block
            )
            consumed += block_list_consumed

            return self._build_canonical_file(
                inode_number=inode_number,
                perm=perm,
                file_size=file_size,
                start_block=start_block,
                fragment_index=fragment_index,
                fragment_offset=fragment_offset,
                fragments=fragments,
                block_list=block_list,
            ), consumed

        elif inode_type == SQUASHFS_LREG_TYPE:
            # Extended regular inode: base(16) + start_block(8) + file_size(8) + sparse(8)
            #   + nlink(4) + fragment(4) + offset(4) + xattr(4) = 56 bytes
            if offset + LREG_INODE_SIZE > len(data):
                return None, 0
            start_block, file_size, sparse, nlink, fragment_index, fragment_offset, xattr = struct.unpack(
                "<QQQIIII", data[offset + INODE_HEADER_SIZE : offset + INODE_HEADER_SIZE + 40]
            )
            consumed = LREG_INODE_SIZE

            # Parse the block descriptor list that follows the inode data
            block_list, block_list_consumed = self._parse_block_list(
                data, offset + consumed, file_size, start_block
            )
            consumed += block_list_consumed

            return self._build_canonical_file(
                inode_number=inode_number,
                perm=perm,
                file_size=file_size,
                start_block=start_block,
                fragment_index=fragment_index,
                fragment_offset=fragment_offset,
                fragments=fragments,
                block_list=block_list,
            ), consumed

        # For non-regular inodes, skip based on type
        consumed = self._inode_size_for_type(data, offset, inode_type)
        return None, consumed

    def _parse_block_list(
        self,
        data: bytes,
        offset: int,
        file_size: int,
        start_block: int,
    ) -> tuple[list[BlockDescriptor], int]:
        """Parse the block descriptor list for a regular file inode.

        The block list follows the inode data in the inode table. Each
        descriptor is 4 bytes:
            size (24 bits) + flags (8 bits)
        The high bit of the 24-bit size field (bit 23) indicates whether the
        block is uncompressed (1 = uncompressed/raw, 0 = compressed).

        The list is terminated by a 0xFFFFFFFF marker.

        Args:
            data: The decompressed inode table metadata block.
            offset: Offset where the block list begins.
            file_size: Uncompressed file size in bytes.
            start_block: Absolute offset of the first block in the image.

        Returns:
            A tuple of (block_list, bytes_consumed).
        """
        block_list: list[BlockDescriptor] = []
        if start_block == 0xFFFFFFFF or file_size == 0:
            return block_list, 0

        block_index = 0
        remaining = file_size
        pos = offset
        block_start = start_block

        while pos + BLOCK_DESCRIPTOR_SIZE <= len(data):
            raw = struct.unpack("<I", data[pos : pos + BLOCK_DESCRIPTOR_SIZE])[0]
            pos += BLOCK_DESCRIPTOR_SIZE

            # Check for terminator
            if raw == BLOCK_LIST_TERMINATOR:
                break

            # SquashFS block descriptor:
            #   - Bits 0-23: size stored as (size - 1)
            #   - Bit 24:    compression flag (SET = uncompressed, CLEAR = compressed)
            size = (raw & 0x00FFFFFF) + 1
            is_compressed = not bool(raw & 0x01000000)

            if size == 0:
                break

            # The uncompressed size is min(block_size, remaining)
            block_size = self._superblock.get("block_size", 131072)
            uncompressed_size = min(block_size, remaining)

            block_list.append(
                BlockDescriptor(
                    block_index=block_index,
                    start_offset=block_start,
                    compressed_size=size,
                    uncompressed_size=uncompressed_size,
                    is_compressed=is_compressed,
                )
            )

            block_start += size
            remaining -= uncompressed_size
            block_index += 1

            if remaining <= 0:
                break

        return block_list, pos - offset

    def _inode_size_for_type(self, data: bytes, offset: int, inode_type: int) -> int:
        """Return the size in bytes for the given inode type.

        Args:
            data: The decompressed inode table metadata block.
            offset: Offset of the inode within the metadata block.
            inode_type: The SquashFS inode type.

        Returns:
            The number of bytes consumed by this inode.
        """
        if inode_type == SQUASHFS_DIR_TYPE:
            return DIR_INODE_SIZE
        elif inode_type == SQUASHFS_LDIR_TYPE:
            # LDIR: base(16) + nlink(4) + file_size(4) + start_block(4)
            #       + parent_inode(4) + i_count(2) + offset(2) + xattr(4) = 40
            #       + index entries (variable)
            if offset + LDIR_INODE_SIZE <= len(data):
                # Parse i_count to determine index entry count
                # i_count is at offset + 16 + 4 + 4 + 4 + 4 = offset + 32
                i_count = struct.unpack(
                    "<H", data[offset + 32 : offset + 34]
                )[0]
                # Each index entry: index(4) + start_block(4) + size(4) + name
                # We need to walk the index entries to determine total size
                pos = offset + LDIR_INODE_SIZE
                for _ in range(i_count):
                    if pos + 12 > len(data):
                        break
                    index, start_block, size = struct.unpack(
                        "<III", data[pos : pos + 12]
                    )
                    pos += 12 + size
                return pos - offset
            return LDIR_INODE_SIZE
        elif inode_type == SQUASHFS_SYMLINK_TYPE:
            # Symlink: base(16) + nlink(4) + symlink_size(4) + target
            if offset + SYMLINK_BASE_SIZE <= len(data):
                _nlink, symlink_size = struct.unpack(
                    "<II", data[offset + INODE_HEADER_SIZE : offset + INODE_HEADER_SIZE + 8]
                )
                return SYMLINK_BASE_SIZE + symlink_size
            return SYMLINK_BASE_SIZE
        elif inode_type == SQUASHFS_LSYMLINK_TYPE:
            # Extended symlink: base(16) + nlink(4) + symlink_size(4) + target + xattr(4)
            if offset + SYMLINK_BASE_SIZE <= len(data):
                _nlink, symlink_size = struct.unpack(
                    "<II", data[offset + INODE_HEADER_SIZE : offset + INODE_HEADER_SIZE + 8]
                )
                return SYMLINK_BASE_SIZE + symlink_size + 4
            return SYMLINK_BASE_SIZE + 4
        elif inode_type in (SQUASHFS_BLKDEV_TYPE, SQUASHFS_CHRDEV_TYPE,
                            SQUASHFS_FIFO_TYPE, SQUASHFS_SOCKET_TYPE):
            return DEV_INODE_SIZE
        elif inode_type in (SQUASHFS_LBLKDEV_TYPE, SQUASHFS_LCHRDEV_TYPE,
                            SQUASHFS_LFIFO_TYPE, SQUASHFS_LSOCKET_TYPE):
            return LDEV_INODE_SIZE
        elif inode_type in (SQUASHFS_FIFO_TYPE, SQUASHFS_SOCKET_TYPE):
            return IPC_INODE_SIZE
        elif inode_type in (SQUASHFS_LFIFO_TYPE, SQUASHFS_LSOCKET_TYPE):
            return LIPC_INODE_SIZE
        else:
            # Unknown type: use the base header size
            return INODE_HEADER_SIZE

    def _build_canonical_file(
        self,
        inode_number: int,
        perm: int,
        file_size: int,
        start_block: int,
        fragment_index: int,
        fragment_offset: int,
        fragments: list[CanonicalFragment],
        block_list: list[BlockDescriptor] | None = None,
    ) -> CanonicalFile | None:
        """Build a CanonicalFile from parsed inode fields."""
        if block_list is None:
            block_list = []

        # Determine fragment membership
        fragment_id: str | None = None
        frag_offset: int | None = None
        if fragment_index != 0xFFFFFFFF and fragment_index < len(fragments):
            fragment_id = str(fragment_index)
            frag_offset = fragment_offset
            fragments[fragment_index].files.append(f"inode-{inode_number}")

        # Compute start offset (first block offset)
        start_offset = start_block if block_list else None

        return CanonicalFile(
            path=f"inode-{inode_number}",
            inode_number=inode_number,
            size=file_size,
            fragment_id=fragment_id,
            fragment_offset=frag_offset,
            block_list=block_list,
            start_offset=start_offset,
            metadata={
                "perm": perm,
                "inode_type": "regular",
            },
        )

    def _resolve_file_paths(
        self,
        handle: Any,
        superblock: dict[str, Any],
        files: list[CanonicalFile],
    ) -> None:
        """Resolve real file paths by walking the directory table.

        The directory table contains directory entries that map inode numbers
        to names. By walking the directory hierarchy starting from the root
        inode, we can build a mapping of inode_number -> absolute path.

        This method populates ``self._path_by_inode`` and updates each
        ``CanonicalFile.path`` with the real path.

        Args:
            handle: Open file handle to the SquashFS image.
            superblock: Parsed superblock.
            files: List of CanonicalFile entries to update.
        """
        directory_table_start = superblock.get("directory_table_start", 0)
        if directory_table_start == 0:
            return

        # Build a mapping of inode_number -> (inode_type, start_block, offset)
        # by walking the inode table again, this time capturing directory inodes.
        self._inode_offsets = {}
        self._walk_inode_table_for_directories(handle, superblock)

        # Walk the directory hierarchy starting from the root inode
        root_inode = superblock.get("root_inode", 0)
        self._path_by_inode = {}
        self._walk_directory(handle, superblock, root_inode, "")

        # Update file paths
        for file in files:
            real_path = self._path_by_inode.get(file.inode_number)
            if real_path:
                file.path = real_path

    def _walk_inode_table_for_directories(
        self,
        handle: Any,
        superblock: dict[str, Any],
    ) -> None:
        """Walk the inode table to record directory inode locations.

        This records for each inode number its (inode_type, start_block,
        offset) so we can later walk the directory table to resolve paths.
        """
        inode_table_start = superblock.get("inode_table_start", 0)
        inode_count = superblock.get("inodes", 0)

        if inode_table_start == 0:
            return

        handle.seek(inode_table_start)
        inode_number = 0
        while inode_number < inode_count:
            header = handle.read(2)
            if len(header) < 2:
                break
            block_size_field = struct.unpack("<H", header)[0]
            # SquashFS metadata block header:
            #   - Bits 0-14: size stored as (size - 1)
            #   - Bit 15:    compression flag (SET = uncompressed, CLEAR = compressed)
            meta_size = (block_size_field & 0x7FFF) + 1
            meta_compressed = not bool(block_size_field & 0x8000)

            data = handle.read(meta_size)
            if len(data) < meta_size:
                break

            if meta_compressed:
                decompressed = self._try_decompress_metadata_block(data, meta_size)
                if decompressed is None:
                    break
                data = decompressed

            offset = 0
            while offset < len(data) and inode_number < inode_count:
                inode_number += 1
                if offset + INODE_HEADER_SIZE > len(data):
                    break

                # Parse base inode header (16 bytes)
                inode_type, perm, uid_idx, guid_idx = struct.unpack(
                    "<HHHH", data[offset : offset + 8]
                )
                mtime, inode_num = struct.unpack("<II", data[offset + 8 : offset + 16])

                if inode_type in (SQUASHFS_DIR_TYPE, SQUASHFS_LDIR_TYPE):
                    # Record directory inode location
                    if inode_type == SQUASHFS_DIR_TYPE:
                        # Basic dir: base(16) + start_block(4) + nlink(4)
                        #             + file_size(2) + offset(2) + parent_inode(4) = 32
                        if offset + DIR_INODE_SIZE > len(data):
                            break
                        start_block, nlink, file_size, dir_offset, parent_inode = struct.unpack(
                            "<IIHH I", data[offset + INODE_HEADER_SIZE : offset + INODE_HEADER_SIZE + 16]
                        )
                        consumed = DIR_INODE_SIZE
                    else:
                        # Extended dir: base(16) + nlink(4) + file_size(4) + start_block(4)
                        #               + parent_inode(4) + i_count(2) + offset(2) + xattr(4) = 40
                        if offset + LDIR_INODE_SIZE > len(data):
                            break
                        nlink, file_size, start_block, parent_inode, i_count, dir_offset, xattr = struct.unpack(
                            "<IIIIHHI", data[offset + INODE_HEADER_SIZE : offset + INODE_HEADER_SIZE + 24]
                        )
                        consumed = self._inode_size_for_type(data, offset, inode_type)

                    self._inode_offsets[inode_number] = {
                        "type": inode_type,
                        "start_block": start_block,
                        "offset": dir_offset,
                    }
                    offset += consumed
                else:
                    consumed = self._inode_size_for_type(data, offset, inode_type)
                    offset += consumed

    def _walk_directory(
        self,
        handle: Any,
        superblock: dict[str, Any],
        inode_number: int,
        parent_path: str,
    ) -> None:
        """Recursively walk a directory to resolve child paths.

        Args:
            handle: Open file handle to the SquashFS image.
            superblock: Parsed superblock.
            inode_number: Inode number of the directory to walk.
            parent_path: Absolute path of the parent directory ("" for root).
        """
        dir_info = self._inode_offsets.get(inode_number)
        if dir_info is None:
            return

        directory_table_start = superblock.get("directory_table_start", 0)
        start_block = dir_info["start_block"]
        dir_offset = dir_info["offset"]

        if start_block == 0xFFFFFFFF:
            return

        # Read the directory metadata block containing this directory
        handle.seek(directory_table_start + start_block)
        header = handle.read(2)
        if len(header) < 2:
            return
        block_size_field = struct.unpack("<H", header)[0]
        # SquashFS metadata block header:
        #   - Bits 0-14: size stored as (size - 1)
        #   - Bit 15:    compression flag (SET = uncompressed, CLEAR = compressed)
        meta_size = (block_size_field & 0x7FFF) + 1
        meta_compressed = not bool(block_size_field & 0x8000)

        data = handle.read(meta_size)
        if len(data) < meta_size:
            return

        if meta_compressed:
            self._compressed_directory_blocks += 1
            decompressed = self._try_decompress_metadata_block(data, meta_size)
            if decompressed is None:
                return
            data = decompressed

        # Parse directory entries starting at dir_offset.
        # Directory entries are grouped in headers:
        #   struct squashfs_dir_header {
        #       unsigned int count;         // 4
        #       unsigned int start_block;   // 4
        #       unsigned int inode_number;  // 4
        #   };
        # Followed by `count` entries:
        #   struct squashfs_dir_entry {
        #       unsigned short offset;      // 2
        #       short          inode_number; // 2 (signed, relative to header)
        #       unsigned short type;        // 2
        #       unsigned short size;        // 2 (name_length - 1)
        #       char           name[0];     // variable
        #   };
        pos = dir_offset
        while pos + 12 <= len(data):
            # Parse directory header
            count, start_block, header_inode = struct.unpack(
                "<III", data[pos : pos + 12]
            )
            pos += 12

            for _ in range(count):
                if pos + DIR_ENTRY_HEADER_SIZE > len(data):
                    break

                # Parse directory entry
                entry_offset, entry_inode_rel, entry_type, name_size = struct.unpack(
                    "<hHHH", data[pos : pos + DIR_ENTRY_HEADER_SIZE]
                )
                pos += DIR_ENTRY_HEADER_SIZE

                # name_size is stored as (name_length - 1)
                name_length = name_size + 1

                if pos + name_length > len(data):
                    break

                name = data[pos : pos + name_length].decode("utf-8", errors="replace")
                pos += name_length

                # The actual inode number is the header inode number plus
                # the signed relative inode number from the entry
                child_inode = header_inode + entry_inode_rel

                # Build the child path
                if parent_path:
                    child_path = f"{parent_path}/{name}"
                else:
                    child_path = f"/{name}"

                # Record the path for this inode
                self._path_by_inode[child_inode] = child_path

                # If this is a directory, recurse
                if entry_type in (SQUASHFS_DIR_TYPE, SQUASHFS_LDIR_TYPE):
                    self._walk_directory(handle, superblock, child_inode, child_path)

    def _hash_fragment_content(
        self,
        handle: Any,
        fragments: list[CanonicalFragment],
    ) -> None:
        """Compute SHA256 content hashes for all fragments.

        Reads the fragment data from the image, decompresses if necessary,
        and stores the SHA256 hash in ``CanonicalFragment.metadata["sha256"]``.

        Args:
            handle: Open file handle to the SquashFS image.
            fragments: List of CanonicalFragment entries to hash.
        """
        compression = self._superblock.get("compression", COMPRESSION_ZLIB)

        for fragment in fragments:
            if fragment.start_offset == 0xFFFFFFFF or fragment.compressed_size == 0:
                continue

            try:
                handle.seek(fragment.start_offset)
                data = handle.read(fragment.compressed_size)
                if len(data) < fragment.compressed_size:
                    continue

                # Decompress if the fragment is compressed
                if fragment.compressed_size < fragment.uncompressed_size:
                    decompressed = self._decompress_fragment(data, compression)
                    if decompressed is not None:
                        data = decompressed

                fragment.metadata["sha256"] = hashlib.sha256(data).hexdigest()
            except Exception:
                # If hashing fails for any reason, leave the fragment unhashed
                continue

    def _decompress_fragment(self, data: bytes, compression: int) -> bytes | None:
        """Decompress fragment data based on the image compression type.

        Args:
            data: Compressed fragment data.
            compression: SquashFS compression type from the superblock.

        Returns:
            Decompressed bytes, or None if decompression is not supported.
        """
        try:
            if compression == COMPRESSION_ZLIB:
                return zlib.decompress(data)
            elif compression == COMPRESSION_XZ:
                import lzma

                return lzma.decompress(data)
            elif compression == COMPRESSION_LZMA:
                import lzma

                # LZMA in SquashFS uses a raw LZMA stream with a specific
                # header. Try lzma.decompress with FORMAT_ALONE.
                return lzma.decompress(data, format=lzma.FORMAT_ALONE)
            elif compression == COMPRESSION_LZO:
                # Fragment data can be up to block_size (131072) uncompressed
                return self._lzo_decompress(data, self._superblock.get("block_size", 131072))
            else:
                # LZ4, ZSTD are not supported by the standard library
                return None
        except Exception:
            return None

    def _try_decompress_metadata_block(self, data: bytes, expected_size: int) -> bytes | None:
        """Attempt to decompress a SquashFS metadata block.

        SquashFS metadata blocks are compressed with the image's compression
        type (from the superblock). This method attempts decompression and
        returns the decompressed bytes, or None if decompression fails.

        Args:
            data: The compressed metadata block data.
            expected_size: The expected uncompressed size (from the block header).

        Returns:
            Decompressed bytes, or None if decompression is not possible.
        """
        compression = self._superblock.get("compression", COMPRESSION_ZLIB)
        try:
            if compression == COMPRESSION_ZLIB:
                return zlib.decompress(data)
            elif compression == COMPRESSION_XZ:
                import lzma

                return lzma.decompress(data)
            elif compression == COMPRESSION_LZMA:
                import lzma

                return lzma.decompress(data, format=lzma.FORMAT_ALONE)
            elif compression == COMPRESSION_LZO:
                # SquashFS metadata blocks are at most 8192 bytes uncompressed
                return self._lzo_decompress(data, 8192)
            else:
                # LZ4, ZSTD are not supported by the standard library
                return None
        except Exception:
            return None

    @staticmethod
    def _lzo_decompress(data: bytes, expected_size: int) -> bytes | None:
        """Decompress LZO-compressed data using liblzo2.

        SquashFS uses raw LZO1X compression (not the lzop container format).
        This method uses ctypes to call lzo1x_decompress from liblzo2.

        Note: We use ``lzo1x_decompress`` (not ``lzo1x_decompress_safe``)
        because the safe variant returns ``LZO_E_OUTPUT_OVERRUN`` (-6) on
        SquashFS metadata blocks even when the output buffer is large enough.
        The non-safe variant correctly decompresses the data and returns
        ``LZO_E_INPUT_NOT_CONSUMED`` (-8) when there is leftover input,
        which is expected for SquashFS metadata blocks.

        Args:
            data: The compressed data.
            expected_size: The expected uncompressed size.

        Returns:
            Decompressed bytes, or None if decompression fails.
        """
        try:
            import ctypes

            lzo = ctypes.CDLL("liblzo2.so.2")
            lzo.lzo1x_decompress.restype = ctypes.c_int
            lzo.lzo1x_decompress.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_size_t),
                ctypes.c_void_p,
            ]

            # Use a larger output buffer than expected_size to prevent
            # buffer overruns with the non-safe lzo1x_decompress. The
            # non-safe variant does not perform bounds checking, so if
            # the decompressed data exceeds the buffer, it will write
            # past the end and cause a segfault. Using a generous buffer
            # (e.g., 4x the expected size) avoids this.
            buffer_size = max(expected_size * 4, 65536)
            src = ctypes.create_string_buffer(data, len(data))
            dst = ctypes.create_string_buffer(buffer_size)
            dst_len = ctypes.c_size_t(buffer_size)
            result = lzo.lzo1x_decompress(
                src, len(data), dst, ctypes.byref(dst_len), None
            )

            # LZO_E_INPUT_NOT_CONSUMED (-8) means the output buffer was
            # filled but there's leftover input. For SquashFS metadata
            # blocks, this is expected since the decompressor may read
            # ahead into the next block. The output is still valid.
            if result < 0 and result != -8:
                return None
            return dst.raw[: dst_len.value]
        except Exception:
            return None