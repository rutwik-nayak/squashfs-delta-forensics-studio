# Report JSON Model

The analyzer writes a single `report.json` file with top-level keys:

- summary
- files
- fragments
- movement_graph
- blast_radius
- reuse_opportunities
- root_causes
- heatmap_data
- executive_summary

Schema is defined in `schema/report.schema.json`.

## Canonical Model

The analysis engine operates exclusively on the canonical model
(`CanonicalImageModel`), which is produced by the metadata extraction layer.
The canonical model is source-agnostic and is the single contract between
extractors and the engine.

### CanonicalFile

- path
- inode_number
- size
- fragment_id
- fragment_offset
- block_list (list of BlockDescriptor)
- start_offset
- metadata

### CanonicalFragment

- fragment_id
- start_offset
- compressed_size
- uncompressed_size
- files (authoritative file->fragment membership)

### CanonicalImageModel

- image_path
- source_type ("squashfs_image" | "unsquashfs_map" | future)
- files
- fragments
- superblock
- extraction_diagnostics

## Key Typed Entities

### FileRecord

- path
- old_size, new_size
- old_fragment, new_fragment
- old_blocks, new_blocks
- same_size, same_fragment
- status
- impact_score
- reuse_score
- directly_changed
- root_cause, root_cause_confidence
- neighbors_old, neighbors_new

### FragmentRecord

- fragment_id
- file_count
- old_file_list, new_file_list
- added_files, removed_files, retained_files
- compressed_size_old, compressed_size_new
- status
- change_reason
- reuse_score
- churn_ratio

### FragmentMovement

- old_fragment
- new_fragment
- moved_files
- movement_ratio

### BlastRadius

- source_file
- impacted_fragments
- impacted_files
- estimated_reuse_loss
- impact_score
