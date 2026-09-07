# Report and Data Model

This document describes the core data structures used throughout SquashFS Delta Forensics Studio.

The platform is built around a canonical model that serves as the contract between metadata extraction and forensic analysis, and a report model that serves as the contract between the analysis engine and visualization layer.

---

## Data Flow

```text
Metadata Sources
        ↓
Metadata Extraction Layer
        ↓
CanonicalImageModel
        ↓
ForensicsAnalyzer
        ↓
AnalysisResult
        ↓
report.json
        ↓
Visualization Studio
```

---

# Report Model

The analyzer generates a single JSON report that is consumed by all visualization pages.

The report schema is defined in:

```text
schema/report.schema.json
```

## Top-Level Report Keys

### summary

High-level analysis statistics and metadata.

Examples include:

- File counts
- Fragment counts
- Reuse ratios
- Membership availability
- Analysis summary metrics

---

### files

Collection of per-file forensic analysis records.

Contains:

- Status classification
- Impact score
- Reuse score
- Root-cause information
- Structural change information

---

### fragments

Collection of per-fragment analysis records.

Contains:

- Fragment churn
- Membership information
- Fragment reuse metrics
- Size evolution
- Fragment status

---

### movement_graph

Fragment-to-fragment movement relationships.

Used by:

- Sankey visualizations
- Movement analysis views

---

### blast_radius

Impact propagation analysis.

Contains:

- Source files
- Impacted fragments
- Impacted files
- Estimated reuse loss

---

### reuse_opportunities

Ranked reuse candidates identified by the analyzer.

---

### root_causes

Root-cause classification results with confidence scoring.

---

### heatmap_data

Visualization-oriented data structures used by:

- Churn heatmaps
- Impact heatmaps
- Reuse heatmaps
- Movement heatmaps

---

### executive_summary

Condensed analysis summary highlighting the most significant findings.

---

### parser_validation

Extraction traceability and validation metadata.

---

### data_confidence

Analysis confidence indicators and metadata availability status.

---

### relationship_graph

Graph representation of extracted structures and relationships.

Examples include:

- File-to-block relationships
- Fragment-to-range relationships

---

### debug_dataset

Optional diagnostic dataset generated for troubleshooting and validation.

---

### warnings

Analyzer-generated warnings and limitations.

---

### offset_analysis

Storage-layout evolution and movement analysis.

Examples include:

- Offset movement
- Storage timelines
- Cascading movement effects

---

# Canonical Model

The analysis engine operates exclusively on the canonical model (`CanonicalImageModel`).

The canonical model is source-agnostic and serves as the single contract between the metadata extraction layer and the analysis engine.

All supported metadata sources must be transformed into this model prior to analysis.

---

## CanonicalFile

Represents a filesystem object.

### Fields

- `path`
- `inode_number`
- `size`
- `fragment_id`
- `fragment_offset`
- `block_list`
- `start_offset`
- `metadata`

### Purpose

Provides a consistent representation of file-level metadata regardless of the original source format.

---

## BlockDescriptor

Represents a storage block associated with a file.

### Fields

- `block_index`
- `start_offset`
- `compressed_size`
- `uncompressed_size`
- `is_compressed`

### Purpose

Provides the foundation for:

- Churn analysis
- Offset analysis
- Block-level reuse calculations

---

## CanonicalFragment

Represents a filesystem fragment.

### Fields

- `fragment_id`
- `start_offset`
- `compressed_size`
- `uncompressed_size`
- `files`

### Purpose

Provides fragment-level metadata and file membership information when available from the source.

---

## CanonicalImageModel

Root container for extracted filesystem metadata.

### Fields

- `image_path`
- `source_type`
- `files`
- `fragments`
- `superblock`
- `extraction_diagnostics`

### Supported Source Types

Current examples:

```text
squashfs_image
unsquashfs_map
```

Future extractors may introduce additional source types without requiring analysis engine changes.

---

# Analysis Entities

The analysis engine transforms canonical objects into structured forensic results.

---

## FileRecord

Represents analysis results for a single file.

### Core Fields

- `path`
- `old_size`
- `new_size`
- `old_fragment`
- `new_fragment`
- `old_blocks`
- `new_blocks`

### Comparison Fields

- `same_size`
- `same_fragment`

### Classification Fields

- `status`
- `root_cause`
- `root_cause_confidence`

### Scoring Fields

- `impact_score`
- `reuse_score`

### Relationship Fields

- `directly_changed`
- `neighbors_old`
- `neighbors_new`

---

## FragmentRecord

Represents analysis results for a fragment.

### Membership Fields

- `old_file_list`
- `new_file_list`
- `added_files`
- `removed_files`
- `retained_files`

### Size Fields

- `compressed_size_old`
- `compressed_size_new`

### Classification Fields

- `status`
- `change_reason`

### Analysis Fields

- `reuse_score`
- `churn_ratio`

---

## FragmentMovement

Represents movement relationships between revisions.

### Fields

- `old_fragment`
- `new_fragment`
- `moved_files`
- `movement_ratio`

### Purpose

Used by:

- Sankey diagrams
- Movement visualizations
- Change attribution workflows

---

## BlastRadius

Represents the downstream impact of a specific change.

### Fields

- `source_file`
- `impacted_fragments`
- `impacted_files`
- `estimated_reuse_loss`
- `impact_score`

### Purpose

Provides an estimate of how localized changes influence surrounding filesystem structures.

---

# Design Principles

The data model is designed around the following principles:

- Source-agnostic analysis
- Explicit contracts between layers
- Strong typing
- Explainable results
- Reproducible analysis
- Visualization-friendly output
- Backward-compatible extensibility

All extraction, analysis, reporting, and visualization components are expected to communicate through these defined contracts.