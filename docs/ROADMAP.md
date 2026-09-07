# Roadmap

This document tracks known limitations, architectural gaps, technical debt, and planned improvements for SquashFS Delta Forensics Studio.

Priorities are based on their impact to analysis accuracy, report quality, extensibility, and long-term maintainability.

---

# Priority 1: SquashFS Extraction Improvements

## Directory Table Parsing

### Current State

The SquashFS extractor currently does not parse directory metadata.

File paths are represented using synthetic identifiers:

```text
inode-{N}
```

### Impact

- Files cannot be matched across images using real paths
- File delta analysis is degraded
- Root-cause attribution loses context
- Real-world analysis quality is reduced

### Planned Work

- Implement directory table parsing
- Resolve real filesystem paths
- Associate directory entries with inode records
- Enable reliable path-based file matching

---

## Accurate Block Descriptor Extraction

### Current State

The extractor currently assumes a simplified block model and does not read actual block descriptor information from the data region.

### Impact

- Block-chain churn metrics are approximate
- Reuse calculations lose fidelity
- Offset movement analysis lacks precision

### Planned Work

- Parse SquashFS block descriptors
- Reconstruct complete file block chains
- Improve churn calculations
- Improve reuse scoring accuracy

---

## Compressed Fragment Metadata Support

### Current State

Compressed fragment metadata blocks are skipped during extraction and reported as diagnostics.

### Impact

- Fragment information may be incomplete
- Fragment-level analytics may be degraded

### Planned Work

- Support compressed fragment metadata blocks
- Expand fragment coverage
- Improve extraction diagnostics

---

## Additional Compression Algorithm Support

### Current State

Metadata extraction currently attempts zlib decompression only.

### Impact

- Images using other SquashFS compression formats may not be fully analyzable

### Planned Work

Add support for:

- LZ4
- LZO
- XZ

---

# Priority 2: Analysis Engine Improvements

## Fragment Membership Propagation

### Current State

Fragment membership information is extracted but not fully propagated throughout the analysis pipeline.

### Observed Gaps

- Fragment records may not reflect membership availability
- File-level fragment references may be lost during canonical conversion
- Membership-aware reports are incomplete

### Planned Work

- Preserve file-to-fragment relationships end-to-end
- Populate `old_fragment` and `new_fragment`
- Propagate membership metadata consistently
- Improve membership-aware reporting

---

## Movement Graph Improvements

### Current State

Movement graph generation uses placeholder movement information in certain scenarios.

### Impact

- Sankey graph relationships may not represent actual moved files
- Movement analysis is less interpretable

### Planned Work

- Track real moved-file relationships
- Improve movement-edge fidelity
- Produce richer movement reports

---

## Reuse Opportunity Enhancements

### Current State

Reuse opportunity reporting is partially detached from fragment-level context.

### Impact

- Reuse candidates lack fragment attribution
- Analysis explainability is reduced

### Planned Work

- Correlate reuse candidates with fragments
- Improve ranking transparency
- Provide stronger forensic evidence

---

## Parser Validation Improvements

### Current State

Some validation fields are statically populated rather than derived from actual extraction results.

### Impact

- Validation reports may not reflect actual extraction capabilities

### Planned Work

- Build validation metadata dynamically
- Improve confidence reporting
- Align validation output with extraction state

---

## Warning System Improvements

### Current State

Certain warning conditions are evaluated conservatively and may produce false positives.

### Impact

- Warning volume may exceed actual risk
- User confidence may be reduced

### Planned Work

- Refine warning generation logic
- Improve metadata-aware gating
- Reduce false-positive reporting

---

# Priority 3: Frontend Improvements

## Membership-Aware Views

### Current State

Some views depend on fragment membership information that is not fully propagated through analysis output.

### Impact

- Membership-based insights are limited
- Certain visualizations may be disabled

### Planned Work

- Complete membership propagation
- Enable richer fragment visualizations
- Improve cross-view consistency

---

## Blast Radius Analysis

### Current State

Blast radius reporting is not yet fully populated by the analysis engine.

### Impact

- Blast radius visualizations provide limited value
- Dependency impact analysis is incomplete

### Planned Work

- Populate blast-radius datasets
- Improve impact propagation analysis
- Extend visualization capabilities

---

## Movement Classification Improvements

### Current State

Movement classification depends on fragment linkage information that is not always available.

### Impact

- Movement visualizations may under-report changes

### Planned Work

- Strengthen movement detection
- Improve fragment-aware classification
- Enhance forensic traceability

---

# Priority 4: Architecture and Infrastructure

## JSON Schema Validation

### Current State

A report schema exists but is not currently enforced during report generation.

### Impact

- Invalid reports may be generated silently
- Report compatibility issues may go undetected

### Planned Work

- Integrate schema validation into the reporting pipeline
- Fail fast on validation errors
- Improve validation diagnostics

---

## Automated Testing

### Current State

The project does not yet provide comprehensive automated test coverage.

### Planned Work

- Unit tests for superblock parsing
- Unit tests for inode parsing
- Unit tests for fragment-table parsing
- Golden sample validation
- Regression testing
- CI integration

---

## Legacy Parser Cleanup

### Current State

Legacy parser infrastructure is retained for compatibility but has limited active usage.

### Impact

- Increased maintenance burden
- Additional architectural complexity

### Planned Work

- Audit parser usage
- Remove unused components
- Simplify compatibility layers

---

## API Cleanup

### Current State

Deprecated fragment-path arguments remain visible in public interfaces.

### Impact

- Increased API surface area
- Potential contributor confusion

### Planned Work

- Remove deprecated APIs
- Simplify CLI contracts
- Improve consistency

---

# Technical Debt

## Duplicate Helper Logic

### Current State

The codebase contains duplicated helper implementations.

### Planned Work

- Consolidate duplicate implementations
- Reduce maintenance overhead
- Improve code consistency

---

## Parser Resilience

### Planned Work

- Improve error handling
- Strengthen diagnostics
- Improve malformed-input detection
- Improve extraction reliability

---

# Long-Term Vision

SquashFS Delta Forensics Studio aims to become a comprehensive forensic analysis platform for understanding structural changes between SquashFS filesystem revisions.

The long-term objective is to help answer:

- What changed?
- What moved?
- What contributed most to churn?
- Where was reuse lost?
- What structures had the greatest downstream impact?

Future development will focus on deeper filesystem understanding, improved explainability, stronger validation, broader format support, and richer visualization capabilities while preserving an offline-first workflow.