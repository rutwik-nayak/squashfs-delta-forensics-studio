# Development Guide

## Repository Structure

forensics_studio/
web/
docs/
schema/
scripts/

## Core Flow

Source
→ Extractor
→ CanonicalImageModel
→ Analyzer
→ report.json
→ UI

## Key Rules

The analyzer must never consume source-specific formats directly.

All source formats must be converted into CanonicalImageModel before analysis.