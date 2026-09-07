# UI Wireframes

The visualization studio is a collection of static HTML pages that consume `report.json` and provide forensic views into filesystem evolution, fragment churn, reuse behavior, and structural movement.

---

# Page 1: Dashboard

Provides a high-level summary of analysis results.

```text
+----------------------------------------------------------------+
| Top Bar                                                        |
| Theme Toggle | Report Loader | Report Metadata                 |
+----------------------------------------------------------------+

+----------------------------------------------------------------+
| KPI Cards                                                      |
| Total Files | Total Fragments | Reuse Ratio | Reuse Loss      |
+----------------------------------------------------------------+

+--------------------------------+-------------------------------+
| File Status Distribution       | Top Disruptive Files          |
| (Pie Chart)                    | (Bar Chart)                  |
+--------------------------------+-------------------------------+

+--------------------------------+-------------------------------+
| Fragment Overview              | Churn Heatmap                |
| (Treemap)                      | (Heat Layer)                |
+--------------------------------+-------------------------------+

+----------------------------------------------------------------+
| Analysis Summary                                            |
+----------------------------------------------------------------+
```

### Primary Data Sources

- `summary`
- `files`
- `fragments`
- `executive_summary`
- `heatmap_data`

---

# Page 2: Side-by-Side Fragment Explorer

Compares file membership between fragment revisions.

```text
+---------------------------+   +---------------------------+
| OLD Fragment              |   | NEW Fragment              |
+---------------------------+   +---------------------------+
| file_a      [retained]    |   | file_a      [retained]    |
| file_b      [removed]     |   | file_x      [added]       |
| file_c      [retained]    |   | file_c      [retained]    |
+---------------------------+   +---------------------------+

Legend:
Retained | Added | Removed
```

### Primary Data Sources

- `fragments`
- `data_confidence`

---

# Page 3: File Explorer

Searchable forensic view for file-level analysis.

```text
+--------------------------------------------------------------------------+
| Search / Filter Controls                                                 |
+--------------------------------------------------------------------------+

path | old_fragment | new_fragment | status | impact | reuse | root cause

--------------------------------------------------------------------------

/system/bin/init
/product/app/example.apk
/vendor/lib/example.so
```

### Attributes

- File status
- Root cause
- Impact score
- Reuse score
- Neighbor relationships

### Primary Data Source

- `files`

---

# Page 4: Fragment Explorer

Detailed fragment-level forensic view.

```text
+--------------------------------------------------------------------------+
| Search / Filter Controls                                                 |
+--------------------------------------------------------------------------+

fragment
old membership
new membership
added files
removed files
retained files
reuse score
churn ratio
```

### Primary Data Sources

- `fragments`
- `data_confidence`

---

# Page 5: Movement Analysis (Sankey)

Visualizes structural movement between revisions.

```text
OLD Fragments
      │
      │ movement
      ▼
NEW Fragments

Link Width = Movement Magnitude

Filters:
- Fragment ID
- File Path
- Directory Token
```

### Visualization

- D3 Sankey Diagram

### Primary Data Source

- `movement_graph`

---

# Page 6: Blast Radius Analysis

Shows downstream effects of structural changes.

```text
+-------------------------------------------------------------+
| File Selector                                               |
+-------------------------------------------------------------+

Selected File
      │
      ├── Impacted Fragments
      ├── Impacted Files
      └── Reuse Loss Estimate

+-------------------------------------------------------------+
| Impact Chart                                                |
+-------------------------------------------------------------+

+-------------------------------------------------------------+
| Dependency Graph                                            |
+-------------------------------------------------------------+
```

### Primary Data Source

- `blast_radius`

---

# Page 7: Reuse Opportunities

Highlights structures that may be optimized for improved reuse.

```text
+-------------------------------------------------------------+
| Ranked Candidate Table                                      |
+-------------------------------------------------------------+

Path | Reason | Reuse Score | Potential Benefit

+-------------------------------------------------------------+
| Opportunity Ranking Chart                                   |
+-------------------------------------------------------------+
```

### Primary Data Source

- `reuse_opportunities`

---

# Page 8: Heatmaps

Provides visual summaries of change intensity.

```text
+-------------------------------------------------------------+
| Fragment Churn Heatmap                                      |
+-------------------------------------------------------------+

+-------------------------------------------------------------+
| Movement Heatmap                                            |
+-------------------------------------------------------------+

+-------------------------------------------------------------+
| Reuse Heatmap                                               |
+-------------------------------------------------------------+

+-------------------------------------------------------------+
| Impact Heatmap                                              |
+-------------------------------------------------------------+
```

### Primary Data Source

- `heatmap_data`

---

# Page 9: Parser Validation

Provides extraction traceability and confidence information.

```text
+-------------------------------------------------------------+
| Confidence Banner                                           |
+-------------------------------------------------------------+

Confidence Level:
HIGH | MEDIUM | LOW

Membership Available:
YES | NO

+-------------------------------------------------------------+
| Validation Records                                          |
+-------------------------------------------------------------+

Source File
Source Line
Parser Rule
Extracted Value
```

### Primary Data Sources

- `parser_validation`
- `data_confidence`
- `warnings`

---

# Page 10: Offset Analysis

Visualizes filesystem layout evolution across revisions.

```text
+-------------------------------------------------------------+
| Storage Timeline                                            |
+-------------------------------------------------------------+

OLD OFFSETS ---------------------------------------------->

NEW OFFSETS ---------------------------------------------->

+-------------------------------------------------------------+
| Largest File Movements                                      |
+-------------------------------------------------------------+

+-------------------------------------------------------------+
| Offset Cascades                                             |
+-------------------------------------------------------------+

+-------------------------------------------------------------+
| Image Shift Statistics                                      |
+-------------------------------------------------------------+
```

### Primary Data Source

- `offset_analysis`

---

# Shared UI Components

All pages inherit common components:

```text
Top Navigation
Theme Toggle
Report Loader
Confidence Banner
Analyzer Warning Banner
Footer
```

---

# Offline Design

The visualization studio supports multiple report-loading modes:

```text
Embedded Report
       ↓
Local Cache
       ↓
report.json
```

This design enables completely offline forensic workflows without requiring a backend service.