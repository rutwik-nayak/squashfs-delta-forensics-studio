# UI Wireframes

## Page 1 Dashboard

```text
+--------------------------------------------------------------+
| Topbar + Theme + report.json loader                          |
+--------------------------------------------------------------+
| KPI Cards: Total Files | Total Fragments | Reuse | Loss      |
+--------------------------------------------------------------+
| Pie: File Status       | Bar: Top Disruptive Files           |
+--------------------------------------------------------------+
| Treemap: Fragments     | Heatmap: Churn                      |
+--------------------------------------------------------------+
```

## Page 2 Side-by-Side

```text
+----------------------+   +----------------------+
| OLD Fragment N       |   | NEW Fragment N       |
| file_a [green]       |   | file_a [green]       |
| file_b [red]         |   | file_x [blue]        |
| file_c [yellow]      |   | file_c [yellow]      |
+----------------------+   +----------------------+
```

## Page 3 File Explorer

```text
Searchable DataTable
path | old/new fragment | sizes | neighbors | status | impact | reuse | root cause
```

## Page 4 Fragment Explorer

```text
Searchable DataTable
fragment | old/new membership | added | removed | retained | churn | reuse
```

## Page 5 Sankey

```text
OLD fragment nodes --> NEW fragment nodes
link width = moved file count
filter box by fragment/path/directory token
```

## Page 6 Blast Radius

```text
select file -> impacted fragments/files + bar chart + dependency graph
```

## Page 7 Reuse Opportunities

```text
ranked DataTable + horizontal importance chart
```

## Page 8 Heatmaps

```text
fragment churn | movement | reuse | impact heat layers
```
