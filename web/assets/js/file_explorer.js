function renderFileExplorer(report) {
  const tbody = document.getElementById("fileTableBody");
  tbody.innerHTML = report.files.map(row => `
    <tr>
      <td>${row.path}</td>
      <td>${row.old_fragment || "-"}</td>
      <td>${row.new_fragment || "-"}</td>
      <td>${row.old_size ?? "-"}</td>
      <td>${row.new_size ?? "-"}</td>
      <td>${formatList(row.neighbors_old)}</td>
      <td>${formatList(row.neighbors_new)}</td>
      <td>${statusChip(row.status)}</td>
      <td>${row.impact_score}</td>
      <td>${row.reuse_score}</td>
      <td>${row.root_cause} (${row.root_cause_confidence})</td>
    </tr>
  `).join("");

  initDataTable("#fileTable");
}
