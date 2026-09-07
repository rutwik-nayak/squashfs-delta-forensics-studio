function renderReuse(report) {
  const tbody = document.getElementById("reuseTableBody");
  tbody.innerHTML = report.reuse_opportunities.map(row => `
    <tr>
      <td>${row.file_path}</td>
      <td>${row.old_fragment}</td>
      <td>${row.new_fragment}</td>
      <td>${row.file_size}</td>
      <td>${row.importance_score}</td>
      <td>${row.reason}</td>
    </tr>
  `).join("");

  initDataTable("#reuseTable");

  Plotly.newPlot("reuseImportance", [{
    x: report.reuse_opportunities.map(row => row.importance_score),
    y: report.reuse_opportunities.map(row => row.file_path),
    type: "bar",
    orientation: "h",
    marker: { color: "#2f7ae5" }
  }], { title: "Reuse Opportunity Ranking", margin: { l: 300 } }, {responsive: true});
}
