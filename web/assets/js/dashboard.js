function renderDashboard(report) {
  const summary = report.summary;
  document.getElementById("kpiFiles").textContent = summary.total_files;
  document.getElementById("kpiFragments").textContent = summary.total_fragments;
  document.getElementById("kpiReuse").textContent = `${(summary.fragment_reuse_ratio * 100).toFixed(2)}%`;
  document.getElementById("kpiLoss").textContent = `${summary.potential_reuse_loss.toFixed(2)}%`;

  Plotly.newPlot("fileStatusPie", [{
    labels: ["Unchanged", "Modified", "Moved", "Added", "Deleted"],
    values: [summary.unchanged_files, summary.modified_files, summary.moved_files, summary.added_files, summary.deleted_files],
    type: "pie",
    marker: { colors: ["#2ca58d", "#f3a712", "#e6c33d", "#2f7ae5", "#cc2936"] }
  }], { title: "File Change Status" }, {responsive: true});

  const topFiles = report.executive_summary.top_20_most_disruptive_files;
  Plotly.newPlot("impactBar", [{
    x: topFiles.map(row => row.impact_score),
    y: topFiles.map(row => row.path),
    type: "bar",
    orientation: "h",
    marker: { color: "#007f5f" }
  }], {
    title: "Top Disruptive Files",
    margin: { l: 280 }
  }, {responsive: true});

  const treemapData = report.fragments.map(row => ({
    label: `Fragment ${row.fragment_id}`,
    value: row.file_count,
    color: row.churn_ratio
  }));

  Plotly.newPlot("fragmentTreemap", [{
    type: "treemap",
    labels: treemapData.map(d => d.label),
    parents: treemapData.map(() => "Fragments"),
    values: treemapData.map(d => d.value),
    marker: { colors: treemapData.map(d => d.color), colorscale: "YlOrRd" },
    textinfo: "label+value"
  }], { title: "Fragment Size/Churn Treemap" }, {responsive: true});

  const heatRows = report.heatmap_data.fragment_churn;
  Plotly.newPlot("churnHeatmap", [{
    z: [heatRows.map(row => row.churn_ratio)],
    x: heatRows.map(row => row.fragment),
    y: ["Churn"],
    type: "heatmap",
    colorscale: "YlGnBu"
  }], { title: "Fragment Churn Heatmap" }, {responsive: true});
}
