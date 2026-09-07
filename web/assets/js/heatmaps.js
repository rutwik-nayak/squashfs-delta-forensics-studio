function renderHeatmaps(report) {
  const fragmentRows = report.heatmap_data.fragment_churn;
  Plotly.newPlot("fragmentHeat", [{
    z: [fragmentRows.map(row => row.churn_ratio)],
    x: fragmentRows.map(row => row.fragment),
    y: ["Fragment Churn"],
    type: "heatmap",
    colorscale: "YlOrRd"
  }], { title: "Fragment Churn Heatmap" }, {responsive: true});

  const movementRows = report.heatmap_data.movement;
  Plotly.newPlot("movementHeat", [{
    z: [movementRows.map(row => row.moved_count)],
    x: movementRows.map(row => `${row.old_fragment}->${row.new_fragment}`),
    y: ["Movement Count"],
    type: "heatmap",
    colorscale: "Blues"
  }], { title: "Movement Heatmap" }, {responsive: true});

  const reuseRows = report.heatmap_data.reuse;
  Plotly.newPlot("reuseHeat", [{
    z: [reuseRows.map(row => row.reuse_score)],
    x: reuseRows.map(row => row.path),
    y: ["Reuse Score"],
    type: "heatmap",
    colorscale: "Greens"
  }], { title: "Reuse Heatmap" }, {responsive: true});

  const impactRows = report.heatmap_data.impact;
  Plotly.newPlot("impactHeat", [{
    z: [impactRows.map(row => row.impact_score)],
    x: impactRows.map(row => row.path),
    y: ["Impact Score"],
    type: "heatmap",
    colorscale: "Reds"
  }], { title: "Impact Heatmap" }, {responsive: true});
}
