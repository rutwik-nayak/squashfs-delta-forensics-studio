function renderBlastRadius(report) {
  const selector = document.getElementById("blastFileSelector");
  const summaryPanel = document.getElementById("blastSummary");

  if (report.summary && report.summary.has_fragment_membership === false) {
    selector.innerHTML = "";
    summaryPanel.innerHTML = "Fragment membership is unavailable/not present in source map. Blast radius requires direct file-to-fragment relationships.";
    Plotly.purge("blastImpactGraph");
    d3.select("#blastDependencyGraph").selectAll("*").remove();
    return;
  }

  selector.innerHTML = report.blast_radius.map((row, idx) =>
    `<option value='${idx}'>${row.source_file}</option>`
  ).join("");

  const draw = index => {
    const row = report.blast_radius[index];
    if (!row) {
      summaryPanel.innerHTML = "No changed files available.";
      return;
    }

    summaryPanel.innerHTML = `
      <div class='kpi'>
        <div class='kpi-label'>Source File</div>
        <div class='kpi-value fs-6'>${row.source_file}</div>
      </div>
      <div class='kpi mt-2'><strong>Impacted Fragments:</strong><br>${row.impacted_fragments.join(", ") || "-"}</div>
      <div class='kpi mt-2'><strong>Impacted Files:</strong><br>${row.impacted_files.join("<br>") || "-"}</div>
      <div class='kpi mt-2'><strong>Estimated Reuse Loss:</strong> ${row.estimated_reuse_loss}%</div>
      <div class='kpi mt-2'><strong>Impact Score:</strong> ${row.impact_score}</div>
    `;

    Plotly.newPlot("blastImpactGraph", [{
      x: row.impacted_fragments,
      y: row.impacted_fragments.map(() => row.impact_score),
      type: "bar",
      marker: { color: "#cc2936" }
    }], { title: "Fragment Impact Distribution" }, {responsive: true});

    const nodes = [row.source_file, ...row.impacted_files];
    const links = row.impacted_files.map(file => ({ source: row.source_file, target: file }));
    drawBlastDependency(nodes, links);
  };

  selector.addEventListener("change", event => draw(Number(event.target.value)));
  draw(0);
}

function drawBlastDependency(nodes, links) {
  const width = 1100;
  const height = 500;

  const root = d3.select("#blastDependencyGraph");
  root.selectAll("*").remove();

  const svg = root.append("svg").attr("viewBox", `0 0 ${width} ${height}`).style("width", "100%");
  const simNodes = nodes.map(id => ({ id }));
  const simLinks = links.map(row => ({ source: row.source, target: row.target }));

  const sim = d3.forceSimulation(simNodes)
    .force("link", d3.forceLink(simLinks).id(d => d.id).distance(90))
    .force("charge", d3.forceManyBody().strength(-180))
    .force("center", d3.forceCenter(width / 2, height / 2));

  const link = svg.append("g").selectAll("line").data(simLinks).join("line")
    .attr("stroke", "#2f7ae5").attr("stroke-opacity", 0.5);

  const node = svg.append("g").selectAll("circle").data(simNodes).join("circle")
    .attr("r", d => d.id === nodes[0] ? 8 : 5)
    .attr("fill", d => d.id === nodes[0] ? "#cc2936" : "#007f5f");

  const label = svg.append("g").selectAll("text").data(simNodes).join("text")
    .text(d => d.id)
    .style("font-size", "10px");

  sim.on("tick", () => {
    link
      .attr("x1", d => d.source.x)
      .attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x)
      .attr("y2", d => d.target.y);
    node.attr("cx", d => d.x).attr("cy", d => d.y);
    label.attr("x", d => d.x + 6).attr("y", d => d.y - 6);
  });
}
