function renderSankey(report) {
  drawSankey(report.movement_graph);
  initMovementFilters(report);
}

function drawSankey(movements) {
  const nodes = [];
  const nodeMap = new Map();

  function getNodeIndex(name) {
    if (!nodeMap.has(name)) {
      nodeMap.set(name, nodes.length);
      nodes.push({ name });
    }
    return nodeMap.get(name);
  }

  const links = movements.map(row => ({
    source: getNodeIndex(`OLD ${row.old_fragment}`),
    target: getNodeIndex(`NEW ${row.new_fragment}`),
    value: row.moved_files.length,
    label: row.moved_files.join(", "),
  }));

  const width = 1200;
  const height = 650;
  const container = d3.select("#sankeyChart");
  container.selectAll("*").remove();

  const svg = container
    .append("svg")
    .attr("viewBox", `0 0 ${width} ${height}`)
    .style("width", "100%")
    .style("height", "100%");

  const sankey = d3.sankey()
    .nodeWidth(20)
    .nodePadding(12)
    .extent([[8, 8], [width - 8, height - 8]]);

  const graph = sankey({ nodes: nodes.map(d => ({ ...d })), links: links.map(d => ({ ...d })) });

  svg.append("g")
    .selectAll("path")
    .data(graph.links)
    .join("path")
    .attr("d", d3.sankeyLinkHorizontal())
    .attr("stroke", "#2f7ae5")
    .attr("stroke-opacity", 0.4)
    .attr("stroke-width", d => Math.max(1, d.width))
    .attr("fill", "none")
    .append("title")
    .text(d => `${d.source.name} -> ${d.target.name}\nMoved Files: ${d.value}`);

  const node = svg.append("g")
    .selectAll("g")
    .data(graph.nodes)
    .join("g");

  node.append("rect")
    .attr("x", d => d.x0)
    .attr("y", d => d.y0)
    .attr("height", d => d.y1 - d.y0)
    .attr("width", d => d.x1 - d.x0)
    .attr("fill", "#007f5f")
    .attr("stroke", "#0d3b2e");

  node.append("text")
    .attr("x", d => d.x0 - 6)
    .attr("y", d => (d.y1 + d.y0) / 2)
    .attr("dy", "0.35em")
    .attr("text-anchor", "end")
    .text(d => d.name)
    .filter(d => d.x0 < width / 2)
    .attr("x", d => d.x1 + 6)
    .attr("text-anchor", "start");

}

function initMovementFilters(report) {
  const input = document.getElementById("movementFilter");
  if (!input || input.dataset.bound === "1") {
    return;
  }
  input.dataset.bound = "1";
  input.addEventListener("input", () => {
    const token = input.value.trim().toLowerCase();
    if (!token) {
      drawSankey(report.movement_graph);
      return;
    }
    const filtered = report.movement_graph.filter(row =>
      row.old_fragment.toLowerCase().includes(token) ||
      row.new_fragment.toLowerCase().includes(token) ||
      row.moved_files.some(path => path.toLowerCase().includes(token))
    );
    drawSankey(filtered);
  });
}
