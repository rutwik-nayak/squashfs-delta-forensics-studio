function renderOffsetAnalysis(report) {
  const analysis = report.offset_analysis || {};
  const timeline = analysis.storage_timeline || { old: [], new: [] };
  const movement = analysis.offset_movement || [];
  const diffs = analysis.fragment_offset_diff || [];
  const imageShift = analysis.image_shift_analysis || {};
  const cascades = analysis.largest_offset_cascades || [];
  const downstream = analysis.downstream_movement_sources || [];

  document.getElementById("shiftTotalFragments").textContent = imageShift.total_fragments_compared ?? "-";
  document.getElementById("shiftedFragments").textContent = imageShift.shifted_fragments ?? "-";
  document.getElementById("maxPositiveShift").textContent = imageShift.max_positive_shift ?? "-";
  document.getElementById("maxNegativeShift").textContent = imageShift.max_negative_shift ?? "-";
  document.getElementById("avgAbsShift").textContent = imageShift.avg_absolute_shift ?? "-";
  document.getElementById("medianAbsShift").textContent = imageShift.median_absolute_shift ?? "-";

  Plotly.newPlot("storageTimelineChart", [
    {
      x: timeline.old.map(row => row.start),
      y: timeline.old.map(() => "OLD"),
      mode: "markers",
      type: "scatter",
      marker: { color: "#007f5f", size: 7 },
      text: timeline.old.map(row => `Fragment ${row.fragment_id}<br>${row.start}-${row.end}`),
      name: "OLD"
    },
    {
      x: timeline.new.map(row => row.start),
      y: timeline.new.map(() => "NEW"),
      mode: "markers",
      type: "scatter",
      marker: { color: "#2f7ae5", size: 7 },
      text: timeline.new.map(row => `Fragment ${row.fragment_id}<br>${row.start}-${row.end}`),
      name: "NEW"
    }
  ], { title: "Storage Timeline View", hovermode: "closest" }, { responsive: true });

  const topMovement = movement.slice(0, 100);
  Plotly.newPlot("offsetMovementChart", [{
    x: topMovement.map(row => row.fragment_id),
    y: topMovement.map(row => row.start_delta),
    type: "bar",
    marker: { color: topMovement.map(row => row.start_delta >= 0 ? "#2f7ae5" : "#cc2936") }
  }], { title: "Offset Movement View (Top 100 entities by shift)", xaxis: { title: "File/Entity" }, yaxis: { title: "Start Delta" } }, { responsive: true });

  const diffBody = document.getElementById("fragmentOffsetDiffBody");
  diffBody.innerHTML = diffs.map(row => `
    <tr>
      <td>${row.fragment_id}</td>
      <td>${row.old_range || "-"}</td>
      <td>${row.new_range || "-"}</td>
      <td>${row.start_delta ?? "-"}</td>
      <td>${row.size_delta ?? "-"}</td>
      <td>${row.confidence ?? "-"}</td>
      <td>${row.inference_method || "-"}</td>
    </tr>
  `).join("");
  initDataTable("#fragmentOffsetDiffTable");

  const cascadeBody = document.getElementById("offsetCascadeBody");
  cascadeBody.innerHTML = cascades.map((row, idx) => `
    <tr>
      <td>${idx + 1}</td>
      <td>${row.first_fragment}</td>
      <td>${row.last_fragment}</td>
      <td>${row.cascade_length}</td>
      <td>${row.total_shift_magnitude}</td>
      <td>${row.fragments.join(", ")}</td>
    </tr>
  `).join("");
  initDataTable("#offsetCascadeTable");

  const downstreamBody = document.getElementById("downstreamSourceBody");
  downstreamBody.innerHTML = downstream.map((row, idx) => `
    <tr>
      <td>${idx + 1}</td>
      <td>${row.source}</td>
      <td>${row.source_type}</td>
      <td>${row.estimated_downstream_shift}</td>
      <td>${row.note || "-"}</td>
    </tr>
  `).join("");
  initDataTable("#downstreamSourceTable");

  Plotly.newPlot("downstreamImpactChart", [{
    x: downstream.slice(0, 25).map(row => row.estimated_downstream_shift),
    y: downstream.slice(0, 25).map(row => row.source),
    type: "bar",
    orientation: "h",
    marker: { color: "#f3a712" }
  }], { title: "Files/Proxies Causing Maximum Downstream Movement", margin: { l: 260 } }, { responsive: true });
}
