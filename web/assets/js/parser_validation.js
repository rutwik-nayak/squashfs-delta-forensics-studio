function renderParserValidation(report) {
  const confidence = report.data_confidence ? report.data_confidence.level : "LOW";
  const confidenceEl = document.getElementById("parserConfidence");
  if (confidenceEl) {
    confidenceEl.textContent = confidence;
    confidenceEl.className = confidence === "HIGH" ? "badge bg-success" : (confidence === "MEDIUM" ? "badge bg-warning text-dark" : "badge bg-danger");
  }

  const files = report.parser_validation ? report.parser_validation.parsed_files || [] : [];
  const fragments = report.parser_validation ? report.parser_validation.parsed_fragments || [] : [];
  const sources = report.parser_validation ? report.parser_validation.source_records || [] : [];
  const assumptions = report.parser_validation ? report.parser_validation.parser_assumptions || [] : [];
  const diagnostics = report.parser_validation ? report.parser_validation.parser_diagnostics || {} : {};

  const assumptionsEl = document.getElementById("parserAssumptions");
  assumptionsEl.innerHTML = assumptions.map(item => `<li>${item}</li>`).join("") || "<li>-</li>";

  const diagnosticsEl = document.getElementById("parserDiagnostics");
  if (diagnosticsEl) {
    const old = diagnostics.old || {};
    const neo = diagnostics.new || {};
    diagnosticsEl.innerHTML = `
      <div><strong>OLD:</strong> total=${old.total_lines ?? "-"}, fragment_rows=${old.fragment_rows ?? "-"}, file_rows=${old.file_rows ?? "-"}, dropped=${old.dropped_rows ?? "-"}, transition_line=${old.transition_line ?? "-"}</div>
      <div><strong>NEW:</strong> total=${neo.total_lines ?? "-"}, fragment_rows=${neo.fragment_rows ?? "-"}, file_rows=${neo.file_rows ?? "-"}, dropped=${neo.dropped_rows ?? "-"}, transition_line=${neo.transition_line ?? "-"}</div>
    `;
  }

  const filesBody = document.getElementById("parsedFilesBody");
  filesBody.innerHTML = files.map((row, idx) => `
    <tr data-trace='${JSON.stringify(row).replace(/'/g, "&#39;")}'>
      <td>${idx + 1}</td>
      <td>${row.path}</td>
      <td>${row.old_fragment || "-"}</td>
      <td>${row.new_fragment || "-"}</td>
      <td>${row.old_start_offset ?? "-"}</td>
      <td>${row.new_start_offset ?? "-"}</td>
      <td>${(row.old_blocks || []).length}</td>
      <td>${(row.new_blocks || []).length}</td>
      <td>${formatList((row.old_extents || []).map(e => `${e[0]}-${e[1]}`))}</td>
      <td>${formatList((row.new_extents || []).map(e => `${e[0]}-${e[1]}`))}</td>
      <td>${formatSource(row.source_old.file, row.source_old.line, row.source_old.rule)}</td>
      <td>${formatSource(row.source_new.file, row.source_new.line, row.source_new.rule)}</td>
      <td>${row.confidence}</td>
    </tr>
  `).join("");

  const fragmentsBody = document.getElementById("parsedFragmentsBody");
  fragmentsBody.innerHTML = fragments.map(row => `
    <tr data-trace='${JSON.stringify(row).replace(/'/g, "&#39;")}'>
      <td>${row.fragment_id}</td>
      <td>${formatList(row.old_members)}</td>
      <td>${formatList(row.new_members)}</td>
      <td>${row.membership_available ? "Yes" : "No"}</td>
      <td>${row.membership_message}</td>
    </tr>
  `).join("");

  const sourcesBody = document.getElementById("sourceRecordsBody");
  sourcesBody.innerHTML = sources.map(row => `
    <tr data-trace='${JSON.stringify(row).replace(/'/g, "&#39;")}'>
      <td>${row.dataset}</td>
      <td>${row.row_type || "-"}</td>
      <td>${row.path}</td>
      <td>${row.fragment_id || "-"}</td>
      <td>${row.size}</td>
      <td>${row.blocks.join(", ")}</td>
      <td>${row.start_offset ?? "-"}</td>
      <td>${formatList((row.extent_ranges || []).map(e => `${e[0]}-${e[1]}`))}</td>
      <td>${formatSource(row.source_file, row.source_line, row.parser_rule)}</td>
      <td>${row.synthetic ? "Yes" : "No"}</td>
    </tr>
  `).join("");

  initDataTable("#parsedFilesTable");
  initDataTable("#parsedFragmentsTable");
  initDataTable("#sourceRecordsTable");

  bindTracePanels();
}

function bindTracePanels() {
  const tracePanel = document.getElementById("tracePanel");
  document.querySelectorAll("table tbody tr").forEach(row => {
    row.addEventListener("click", () => {
      const payload = row.getAttribute("data-trace");
      if (!payload || !tracePanel) {
        return;
      }
      try {
        const json = JSON.parse(payload);
        tracePanel.textContent = JSON.stringify(json, null, 2);
      } catch (_error) {
        tracePanel.textContent = "Unable to parse trace payload.";
      }
    });
  });
}
