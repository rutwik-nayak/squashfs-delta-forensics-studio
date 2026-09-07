function renderFragmentExplorer(report) {
  const notice = document.getElementById("fragmentMembershipNotice");
  if (report.summary && report.summary.has_fragment_membership === false) {
    if (notice) {
      notice.classList.remove("d-none");
      notice.textContent = "Fragment membership is unavailable/not present in source map. Added/Removed/Retained memberships and blast radius are intentionally disabled.";
    }
  } else if (notice) {
    notice.classList.add("d-none");
  }

  const tbody = document.getElementById("fragmentTableBody");
  tbody.innerHTML = report.fragments.map(row => `
    <tr>
      <td>${row.fragment_id}</td>
      <td>${row.file_count}</td>
      <td>${row.old_offset_range || "-"}</td>
      <td>${row.new_offset_range || "-"}</td>
      <td>${formatList(row.old_file_list)}</td>
      <td>${formatList(row.new_file_list)}</td>
      <td>${row.membership_available ? formatList(row.added_files) : "Insufficient fragment membership data"}</td>
      <td>${row.membership_available ? formatList(row.removed_files) : "Insufficient fragment membership data"}</td>
      <td>${row.membership_available ? formatList(row.retained_files) : "Insufficient fragment membership data"}</td>
      <td>${formatList(row.overlapping_files_old)}</td>
      <td>${formatList(row.overlapping_files_new)}</td>
      <td>${row.overlap_confidence_score}</td>
      <td>${row.inference_method}</td>
      <td>${statusChip(row.status)}</td>
      <td>${row.churn_ratio}</td>
      <td>${row.reuse_score}</td>
      <td>${row.change_reason}<br><small>${row.membership_message || ""}</small></td>
    </tr>
  `).join("");

  initDataTable("#fragmentTable");
}
