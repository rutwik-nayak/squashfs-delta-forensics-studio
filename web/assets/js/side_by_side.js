function renderSideBySide(report) {
  const container = document.getElementById("sideBySideContainer");
  const fragments = report.fragments;

  let html = "<div class='fragment-grid'>";
  for (const fragment of fragments) {
    const oldSet = new Set(fragment.old_file_list);
    const newSet = new Set(fragment.new_file_list);

    const oldTags = fragment.old_file_list.map(path => {
      let cls = "file-unchanged";
      if (!newSet.has(path)) {
        cls = "file-removed";
      } else if (pathMoved(report.files, path, fragment.fragment_id)) {
        cls = "file-moved";
      }
      return `<span class='file-tag ${cls}'>${path}</span>`;
    }).join("");

    const newTags = fragment.new_file_list.map(path => {
      let cls = "file-unchanged";
      if (!oldSet.has(path)) {
        cls = "file-added";
      } else if (pathMoved(report.files, path, fragment.fragment_id)) {
        cls = "file-moved";
      }
      return `<span class='file-tag ${cls}'>${path}</span>`;
    }).join("");

    html += `
      <div class='page-card p-3'>
        <h6 class='panel-title'>Fragment ${fragment.fragment_id}</h6>
        <div class='row g-2'>
          <div class='col-md-6'>
            <div class='fragment-column'>
              <strong>OLD</strong><hr>
              ${oldTags || "-"}
            </div>
          </div>
          <div class='col-md-6'>
            <div class='fragment-column'>
              <strong>NEW</strong><hr>
              ${newTags || "-"}
            </div>
          </div>
        </div>
      </div>`;
  }
  html += "</div>";
  container.innerHTML = html;
}

function pathMoved(files, path, currentFragment) {
  const row = files.find(item => item.path === path);
  if (!row) {
    return false;
  }
  return row.status === "moved" && (row.old_fragment === currentFragment || row.new_fragment === currentFragment);
}
