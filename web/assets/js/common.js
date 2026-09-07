const DATA_URL = "assets/data/report.json";
const REPORT_CACHE_KEY = "forensics-report-cache-v1";

async function loadReport() {
  const errorBox = document.getElementById("loadError");
  const embedded = getEmbeddedReport();
  if (embedded) {
    cacheReport(embedded);
    hideLoadError(errorBox);
    return embedded;
  }

  const cached = getCachedReport();
  if (cached) {
    hideLoadError(errorBox);
    return cached;
  }

  try {
    const response = await fetch(resolveAssetPath(DATA_URL));
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const report = await response.json();
    cacheReport(report);
    hideLoadError(errorBox);
    return report;
  } catch (error) {
    showLoadError(
      errorBox,
      `Unable to auto-load report.json (${error.message}). Use the local file picker or keep report.inline.js next to assets/data/.`
    );
    return null;
  }
}

function resolveAssetPath(relativePath) {
  const path = window.location.pathname;
  if (path.includes("/pages/")) {
    return `../${relativePath}`;
  }
  return relativePath;
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("forensics-theme", theme);
}

function initTheme() {
  const saved = localStorage.getItem("forensics-theme") || "light";
  applyTheme(saved);
  const toggle = document.getElementById("themeToggle");
  if (toggle) {
    toggle.checked = saved === "dark";
    toggle.addEventListener("change", () => applyTheme(toggle.checked ? "dark" : "light"));
  }
}

function initFileLoader(onLoad) {
  const fileInput = document.getElementById("reportFile");
  if (!fileInput) {
    return;
  }
  fileInput.addEventListener("change", event => {
    const file = event.target.files[0];
    if (!file) {
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const payload = JSON.parse(reader.result);
        cacheReport(payload);
        hideLoadError(document.getElementById("loadError"));
        onLoad(payload);
      } catch (error) {
        alert(`Invalid report JSON: ${error.message}`);
      }
    };
    reader.readAsText(file);
  });
}

function getEmbeddedReport() {
  if (typeof window.__FORENSICS_REPORT__ === "object" && window.__FORENSICS_REPORT__) {
    return window.__FORENSICS_REPORT__;
  }
  return null;
}

function cacheReport(report) {
  try {
    localStorage.setItem(REPORT_CACHE_KEY, JSON.stringify(report));
  } catch (_error) {
    // Ignore quota and private-mode failures.
  }
}

function getCachedReport() {
  try {
    const raw = localStorage.getItem(REPORT_CACHE_KEY);
    if (!raw) {
      return null;
    }
    return JSON.parse(raw);
  } catch (_error) {
    return null;
  }
}

function hideLoadError(errorBox) {
  if (errorBox) {
    errorBox.classList.add("d-none");
  }
}

function showLoadError(errorBox, message) {
  if (errorBox) {
    errorBox.classList.remove("d-none");
    errorBox.textContent = message;
  }
}

function statusChip(status) {
  return `<span class="status-chip status-${status}">${status}</span>`;
}

function formatList(value) {
  if (!value || value.length === 0) {
    return "-";
  }
  return value.join("<br>");
}

function initDataTable(selector) {
  if (!window.jQuery || !window.jQuery.fn.DataTable) {
    return;
  }
  window.jQuery(selector).DataTable({
    pageLength: 15,
    responsive: true,
    order: [],
  });
}

function renderGlobalDiagnostics(report) {
  renderAnalyzerWarnings(report);
  renderConfidenceBanner(report);
}

function renderAnalyzerWarnings(report) {
  const topbar = document.querySelector(".topbar");
  if (!topbar) {
    return;
  }

  const old = document.getElementById("analysisWarnings");
  if (old) {
    old.remove();
  }

  const warnings = Array.isArray(report.warnings) ? report.warnings : [];
  if (warnings.length === 0) {
    return;
  }

  const box = document.createElement("div");
  box.id = "analysisWarnings";
  box.className = "alert alert-danger mt-3 mb-0";
  box.innerHTML = `<strong>Parser/Modeling Warning</strong><br>${warnings.join("<br>")}`;
  topbar.appendChild(box);
}

function renderConfidenceBanner(report) {
  const topbar = document.querySelector(".topbar");
  if (!topbar || !report.data_confidence) {
    return;
  }

  const old = document.getElementById("confidenceBanner");
  if (old) {
    old.remove();
  }

  const level = report.data_confidence.level || "LOW";
  const message = report.summary && report.summary.fragment_membership_message
    ? report.summary.fragment_membership_message
    : "Unknown parser confidence";
  const membershipStatus = (report.summary && report.summary.membership_status)
    || (report.data_confidence && report.data_confidence.membership_status)
    || "unknown";

  const cssClass = level === "HIGH" ? "alert-success" : (level === "MEDIUM" ? "alert-warning" : "alert-danger");
  const box = document.createElement("div");
  box.id = "confidenceBanner";
  box.className = `alert ${cssClass} mt-3 mb-0`;
  box.innerHTML = `<strong>Data Confidence: ${level}</strong><br>${message}<br><small>Fragment membership: ${membershipStatus}</small>`;
  topbar.appendChild(box);
}

function formatSource(sourceFile, sourceLine, sourceRule) {
  const fileText = sourceFile || "-";
  const lineText = sourceLine || "-";
  const ruleText = sourceRule || "-";
  return `${fileText}:${lineText}<br><small>${ruleText}</small>`;
}
