
// Files to load. In a real scenario we could discover dynamically, but static hosting
// typically can't list directories. Using explicit filenames keeps it simple.
const DATA_FILES = [
  "data/openmrs-core.json",
  "data/openmrs-module-billing.json",
  "data/openmrs-module-idgen.json",
];

// Severity to numeric score mapping. The provided JSON lacks some explicit numeric CVSS scores,
// but includes "severity" strings. So we use sensible weights to support this sorting.
const SEVERITY_SCORE = {
  Critical: 9.5,
  High: 8.0,
  Medium: 5.0,
  Low: 2.5,
};

function compareVersions(a, b) {
  if (!a && !b) return 0;
  if (!a) return -1;
  if (!b) return 1;
  const pa = String(a).split(".").map((x) => parseInt(x, 10));
  const pb = String(b).split(".").map((x) => parseInt(x, 10));
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const va = pa[i] ?? 0;
    const vb = pb[i] ?? 0;
    if (va > vb) return 1;
    if (va < vb) return -1;
  }
  return 0;
}

// Helper to derive a numeric "score" from a vulnerability item.
// If no numeric score is available, map severity -> score. Unknown -> 0.
function getVulnScore(v) {
  // Some schemas include fields like cvss.score; our sample does not.
  // We check common places, otherwise fall back to severity mapping.
  const explicit =
    v?.cvss?.score ??
    v?.cvss_v3?.score ??
    v?.cvss_v2?.score ??
    null;
  if (typeof explicit === "number") return explicit;
  const sev = (v?.severity || "").trim();
  return SEVERITY_SCORE[sev] ?? 0;
}

// Compute normalized severity label for display and pill color class.
function normalizeSeverity(sev) {
  if (!sev) return "Unknown";
  const s = sev.trim();
  if (["Critical", "High", "Medium", "Low"].includes(s)) return s;
  return "Unknown";
}

// Safe text accessor: gracefully handles undefined/missing by returning "–"
function textOrDash(value) {
  if (value === null || value === undefined) return "–";
  const s = String(value).trim();
  return s.length ? s : "–";
}

// Given a report JSON and a repository name (from filename), aggregate dependencies.
function parseRepositoryReport(report, repoName) {
  const vulnerabilities = Array.isArray(report?.vulnerabilities)
    ? report.vulnerabilities
    : [];

  // Group vulnerabilities by dependency package name
  const depMap = new Map();
  for (const v of vulnerabilities) {
    const depName = v?.location?.dependency?.package?.name || "unknown-dependency";
    if (!depMap.has(depName)) {
      depMap.set(depName, []);
    }
    depMap.get(depName).push(v);
  }

  // Transform to dependency objects with computed severity and highest score
  const dependencies = [];
  for (const [name, vulns] of depMap.entries()) {
    const scores = vulns.map(getVulnScore);
    const highestScore = scores.length ? Math.max(...scores) : 0;
    // Severity derived from the highest scored vulnerability
    const topVuln =
      vulns
        .slice()
        .sort((a, b) => getVulnScore(b) - getVulnScore(a))[0] || null;
    const severity = normalizeSeverity(topVuln?.severity);
    dependencies.push({
      name,
      severity,
      highestScore,
      vulnerabilities: vulns.slice().sort((a, b) => getVulnScore(b) - getVulnScore(a)),
    });
  }

  // Repository severity is the highest CVE score across all dependencies
  const repoHighest = dependencies.length
    ? Math.max(...dependencies.map((d) => d.highestScore))
    : 0;
  const repoSeverity =
    dependencies
      .slice()
      .sort((a, b) => b.highestScore - a.highestScore)[0]?.severity || "Unknown";

  return {
    name: repoName,
    severity: repoSeverity,
    highestCveScore: repoHighest,
    dependencies,
  };
}

// Sorting helpers for repositories
const repoSorters = {
  severity: (a, b) => b.highestCveScore - a.highestCveScore, // severity is derived from highest score
  highestCveScore: (a, b) => b.highestCveScore - a.highestCveScore,
  name: (a, b) => a.name.localeCompare(b.name),
};

// Sorting helpers for dependencies
const depSorters = {
  severity: (a, b) => b.highestScore - a.highestScore, // derived from score
  highestCveScore: (a, b) => b.highestScore - a.highestScore,
  name: (a, b) => a.name.localeCompare(b.name),
};

// Severity pill class
function severityClass(sev) {
  const s = normalizeSeverity(sev);
  switch (s) {
    case "Critical":
      return "severity-pill sev-critical";
    case "High":
      return "severity-pill sev-high";
    case "Medium":
      return "severity-pill sev-medium";
    case "Low":
      return "severity-pill sev-low";
    default:
      return "severity-pill sev-unknown";
  }
}

// Derive extra fields to match reference UI
function deriveDependencyMeta(dep) {
  const versions = dep.vulnerabilities
    .map((v) => v?.location?.dependency?.version)
    .filter(Boolean);
  // Pick the most common version value; fallback to first or "–"
  const version =
    versions.length
      ? versions.sort((a, b) =>
          versions.filter((x) => x === a).length - versions.filter((x) => x === b).length
        ).pop()
      : null;

  const cvesCount = dep.vulnerabilities.length;

  // Exploit? "Yes" if any link entry contains "EXPLOIT"
  const exploitYes = dep.vulnerabilities.some((v) =>
    Array.isArray(v?.links) && v.links.some((l) => String(l?.name || "").includes("EXPLOIT"))
  );

  // Fixed Version is not standardized in sample; try v.fixed_in and pick a value if present
  const fixes = dep.vulnerabilities.map((v) => v?.fixed_in).filter(Boolean);
  let fixVersion = null;
  if (fixes.length) {
    fixVersion = fixes.reduce((max, cur) => (compareVersions(cur, max) > 0 ? cur : max), fixes[0]);
  }

  return {
    version: version || "–",
    cvesCount,
    exploit: exploitYes ? "Yes" : "–",
    fixVersion: fixVersion || "–",
  };
}

// Render CVE table for a dependency
function renderCveTable(vulns) {
  const rows = vulns
    .map((v) => {
      const id = textOrDash(v?.name || v?.id);
      const score = getVulnScore(v);
      const scoreText = score ? String(score) : "–";
      const sev = normalizeSeverity(v?.severity);
      // "Fixed In" is often located in links or remediation data; our sample lacks explicit field.
      // We try common locations; if not present, display "–".
      const fixedRaw = v?.fixed_in;
      const fixedIn = fixedRaw ? String(fixedRaw) : "Not provided";
      const affectedRaw = v?.affected_versions;
      const affected = affectedRaw ? String(affectedRaw) : "Current: " + textOrDash(v?.location?.dependency?.version);
      const cwe = extractCwe(v) || "Unknown";
      return `
        <tr>
          <td>${id}</td>
          <td><span class="${severityClass(sev)}">${sev}</span></td>
          <td>${scoreText}${score ? "/10" : ""}</td>
          <td class="cell-desc">${textOrDash(v?.description)}</td>
          <td>${affected}</td>
          <td>${fixedIn}</td>
          <td>${cwe}</td>
        </tr>
      `;
    })
    .join("");

  return `
    <table class="cve-table" aria-label="CVE list">
      <thead>
        <tr>
          <th>CVE ID</th>
          <th>Severity</th>
          <th>Score</th>
          <th>Description</th>
          <th>Affected Versions</th>
          <th>Fixed In</th>
          <th>CWE</th>
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  `;
}

// Render a dependency as a table-like collapsible row
function renderDependency(dep) {
  const meta = deriveDependencyMeta(dep);
  return `
    <details class="dep-row">
      <summary>
        <span class="dep-name">${textOrDash(dep.name)}</span>
        <span class="dep-version">${textOrDash(meta.version)}</span>
        <span class="${severityClass(dep.severity)}">${normalizeSeverity(dep.severity)}</span>
        <span class="dep-count">${meta.cvesCount}</span>
        <span class="dep-exploit">${meta.exploit}</span>
        <span class="dep-fix">${textOrDash(meta.fixVersion)}</span>
        <span class="toggle-btn"><span class="chevron" aria-hidden="true"></span></span>
      </summary>
      ${renderCveTable(dep.vulnerabilities)}
    </details>
  `;
}

// Render repository section with collapsible dependencies and a local sort control
function renderRepository(repo) {
  const title = `
    <div class="repo-title">
      <span>${textOrDash(repo.name)}</span>
      <span class="${severityClass(repo.severity)}">${normalizeSeverity(repo.severity)}</span>
    </div>
  `;

  const headerRow = `
    <div class="dep-header">
      <span class="click-sort" data-sort="name">Dependency</span>
      <span>Version</span>
      <span class="click-sort" data-sort="severity">Severity</span>
      <span class="click-sort" data-sort="highestCveScore">CVEs</span>
      <span>Exploit?</span>
      <span>Fix Version</span>
      <span></span>
    </div>
  `;

  const depsHtml = repo.dependencies.map(renderDependency).join("");
  return `
    <details class="repository" data-repo="${cssSafeId(repo.name)}">
      <summary>
        ${title}
        <span class="toggle-btn"><span class="chevron" aria-hidden="true"></span></span>
      </summary>
      <div class="dependency-table">
        <div class="repo-tools">
          <label for="dep-sort-${cssSafeId(repo.name)}" class="muted">Sort dependencies:</label>
          <select id="dep-sort-${cssSafeId(repo.name)}" data-repo="${cssSafeId(repo.name)}">
            <option value="severity">Severity (desc)</option>
            <option value="highestCveScore">Highest CVE Score (desc)</option>
            <option value="name">Name (A–Z)</option>
          </select>
        </div>
        ${headerRow}
        <div class="dep-list-scroll">
          ${depsHtml}
        </div>
      </div>
    </details>
  `;
}

// Safe id attribute from repository name
function cssSafeId(name) {
  return String(name).replace(/[^a-zA-Z0-9_-]/g, "_");
}

// Main render function for repositories
function renderDashboard(repos) {
  const container = document.getElementById("dashboard");
  container.innerHTML = repos.map(renderRepository).join("");
}

// Apply repository-level sorting
function sortRepositories(repos, key) {
  const sorter = repoSorters[key] || repoSorters.severity;
  repos.sort(sorter);
}

// Apply dependency-level sorting inside a repository
function sortDependencies(repo, key) {
  const sorter = depSorters[key] || depSorters.severity;
  repo.dependencies.sort(sorter);
}

// Re-render only the dependency list of a repository, preserving open rows
function sortAndRenderDependencies(repoEl, repo, key) {
  // Capture currently open dependency names
  const openNames = new Set(
    Array.from(repoEl.querySelectorAll(".dep-row[open] .dep-name")).map((el) =>
      String(el.textContent || "").trim()
    )
  );
  // Sort data
  sortDependencies(repo, key);
  // Rebuild inner list only
  const listEl = repoEl.querySelector(".dep-list-scroll");
  if (!listEl) return;
  listEl.innerHTML = repo.dependencies.map(renderDependency).join("");
  // Restore open state
  Array.from(listEl.querySelectorAll(".dep-row")).forEach((row) => {
    const nameEl = row.querySelector(".dep-name");
    const name = String(nameEl?.textContent || "").trim();
    if (openNames.has(name)) {
      row.setAttribute("open", "");
    }
  });
}

function attachRepoSortControl(repos) {
  const select = document.getElementById("repo-sort");
  if (!select) return;
  select.addEventListener("change", () => {
    sortRepositories(repos, select.value);
    renderDashboard(repos);
    attachRepoSortControl(repos);
    attachDepHeaderSort(repos);
  });
}

function attachDepHeaderSort(repos) {
  document.querySelectorAll("details.repository").forEach((repoEl) => {
    const repoId = repoEl.getAttribute("data-repo");
    const repo = repos.find((r) => cssSafeId(r.name) === repoId);
    const header = repoEl.querySelector(".dep-header");
    if (!repo || !header) return;
    header.querySelectorAll(".click-sort").forEach((el) => {
      el.addEventListener("click", () => {
        const key = el.getAttribute("data-sort");
        sortAndRenderDependencies(repoEl, repo, key);
      });
    });
  });
}

function attachDepSelectSort(repos) {
  document.querySelectorAll('select[id^="dep-sort-"]').forEach((sel) => {
    sel.addEventListener("change", () => {
      const repoId = sel.getAttribute("data-repo");
      const repo = repos.find((r) => cssSafeId(r.name) === repoId);
      if (!repo) return;
      const repoEl = document.querySelector(`details.repository[data-repo="${repoId}"]`);
      if (!repoEl) return;
      sortAndRenderDependencies(repoEl, repo, sel.value);
    });
  });
}

// Fetch all data files and build repositories
async function loadReports() {
  const results = [];
  for (const path of DATA_FILES) {
    try {
      const res = await fetch(path);
      const json = await res.json();
      // Use filename stem as repository name
      const repoName = path.split("/").pop().replace(".json", "");
      results.push(parseRepositoryReport(json, repoName));
    } catch (err) {
      // Graceful handling: if a file fails to load, show an empty repo with a note.
      const repoName = path.split("/").pop().replace(".json", "");
      results.push({
        name: repoName,
        severity: "Unknown",
        highestCveScore: 0,
        dependencies: [],
        error: true,
      });
      console.warn("Failed to load", path, err);
    }
  }
  return results;
}

// Init
(async function init() {
  const repos = await loadReports();
  // Default sort by repository severity (derived from highest score)
  sortRepositories(repos, "severity");
  renderDashboard(repos);
  attachRepoSortControl(repos);
  attachDepHeaderSort(repos);
  attachDepSelectSort(repos);
})();

// Extract CWE from known fields or from description/links text
function extractCwe(v) {
  if (v?.cwe || v?.cwe_id) return v.cwe || v.cwe_id;
  const desc = String(v?.description || "");
  const fromDesc = desc.match(/CWE-\d+/i);
  if (fromDesc) return fromDesc[0];
  if (Array.isArray(v?.links)) {
    for (const l of v.links) {
      const name = String(l?.name || "");
      const url = String(l?.url || "");
      const m = name.match(/CWE-\d+/i) || url.match(/CWE-\d+/i);
      if (m) return m[0];
    }
  }
  return null;
}
