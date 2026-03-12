import { getSeverityTagColor, escapeHtml } from "../helpers.js";

export function renderProjectAccordion(project) {
  const tagColor = getSeverityTagColor(project.highestSeverity);

  const title = `${escapeHtml(project.projectName)}`;

  // Build the inner content: dependency table with nested CVE accordions
  const innerContent = renderDependencySection(project.dependencies);

  return `
    <cds-accordion-item title-text="${title}" class="project-accordion-item">
      <span slot="title" class="project-title">
        <span class="project-name">${escapeHtml(project.projectName)}</span>
        <cds-tag type="${tagColor}" class="severity-tag" style="padding: 0.2rem 0.5rem;">${escapeHtml(project.highestSeverity)}</cds-tag>
      </span>
      ${innerContent}
    </cds-accordion-item>
  `;
}
/**
 * Render the dependency table section.
 * Each dependency row contains an inner accordion for CVE details.
 */
function renderDependencySection(dependencies) {
  if (dependencies.length === 0) {
    return '<p class="no-data">No vulnerable dependencies found.</p>';
  }

  const rows = dependencies
    .map((dep) => {
      const tagColor = getSeverityTagColor(dep.severity);
      const cveTableHtml = renderCVETable(dep.cves);

      return `
        <cds-table-row>
          <cds-table-cell class="dep-name">${escapeHtml(dep.name)}</cds-table-cell>
          <cds-table-cell class="dep-version">${escapeHtml(dep.version)}</cds-table-cell>
          <cds-table-cell><cds-tag type="${tagColor}" size="sm" style="padding: 0.2rem 0.5rem;">${escapeHtml(dep.severity)}</cds-tag></cds-table-cell>
          <cds-table-cell class="dep-cve-count">${dep.cveCount}</cds-table-cell>
          <cds-table-cell class="dep-exploit">${escapeHtml(dep.exploit)}</cds-table-cell>
          <cds-table-cell class="dep-fix">${escapeHtml(dep.fixVersion)}</cds-table-cell>
        </cds-table-row>
        <cds-table-expanded-row col-span="7">
          <div class="cve-details-wrapper">
            ${cveTableHtml}
          </div>
        </cds-table-expanded-row>
      `;
    })
    .join("");

  return `
    <cds-table expandable class="dep-table">
      <cds-table-head>
        <cds-table-header-row>
          <cds-table-header-cell>Dependency</cds-table-header-cell>
          <cds-table-header-cell>Version</cds-table-header-cell>
          <cds-table-header-cell>Severity</cds-table-header-cell>
          <cds-table-header-cell>CVEs</cds-table-header-cell>
          <cds-table-header-cell>Exploit?</cds-table-header-cell>
          <cds-table-header-cell>Fix Version</cds-table-header-cell>
        </cds-table-header-row>
      </cds-table-head>
      <cds-table-body>
        ${rows}
      </cds-table-body>
    </cds-table>
  `;
}

/**
 * Render the CVE detail table for a single dependency.
 */
function renderCVETable(cves) {
  if (!cves || cves.length === 0) {
    return '<p class="no-data">No CVE details available.</p>';
  }

  const rows = cves
    .map((cve) => {
      const tagColor = getSeverityTagColor(cve.severity);
      const roundedScore =
        cve.score !== "-" ? Math.round(Number(cve.score) * 1000) / 1000 : "-";
      const scoreDisplay = roundedScore !== "-" ? `${roundedScore}/10` : "-";

      return `
        <cds-table-row >
          <cds-table-cell class="cve-id-cell">${escapeHtml(cve.cveId)}</cds-table-cell>
          <cds-table-cell><cds-tag type="${tagColor}" size="sm" style="padding: 0 0.5rem;">${escapeHtml(cve.severity)}</cds-tag></cds-table-cell>
          <cds-table-cell>${escapeHtml(String(scoreDisplay))}</cds-table-cell>
          <cds-table-cell>${escapeHtml(cve.description)}</cds-table-cell>
          <cds-table-cell>${escapeHtml(cve.affectedVersion)}</cds-table-cell>
          <cds-table-cell>${escapeHtml(cve.fixedIn)}</cds-table-cell>
          <cds-table-cell>${escapeHtml(cve.cwe)}</cds-table-cell>
        </cds-table-row>
      `;
    })
    .join("");

  return `
    <cds-table class="cve-table" >
      <cds-table-head>
        <cds-table-header-row>
          <cds-table-header-cell>CVE ID</cds-table-header-cell>
          <cds-table-header-cell is-sortable>Severity</cds-table-header-cell>
          <cds-table-header-cell>Score</cds-table-header-cell>
          <cds-table-header-cell>Description</cds-table-header-cell>
          <cds-table-header-cell>Affected Versions</cds-table-header-cell>
          <cds-table-header-cell>Fixed In</cds-table-header-cell>
          <cds-table-header-cell>CWE</cds-table-header-cell>
        </cds-table-header-row>
      </cds-table-head>
      <cds-table-body>
        ${rows}
      </cds-table-body>
    </cds-table>
  `;
}
