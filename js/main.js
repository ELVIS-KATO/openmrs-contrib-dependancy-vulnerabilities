import { fetchReports } from "./fetchReports.js";
import { parseReports } from "./parseReports.js";
import { renderProjectAccordion } from "./components/table.js";

/**
 * Main entry point.
 * Fetches reports, parses them, and renders the dashboard UI.
 */
async function init() {
  const appContainer = document.getElementById("app");

  try {
    // Show loading state
    appContainer.innerHTML =
      '<p class="loading">Loading vulnerability reports…</p>';

    // 1. Fetch
    const rawReports = await fetchReports();

    // 2. Parse
    const projects = parseReports(rawReports);

    // 3. Render
    const accordionItems = projects
      .map((project) => renderProjectAccordion(project))
      .join("");

    appContainer.innerHTML = `
      <div class="dashboard-header">
        <h1 class="dashboard-title">OpenMRS Dependency Vulnerability Report</h1>
        <span class="title-accent"></span>
        <p class="dashboard-subtitle">A summary of known security vulnerabilities detected across OpenMRS modules by automated dependency scanning. Each module lists its vulnerable dependencies, severity levels, and recommended fix versions to help maintainers prioritize upgrades.</p>
      </div>
      <cds-accordion alignment="start" class="project-accordion">
        ${accordionItems}
      </cds-accordion>
    `;
  } catch (error) {
    console.error("Failed to load vulnerability reports:", error);
    appContainer.innerHTML = `
      <p class="error">Failed to load vulnerability reports. Check the console for details.</p>
    `;
  }
}

// Run on DOM ready
document.addEventListener("DOMContentLoaded", init);
