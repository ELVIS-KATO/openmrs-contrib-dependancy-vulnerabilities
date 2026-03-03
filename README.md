# Dependency Vulnerability Dashboard (GSoC Starter Challenge)
This repository contains a plain HTML/CSS/JS dashboard that visualizes dependency vulnerability reports for OpenMRS modules. It loads three JSON files from the data/ directory and presents:
- Collapsible repository sections
- Collapsible dependency rows
- Severity pills for repositories, dependencies, and CVEs
- CVE tables sorted by score (descending)
- Robust sorting for repositories and dependencies

## Run Locally
1. Start any static server at the repository root (to allow fetch of JSON files):
   -Open with Live server in the IDE (VSCode). The Json file will open together with the HTML File
2. Open `http://localhost:5500/` in your browser.

## Data Location
- JSON reports live in `data/`:
  - `data/openmrs-core.json`
  - `data/openmrs-module-billing.json`
  - `data/openmrs-module-idgen.json`
- To add more, place files in `data/` and update `DATA_FILES` in `script.js`.

## Sorting
- Repositories (top-right control):
  - Repository Severity (desc)
  - Highest CVE Score (desc)
  - Name (A–Z)
- Dependencies (per repository):
  - Header clicks: Dependency (A–Z), Severity (desc), CVEs (highest score desc)
  - Per-repo select: Severity (desc), Highest CVE Score (desc), Name (A–Z)
- Sorting preserves open rows and does not close sections.

## Collapsibles and UI
- Right-side dropdown buttons (chevrons) toggle sections:
  - Repositories: summary bar with name + severity on the left; chevron on the right
  - Dependencies: row data left-to-right; chevron on the right
- A subtle grey content panel separates the data area from the page background.
- Transitions:
  - Chevron rotates smoothly on open/close
  - CVE table fades in when a dependency is expanded

## Notes
- Keep JSON under `data/` and serve the repo with a static server for fetch() to work.
- When adding more reports, update `DATA_FILES` in `script.js` to include them.
- The layout uses responsive CSS grid to avoid content cut-off; columns line up between header and rows.
