# openmrs-contrib-dependancy-vulnerabilities

## Components Used for displaying data

Carbon Web Components (loaded from CDN)

```html
<script
  type="module"
  src="https://1.www.s81c.com/common/carbon/web-components/version/v2.49.0/accordion.min.js"
></script>
<script
  type="module"
  src="https://1.www.s81c.com/common/carbon/web-components/version/v2.49.0/data-table.min.js"
></script>
<script
  type="module"
  src="https://1.www.s81c.com/common/carbon/web-components/version/v2.49.0/tag.min.js"
></script>
```

Used components:

- `cds-accordion`
- `cds-table`
- `cds-tag`

---

## Project Structure

```
data/
 ├─ billing.json
 ├─ idgen.json
 └─ openmrs-core.json

js/
 ├─ main.js : controls the flow
 ├─ fetchReports.js : fetches the data
 ├─ parseReports.js : parses the data
 ├─ table.js
 └─ helpers.js
```

### parseReports.js

Extracts relevant fields from the dependency check reports.

Fallback value to "-" if missing:

#### Dependency Table Fields

| Field       | Source                                                             |
| ----------- | ------------------------------------------------------------------ |
| dependency  | `report.dependencies.packages[0].id` (name extract using regex)    |
| version     | `report.dependencies.packages[0].id` (version extract using regex) |
| severity    | highest severity among vulnerabilities                             |
| cves        | `vulnerabilities.length`                                           |
| exploit     | `references[].name` which contains `"EXPLOIT"`                     |
| fix version | `versionEndExcluding`                                              |

---

#### CVE Table Fields (for severity two different version are available)

| Field            | Source                                            |
| ---------------- | ------------------------------------------------- |
| cve_id           | `vulnerability.name`                              |
| severity         | `cvssv3.baseSeverity` or `vulnerability.severity` |
| score            | `cvssv3.baseScore` or `cvssv2.score`              |
| description      | `vulnerability.description`                       |
| affected version | `vulnerableSoftware.software.versionEndExcluding` |
| fixed in         | `versionEndExcluding` or `versionEndIncluding`    |
| cwe              | `vulnerability.cwes`                              |

## run using

npx -y serve . -l 3000
