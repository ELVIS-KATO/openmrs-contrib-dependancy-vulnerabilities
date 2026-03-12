/**
 * a numerical value to each "string" level as makes the sorting calculation easier
 */
export const SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  "-": 4,
};

export function getHighestSeverity(vulnerabilities) {
  if (!vulnerabilities || vulnerabilities.length === 0) return "-";

  let highestOrder = SEVERITY_ORDER["-"];
  let highestSeverity = "-";

  for (const vuln of vulnerabilities) {
    const sev = (
      vuln.cvssv3?.baseSeverity ||
      vuln.severity ||
      ""
    ).toLowerCase();
    const order = SEVERITY_ORDER[sev] ?? SEVERITY_ORDER["-"];

    if (order < highestOrder) {
      highestOrder = order;
      highestSeverity = sev;
    }
  }

  return highestSeverity !== "-" ? capitalizeSeverity(highestSeverity) : "-";
}

//Capitalize severity text.
export function capitalizeSeverity(severity) {
  if (!severity || severity === "-") return "-";
  const lower = severity.toLowerCase();
  return lower.charAt(0).toUpperCase() + lower.slice(1);
}

//extracting dependecy name using regex
export function extractNameFromPackageId(id) {
  if (!id) return "-";

  // Maven: pkg:maven/com.itextpdf/barcodes@8.0.2
  const mavenMatch = id.match(/^pkg:maven\/(.+?)\/(.+?)@/);
  if (mavenMatch) {
    return `${mavenMatch[1]}:${mavenMatch[2]}`;
  }

  // NPM: pkg:npm/axios@0.21.2
  const npmMatch = id.match(/^pkg:npm\/(.+?)@/);
  if (npmMatch) {
    return npmMatch[1];
  }

  return id;
}

//extracting dependecy version using regex
export function extractVersionFromPackageId(id) {
  if (!id) return "-";
  const match = id.match(/@(.+)$/);
  return match ? match[1] : "-";
}

/**
 * Check if a vulnerability has exploits by searching references.
 */
export function hasExploit(vulnerability) {
  if (!vulnerability.references) return false;
  return vulnerability.references.some(
    (ref) => ref.name && ref.name.toUpperCase().includes("EXPLOIT"),
  );
}

/**
 * Check if any vulnerability in an array has exploits.
 */
export function hasAnyExploit(vulnerabilities) {
  if (!vulnerabilities) return "No";
  return vulnerabilities.some((v) => hasExploit(v)) ? "Yes" : "No";
}

/**
 * Get fix version from a vulnerability's vulnerableSoftware entries.
 * Looks for versionEndExcluding first, then versionEndIncluding.
 */
export function getFixVersion(vulnerability) {
  if (!vulnerability.vulnerableSoftware) return "-";
  for (const vs of vulnerability.vulnerableSoftware) {
    if (vs.software?.versionEndExcluding)
      return vs.software.versionEndExcluding;
    if (vs.software?.versionEndIncluding)
      return vs.software.versionEndIncluding;
  }
  return "-";
}

/**
 * Get the first available fix version from all vulnerabilities of a dependency.
 */
export function getFirstFixVersion(vulnerabilities) {
  if (!vulnerabilities) return "-";
  for (const vuln of vulnerabilities) {
    const fix = getFixVersion(vuln);
    if (fix !== "-") return fix;
  }
  return "-";
}

/**
 * Get affected version string from vulnerableSoftware.
 */
export function getAffectedVersion(vulnerability) {
  if (!vulnerability.vulnerableSoftware) return "-";
  const parts = [];
  for (const vs of vulnerability.vulnerableSoftware) {
    const sw = vs.software;
    if (!sw) continue;
    if (sw.versionEndExcluding) {
      parts.push(`< ${sw.versionEndExcluding}`);
    } else if (sw.versionEndIncluding) {
      parts.push(`>= ${sw.versionEndIncluding}`);
    }
  }
  return parts.length > 0 ? parts.join(", ") : "-";
}

/**
 * Map severity to Carbon tag color attribute.
 */
export function getSeverityTagColor(severity) {
  if (!severity) return "gray";
  switch (severity.toLowerCase()) {
    case "critical":
      return "red";
    case "high":
      return "magenta";
    case "medium":
      return "yellow";
    case "low":
      return "teal";
    default:
      return "gray";
  }
}

/**
 * Escape HTML special chars to avoid XSS.
 */
export function escapeHtml(str) {
  if (!str) return "-";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
