/**
 * Fetch all three vulnerability report JSON files.
 * Returns an array of parsed JSON objects.
 */
export async function fetchReports() {
  const reports = [
    "openmrs-core.json",
    "openmrs-module-billing.json",
    "openmrs-module-idgen.json",
    "openmrs-module-patientflags.json",
    "openmrs-module-referencedemodata.json",
    "openmrs-module-webservices.rest.json",
    "openmrs-module-attachments.json",
    "openmrs-module-fhir2.json",
  ];

  const responses = await Promise.all(
    reports.map((report) => fetch(`data/${report}`).then((r) => r.json())),
  );

  return responses;
}
