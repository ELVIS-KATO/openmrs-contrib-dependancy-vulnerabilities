/**
 * Fetch all three vulnerability report JSON files.
 * Returns an array of parsed JSON objects.
 */
export async function fetchReports() {
  const files = ["data/billing.json", "data/idgen.json", "data/core.json"];

  const responses = await Promise.all(
    files.map((file) => fetch(file).then((r) => r.json())),
  );

  return responses;
}
