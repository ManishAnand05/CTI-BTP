const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

async function apiRequest(endpoint, options = {}) {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    const message =
      typeof data === "object" && data !== null
        ? data.error || data.message || JSON.stringify(data)
        : data;

    throw new Error(message || `Request failed: ${response.status}`);
  }

  return data;
}

export const api = {
  getAdvancedCTI: () => apiRequest("/api/cti/advanced"),

  getCorrelations: () => apiRequest("/api/correlations"),

  getOrganizations: () => apiRequest("/api/organizations"),

  getPolicies: () => apiRequest("/api/policies"),

  getRisk: () => apiRequest("/api/risk"),

  submitCTI: (record) =>
    apiRequest("/api/cti/submit", {
      method: "POST",
      body: JSON.stringify(record),
    }),
};

export { API_BASE_URL };