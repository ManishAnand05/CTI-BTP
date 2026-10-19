
const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000"
).replace(/\/+$/, "");

const REQUEST_TIMEOUT_MS = 15000;
const TOKEN_KEY = "cti_access_token";

export class ApiError extends Error {
  constructor(message, { status = 0, data = null } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
  }
}

// TOKEN STORAGE

export function getAccessToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setAccessToken(token) {
  try {
    if (token) {
      sessionStorage.setItem(TOKEN_KEY, token);
    } else {
      sessionStorage.removeItem(TOKEN_KEY);
    }
  } catch {
    // Browser storage may be unavailable.
  }
}

export function clearAccessToken() {
  setAccessToken(null);
}

// RESPONSE HELPERS

async function parseBody(response) {
  const contentType = response.headers.get("content-type") || "";

  if (contentType.includes("application/json")) {
    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  try {
    return await response.text();
  } catch {
    return null;
  }
}

function buildMessage(data, status) {
  if (data && typeof data === "object") {
    const base =
      data.error || data.message || `Request failed: ${status}`;

    if (
      Array.isArray(data.missing_fields) &&
      data.missing_fields.length > 0
    ) {
      return `${base} (${data.missing_fields.join(", ")})`;
    }

    return base;
  }

  if (typeof data === "string" && data.trim()) {
    return data.trim().startsWith("<")
      ? `Request failed: ${status}`
      : data.trim().slice(0, 300);
  }

  return `Request failed: ${status}`;
}

// CORE REQUEST

async function apiRequest(endpoint, options = {}) {
  const { headers, body, signal, auth = true, ...rest } = options;

  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    REQUEST_TIMEOUT_MS,
  );

  const forwardAbort = () => controller.abort();

  if (signal) {
    if (signal.aborted) {
      controller.abort();
    } else {
      signal.addEventListener("abort", forwardAbort, { once: true });
    }
  }

  const token = auth ? getAccessToken() : null;

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...rest,
      body,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(body !== undefined
          ? { "Content-Type": "application/json" }
          : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
    });

    const data = await parseBody(response);

    if (!response.ok) {
      if (response.status === 401 && token) {
        clearAccessToken();

        if (typeof window !== "undefined") {
          window.dispatchEvent(new CustomEvent("cti:unauthorized"));
        }
      }

      throw new ApiError(buildMessage(data, response.status), {
        status: response.status,
        data,
      });
    }

    return data;
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }

    if (error?.name === "AbortError") {
      if (signal?.aborted) {
        throw error;
      }

      throw new ApiError("The request timed out. Please try again.");
    }

    throw new ApiError(
      `Cannot reach the API at ${API_BASE_URL}. Check that the backend is running.`,
    );
  } finally {
    clearTimeout(timeout);

    if (signal) {
      signal.removeEventListener("abort", forwardAbort);
    }
  }
}

function withQuery(endpoint, params = {}) {
  const query = new URLSearchParams();

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) {
      query.set(key, String(value));
    }
  }

  const queryString = query.toString();

  return queryString ? `${endpoint}?${queryString}` : endpoint;
}

// API METHODS

export const api = {
  // Authentication

  login: async (email, password) => {
    const data = await apiRequest("/api/auth/login", {
      method: "POST",
      auth: false,
      body: JSON.stringify({ email, password }),
    });

    const token = data?.access_token || data?.token;

    if (token) {
      setAccessToken(token);
    }

    return data;
  },

  register: (name, email, password, organization_id = null) =>
    apiRequest("/api/auth/register", {
      method: "POST",
      auth: false,
      body: JSON.stringify({
        name,
        email,
        password,
        organization_id,
      }),
    }),

  logout: () => clearAccessToken(),

  isAuthenticated: () => Boolean(getAccessToken()),

  // Advanced CTI

  getAdvancedCTI: ({ limit = 500, offset = 0 } = {}) =>
    apiRequest(withQuery("/api/cti/advanced", { limit, offset })),

  getCTISubmissions: (recordId) =>
    apiRequest(
      `/api/cti/advanced/${encodeURIComponent(recordId)}/submissions`,
    ),

  getEvidenceTimeline: (recordId) =>
    apiRequest(
      `/api/cti/advanced/${encodeURIComponent(recordId)}/evidence-timeline`,
    ),

  submitCTI: (record) =>
    apiRequest("/api/cti/submit", {
      method: "POST",
      body: JSON.stringify(record),
    }),

  // Temporal intelligence

  getTemporalIntelligence: () =>
    apiRequest("/api/cti/temporal-intelligence"),

  // Organizations

  getOrganizations: () => apiRequest("/api/organizations"),

  // Policies

  // No policy-list GET endpoint currently exists.
  getPolicies: async () => ({ policies: [] }),

  evaluateAdvancedPolicy: (organization_id, record_id) =>
    apiRequest("/api/advanced-policies", {
      method: "POST",
      body: JSON.stringify({
        organization_id,
        record_id,
      }),
    }),

  // Risk and correlation

  getCorrelations: () => apiRequest("/api/correlations"),

  getRisk: () => apiRequest("/api/risk"),

  // Knowledge graph

  getKnowledgeGraph: () =>
    apiRequest("/api/cti/knowledge-graph"),
};

export { API_BASE_URL };
