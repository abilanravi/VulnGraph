import "server-only";
import { getToken } from "./session";

const BACKEND_URL = process.env.BACKEND_URL ?? "http://localhost:8000";

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type FindingStatus = "OPEN" | "RESOLVED" | "IGNORED";

export interface Repository {
  id: string;
  name: string;
  owner: string;
  url: string | null;
  created_at: string;
}

export interface Vulnerability {
  id: string;
  cve: string;
  severity: Severity;
  description: string;
  created_at: string;
}

export interface Finding {
  id: string;
  status: FindingStatus;
  detected_at: string;
  vulnerability: Vulnerability;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, options: RequestInit = {}, token?: string): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const res = await fetch(`${BACKEND_URL}/api${path}`, { ...options, headers });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(res.status, body.detail ?? `Request failed with status ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

async function authRequest<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = await getToken();
  if (!token) throw new ApiError(401, "Not authenticated");
  return request<T>(path, options, token);
}

// -- Auth (no session token yet) --

export function login(email: string, password: string): Promise<{ access_token: string }> {
  return request("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
}

export function signup(email: string, password: string): Promise<{ access_token: string }> {
  return request("/auth/signup", { method: "POST", body: JSON.stringify({ email, password }) });
}

// -- Repositories --

export function getRepositories(): Promise<Repository[]> {
  return authRequest("/repositories");
}

export function getRepository(id: string): Promise<Repository> {
  return authRequest(`/repositories/${id}`);
}

export function createRepository(data: { name: string; owner: string; url?: string }): Promise<Repository> {
  return authRequest("/repositories", { method: "POST", body: JSON.stringify(data) });
}

// -- Findings --

export function getFindings(repositoryId: string): Promise<Finding[]> {
  return authRequest(`/repositories/${repositoryId}/findings`);
}

export function createFinding(
  repositoryId: string,
  data: { cve: string; severity: Severity; description: string; status?: FindingStatus },
): Promise<Finding> {
  return authRequest(`/repositories/${repositoryId}/findings`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}
