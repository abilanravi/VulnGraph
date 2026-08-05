import "server-only";
import { getToken } from "./session";

const BACKEND_URL = process.env.BACKEND_URL ?? "http://localhost:8000";

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type FindingStatus = "OPEN" | "IN_PROGRESS" | "RESOLVED" | "FALSE_POSITIVE";
export type Scanner = "MANUAL" | "SEMGREP" | "OSV";
export type FindingType = "MANUAL" | "SAST" | "SCA";
export type ScanStatus = "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";

export interface Repository {
  id: string;
  name: string;
  owner: string;
  url: string | null;
  created_at: string;
}

export interface Finding {
  id: string;
  repository_id: string;
  scan_id: string | null;
  scanner: Scanner;
  finding_type: FindingType;
  severity: Severity;
  title: string;
  description: string | null;
  file_path: string | null;
  line_start: number | null;
  package_name: string | null;
  package_version: string | null;
  cve: string | null;
  status: FindingStatus;
  detected_at: string;
  last_seen_at: string;
  resolved_at: string | null;
}

export interface Scan {
  id: string;
  repository_id: string;
  scanner: Scanner;
  status: ScanStatus;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  total_findings: number | null;
  new_findings: number | null;
  resolved_findings: number | null;
  created_at: string;
}

export interface DashboardSummary {
  total_repositories: number;
  total_open_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  recent_findings: Finding[];
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

export function updateFindingStatus(
  repositoryId: string,
  findingId: string,
  status: FindingStatus,
): Promise<Finding> {
  return authRequest(`/repositories/${repositoryId}/findings/${findingId}`, {
    method: "PATCH",
    body: JSON.stringify({ status }),
  });
}

// -- Scans --

export function getScans(repositoryId: string): Promise<Scan[]> {
  return authRequest(`/repositories/${repositoryId}/scans`);
}

export function triggerSemgrepScan(repositoryId: string, path: string): Promise<Scan> {
  return authRequest(`/repositories/${repositoryId}/scans/semgrep`, {
    method: "POST",
    body: JSON.stringify({ path }),
  });
}

export function triggerOsvScan(repositoryId: string, path: string): Promise<Scan> {
  return authRequest(`/repositories/${repositoryId}/scans/osv`, {
    method: "POST",
    body: JSON.stringify({ path }),
  });
}

// -- Dashboard --

export function getDashboardSummary(): Promise<DashboardSummary> {
  return authRequest("/dashboard/summary");
}
