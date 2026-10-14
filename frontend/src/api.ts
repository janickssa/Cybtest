export type Severity = "high" | "medium" | "low" | "info";

export interface TagDef {
  id: string;
  label: string;
  category: string;
}

export interface DetectedTag {
  id: string;
  label: string;
  evidence: string;
}

export interface PlanAction {
  id: string;
  title: string;
  tool: string;
  input: string;
  mode: string;
  est_minutes: number;
  command: string;
}

export interface PlanItem {
  rule_id: string;
  title: string;
  severity: Severity;
  references: string[];
  description: string;
  expected_secure_behavior: string | null;
  why: string[];
  actions: PlanAction[];
  active: boolean;
  preselected: boolean;
}

export interface ExportRequest {
  project_name: string;
  url: string;
  description: string;
  tags: string[];
  selected: string[];
}

export interface Upload {
  workspace_id: string;
  file_count: number;
  total_bytes: number;
  tags: DetectedTag[];
}

export type JobStatus = "queued" | "running" | "done" | "failed" | "stopped";

export interface Finding {
  tool: string;
  rule_id: string;
  title: string;
  severity: Severity;
  location: string | null;
  message: string;
  snippet: string | null;
  help: string | null;
  help_url: string | null;
}

export interface RunJob {
  job_id: string;
  action_id: string;
  title: string;
  tool: string;
  tests: string[];
  status: JobStatus;
  elapsed_secs: number;
  exit_code: number | null;
  error: string | null;
  log: string[];
  finding_count: number;
}

export interface RunState {
  run_id: string;
  finished: boolean;
  jobs: RunJob[];
  findings: Finding[];
}

export interface RunRequest {
  workspace_id: string | null;
  url: string;
  tags: string[];
  selected: string[];
  rate_limit_rps: number;
  confirm_host: string | null;
}

export interface ScopeStatus {
  allowed: boolean;
  message: string;
}

export interface AnalyzeResult {
  tags: DetectedTag[];
  scope: ScopeStatus | null;
  fingerprint_note: string | null;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request(path: string, body?: unknown): Promise<Response> {
  const raw = body instanceof Blob;
  const res = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? {} : { "Content-Type": raw ? "application/zip" : "application/json" },
    body: body === undefined ? undefined : raw ? body : JSON.stringify(body),
    credentials: "same-origin",
  });
  if (!res.ok) {
    let message = res.status === 401 ? "Not logged in" : `Request failed (${res.status})`;
    try {
      message = (await res.json()).error ?? message;
    } catch {
      // Not JSON; keep the generic message.
    }
    throw new ApiError(res.status, message);
  }
  return res;
}

export const api = {
  me: () => request("/api/me"),
  login: (password: string) => request("/api/login", { password }),
  logout: () => request("/api/logout", {}),
  tags: async (): Promise<TagDef[]> => (await request("/api/tags")).json(),
  analyze: async (description: string, url: string): Promise<AnalyzeResult> =>
    (await request("/api/analyze", { description, url })).json(),
  plan: async (tags: string[], url: string): Promise<PlanItem[]> =>
    (await request("/api/plan", { tags, url })).json(),
  upload: async (file: File): Promise<Upload> => (await request("/api/upload", file)).json(),
  startRun: async (req: RunRequest): Promise<{ run_id: string }> => (await request("/api/runs", req)).json(),
  run: async (id: string): Promise<RunState> => (await request(`/api/runs/${id}`)).json(),
  stopRun: (id: string) => request(`/api/runs/${id}/stop`, {}),
  stopJob: (id: string, jobId: string) => request(`/api/runs/${id}/jobs/${jobId}/stop`, {}),
  exportMarkdown: async (req: ExportRequest): Promise<Blob> =>
    (await request("/api/export/markdown", req)).blob(),
};
