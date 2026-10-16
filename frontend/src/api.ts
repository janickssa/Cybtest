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

export interface Triage {
  status: "false_positive" | "accepted_risk";
  note: string;
}

export interface FindingView extends Finding {
  fingerprint: string;
  is_new: boolean;
  triage: Triage | null;
}

export interface Comparison {
  previous_run_id: string;
  previous_created_at: number;
  new_count: number;
  unchanged_count: number;
  fixed: Finding[];
}

export interface RunState {
  run_id: string;
  project_id: string;
  project_name: string;
  created_at: number;
  finished: boolean;
  jobs: RunJob[];
  findings: FindingView[];
  comparison: Comparison | null;
}

export interface UploadInfo {
  workspace_id: string;
  name: string;
  file_count: number;
  total_bytes: number;
}

export interface ProjectData {
  name: string;
  url: string;
  description: string;
  rps: number;
  tags: DetectedTag[];
  upload: UploadInfo | null;
}

export interface Counts {
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface RunSummary {
  id: string;
  created_at: number;
  finished: boolean;
  counts: Counts | null;
}

export interface ProjectSummary {
  id: string;
  name: string;
  url: string;
  tags: string[];
  upload_name: string | null;
  updated_at: number;
  last_run: RunSummary | null;
}

export interface ProjectDetail {
  id: string;
  project: ProjectData;
  runs: RunSummary[];
}

export interface RunRequest {
  project_id: string | null;
  project: ProjectData;
  selected: string[];
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
  startRun: async (req: RunRequest): Promise<{ run_id: string; project_id: string }> =>
    (await request("/api/runs", req)).json(),
  projects: async (): Promise<ProjectSummary[]> => (await request("/api/projects")).json(),
  project: async (id: string): Promise<ProjectDetail> => (await request(`/api/projects/${id}`)).json(),
  deleteProject: async (id: string) => {
    const res = await fetch(`/api/projects/${id}`, { method: "DELETE", credentials: "same-origin" });
    if (!res.ok) throw new ApiError(res.status, "Could not delete the project");
  },
  setTriage: (projectId: string, fingerprint: string, status: Triage["status"] | null, note = "") =>
    request(`/api/projects/${projectId}/triage`, { fingerprint, status, note }),
  sarif: async (runId: string): Promise<Blob> => (await request(`/api/runs/${runId}/export/sarif`)).blob(),
  run: async (id: string): Promise<RunState> => (await request(`/api/runs/${id}`)).json(),
  stopRun: (id: string) => request(`/api/runs/${id}/stop`, {}),
  stopJob: (id: string, jobId: string) => request(`/api/runs/${id}/jobs/${jobId}/stop`, {}),
  exportMarkdown: async (req: ExportRequest): Promise<Blob> =>
    (await request("/api/export/markdown", req)).blob(),
};
