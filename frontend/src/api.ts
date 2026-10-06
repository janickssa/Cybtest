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

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request(path: string, body?: unknown): Promise<Response> {
  const res = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
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
  analyze: async (description: string, url: string): Promise<DetectedTag[]> =>
    (await request("/api/analyze", { description, url })).json(),
  plan: async (tags: string[], url: string): Promise<PlanItem[]> =>
    (await request("/api/plan", { tags, url })).json(),
  exportMarkdown: async (req: ExportRequest): Promise<Blob> =>
    (await request("/api/export/markdown", req)).blob(),
};
