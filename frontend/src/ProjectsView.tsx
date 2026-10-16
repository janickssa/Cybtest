import { useEffect, useState } from "react";
import { api, type ProjectDetail, type ProjectSummary } from "./api";
import { countsText, formatDate } from "./format";
import { Badge, Button, Card } from "./ui";

interface Props {
  onOpen: (detail: ProjectDetail) => void;
  onOpenRun: (projectId: string, runId: string) => void;
  onNew: () => void;
  onError: (e: unknown) => void;
}

export default function ProjectsView({ onOpen, onOpenRun, onNew, onError }: Props) {
  const [projects, setProjects] = useState<ProjectSummary[] | null>(null);
  const [history, setHistory] = useState<ProjectDetail | null>(null);

  useEffect(() => {
    api.projects().then(setProjects, onError);
  }, [onError]);

  async function toggleHistory(id: string) {
    if (history?.id === id) return setHistory(null);
    try {
      setHistory(await api.project(id));
    } catch (e) {
      onError(e);
    }
  }

  async function remove(p: ProjectSummary) {
    if (!window.confirm(`Delete “${p.name || "Untitled project"}” and all its runs?`)) return;
    try {
      await api.deleteProject(p.id);
      setProjects((list) => list?.filter((x) => x.id !== p.id) ?? null);
    } catch (e) {
      onError(e);
    }
  }

  if (projects === null) return <p className="text-sm text-slate-500">Loading projects…</p>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Projects</h2>
        <Button variant="primary" onClick={onNew}>
          + New project
        </Button>
      </div>
      {projects.length === 0 && (
        <Card>
          <p className="text-sm text-slate-500">No projects yet. A project is saved when you run its first tests.</p>
        </Card>
      )}
      {projects.map((p) => (
        <Card key={p.id} className="space-y-3">
          <div className="flex flex-wrap items-start gap-3">
            <div className="min-w-0 flex-1">
              <h3 className="font-medium">{p.name || "Untitled project"}</h3>
              <p className="truncate text-xs text-slate-500">
                {[p.url, p.upload_name && `📦 ${p.upload_name}`].filter(Boolean).join(" · ") || "No target"}
              </p>
            </div>
            <div className="text-right text-xs text-slate-500">
              {p.last_run ? (
                <>
                  <p>Last run {formatDate(p.last_run.created_at)}</p>
                  <p className="text-sm text-slate-700 dark:text-slate-300">{countsText(p.last_run.counts)}</p>
                </>
              ) : (
                <p>No runs</p>
              )}
            </div>
          </div>
          {p.tags.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {p.tags.slice(0, 8).map((t) => (
                <Badge key={t}>{t}</Badge>
              ))}
              {p.tags.length > 8 && <Badge>+{p.tags.length - 8}</Badge>}
            </div>
          )}
          <div className="flex flex-wrap gap-2">
            <Button
              variant="primary"
              className="!py-1"
              onClick={() => api.project(p.id).then(onOpen, onError)}
            >
              Open
            </Button>
            {p.last_run && (
              <Button className="!py-1" onClick={() => onOpenRun(p.id, p.last_run!.id)}>
                Latest results
              </Button>
            )}
            <Button variant="ghost" className="!py-1" aria-expanded={history?.id === p.id} onClick={() => toggleHistory(p.id)}>
              History
            </Button>
            <span className="flex-1" />
            <Button variant="ghost" className="!py-1 text-red-700 dark:text-red-400" onClick={() => remove(p)}>
              Delete
            </Button>
          </div>
          {history?.id === p.id && (
            <ul className="divide-y divide-slate-100 rounded-lg bg-slate-50 px-3 text-sm dark:divide-slate-800 dark:bg-slate-950">
              {history.runs.map((r) => (
                <li key={r.id} className="flex items-center gap-3 py-2">
                  <span className="flex-1">{formatDate(r.created_at)}</span>
                  <span>{countsText(r.counts)}</span>
                  <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => onOpenRun(p.id, r.id)}>
                    View
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </Card>
      ))}
    </div>
  );
}
