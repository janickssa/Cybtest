import { useEffect, useRef, useState } from "react";
import { api, type JobStatus, type RunState } from "./api";
import { Badge, Button, Card, ErrorNote } from "./ui";

const statusStyle: Record<JobStatus, { icon: string; label: string; className: string }> = {
  queued: { icon: "⏳", label: "Queued", className: "text-slate-500" },
  running: { icon: "⚙️", label: "Running", className: "text-indigo-600 dark:text-indigo-400" },
  done: { icon: "✅", label: "Done", className: "text-green-700 dark:text-green-400" },
  failed: { icon: "❌", label: "Failed", className: "text-red-700 dark:text-red-400" },
  stopped: { icon: "⏹", label: "Stopped", className: "text-slate-500" },
};

function duration(secs: number) {
  return secs < 60 ? `${secs}s` : `${Math.floor(secs / 60)}m ${secs % 60}s`;
}

export function severityCounts(run: RunState) {
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of run.findings) counts[f.severity]++;
  return counts;
}

interface Props {
  runId: string;
  run: RunState | null;
  setRun: (r: RunState) => void;
  onResults: () => void;
  onError: (e: unknown) => void;
}

export default function StepRun({ runId, run, setRun, onResults, onError }: Props) {
  const [openJob, setOpenJob] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const logRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    async function poll() {
      try {
        const state = await api.run(runId);
        if (cancelled) return;
        setRun(state);
        setError(null);
        if (!state.finished) timer = window.setTimeout(poll, 1000);
      } catch (e) {
        if (cancelled) return;
        onError(e);
        setError("Lost contact with the server; retrying…");
        timer = window.setTimeout(poll, 3000);
      }
    }
    poll();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [runId, setRun, onError]);

  const job = run?.jobs.find((j) => j.job_id === openJob);
  useEffect(() => {
    logRef.current?.scrollTo(0, logRef.current.scrollHeight);
  }, [job?.log.length]);

  if (!run) return <p className="text-sm text-slate-500">Starting…</p>;
  const counts = severityCounts(run);
  const finishedJobs = run.jobs.filter((j) => ["done", "failed", "stopped"].includes(j.status)).length;

  return (
    <div className="space-y-4">
      <Card className="space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="flex-1 font-semibold">
            {run.finished ? "Run finished" : "Running tests"}{" "}
            <span className="font-normal text-slate-500">
              · {finishedJobs} of {run.jobs.length} done
            </span>
          </h2>
          <span className="text-sm" aria-live="polite">
            {run.findings.length === 0
              ? "No findings yet"
              : `${counts.high} high, ${counts.medium} medium, ${counts.low + counts.info} low${run.finished ? "" : " so far"}`}
          </span>
          {!run.finished && (
            <Button onClick={() => api.stopRun(runId).catch(onError)}>⏹ Stop all</Button>
          )}
        </div>
        <div className="h-1.5 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
          <div
            className="h-full bg-indigo-500 transition-all"
            style={{ width: `${(finishedJobs / Math.max(run.jobs.length, 1)) * 100}%` }}
          />
        </div>
        <ErrorNote message={error} />
        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
          {run.jobs.map((j) => {
            const s = statusStyle[j.status];
            const isOpen = openJob === j.job_id;
            return (
              <li key={j.job_id} className="py-2">
                <div className="flex items-center gap-3">
                  <button
                    className="flex min-w-0 flex-1 items-center gap-3 rounded text-left hover:bg-slate-50 dark:hover:bg-slate-800/50"
                    aria-expanded={isOpen}
                    onClick={() => setOpenJob(isOpen ? null : j.job_id)}
                  >
                    <span aria-hidden className={j.status === "running" ? "animate-spin" : ""}>
                      {s.icon}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block text-sm font-medium">{j.title}</span>
                      <span className="block truncate text-xs text-slate-500">{j.tests.join(" · ")}</span>
                    </span>
                    <Badge>{j.tool}</Badge>
                    <span className={`w-20 text-sm ${s.className}`}>{s.label}</span>
                    <span className="w-14 text-right text-xs text-slate-500">
                      {j.status === "queued" ? "" : duration(j.elapsed_secs)}
                    </span>
                    <span className="w-16 text-right text-xs text-slate-500">
                      {j.status === "done" ? `${j.finding_count} found` : ""}
                    </span>
                  </button>
                  {(j.status === "queued" || j.status === "running") && (
                    <Button variant="ghost" className="!px-2 !py-1" onClick={() => api.stopJob(runId, j.job_id).catch(onError)}>
                      Stop
                    </Button>
                  )}
                </div>
                {j.error && <p className="mt-1 pl-8 text-sm text-red-700 dark:text-red-400">{j.error}</p>}
                {isOpen && (
                  <pre
                    ref={logRef}
                    className="mt-2 max-h-80 overflow-auto rounded-md bg-slate-900 p-3 text-xs leading-relaxed text-slate-100"
                    aria-label={`Log for ${j.title}`}
                  >
                    {j.log.length ? j.log.join("\n") : "No output yet."}
                  </pre>
                )}
              </li>
            );
          })}
        </ul>
        <p className="text-xs text-slate-500">Click a test to see its live log.</p>
      </Card>
      <div className="flex justify-end">
        <Button variant="primary" disabled={!run.finished} onClick={onResults}>
          {run.finished ? "View results →" : "Waiting for tests to finish…"}
        </Button>
      </div>
    </div>
  );
}
