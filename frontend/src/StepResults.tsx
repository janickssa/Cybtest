import { forwardRef, useMemo, useState } from "react";
import type { Finding, RunState, Severity } from "./api";
import { severityCounts } from "./StepRun";
import { Badge, Button, Card, SeverityDot, inputClass } from "./ui";

interface Props {
  run: RunState;
  projectName: string;
  onBack: () => void;
  onRerun: () => void;
  busy: boolean;
}

function download(name: string, type: string, text: string) {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([text], { type }));
  link.download = name;
  link.click();
  URL.revokeObjectURL(link.href);
}

function markdown(run: RunState, project: string): string {
  const lines = [`# Security findings: ${project || "Untitled project"}`, ""];
  const c = severityCounts(run);
  lines.push(`${run.findings.length} findings: ${c.high} high, ${c.medium} medium, ${c.low} low, ${c.info} info.`, "");
  for (const j of run.jobs) {
    if (j.status !== "done") lines.push(`> ⚠️ ${j.title} (${j.tool}) did not complete: ${j.error ?? j.status}`);
  }
  for (const f of run.findings) {
    lines.push("", `## [${f.severity.toUpperCase()}] ${f.title}`, "");
    lines.push(`**Tool:** ${f.tool} (\`${f.rule_id}\`)  `);
    if (f.location) lines.push(`**Location:** \`${f.location}\`  `);
    if (f.message) lines.push("", f.message);
    if (f.snippet) lines.push("", "```", f.snippet, "```");
    if (f.help) lines.push("", `**How to fix:** ${f.help}`);
    if (f.help_url) lines.push("", `More: <${f.help_url}>`);
  }
  return lines.join("\n") + "\n";
}

function FindingRow({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <li className="py-2">
      <button
        className="flex w-full items-center gap-3 rounded text-left hover:bg-slate-50 dark:hover:bg-slate-800/50"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        <SeverityDot severity={f.severity} />
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-medium">{f.title}</span>
          {f.location && <code className="block truncate text-xs text-slate-500">{f.location}</code>}
        </span>
        <Badge>{f.tool}</Badge>
        <span className="text-slate-500" aria-hidden>
          {open ? "▾" : "▸"}
        </span>
      </button>
      {open && (
        <div className="mt-3 space-y-3 rounded-lg bg-slate-50 p-4 text-sm dark:bg-slate-950">
          {f.message && <p className="whitespace-pre-wrap">{f.message}</p>}
          {f.snippet && (
            <pre className="overflow-x-auto rounded-md bg-slate-900 p-3 text-xs text-slate-100">
              <code>{f.snippet}</code>
            </pre>
          )}
          {f.help && (
            <p className="whitespace-pre-wrap">
              <span className="font-medium">How to fix:</span> {f.help}
            </p>
          )}
          <p className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
            <Badge>{f.rule_id}</Badge>
            {f.help_url && (
              <a className="text-indigo-600 underline dark:text-indigo-400" href={f.help_url} target="_blank" rel="noreferrer noopener">
                More information ↗
              </a>
            )}
          </p>
        </div>
      )}
    </li>
  );
}

const StepResults = forwardRef<HTMLInputElement, Props>(function StepResults(
  { run, projectName, onBack, onRerun, busy },
  searchRef,
) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const counts = severityCounts(run);
  const incomplete = run.jobs.filter((j) => j.status !== "done");

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    return run.findings.filter(
      (f) =>
        (severity === "all" || f.severity === severity) &&
        (!q || [f.title, f.location ?? "", f.tool, f.rule_id].some((s) => s.toLowerCase().includes(q))),
    );
  }, [run.findings, search, severity]);

  const slug = (projectName || "untitled project").toLowerCase().replace(/[^a-z0-9]/g, "-");

  return (
    <div className="space-y-4">
      <Card className="space-y-4">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <h2 className="font-semibold">{run.findings.length} findings</h2>
          <span className="flex items-center gap-3 text-sm">
            <span>🔴 {counts.high}</span>
            <span>🟠 {counts.medium}</span>
            <span>🟡 {counts.low + counts.info}</span>
          </span>
          <span className="flex-1" />
          <select
            aria-label="Filter by severity"
            className={`${inputClass} !w-auto`}
            value={severity}
            onChange={(e) => setSeverity(e.target.value as Severity | "all")}
          >
            <option value="all">All severities</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <input
            ref={searchRef}
            aria-label="Search findings"
            placeholder="🔍 Search  ( / )"
            className={`${inputClass} !w-48`}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        {incomplete.length > 0 && (
          <div className="rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:bg-amber-950 dark:text-amber-300">
            {incomplete.map((j) => (
              <p key={j.job_id}>
                ⚠️ {j.title} ({j.tool}) didn’t complete{j.error ? `: ${j.error}` : ""}. Its findings are missing.
              </p>
            ))}
          </div>
        )}
        {run.findings.length === 0 && incomplete.length === 0 && (
          <p className="text-sm text-green-700 dark:text-green-400">✅ No findings. Nice work.</p>
        )}
        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
          {visible.map((f) => (
            <FindingRow key={`${f.tool}|${f.rule_id}|${f.location}`} f={f} />
          ))}
        </ul>
        {run.findings.length > 0 && visible.length === 0 && (
          <p className="text-sm text-slate-500">No findings match the filter.</p>
        )}
      </Card>
      <div className="flex flex-wrap items-center gap-3">
        <Button onClick={onBack}>← Back to plan</Button>
        <span className="flex-1" />
        <Button onClick={() => download(`${slug}-findings.json`, "application/json", JSON.stringify(run.findings, null, 2))}>
          Export JSON
        </Button>
        <Button onClick={() => download(`${slug}-findings.md`, "text/markdown", markdown(run, projectName))}>
          Export Markdown
        </Button>
        <Button variant="primary" onClick={onRerun} disabled={busy}>
          {busy ? "Starting…" : "↻ Re-run"}
        </Button>
      </div>
    </div>
  );
});

export default StepResults;
