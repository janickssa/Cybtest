import { forwardRef, useMemo, useState } from "react";
import { api, type Finding, type FindingView, type RunState, type Severity, type Triage } from "./api";
import { download, formatDate } from "./format";
import { Badge, Button, Card, SeverityDot, inputClass, safeUrl } from "./ui";

interface Props {
  run: RunState;
  onBack: () => void;
  onRerun: () => void;
  onChanged: () => void;
  onError: (e: unknown) => void;
  busy: boolean;
}

const triageLabel: Record<Triage["status"], string> = {
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
};

function countOf(findings: Finding[]) {
  const c = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

function markdown(run: RunState, visible: FindingView[], hidden: number): string {
  const lines = [`# Security findings: ${run.project_name || "Untitled project"}`, "", `Run of ${formatDate(run.created_at)}.`, ""];
  const c = countOf(visible);
  lines.push(`${visible.length} findings: ${c.high} high, ${c.medium} medium, ${c.low} low, ${c.info} info.`);
  if (hidden) lines.push(`${hidden} findings marked as false positive or accepted risk are not listed.`);
  if (run.comparison) {
    lines.push(`Compared with the run of ${formatDate(run.comparison.previous_created_at)}: ${run.comparison.new_count} new, ${run.comparison.fixed.length} fixed.`);
  }
  lines.push("");
  for (const j of run.jobs) {
    if (j.status !== "done") lines.push(`> ⚠️ ${j.title} (${j.tool}) did not complete: ${j.error ?? j.status}`);
  }
  for (const f of visible) {
    lines.push("", `## [${f.severity.toUpperCase()}] ${f.title}${f.is_new ? " (new)" : ""}`, "");
    lines.push(`**Tool:** ${f.tool} (\`${f.rule_id}\`)  `);
    if (f.location) lines.push(`**Location:** \`${f.location}\`  `);
    if (f.message) lines.push("", f.message);
    if (f.snippet) lines.push("", "```", f.snippet, "```");
    if (f.help) lines.push("", `**How to fix:** ${f.help}`);
    if (f.help_url) lines.push("", `More: <${f.help_url}>`);
  }
  if (run.comparison?.fixed.length) {
    lines.push("", "## Fixed since the previous run", "");
    for (const f of run.comparison.fixed) lines.push(`- ${f.title}${f.location ? ` (\`${f.location}\`)` : ""}`);
  }
  return lines.join("\n") + "\n";
}

function FindingRow({ f, onTriage }: { f: FindingView; onTriage: (status: Triage["status"] | null) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <li className={`py-2 ${f.triage ? "opacity-60" : ""}`}>
      <button
        className="flex w-full items-center gap-3 rounded text-left hover:bg-slate-50 dark:hover:bg-slate-800/50"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        <SeverityDot severity={f.severity} />
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-medium">
            {f.title}
            {f.is_new && <Badge className="ml-2 !bg-indigo-100 !text-indigo-800 dark:!bg-indigo-950 dark:!text-indigo-300">NEW</Badge>}
            {f.triage && <Badge className="ml-2">{triageLabel[f.triage.status]}</Badge>}
          </span>
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
          {f.triage?.note && (
            <p>
              <span className="font-medium">{triageLabel[f.triage.status]}:</span> {f.triage.note}
            </p>
          )}
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
            <Badge>{f.rule_id}</Badge>
            {safeUrl(f.help_url) && (
              <a className="text-indigo-600 underline dark:text-indigo-400" href={safeUrl(f.help_url)!} target="_blank" rel="noreferrer noopener">
                More information ↗
              </a>
            )}
            <span className="flex-1" />
            {f.triage ? (
              <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => onTriage(null)}>
                Show in future runs again
              </Button>
            ) : (
              <>
                <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => onTriage("false_positive")}>
                  Mark as false positive
                </Button>
                <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => onTriage("accepted_risk")}>
                  Accept risk
                </Button>
              </>
            )}
          </div>
        </div>
      )}
    </li>
  );
}

const StepResults = forwardRef<HTMLInputElement, Props>(function StepResults(
  { run, onBack, onRerun, onChanged, onError, busy },
  searchRef,
) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [showHidden, setShowHidden] = useState(false);
  const [showFixed, setShowFixed] = useState(false);

  const shown = run.findings.filter((f) => !f.triage);
  const hiddenCount = run.findings.length - shown.length;
  const counts = countOf(shown);
  const incomplete = run.jobs.filter((j) => j.status !== "done");
  const fixed = run.comparison?.fixed ?? [];

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    return run.findings.filter(
      (f) =>
        (showHidden || !f.triage) &&
        (severity === "all" || f.severity === severity) &&
        (!q || [f.title, f.location ?? "", f.tool, f.rule_id].some((s) => s.toLowerCase().includes(q))),
    );
  }, [run.findings, search, severity, showHidden]);

  async function triage(f: FindingView, status: Triage["status"] | null) {
    let note = "";
    if (status) {
      const answer = window.prompt(`${triageLabel[status]}: why? (optional, saved with the decision)`);
      if (answer === null) return;
      note = answer;
    }
    try {
      await api.setTriage(run.project_id, f.fingerprint, status, note);
      onChanged();
    } catch (e) {
      onError(e);
    }
  }

  const slug = (run.project_name || "untitled project").toLowerCase().replace(/[^a-z0-9]/g, "-");

  return (
    <div className="space-y-4">
      <Card className="space-y-4">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <h2 className="font-semibold">{shown.length} findings</h2>
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
        <p className="text-xs text-slate-500">
          {run.project_name || "Untitled project"} · run of {formatDate(run.created_at)}
          {run.comparison ? (
            <>
              {" "}
              · vs run of {formatDate(run.comparison.previous_created_at)}:{" "}
              <span className="font-medium text-slate-700 dark:text-slate-300">
                {run.comparison.new_count} new, {fixed.length} fixed, {run.comparison.unchanged_count} unchanged
              </span>
            </>
          ) : (
            " · first run of this project"
          )}
        </p>
        {incomplete.length > 0 && (
          <div className="rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:bg-amber-950 dark:text-amber-300">
            {incomplete.map((j) => (
              <p key={j.job_id}>
                ⚠️ {j.title} ({j.tool}) didn’t complete{j.error ? `: ${j.error}` : ""}. Its findings are missing.
              </p>
            ))}
          </div>
        )}
        {shown.length === 0 && incomplete.length === 0 && (
          <p className="text-sm text-green-700 dark:text-green-400">✅ No open findings. Nice work.</p>
        )}
        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
          {visible.map((f) => (
            <FindingRow key={f.fingerprint} f={f} onTriage={(status) => triage(f, status)} />
          ))}
        </ul>
        {shown.length > 0 && visible.length === 0 && <p className="text-sm text-slate-500">No findings match the filter.</p>}
        <div className="flex flex-wrap gap-2">
          {hiddenCount > 0 && (
            <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => setShowHidden(!showHidden)}>
              {showHidden ? "Hide" : "Show"} {hiddenCount} false positive / accepted risk
            </Button>
          )}
          {fixed.length > 0 && (
            <Button variant="ghost" className="!px-2 !py-1 !text-xs" aria-expanded={showFixed} onClick={() => setShowFixed(!showFixed)}>
              {showFixed ? "Hide" : "Show"} {fixed.length} fixed since last run
            </Button>
          )}
        </div>
        {showFixed && (
          <ul className="space-y-1 rounded-lg bg-green-50 p-3 text-sm dark:bg-green-950">
            {fixed.map((f) => (
              <li key={`${f.tool}|${f.rule_id}|${f.location}`} className="flex items-center gap-2">
                <span aria-hidden>✅</span>
                <span className="flex-1">
                  {f.title} {f.location && <code className="text-xs text-slate-500">{f.location}</code>}
                </span>
                <Badge>{f.tool}</Badge>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <div className="flex flex-wrap items-center gap-3">
        <Button onClick={onBack}>← Back to plan</Button>
        <span className="flex-1" />
        <Button onClick={() => download(`${slug}-findings.json`, new Blob([JSON.stringify(run.findings, null, 2)], { type: "application/json" }))}>
          JSON
        </Button>
        <Button onClick={() => download(`${slug}-findings.md`, new Blob([markdown(run, shown, hiddenCount)], { type: "text/markdown" }))}>
          Markdown
        </Button>
        <Button onClick={() => api.sarif(run.run_id).then((b) => download(`${slug}.sarif`, b), onError)}>SARIF</Button>
        <Button variant="primary" onClick={onRerun} disabled={busy}>
          {busy ? "Starting…" : "↻ Re-run"}
        </Button>
      </div>
    </div>
  );
});

export default StepResults;
