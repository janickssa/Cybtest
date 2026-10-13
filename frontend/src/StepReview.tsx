import { forwardRef, useMemo, useState } from "react";
import type { PlanItem, Severity } from "./api";
import { Badge, Button, Card, SeverityDot, inputClass } from "./ui";

interface Props {
  plan: PlanItem[];
  selected: Set<string>;
  setSelected: (s: Set<string>) => void;
  url: string;
  hasSource: boolean;
  onBack: () => void;
  onExport: () => void;
  onRun: () => void;
  canRun: boolean;
  busy: boolean;
}

const StepReview = forwardRef<HTMLInputElement, Props>(function StepReview(
  { plan, selected, setSelected, url, hasSource, onBack, onExport, onRun, canRun, busy },
  searchRef,
) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [open, setOpen] = useState<Set<string>>(new Set());

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    return plan.filter(
      (i) =>
        (severity === "all" || i.severity === severity) &&
        (!q ||
          i.title.toLowerCase().includes(q) ||
          i.actions.some((a) => a.tool.toLowerCase().includes(q)) ||
          i.references.some((r) => r.toLowerCase().includes(q))),
    );
  }, [plan, search, severity]);

  const host = (() => {
    try {
      return new URL(url).hostname;
    } catch {
      return "";
    }
  })();

  function toggle(item: PlanItem) {
    const next = new Set(selected);
    if (next.has(item.rule_id)) {
      next.delete(item.rule_id);
    } else {
      if (item.active) {
        const answer = window.prompt(
          `“${item.title}” is an ACTIVE test: it sends attack payloads to the target.\n\nType the hostname${host ? ` (${host})` : ""} to confirm.`,
        );
        if (answer === null || answer.trim() !== host) return;
      }
      next.add(item.rule_id);
    }
    setSelected(next);
  }

  function toggleOpen(id: string) {
    const next = new Set(open);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setOpen(next);
  }

  const chosen = plan.filter((i) => selected.has(i.rule_id));
  const minutes = chosen.flatMap((i) => i.actions).reduce((sum, a) => sum + a.est_minutes, 0);
  const runnable = chosen.filter((i) => hasSource && i.actions.some((a) => a.input === "source" && a.mode === "passive"));
  const automated = visible.filter((i) => i.actions.length > 0);
  const manual = visible.filter((i) => i.actions.length === 0);

  function missingInput(item: PlanItem): string | null {
    if (item.actions.some((a) => a.input === "url") && !url) return "Needs a target URL";
    if (item.actions.some((a) => a.input === "source") && !hasSource) return "Needs source code";
    return null;
  }

  function row(item: PlanItem) {
    const isOpen = open.has(item.rule_id);
    const tools = [...new Set(item.actions.map((a) => a.tool))];
    const inputs = [...new Set(item.actions.map((a) => (a.input === "url" ? "URL" : "Code")))];
    const est = item.actions.reduce((s, a) => s + a.est_minutes, 0);
    const missing = missingInput(item);
    return (
      <li key={item.rule_id} className="py-2">
        <div className="flex items-center gap-3">
          <input
            type="checkbox"
            id={`sel-${item.rule_id}`}
            className="h-4 w-4 accent-indigo-600"
            checked={selected.has(item.rule_id)}
            onChange={() => toggle(item)}
          />
          <SeverityDot severity={item.severity} />
          <label htmlFor={`sel-${item.rule_id}`} className="min-w-0 flex-1 cursor-pointer text-sm font-medium">
            {item.title}
            {item.active && <Badge className="ml-2 !bg-amber-100 !text-amber-800 dark:!bg-amber-950 dark:!text-amber-300">⚡ ACTIVE</Badge>}
          </label>
          <div className="hidden items-center gap-1.5 sm:flex">
            {tools.map((t) => (
              <Badge key={t}>{t}</Badge>
            ))}
            {inputs.map((i) => (
              <Badge key={i}>{i}</Badge>
            ))}
            {est > 0 && <span className="w-14 text-right text-xs text-slate-500">~{est} min</span>}
          </div>
          <button
            className="rounded px-2 py-1 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800"
            aria-expanded={isOpen}
            aria-label={`${isOpen ? "Hide" : "Show"} details for ${item.title}`}
            onClick={() => toggleOpen(item.rule_id)}
          >
            {isOpen ? "▾" : "▸"}
          </button>
        </div>
        {isOpen && (
          <div className="mt-3 space-y-3 rounded-lg bg-slate-50 p-4 text-sm dark:bg-slate-950">
            <p>
              <span className="font-medium">Why:</span> {item.why.join(", ")}
            </p>
            <p className="text-slate-700 dark:text-slate-300">{item.description}</p>
            {item.expected_secure_behavior && (
              <p>
                <span className="font-medium">Expected secure behavior:</span> {item.expected_secure_behavior}
              </p>
            )}
            {missing && <p className="text-amber-700 dark:text-amber-400">⚠ {missing} to run this automatically.</p>}
            {item.actions.map((a) => (
              <div key={a.id} className="space-y-1">
                <p className="font-medium">
                  {a.title} <span className="font-normal text-slate-500">· {a.mode} · ~{a.est_minutes} min</span>
                </p>
                <pre className="overflow-x-auto rounded-md bg-slate-900 p-3 text-xs text-slate-100">
                  <code>{a.command}</code>
                </pre>
              </div>
            ))}
            {item.references.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {item.references.map((r) => (
                  <Badge key={r}>{r}</Badge>
                ))}
              </div>
            )}
          </div>
        )}
      </li>
    );
  }

  return (
    <div className="space-y-4">
      <Card className="space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="flex-1 font-semibold">{plan.length} tests suggested</h2>
          <select
            aria-label="Filter by priority"
            className={`${inputClass} !w-auto`}
            value={severity}
            onChange={(e) => setSeverity(e.target.value as Severity | "all")}
          >
            <option value="all">All priorities</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <input
            ref={searchRef}
            aria-label="Search tests"
            placeholder="🔍 Search  ( / )"
            className={`${inputClass} !w-48`}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {automated.length > 0 && (
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Automated tests</h3>
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">{automated.map(row)}</ul>
          </section>
        )}
        {manual.length > 0 && (
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Manual tests</h3>
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">{manual.map(row)}</ul>
          </section>
        )}
        {visible.length === 0 && <p className="text-sm text-slate-500">No tests match the filter.</p>}
      </Card>

      <div className="sticky bottom-0 -mx-4 border-t border-slate-200 bg-slate-50/95 px-4 py-3 backdrop-blur dark:border-slate-800 dark:bg-slate-950/95">
        <div className="flex flex-wrap items-center gap-3">
          <Button onClick={onBack}>← Back</Button>
          <span className="flex-1 text-sm text-slate-600 dark:text-slate-400">
            {chosen.length} selected{minutes > 0 && ` · ~${minutes} min automated`}
          </span>
          <Button disabled={chosen.length === 0 || busy} onClick={onExport}>
            Export plan
          </Button>
          {canRun && (
            <Button variant="primary" disabled={runnable.length === 0 || busy} onClick={onRun}>
              {busy ? "Starting…" : `Approve & run ${runnable.length} →`}
            </Button>
          )}
        </div>
        <p className="mt-1 text-xs text-slate-500">
          {hasSource
            ? "Code tests run on the isolated runner. URL and manual tests are included in the exported plan; running URL tests arrives in a later version."
            : "Upload the project in step 1 to run code tests here. Otherwise, export the plan and run the commands yourself."}
        </p>
      </div>
    </div>
  );
});

export default StepReview;
