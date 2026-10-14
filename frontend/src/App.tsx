import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, type DetectedTag, type PlanItem, type RunState, type ScopeStatus, type Upload } from "./api";
import Login from "./Login";
import StepResults from "./StepResults";
import StepReview from "./StepReview";
import StepRun from "./StepRun";
import StepTarget, { type Target } from "./StepTarget";
import { Button, ErrorNote } from "./ui";

const STEPS = ["Add target", "Review & approve", "Run", "Results"];

function Stepper({ step }: { step: number }) {
  return (
    <ol className="flex flex-wrap items-center gap-2 text-sm">
      {STEPS.map((label, i) => {
        const n = i + 1;
        const state = n === step ? "current" : n < step ? "done" : "todo";
        return (
          <li key={label} className="flex items-center gap-2" aria-current={state === "current" ? "step" : undefined}>
            {i > 0 && <span className="text-slate-300 dark:text-slate-700">──▶</span>}
            <span
              className={
                state === "current"
                  ? "font-semibold text-indigo-600 dark:text-indigo-400"
                  : state === "done"
                    ? "text-slate-700 dark:text-slate-300"
                    : "text-slate-400 dark:text-slate-600"
              }
            >
              {"①②③④"[i]} {label}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

export default function App() {
  const [auth, setAuth] = useState<"checking" | "out" | "in">("checking");
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  const [target, setTarget] = useState<Target>({ name: "", url: "", description: "", rps: 10 });
  const [scope, setScope] = useState<ScopeStatus | null>(null);
  const [tags, setTags] = useState<DetectedTag[] | null>(null);
  const [upload, setUpload] = useState<(Upload & { name: string }) | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [run, setRun] = useState<RunState | null>(null);
  const [plan, setPlan] = useState<PlanItem[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    api.me().then(
      () => setAuth("in"),
      () => setAuth("out"),
    );
  }, []);

  const onError = useCallback((e: unknown) => {
    if (e instanceof ApiError && e.status === 401) setAuth("out");
    else setError(e instanceof Error ? e.message : String(e));
  }, []);

  const buildPlan = useCallback(async () => {
    if (!tags || tags.length === 0) return;
    setBusy(true);
    setError(null);
    try {
      const items = await api.plan(
        tags.map((t) => t.id),
        target.url,
      );
      setPlan(items);
      setSelected(new Set(items.filter((i) => i.preselected).map((i) => i.rule_id)));
      setStep(2);
      window.scrollTo(0, 0);
    } catch (e) {
      onError(e);
    } finally {
      setBusy(false);
    }
  }, [tags, target.url, onError]);

  const exportPlan = useCallback(async () => {
    if (!tags || selected.size === 0) return;
    setBusy(true);
    setError(null);
    try {
      const blob = await api.exportMarkdown({
        project_name: target.name,
        url: target.url,
        description: target.description,
        tags: tags.map((t) => t.id),
        selected: [...selected],
      });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      const slug = (target.name || "untitled project").toLowerCase().replace(/[^a-z0-9]/g, "-");
      link.download = `${slug}-test-plan.md`;
      link.click();
      URL.revokeObjectURL(link.href);
    } catch (e) {
      onError(e);
    } finally {
      setBusy(false);
    }
  }, [tags, selected, target, onError]);

  const startRun = useCallback(async () => {
    const urlAllowed = scope?.allowed === true && target.url.trim() !== "";
    if (!tags || (!upload && !urlAllowed) || selected.size === 0) return;
    const hasActive = plan.some((i) => i.active && selected.has(i.rule_id));
    let host: string | null = null;
    try {
      host = target.url ? new URL(target.url).hostname : null;
    } catch {
      host = null;
    }
    setBusy(true);
    setError(null);
    try {
      const { run_id } = await api.startRun({
        workspace_id: upload?.workspace_id ?? null,
        url: target.url,
        tags: tags.map((t) => t.id),
        selected: [...selected],
        rate_limit_rps: target.rps,
        // Active tests were confirmed by typing the hostname when they were selected.
        confirm_host: hasActive ? host : null,
      });
      setRun(null);
      setRunId(run_id);
      setStep(3);
      window.scrollTo(0, 0);
    } catch (e) {
      onError(e);
    } finally {
      setBusy(false);
    }
  }, [tags, upload, selected, target.url, target.rps, scope, plan, onError]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        if (step === 1) buildPlan();
        else if (step === 2) (upload || scope?.allowed ? startRun : exportPlan)();
        else if (step === 3 && run?.finished) setStep(4);
      } else if (e.key === "/" && (step === 2 || step === 4) && !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement)) {
        e.preventDefault();
        searchRef.current?.focus();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [step, buildPlan, exportPlan, startRun, upload, scope, run?.finished]);

  if (auth === "checking") return null;
  if (auth === "out") return <Login onLogin={() => setAuth("in")} />;

  async function logout() {
    await api.logout().catch(() => {});
    setAuth("out");
  }

  return (
    <div className="mx-auto max-w-4xl px-4 pb-8">
      <header className="flex items-center justify-between py-5">
        <h1 className="text-lg font-semibold">SecTestGen</h1>
        <Button variant="ghost" onClick={logout}>
          Log out
        </Button>
      </header>
      <p className="mb-4 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:bg-amber-950 dark:text-amber-300">
        ⚠️ Only test systems you own or have explicit written permission to test.
      </p>
      <nav aria-label="Progress" className="mb-6">
        <Stepper step={step} />
      </nav>
      {step === 1 ? (
        <StepTarget
          target={target}
          setTarget={setTarget}
          tags={tags}
          setTags={setTags}
          upload={upload}
          setUpload={setUpload}
          scope={scope}
          setScope={setScope}
          onContinue={buildPlan}
          busy={busy}
          error={error}
          onError={onError}
        />
      ) : step === 2 ? (
        <>
          <ErrorNote message={error} />
          <StepReview
            ref={searchRef}
            plan={plan}
            selected={selected}
            setSelected={setSelected}
            url={target.url}
            hasSource={upload !== null}
            rps={target.rps}
            urlAllowed={scope?.allowed === true}
            canRun={upload !== null || scope?.allowed === true}
            onRun={startRun}
            onBack={() => {
              setError(null);
              setStep(1);
            }}
            onExport={exportPlan}
            busy={busy}
          />
        </>
      ) : step === 3 && runId ? (
        <StepRun runId={runId} run={run} setRun={setRun} onResults={() => setStep(4)} onError={onError} />
      ) : run ? (
        <>
          <ErrorNote message={error} />
          <StepResults
            ref={searchRef}
            run={run}
            projectName={target.name}
            onBack={() => setStep(2)}
            onRerun={startRun}
            busy={busy}
          />
        </>
      ) : null}
    </div>
  );
}
