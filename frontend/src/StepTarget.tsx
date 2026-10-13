import { useEffect, useMemo, useState } from "react";
import { api, type DetectedTag, type TagDef, type Upload } from "./api";
import { Button, Card, ErrorNote, inputClass } from "./ui";

export interface Target {
  name: string;
  url: string;
  description: string;
}

export const MANUAL_EVIDENCE = "Added by you";

interface Props {
  target: Target;
  setTarget: (t: Target) => void;
  tags: DetectedTag[] | null;
  setTags: (t: DetectedTag[] | null) => void;
  upload: (Upload & { name: string }) | null;
  setUpload: (u: (Upload & { name: string }) | null) => void;
  onContinue: () => void;
  busy: boolean;
  error: string | null;
  onError: (e: unknown) => void;
}

function formatSize(bytes: number) {
  return bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} kB`;
}

export default function StepTarget({ target, setTarget, tags, setTags, upload, setUpload, onContinue, busy, error, onError }: Props) {
  const [vocabulary, setVocabulary] = useState<TagDef[]>([]);
  const [analyzing, setAnalyzing] = useState(false);
  const [picking, setPicking] = useState(false);
  const [search, setSearch] = useState("");
  const [uploading, setUploading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  useEffect(() => {
    api.tags().then(setVocabulary, onError);
  }, [onError]);

  const hasInput = target.url.trim() !== "" || target.description.trim() !== "";

  async function uploadFile(file: File) {
    if (!file.name.toLowerCase().endsWith(".zip")) {
      setUploadError("Choose a .zip file.");
      return;
    }
    setUploading(true);
    setUploadError(null);
    try {
      const result = await api.upload(file);
      setUpload({ ...result, name: file.name });
      const current = tags ?? [];
      setTags([...current, ...result.tags.filter((t) => !current.some((c) => c.id === t.id))]);
    } catch (e) {
      if (e instanceof Error && !("status" in e && e.status === 401)) setUploadError(e.message);
      else onError(e);
    } finally {
      setUploading(false);
    }
  }

  async function analyze() {
    setAnalyzing(true);
    try {
      const detected = await api.analyze(target.description, target.url);
      const manual = (tags ?? []).filter(
        (t) => t.evidence === MANUAL_EVIDENCE && !detected.some((d) => d.id === t.id),
      );
      setTags([...detected, ...manual]);
    } catch (e) {
      onError(e);
    } finally {
      setAnalyzing(false);
    }
  }

  function addTag(id: string, label: string) {
    if (!tags?.some((t) => t.id === id)) {
      setTags([...(tags ?? []), { id, label, evidence: MANUAL_EVIDENCE }]);
    }
    setSearch("");
  }

  const grouped = useMemo(() => {
    const q = search.trim().toLowerCase();
    const groups = new Map<string, TagDef[]>();
    for (const t of vocabulary) {
      if (tags?.some((x) => x.id === t.id)) continue;
      if (q && !t.label.toLowerCase().includes(q) && !t.id.includes(q)) continue;
      groups.set(t.category, [...(groups.get(t.category) ?? []), t]);
    }
    return groups;
  }, [vocabulary, tags, search]);

  const customTag = search.trim().toLowerCase();
  const canAddCustom =
    /^[a-z0-9]+:[a-z0-9._-]+$/.test(customTag) && !vocabulary.some((t) => t.id === customTag);

  return (
    <div className="space-y-6">
      <Card className="space-y-5">
        <div className="space-y-1">
          <label htmlFor="name" className="text-sm font-medium">
            Project name
          </label>
          <input
            id="name"
            className={inputClass}
            placeholder="Webshop API"
            value={target.name}
            onChange={(e) => setTarget({ ...target, name: e.target.value })}
          />
        </div>

        <div className="space-y-2">
          <span className="text-sm font-medium">📦 Upload project <span className="font-normal text-slate-500">(optional)</span></span>
          {upload ? (
            <div className="flex items-center gap-3 rounded-lg bg-green-50 px-4 py-3 text-sm dark:bg-green-950">
              <span className="flex-1">
                ✅ {upload.name} ({formatSize(upload.total_bytes)}, {upload.file_count.toLocaleString("da-DK")} files)
              </span>
              <Button variant="ghost" className="!py-1" onClick={() => setUpload(null)}>
                Remove
              </Button>
            </div>
          ) : (
            <label
              onDragOver={(e) => {
                e.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragging(false);
                const file = e.dataTransfer.files[0];
                if (file) uploadFile(file);
              }}
              className={`flex cursor-pointer flex-col items-center rounded-lg border-2 border-dashed px-4 py-6 text-center text-sm transition focus-within:outline-2 focus-within:outline-indigo-500 ${
                dragging ? "border-indigo-500 bg-indigo-50 dark:bg-indigo-950" : "border-slate-300 dark:border-slate-700"
              }`}
            >
              <input
                type="file"
                accept=".zip,application/zip"
                className="sr-only"
                disabled={uploading}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) uploadFile(file);
                  e.target.value = "";
                }}
              />
              {uploading ? (
                <span>Uploading and analyzing…</span>
              ) : (
                <>
                  <span>Drop project.zip here or click to browse</span>
                  <span className="text-xs text-slate-500">The code is analyzed and scanned, never built or run.</span>
                </>
              )}
            </label>
          )}
          <ErrorNote message={uploadError} />
        </div>

        <div className="space-y-1">
          <label htmlFor="url" className="text-sm font-medium">
            🌐 Target URL <span className="font-normal text-slate-500">(optional)</span>
          </label>
          <input
            id="url"
            type="url"
            className={inputClass}
            placeholder="https://internaltest.example.dk"
            value={target.url}
            onChange={(e) => setTarget({ ...target, url: e.target.value })}
          />
          <p className="text-xs text-slate-500">Nothing is sent to this URL in this version.</p>
        </div>

        <div className="space-y-1">
          <label htmlFor="description" className="text-sm font-medium">
            ✏️ Describe the project
          </label>
          <textarea
            id="description"
            rows={4}
            className={inputClass}
            placeholder="Rust Axum API with PostgreSQL via sqlx, JWT login, React frontend, runs in Docker behind nginx."
            value={target.description}
            onChange={(e) => setTarget({ ...target, description: e.target.value })}
          />
        </div>

        {tags === null && (
          <div className="flex justify-end">
            <Button variant="primary" disabled={!hasInput || analyzing || uploading} onClick={analyze}>
              {analyzing ? "Analyzing…" : "Analyze →"}
            </Button>
          </div>
        )}
      </Card>

      {tags !== null && (
        <Card className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold">Detected stack</h2>
            <Button variant="ghost" onClick={analyze} disabled={analyzing}>
              {analyzing ? "Analyzing…" : "↻ Re-analyze"}
            </Button>
          </div>
          {tags.length === 0 && (
            <p className="text-sm text-slate-500">Nothing detected yet. Add tags that describe the project.</p>
          )}
          <ul className="flex flex-wrap gap-2">
            {tags.map((t) => (
              <li
                key={t.id}
                className="inline-flex items-center gap-1 rounded-full bg-indigo-50 py-1 pl-3 pr-1 text-sm text-indigo-800 dark:bg-indigo-950 dark:text-indigo-200"
              >
                {t.label}
                <button
                  className="rounded-full px-1.5 hover:bg-indigo-200 dark:hover:bg-indigo-800"
                  aria-label={`Remove ${t.label}`}
                  onClick={() => setTags(tags.filter((x) => x.id !== t.id))}
                >
                  ✕
                </button>
              </li>
            ))}
            <li>
              <Button variant="ghost" className="!py-1" aria-expanded={picking} onClick={() => setPicking(!picking)}>
                + Add tag
              </Button>
            </li>
          </ul>

          {picking && (
            <div className="space-y-3 rounded-lg border border-slate-200 p-3 dark:border-slate-800">
              <input
                className={inputClass}
                placeholder="Search tags, or type a custom one like lib:diesel"
                aria-label="Search tags"
                value={search}
                autoFocus
                onChange={(e) => setSearch(e.target.value)}
              />
              {canAddCustom && (
                <Button variant="ghost" onClick={() => addTag(customTag, customTag)}>
                  + Add custom tag “{customTag}”
                </Button>
              )}
              <div className="max-h-72 space-y-3 overflow-y-auto">
                {[...grouped].map(([category, defs]) => (
                  <div key={category}>
                    <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">{category}</h3>
                    <div className="flex flex-wrap gap-1.5">
                      {defs.map((d) => (
                        <button
                          key={d.id}
                          className="rounded-full border border-slate-300 px-2.5 py-0.5 text-sm hover:border-indigo-500 hover:text-indigo-600 dark:border-slate-700"
                          onClick={() => addTag(d.id, d.label)}
                        >
                          {d.label}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {tags.length > 0 && (
            <details className="text-sm">
              <summary className="cursor-pointer text-slate-600 dark:text-slate-400">Why?</summary>
              <ul className="mt-2 space-y-1 pl-4">
                {tags.map((t) => (
                  <li key={t.id}>
                    <span className="font-medium">{t.label}</span>{" "}
                    <span className="text-slate-500">→ {t.evidence}</span>
                  </li>
                ))}
              </ul>
            </details>
          )}

          <ErrorNote message={error} />
          <div className="flex justify-end">
            <Button variant="primary" disabled={tags.length === 0 || busy} onClick={onContinue}>
              {busy ? "Building plan…" : "Continue → review plan"}
            </Button>
          </div>
        </Card>
      )}
      {tags === null && <ErrorNote message={error} />}
    </div>
  );
}
