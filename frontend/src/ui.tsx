import type { ButtonHTMLAttributes, ReactNode } from "react";
import type { Severity } from "./api";

export function Button({
  variant = "secondary",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" }) {
  const styles = {
    primary:
      "bg-indigo-600 text-white hover:bg-indigo-500 disabled:bg-indigo-300 dark:disabled:bg-indigo-900",
    secondary:
      "border border-slate-300 bg-white hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900 dark:hover:bg-slate-800",
    ghost: "text-slate-600 hover:bg-slate-200 dark:text-slate-300 dark:hover:bg-slate-800",
  }[variant];
  return (
    <button
      className={`rounded-lg px-4 py-2 text-sm font-medium transition focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:cursor-not-allowed ${styles} ${className}`}
      {...props}
    />
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={`rounded-xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900 ${className}`}
    >
      {children}
    </div>
  );
}

export function Badge({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-md bg-slate-100 px-1.5 py-0.5 text-xs font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-300 ${className}`}
    >
      {children}
    </span>
  );
}

const severityStyle: Record<Severity, { dot: string; label: string }> = {
  high: { dot: "bg-red-500", label: "High" },
  medium: { dot: "bg-orange-400", label: "Medium" },
  low: { dot: "bg-yellow-400", label: "Low" },
  info: { dot: "bg-slate-400", label: "Info" },
};

export function SeverityDot({ severity }: { severity: Severity }) {
  const s = severityStyle[severity];
  return (
    <span className="inline-flex items-center" title={`${s.label} priority`}>
      <span className={`h-2.5 w-2.5 rounded-full ${s.dot}`} aria-hidden />
      <span className="sr-only">{s.label} priority</span>
    </span>
  );
}

export const inputClass =
  "w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm placeholder:text-slate-400 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 dark:border-slate-700 dark:bg-slate-950";

export function ErrorNote({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <p role="alert" className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-950 dark:text-red-300">
      {message}
    </p>
  );
}
