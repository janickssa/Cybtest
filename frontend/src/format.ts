import type { Counts } from "./api";

export function formatDate(unixSecs: number): string {
  return new Date(unixSecs * 1000).toLocaleString("da-DK", { dateStyle: "short", timeStyle: "short" });
}

export function countsText(c: Counts | null): string {
  if (!c) return "not finished";
  const total = c.high + c.medium + c.low + c.info;
  return total === 0 ? "no findings" : `🔴 ${c.high}  🟠 ${c.medium}  🟡 ${c.low + c.info}`;
}

export function download(name: string, blob: Blob) {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = name;
  link.click();
  URL.revokeObjectURL(link.href);
}
