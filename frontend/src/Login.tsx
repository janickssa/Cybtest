import { useState, type FormEvent } from "react";
import { api } from "./api";
import { Button, Card, ErrorNote, inputClass } from "./ui";

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(password);
      onLogin();
    } catch {
      setError("Wrong password.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <Card className="w-full max-w-sm">
        <form onSubmit={submit} className="space-y-4">
          <h1 className="text-xl font-semibold">SecTestGen</h1>
          <div className="space-y-1">
            <label htmlFor="password" className="text-sm font-medium">
              Password
            </label>
            <input
              id="password"
              type="password"
              autoFocus
              autoComplete="current-password"
              className={inputClass}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <ErrorNote message={error} />
          <Button type="submit" variant="primary" className="w-full" disabled={busy || !password}>
            {busy ? "Logging in…" : "Log in"}
          </Button>
        </form>
      </Card>
    </main>
  );
}
