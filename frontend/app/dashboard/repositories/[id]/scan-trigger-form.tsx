"use client";

import { useActionState } from "react";
import { runFullScanAction, type TriggerScanState } from "@/lib/actions/scans";
import type { RepositorySource } from "@/lib/api";

export function ScanTriggerForm({
  repositoryId,
  source,
}: {
  repositoryId: string;
  source: RepositorySource;
}) {
  const requiresPath = source !== "GITHUB";
  const [state, formAction, pending] = useActionState<TriggerScanState, FormData>(
    runFullScanAction.bind(null, repositoryId, requiresPath),
    undefined,
  );

  return (
    <form action={formAction} className="flex flex-col gap-2 rounded-md border border-current/10 p-3">
      <p className="text-sm font-medium">Run Semgrep (SAST) + OSV Scanner (SCA)</p>
      <div className="flex gap-2">
        {requiresPath ? (
          <input
            name="path"
            type="text"
            placeholder="Local path to scan, e.g. C:\\code\\webapp"
            required
            className="flex-1 rounded-md border border-current/20 bg-transparent px-2 py-1.5 text-sm"
          />
        ) : (
          <p className="flex-1 self-center text-sm opacity-60">
            VulnGraph will clone this repository from GitHub for the scan.
          </p>
        )}
        <button
          type="submit"
          disabled={pending}
          className="rounded-md bg-foreground px-3 py-1.5 text-sm font-medium text-background disabled:opacity-50"
        >
          {pending ? "Scanning…" : "Run Scan"}
        </button>
      </div>
      {state?.error && <p className="text-sm text-red-500">{state.error}</p>}
      {state?.success && <p className="text-sm text-green-600 dark:text-green-400">{state.success}</p>}
    </form>
  );
}
