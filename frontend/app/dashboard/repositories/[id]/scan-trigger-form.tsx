"use client";

import { useActionState } from "react";
import { triggerOsvScanAction, triggerSemgrepScanAction, type TriggerScanState } from "@/lib/actions/scans";

export function ScanTriggerForm({
  repositoryId,
  scanner,
}: {
  repositoryId: string;
  scanner: "semgrep" | "osv";
}) {
  const action = scanner === "semgrep" ? triggerSemgrepScanAction : triggerOsvScanAction;
  const [state, formAction, pending] = useActionState<TriggerScanState, FormData>(
    action.bind(null, repositoryId),
    undefined,
  );

  return (
    <form action={formAction} className="flex flex-col gap-2 rounded-md border border-current/10 p-3">
      <p className="text-sm font-medium">{scanner === "semgrep" ? "Semgrep (SAST)" : "OSV Scanner (SCA)"}</p>
      <div className="flex gap-2">
        <input
          name="path"
          type="text"
          placeholder="Local path to scan, e.g. C:\\code\\webapp"
          required
          className="flex-1 rounded-md border border-current/20 bg-transparent px-2 py-1.5 text-sm"
        />
        <button
          type="submit"
          disabled={pending}
          className="rounded-md bg-foreground px-3 py-1.5 text-sm font-medium text-background disabled:opacity-50"
        >
          {pending ? "Scanning…" : "Run scan"}
        </button>
      </div>
      {state?.error && <p className="text-sm text-red-500">{state.error}</p>}
      {state?.success && <p className="text-sm text-green-600 dark:text-green-400">{state.success}</p>}
    </form>
  );
}
