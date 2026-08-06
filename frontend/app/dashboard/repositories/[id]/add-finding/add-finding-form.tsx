"use client";

import { useActionState } from "react";
import { addFindingAction } from "@/lib/actions/findings";

export function AddFindingForm({ repositoryId }: { repositoryId: string }) {
  const [state, formAction, pending] = useActionState(addFindingAction.bind(null, repositoryId), undefined);

  return (
    <div className="mx-auto flex w-full max-w-md flex-col gap-6">
      <h1 className="text-xl font-semibold">Add finding</h1>
      <form action={formAction} className="flex flex-col gap-4">
        <div className="flex flex-col gap-1">
          <label htmlFor="cve" className="text-sm font-medium">
            CVE
          </label>
          <input
            id="cve"
            name="cve"
            type="text"
            placeholder="CVE-2024-12345"
            required
            className="rounded-md border border-current/20 bg-transparent px-3 py-2 font-mono"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="severity" className="text-sm font-medium">
            Severity
          </label>
          <select
            id="severity"
            name="severity"
            required
            defaultValue="HIGH"
            className="rounded-md border border-current/20 bg-transparent px-3 py-2"
          >
            <option value="LOW">Low</option>
            <option value="MEDIUM">Medium</option>
            <option value="HIGH">High</option>
            <option value="CRITICAL">Critical</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="description" className="text-sm font-medium">
            Description
          </label>
          <textarea
            id="description"
            name="description"
            rows={4}
            required
            className="rounded-md border border-current/20 bg-transparent px-3 py-2"
          />
        </div>
        {state?.error && <p className="text-sm text-red-500">{state.error}</p>}
        <button
          type="submit"
          disabled={pending}
          className="rounded-md bg-foreground px-3 py-2 text-sm font-medium text-background disabled:opacity-50"
        >
          {pending ? "Adding…" : "Add finding"}
        </button>
      </form>
    </div>
  );
}
