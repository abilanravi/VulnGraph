"use client";

import { useActionState, useState } from "react";
import { addRepositoryAction } from "@/lib/actions/repositories";

export function AddRepositoryForm() {
  const [state, formAction, pending] = useActionState(addRepositoryAction, undefined);
  const [mode, setMode] = useState<"github" | "manual">("github");

  return (
    <div className="mx-auto flex w-full max-w-md flex-col gap-6">
      <h1 className="text-xl font-semibold">Add repository</h1>

      <div className="flex gap-2 text-sm">
        <button
          type="button"
          onClick={() => setMode("github")}
          className={`rounded-md px-3 py-1.5 font-medium ${mode === "github" ? "bg-foreground text-background" : "border border-current/20"}`}
        >
          From GitHub
        </button>
        <button
          type="button"
          onClick={() => setMode("manual")}
          className={`rounded-md px-3 py-1.5 font-medium ${mode === "manual" ? "bg-foreground text-background" : "border border-current/20"}`}
        >
          Manual entry
        </button>
      </div>

      <form action={formAction} className="flex flex-col gap-4">
        {mode === "github" ? (
          <div className="flex flex-col gap-1">
            <label htmlFor="url" className="text-sm font-medium">
              GitHub repository URL
            </label>
            <input
              id="url"
              name="url"
              type="url"
              placeholder="https://github.com/acme-corp/webapp"
              required
              className="rounded-md border border-current/20 bg-transparent px-3 py-2"
            />
            <p className="text-xs opacity-60">
              Public repositories only. VulnGraph clones the repository (shallow, temporary) each
              time you run a scan.
            </p>
          </div>
        ) : (
          <>
            <div className="flex flex-col gap-1">
              <label htmlFor="owner" className="text-sm font-medium">
                Owner
              </label>
              <input
                id="owner"
                name="owner"
                type="text"
                placeholder="acme-corp"
                required
                className="rounded-md border border-current/20 bg-transparent px-3 py-2"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label htmlFor="name" className="text-sm font-medium">
                Name
              </label>
              <input
                id="name"
                name="name"
                type="text"
                placeholder="webapp"
                required
                className="rounded-md border border-current/20 bg-transparent px-3 py-2"
              />
            </div>
            <p className="text-xs opacity-60">
              For repositories you&apos;ll scan by supplying a local path at scan time.
            </p>
          </>
        )}
        {state?.error && <p className="text-sm text-red-500">{state.error}</p>}
        <button
          type="submit"
          disabled={pending}
          className="rounded-md bg-foreground px-3 py-2 text-sm font-medium text-background disabled:opacity-50"
        >
          {pending ? "Adding…" : "Add repository"}
        </button>
      </form>
    </div>
  );
}
