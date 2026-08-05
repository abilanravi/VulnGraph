"use client";

import { useActionState } from "react";
import { addRepositoryAction } from "@/lib/actions/repositories";

export default function AddRepositoryPage() {
  const [state, formAction, pending] = useActionState(addRepositoryAction, undefined);

  return (
    <div className="mx-auto flex w-full max-w-md flex-col gap-6">
      <h1 className="text-xl font-semibold">Add repository</h1>
      <form action={formAction} className="flex flex-col gap-4">
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
        <div className="flex flex-col gap-1">
          <label htmlFor="url" className="text-sm font-medium">
            URL <span className="opacity-60">(optional)</span>
          </label>
          <input
            id="url"
            name="url"
            type="url"
            placeholder="https://github.com/acme-corp/webapp"
            className="rounded-md border border-current/20 bg-transparent px-3 py-2"
          />
        </div>
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
