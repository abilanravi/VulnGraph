"use client";

import { useActionState } from "react";
import { updateUserActiveAction, updateUserRoleAction } from "@/lib/actions/users";
import type { CurrentUser, UserRole } from "@/lib/api";

const ROLES: UserRole[] = ["ADMIN", "DEVELOPER", "VIEWER"];

export function UserRowActions({ user, isSelf }: { user: CurrentUser; isSelf: boolean }) {
  const [roleState, roleAction, rolePending] = useActionState(
    async (_prev: { error?: string } | undefined, formData: FormData) =>
      updateUserRoleAction(user.id, formData.get("role") as UserRole),
    undefined,
  );
  const [activeState, activeAction, activePending] = useActionState(
    async () => updateUserActiveAction(user.id, !user.is_active),
    undefined,
  );

  if (isSelf) {
    return <span className="text-xs opacity-50">(you)</span>;
  }

  return (
    <div className="flex items-center gap-2">
      <form action={roleAction} className="flex items-center gap-1">
        <select
          name="role"
          defaultValue={user.role}
          className="rounded-md border border-current/20 bg-transparent px-2 py-1 text-xs"
        >
          {ROLES.map((role) => (
            <option key={role} value={role}>
              {role}
            </option>
          ))}
        </select>
        <button
          type="submit"
          disabled={rolePending}
          className="rounded-md border border-current/20 px-2 py-1 text-xs disabled:opacity-50"
        >
          Save
        </button>
      </form>
      <form action={activeAction}>
        <button
          type="submit"
          disabled={activePending}
          className="rounded-md border border-current/20 px-2 py-1 text-xs disabled:opacity-50"
        >
          {user.is_active ? "Deactivate" : "Reactivate"}
        </button>
      </form>
      {(roleState?.error || activeState?.error) && (
        <span className="text-xs text-red-500">{roleState?.error ?? activeState?.error}</span>
      )}
    </div>
  );
}
