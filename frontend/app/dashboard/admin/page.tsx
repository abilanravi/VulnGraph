import { redirect } from "next/navigation";
import { ApiError, getAuditLogs, getCurrentUser, getUsers } from "@/lib/api";
import { UserRowActions } from "./user-row-actions";

export default async function AdminPage() {
  let currentUser;
  try {
    currentUser = await getCurrentUser();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) redirect("/login");
    throw err;
  }

  if (currentUser.role !== "ADMIN") {
    // Mirrors the backend: non-admins get a 403 from every endpoint on this page, so there's
    // nothing useful to render for them here either.
    return (
      <div className="flex flex-col gap-2">
        <h1 className="text-xl font-semibold">Forbidden</h1>
        <p className="opacity-60">This page is only available to administrators.</p>
      </div>
    );
  }

  const [users, auditLogs] = await Promise.all([getUsers(), getAuditLogs()]);

  return (
    <div className="flex flex-col gap-10">
      <div>
        <h1 className="mb-4 text-xl font-semibold">Users</h1>
        <ul className="flex flex-col divide-y divide-current/10 rounded-md border border-current/10">
          {users.map((user) => (
            <li key={user.id} className="flex items-center justify-between gap-3 px-4 py-3">
              <div>
                <p className="text-sm font-medium">{user.email}</p>
                <p className="text-xs opacity-50">
                  {user.role} · {user.is_active ? "active" : "deactivated"}
                </p>
              </div>
              <UserRowActions user={user} isSelf={user.id === currentUser.id} />
            </li>
          ))}
        </ul>
      </div>

      <div>
        <h2 className="mb-4 text-xl font-semibold">Audit log</h2>
        {auditLogs.length === 0 ? (
          <p className="opacity-60">No audit events recorded yet.</p>
        ) : (
          <ul className="flex flex-col divide-y divide-current/10 rounded-md border border-current/10">
            {auditLogs.map((log) => (
              <li key={log.id} className="flex flex-col gap-1 px-4 py-2 text-sm">
                <div className="flex items-center justify-between">
                  <span className="font-mono">{log.action}</span>
                  <span className="text-xs opacity-50">{new Date(log.created_at).toLocaleString()}</span>
                </div>
                <p className="text-xs opacity-50">
                  {log.resource_type ? `${log.resource_type} ${log.resource_id}` : null}
                  {log.ip_address ? ` · ${log.ip_address}` : ""}
                </p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
