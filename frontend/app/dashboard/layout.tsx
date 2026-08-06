import Link from "next/link";
import { logoutAction } from "@/lib/actions/auth";
import { getCurrentUser } from "@/lib/api";

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  // Best-effort: if this fails (e.g. an expired cookie the proxy hasn't caught yet), just
  // render without the role badge rather than crashing the whole dashboard shell — the actual
  // page content underneath still enforces auth itself.
  const currentUser = await getCurrentUser().catch(() => null);

  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex items-center justify-between border-b border-current/10 px-6 py-4">
        <div className="flex items-center gap-4">
          <Link href="/dashboard" className="text-lg font-semibold">
            VulnGraph
          </Link>
          {currentUser?.role === "ADMIN" && (
            <Link href="/dashboard/admin" className="text-sm opacity-70 hover:opacity-100 hover:underline">
              Admin
            </Link>
          )}
        </div>
        <div className="flex items-center gap-3">
          {currentUser && (
            <span className="text-xs opacity-60">
              {currentUser.email} · {currentUser.role}
            </span>
          )}
          <form action={logoutAction}>
            <button type="submit" className="text-sm underline opacity-70 hover:opacity-100">
              Log out
            </button>
          </form>
        </div>
      </header>
      <main className="mx-auto w-full max-w-4xl flex-1 px-6 py-8">{children}</main>
    </div>
  );
}
