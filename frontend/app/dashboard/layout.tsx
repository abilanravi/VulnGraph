import Link from "next/link";
import { logoutAction } from "@/lib/actions/auth";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex items-center justify-between border-b border-current/10 px-6 py-4">
        <Link href="/dashboard" className="text-lg font-semibold">
          VulnGraph
        </Link>
        <form action={logoutAction}>
          <button type="submit" className="text-sm underline opacity-70 hover:opacity-100">
            Log out
          </button>
        </form>
      </header>
      <main className="mx-auto w-full max-w-4xl flex-1 px-6 py-8">{children}</main>
    </div>
  );
}
