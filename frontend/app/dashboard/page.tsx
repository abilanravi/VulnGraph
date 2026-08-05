import Link from "next/link";
import { redirect } from "next/navigation";
import { ApiError, getDashboardSummary, getRepositories, type Severity } from "@/lib/api";

const SEVERITY_STYLES: Record<Severity, string> = {
  LOW: "bg-blue-500/10 text-blue-600 dark:text-blue-400",
  MEDIUM: "bg-yellow-500/10 text-yellow-600 dark:text-yellow-400",
  HIGH: "bg-orange-500/10 text-orange-600 dark:text-orange-400",
  CRITICAL: "bg-red-500/10 text-red-600 dark:text-red-400",
};

export default async function DashboardPage() {
  let summary, repositories;
  try {
    [summary, repositories] = await Promise.all([getDashboardSummary(), getRepositories()]);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) redirect("/login");
    throw err;
  }

  const tiles = [
    { label: "Repositories", value: summary.total_repositories },
    { label: "Open findings", value: summary.total_open_findings },
    { label: "Critical", value: summary.critical_findings },
    { label: "High", value: summary.high_findings },
    { label: "Medium", value: summary.medium_findings },
    { label: "Low", value: summary.low_findings },
  ];

  return (
    <div className="flex flex-col gap-8">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {tiles.map((tile) => (
          <div key={tile.label} className="rounded-md border border-current/10 px-4 py-3">
            <p className="text-2xl font-semibold">{tile.value}</p>
            <p className="text-xs opacity-60">{tile.label}</p>
          </div>
        ))}
      </div>

      <div className="flex flex-col gap-6">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-semibold">Repositories</h1>
          <Link
            href="/dashboard/add-repository"
            className="rounded-md bg-foreground px-3 py-2 text-sm font-medium text-background"
          >
            Add repository
          </Link>
        </div>

        {repositories.length === 0 ? (
          <p className="opacity-60">No repositories yet. Add one to get started.</p>
        ) : (
          <ul className="flex flex-col divide-y divide-current/10 rounded-md border border-current/10">
            {repositories.map((repo) => (
              <li key={repo.id}>
                <Link
                  href={`/dashboard/repositories/${repo.id}`}
                  className="flex items-center justify-between px-4 py-3 hover:bg-current/5"
                >
                  <div>
                    <p className="font-medium">
                      {repo.owner}/{repo.name}
                    </p>
                    {repo.url && <p className="text-sm opacity-60">{repo.url}</p>}
                  </div>
                  <span className="text-sm opacity-60">View →</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="flex flex-col gap-3">
        <h2 className="text-sm font-medium opacity-70">Recent findings</h2>
        {summary.recent_findings.length === 0 ? (
          <p className="opacity-60">No findings yet.</p>
        ) : (
          <ul className="flex flex-col divide-y divide-current/10 rounded-md border border-current/10">
            {summary.recent_findings.map((finding) => (
              <li key={finding.id} className="flex items-center justify-between gap-3 px-4 py-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{finding.title}</p>
                  <p className="text-xs opacity-50">
                    {finding.scanner} · {finding.status} · {new Date(finding.detected_at).toLocaleDateString()}
                  </p>
                </div>
                <span
                  className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ${SEVERITY_STYLES[finding.severity]}`}
                >
                  {finding.severity}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
