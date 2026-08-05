import Link from "next/link";
import { redirect } from "next/navigation";
import { ApiError, getFindings, getRepository, type Severity } from "@/lib/api";

const SEVERITY_STYLES: Record<Severity, string> = {
  LOW: "bg-blue-500/10 text-blue-600 dark:text-blue-400",
  MEDIUM: "bg-yellow-500/10 text-yellow-600 dark:text-yellow-400",
  HIGH: "bg-orange-500/10 text-orange-600 dark:text-orange-400",
  CRITICAL: "bg-red-500/10 text-red-600 dark:text-red-400",
};

export default async function RepositoryDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  let repository, findings;
  try {
    [repository, findings] = await Promise.all([getRepository(id), getFindings(id)]);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) redirect("/login");
    if (err instanceof ApiError && err.status === 404) redirect("/dashboard");
    throw err;
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <Link href="/dashboard" className="text-sm opacity-60 hover:underline">
          ← Repositories
        </Link>
        <div className="mt-2 flex items-center justify-between">
          <h1 className="text-xl font-semibold">
            {repository.owner}/{repository.name}
          </h1>
          <Link
            href={`/dashboard/repositories/${repository.id}/add-finding`}
            className="rounded-md bg-foreground px-3 py-2 text-sm font-medium text-background"
          >
            Add finding
          </Link>
        </div>
        {repository.url && (
          <a
            href={repository.url}
            target="_blank"
            rel="noreferrer"
            className="text-sm opacity-60 hover:underline"
          >
            {repository.url}
          </a>
        )}
      </div>

      <div>
        <h2 className="mb-3 text-sm font-medium opacity-70">Vulnerabilities</h2>
        {findings.length === 0 ? (
          <p className="opacity-60">No findings recorded for this repository yet.</p>
        ) : (
          <ul className="flex flex-col divide-y divide-current/10 rounded-md border border-current/10">
            {findings.map((finding) => (
              <li key={finding.id} className="flex flex-col gap-2 px-4 py-3">
                <div className="flex items-center justify-between">
                  <p className="font-mono text-sm font-medium">{finding.vulnerability.cve}</p>
                  <span
                    className={`rounded-full px-2 py-0.5 text-xs font-medium ${SEVERITY_STYLES[finding.vulnerability.severity]}`}
                  >
                    {finding.vulnerability.severity}
                  </span>
                </div>
                <p className="text-sm opacity-80">{finding.vulnerability.description}</p>
                <p className="text-xs opacity-50">
                  Status: {finding.status} · Detected {new Date(finding.detected_at).toLocaleDateString()}
                </p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
