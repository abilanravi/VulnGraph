import Link from "next/link";
import { redirect } from "next/navigation";
import { ApiError, getFindings, getRepository, getScans, type Finding, type FindingStatus, type Severity } from "@/lib/api";
import { updateFindingStatusAction } from "@/lib/actions/findings";
import { ScanTriggerForm } from "./scan-trigger-form";

const SEVERITY_STYLES: Record<Severity, string> = {
  LOW: "bg-blue-500/10 text-blue-600 dark:text-blue-400",
  MEDIUM: "bg-yellow-500/10 text-yellow-600 dark:text-yellow-400",
  HIGH: "bg-orange-500/10 text-orange-600 dark:text-orange-400",
  CRITICAL: "bg-red-500/10 text-red-600 dark:text-red-400",
};

const STATUS_TRANSITIONS: Record<FindingStatus, { label: string; next: FindingStatus }[]> = {
  OPEN: [
    { label: "Start", next: "IN_PROGRESS" },
    { label: "Resolve", next: "RESOLVED" },
    { label: "False positive", next: "FALSE_POSITIVE" },
  ],
  IN_PROGRESS: [
    { label: "Resolve", next: "RESOLVED" },
    { label: "False positive", next: "FALSE_POSITIVE" },
  ],
  RESOLVED: [{ label: "Reopen", next: "OPEN" }],
  FALSE_POSITIVE: [{ label: "Reopen", next: "OPEN" }],
};

function findingLocation(finding: Finding): string | null {
  if (finding.file_path) return finding.line_start ? `${finding.file_path}:${finding.line_start}` : finding.file_path;
  if (finding.package_name) return `${finding.package_name}${finding.package_version ? `@${finding.package_version}` : ""}`;
  return null;
}

export default async function RepositoryDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  let repository, findings, scans;
  try {
    [repository, findings, scans] = await Promise.all([getRepository(id), getFindings(id), getScans(id)]);
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

      <div className="grid gap-3 sm:grid-cols-2">
        <ScanTriggerForm repositoryId={repository.id} scanner="semgrep" />
        <ScanTriggerForm repositoryId={repository.id} scanner="osv" />
      </div>

      {scans.length > 0 && (
        <div>
          <h2 className="mb-3 text-sm font-medium opacity-70">Recent scans</h2>
          <ul className="flex flex-col divide-y divide-current/10 rounded-md border border-current/10">
            {scans.slice(0, 5).map((scan) => (
              <li key={scan.id} className="flex items-center justify-between px-4 py-2 text-sm">
                <span>
                  {scan.scanner} · {scan.status}
                  {scan.status === "FAILED" && scan.error_message ? ` — ${scan.error_message}` : ""}
                </span>
                <span className="opacity-50">
                  {scan.status === "COMPLETED"
                    ? `${scan.new_findings ?? 0} new · ${scan.resolved_findings ?? 0} resolved`
                    : new Date(scan.created_at).toLocaleString()}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div>
        <h2 className="mb-3 text-sm font-medium opacity-70">Findings</h2>
        {findings.length === 0 ? (
          <p className="opacity-60">No findings recorded for this repository yet.</p>
        ) : (
          <ul className="flex flex-col divide-y divide-current/10 rounded-md border border-current/10">
            {findings.map((finding) => (
              <li key={finding.id} className="flex flex-col gap-2 px-4 py-3">
                <div className="flex items-center justify-between gap-2">
                  <p className="font-mono text-sm font-medium">{finding.title}</p>
                  <span
                    className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ${SEVERITY_STYLES[finding.severity]}`}
                  >
                    {finding.severity}
                  </span>
                </div>
                {finding.description && <p className="text-sm opacity-80">{finding.description}</p>}
                <p className="text-xs opacity-50">
                  {finding.scanner} · {finding.finding_type}
                  {findingLocation(finding) ? ` · ${findingLocation(finding)}` : ""}
                  {finding.cve ? ` · ${finding.cve}` : ""}
                </p>
                <p className="text-xs opacity-50">
                  Status: {finding.status} · Detected {new Date(finding.detected_at).toLocaleDateString()} · Last
                  seen {new Date(finding.last_seen_at).toLocaleDateString()}
                </p>
                <div className="flex gap-2">
                  {STATUS_TRANSITIONS[finding.status].map((transition) => (
                    <form
                      key={transition.next}
                      action={updateFindingStatusAction.bind(null, repository.id, finding.id, transition.next)}
                    >
                      <button type="submit" className="text-xs underline opacity-70 hover:opacity-100">
                        {transition.label}
                      </button>
                    </form>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
