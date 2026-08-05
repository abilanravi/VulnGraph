import Link from "next/link";
import { redirect } from "next/navigation";
import { ApiError, getRepositories } from "@/lib/api";

export default async function DashboardPage() {
  let repositories;
  try {
    repositories = await getRepositories();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) redirect("/login");
    throw err;
  }

  return (
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
  );
}
