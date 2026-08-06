import { redirect } from "next/navigation";
import { ApiError, getCurrentUser } from "@/lib/api";
import { AddFindingForm } from "./add-finding-form";

export default async function AddFindingPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id: repositoryId } = await params;

  let currentUser;
  try {
    currentUser = await getCurrentUser();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) redirect("/login");
    throw err;
  }

  // UX guard only — the backend rejects this for VIEWER regardless (see require_scan_access in
  // app/api/routes/findings.py).
  if (currentUser.role === "VIEWER") {
    return (
      <div className="mx-auto flex w-full max-w-md flex-col gap-2">
        <h1 className="text-xl font-semibold">Forbidden</h1>
        <p className="opacity-60">Viewer accounts cannot add findings.</p>
      </div>
    );
  }

  return <AddFindingForm repositoryId={repositoryId} />;
}
