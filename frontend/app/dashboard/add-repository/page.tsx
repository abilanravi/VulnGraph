import { redirect } from "next/navigation";
import { ApiError, getCurrentUser } from "@/lib/api";
import { AddRepositoryForm } from "./add-repository-form";

export default async function AddRepositoryPage() {
  let currentUser;
  try {
    currentUser = await getCurrentUser();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) redirect("/login");
    throw err;
  }

  // UX guard only — the backend rejects POST /repositories for VIEWER regardless (see
  // require_scan_access in app/api/routes/repositories.py).
  if (currentUser.role === "VIEWER") {
    return (
      <div className="mx-auto flex w-full max-w-md flex-col gap-2">
        <h1 className="text-xl font-semibold">Forbidden</h1>
        <p className="opacity-60">Viewer accounts cannot create repositories.</p>
      </div>
    );
  }

  return <AddRepositoryForm />;
}
