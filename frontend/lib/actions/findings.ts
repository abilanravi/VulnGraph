"use server";

import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { ApiError, createFinding, type Severity } from "@/lib/api";

export type AddFindingState = { error?: string } | undefined;

const VALID_SEVERITIES: Severity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

export async function addFindingAction(
  repositoryId: string,
  _prevState: AddFindingState,
  formData: FormData,
): Promise<AddFindingState> {
  const cve = String(formData.get("cve") ?? "").trim();
  const severity = String(formData.get("severity") ?? "") as Severity;
  const description = String(formData.get("description") ?? "").trim();

  if (!cve || !description) {
    return { error: "CVE and description are required." };
  }
  if (!VALID_SEVERITIES.includes(severity)) {
    return { error: "Invalid severity." };
  }

  try {
    await createFinding(repositoryId, { cve, severity, description });
  } catch (err) {
    if (err instanceof ApiError) return { error: err.message };
    return { error: "Something went wrong. Please try again." };
  }

  revalidatePath(`/dashboard/repositories/${repositoryId}`);
  redirect(`/dashboard/repositories/${repositoryId}`);
}
