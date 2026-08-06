"use server";

import { revalidatePath } from "next/cache";
import { ApiError, runFullScan } from "@/lib/api";

export type TriggerScanState = { error?: string; success?: string } | undefined;

export async function runFullScanAction(
  repositoryId: string,
  requiresPath: boolean,
  _prevState: TriggerScanState,
  formData: FormData,
): Promise<TriggerScanState> {
  const path = String(formData.get("path") ?? "").trim();
  if (requiresPath && !path) return { error: "Path is required for repositories without a GitHub URL." };

  let scans;
  try {
    scans = await runFullScan(repositoryId, path || undefined);
  } catch (err) {
    if (err instanceof ApiError) return { error: err.message };
    return { error: "Something went wrong. Please try again." };
  }

  revalidatePath(`/dashboard/repositories/${repositoryId}`);
  const failed = scans.filter((scan) => scan.status === "FAILED");
  if (failed.length > 0) {
    return { error: failed.map((scan) => `${scan.scanner}: ${scan.error_message}`).join(" · ") };
  }
  const newTotal = scans.reduce((sum, scan) => sum + (scan.new_findings ?? 0), 0);
  const resolvedTotal = scans.reduce((sum, scan) => sum + (scan.resolved_findings ?? 0), 0);
  return { success: `Scan complete: ${newTotal} new, ${resolvedTotal} resolved.` };
}
