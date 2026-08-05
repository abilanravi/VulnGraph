"use server";

import { revalidatePath } from "next/cache";
import { ApiError, triggerOsvScan, triggerSemgrepScan } from "@/lib/api";

export type TriggerScanState = { error?: string; success?: string } | undefined;

async function runScan(
  repositoryId: string,
  run: (repositoryId: string, path: string) => Promise<unknown>,
  formData: FormData,
): Promise<TriggerScanState> {
  const path = String(formData.get("path") ?? "").trim();
  if (!path) return { error: "Path is required." };

  try {
    await run(repositoryId, path);
  } catch (err) {
    if (err instanceof ApiError) return { error: err.message };
    return { error: "Something went wrong. Please try again." };
  }

  revalidatePath(`/dashboard/repositories/${repositoryId}`);
  return { success: "Scan complete." };
}

export async function triggerSemgrepScanAction(
  repositoryId: string,
  _prevState: TriggerScanState,
  formData: FormData,
): Promise<TriggerScanState> {
  return runScan(repositoryId, triggerSemgrepScan, formData);
}

export async function triggerOsvScanAction(
  repositoryId: string,
  _prevState: TriggerScanState,
  formData: FormData,
): Promise<TriggerScanState> {
  return runScan(repositoryId, triggerOsvScan, formData);
}
