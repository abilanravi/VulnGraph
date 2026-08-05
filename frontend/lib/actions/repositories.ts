"use server";

import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { ApiError, createRepository } from "@/lib/api";

export type AddRepositoryState = { error?: string } | undefined;

export async function addRepositoryAction(
  _prevState: AddRepositoryState,
  formData: FormData,
): Promise<AddRepositoryState> {
  const name = String(formData.get("name") ?? "").trim();
  const owner = String(formData.get("owner") ?? "").trim();
  const url = String(formData.get("url") ?? "").trim();

  if (!name || !owner) {
    return { error: "Name and owner are required." };
  }

  let repository;
  try {
    repository = await createRepository({ name, owner, url: url || undefined });
  } catch (err) {
    if (err instanceof ApiError) return { error: err.message };
    return { error: "Something went wrong. Please try again." };
  }

  revalidatePath("/dashboard");
  redirect(`/dashboard/repositories/${repository.id}`);
}
