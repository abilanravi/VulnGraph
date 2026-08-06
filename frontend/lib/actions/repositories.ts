"use server";

import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { ApiError, createRepository } from "@/lib/api";

export type AddRepositoryState = { error?: string } | undefined;

export async function addRepositoryAction(
  _prevState: AddRepositoryState,
  formData: FormData,
): Promise<AddRepositoryState> {
  const url = String(formData.get("url") ?? "").trim();
  const name = String(formData.get("name") ?? "").trim();
  const owner = String(formData.get("owner") ?? "").trim();

  if (!url && (!name || !owner)) {
    return { error: "Provide a GitHub URL, or a name and owner." };
  }

  let repository;
  try {
    repository = url ? await createRepository({ url }) : await createRepository({ name, owner });
  } catch (err) {
    if (err instanceof ApiError) return { error: err.message };
    return { error: "Something went wrong. Please try again." };
  }

  revalidatePath("/dashboard");
  redirect(`/dashboard/repositories/${repository.id}`);
}
