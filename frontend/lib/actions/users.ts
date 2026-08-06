"use server";

import { revalidatePath } from "next/cache";
import { ApiError, updateUserActive, updateUserRole, type UserRole } from "@/lib/api";

export type AdminActionState = { error?: string } | undefined;

export async function updateUserRoleAction(
  userId: string,
  role: UserRole,
): Promise<AdminActionState> {
  try {
    await updateUserRole(userId, role);
  } catch (err) {
    if (err instanceof ApiError) return { error: err.message };
    return { error: "Something went wrong. Please try again." };
  }
  revalidatePath("/dashboard/admin");
}

export async function updateUserActiveAction(
  userId: string,
  isActive: boolean,
): Promise<AdminActionState> {
  try {
    await updateUserActive(userId, isActive);
  } catch (err) {
    if (err instanceof ApiError) return { error: err.message };
    return { error: "Something went wrong. Please try again." };
  }
  revalidatePath("/dashboard/admin");
}
