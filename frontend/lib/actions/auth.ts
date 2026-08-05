"use server";

import { redirect } from "next/navigation";
import { ApiError, login as apiLogin, signup as apiSignup } from "@/lib/api";
import { clearToken, setToken } from "@/lib/session";

export type AuthActionState = { error?: string } | undefined;

export async function loginAction(
  _prevState: AuthActionState,
  formData: FormData,
): Promise<AuthActionState> {
  const email = String(formData.get("email") ?? "");
  const password = String(formData.get("password") ?? "");

  try {
    const { access_token } = await apiLogin(email, password);
    await setToken(access_token);
  } catch (err) {
    if (err instanceof ApiError) return { error: err.message };
    return { error: "Something went wrong. Please try again." };
  }

  redirect("/dashboard");
}

export async function signupAction(
  _prevState: AuthActionState,
  formData: FormData,
): Promise<AuthActionState> {
  const email = String(formData.get("email") ?? "");
  const password = String(formData.get("password") ?? "");

  try {
    const { access_token } = await apiSignup(email, password);
    await setToken(access_token);
  } catch (err) {
    if (err instanceof ApiError) return { error: err.message };
    return { error: "Something went wrong. Please try again." };
  }

  redirect("/dashboard");
}

export async function logoutAction(): Promise<void> {
  await clearToken();
  redirect("/login");
}
