'use server';

import { cookies } from "next/headers";
import { getTokensFromCookies } from "./utils";

export async function logout() {
    const { authToken, refreshToken } = await getTokensFromCookies();

    const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/logout`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Cookie: `refresh_token=${refreshToken}; auth_token=${authToken}`,
        },
    })

    if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to logout');
    }
    const cookieStore = await cookies();
    cookieStore.delete("__Secure-auth_token");
    cookieStore.delete("auth_token");
    cookieStore.delete("__Host-refresh_token");
    cookieStore.delete("refresh_token");

    return;
}