'use server';

import { JWTData } from "@/models/jwt-data";
import { revalidatePath } from "next/cache";
import { cookies } from "next/headers";

export async function getTokensFromCookies(): Promise<{ authToken: string | undefined, refreshToken: string | undefined }> {
    const cookieStore = await cookies();
    const authToken =
        cookieStore.get("__Secure-auth_token")?.value ||
        cookieStore.get("auth_token")?.value;
    const refreshToken = cookieStore.get("__Host-refresh_token")?.value ||
        cookieStore.get("refresh_token")?.value;

    return { authToken: authToken, refreshToken: refreshToken };
}

export async function decodeVerifyAuthToken(): Promise<JWTData | null> {
    const { authToken } = await getTokensFromCookies();

    if (!authToken) {
        return null;
    }

    const [_, payload_encoded] = authToken.split('.');

    const payload_decoded = Buffer.from(payload_encoded, 'base64').toString('utf-8');
    const payload: JWTData = JSON.parse(payload_decoded);

    return payload;
}

export async function refreshAuthToken() {
    const { refreshToken } = await getTokensFromCookies();
    const refreshRes = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/refresh`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Cookie: `refresh_token=${refreshToken}`,
        },
        credentials: 'include',
    })

    revalidatePath('/', 'layout');

    return refreshRes;
}