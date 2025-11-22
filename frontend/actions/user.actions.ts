'use server';

import { User } from "@/models/user";
import { decodeVerifyAuthToken, getTokensFromCookies, refreshAuthToken } from "./utils";

export async function getLoggedUser() {
    const { authToken, refreshToken } = await getTokensFromCookies();
    if (authToken) {
        const data = await decodeVerifyAuthToken();
        if (!data) {
            throw new Error('Invalid auth token');
        }
    } else {
        const res = await refreshAuthToken();

        if (!res.ok) {
            throw new Error('Failed to refresh auth token');
        }
    }

    const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/users/me`, {
        headers: {
            Cookie: `auth_token=${authToken}; refresh_token=${refreshToken}`,
        }
    });
    if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to fetch user data');
    }
    const user = await res.json();
    return user as User;
}