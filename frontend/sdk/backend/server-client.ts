import { Client, IClientTokens } from "./client";
import { cookies } from 'next/headers';

export class ServerClient extends Client {
    async getTokens(): Promise<IClientTokens> {
        const cookieStore = await cookies();
        const accessToken = cookieStore.get("__Secure-access_token")?.value ||
            cookieStore.get("access_token")?.value || null;
        const refreshToken = cookieStore.get("__Host-refresh_token")?.value ||
            cookieStore.get("refresh_token")?.value || null;
        return { accessToken, refreshToken };
    }
}