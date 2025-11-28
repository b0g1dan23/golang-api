import { Client, IClientTokens } from "./client";

export class BrowserClient extends Client {
    async getTokens(): Promise<IClientTokens> {
        let accessToken = localStorage.getItem("access_token");
        let refreshToken = localStorage.getItem("refresh_token");
        if (!accessToken) {
            const refreshed = await this.trySilentRefresh();

            if (refreshed) {
                accessToken = refreshed.access_token;
                refreshToken = refreshed.refresh_token;
            }
        }
        return {
            accessToken,
            refreshToken
        };
    }

    async trySilentRefresh() {
        const res = await fetch(`${this.apiUrl}/auth/refresh`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            credentials: 'include',
        });

        if (!res.ok)
            return null;

        const data = await res.json();

        localStorage.setItem("access_token", data.access_token);
        localStorage.setItem("refresh_token", data.refresh_token);

        return data as { access_token: string, refresh_token: string };
    }
}