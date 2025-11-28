import { User } from "@/models/user";
import { IClientTokens } from "./client";

export interface PasswordSignInCredentials {
    email: string;
    password: string;
}

export interface PasswordSignUpCredentials extends PasswordSignInCredentials {
    firstname: string;
    lastname: string;
}

export class Authentication {
    private _apiUrl: string | null = null;
    private _tokenProvider: () => Promise<IClientTokens>;

    constructor(provider: () => Promise<IClientTokens>, apiUrl: string) {
        this._apiUrl = apiUrl;
        this._tokenProvider = provider;
    }

    async signInWithPassword(body: PasswordSignInCredentials): Promise<User> {
        const res = await fetch(`${this._apiUrl}/auth/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            credentials: 'include',
            body: JSON.stringify(body)
        })

        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.error || 'Server error');
        }

        localStorage.setItem("access_token", data.access_token);
        localStorage.setItem("refresh_token", data.refresh_token);

        return data as User;
    }

    async signUpWithPassword(body: PasswordSignUpCredentials): Promise<User> {
        const res = await fetch(`${this._apiUrl}/auth/register`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            credentials: 'include',
            body: JSON.stringify(body)
        })

        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.error || 'Server error');
        }

        localStorage.setItem("access_token", data.access_token);
        localStorage.setItem("refresh_token", data.refresh_token);

        return data as User;
    }

    async signOut(): Promise<void> {
        const res = await fetch(`${this._apiUrl}/auth/logout`, {
            method: "POST",
            credentials: 'include',
        });

        if (!res.ok) {
            const data = await res.json();
            throw new Error(data.error || 'Failed to logout');
        }

        localStorage.removeItem("access_token");
        localStorage.removeItem("refresh_token");
        return;
    }

    async refreshTokens() {
        const { refreshToken } = await this._tokenProvider();
        const refreshRes = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/refresh`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            credentials: 'include',
        })

        return refreshRes;
    }
}