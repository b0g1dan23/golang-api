import { User } from "@/models/user";
import { Authentication } from "./authentication";

export interface IClientTokens {
    accessToken: string | null;
    refreshToken: string | null;
}

export interface IClient {
    getTokens(): Promise<IClientTokens>;
}

export abstract class Client implements IClient {
    public apiUrl: string = process.env.NEXT_PUBLIC_API_URL!;
    public auth: Authentication;

    constructor() {
        this.auth = new Authentication(this.getTokens, this.apiUrl);
    }

    abstract getTokens(): Promise<IClientTokens>;

    async getUser(): Promise<User | null> {
        const res = await fetch(`${this.apiUrl}/auth/me`, {
            method: "GET",
            credentials: 'include',
        });

        if (!res.ok) {
            const data = await res.json();
            return null;
        }

        const user = await res.json();
        return user as User;
    }
}