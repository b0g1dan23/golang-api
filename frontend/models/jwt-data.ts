export enum UserRole {
    USER = 'user',
    ADMIN = 'admin',
    OWNER = 'owner',
}

export interface JWTData {
    sub: string;
    email: string;
    role: UserRole;
    exp: number;
    iat: number;
}