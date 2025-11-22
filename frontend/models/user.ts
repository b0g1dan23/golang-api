import { UserRole } from "./jwt-data";

export interface User {
    id: string;
    firstname: string;
    lastname: string;
    email: string;
    role: UserRole;
    created_at: string;
    updated_at: string;
}