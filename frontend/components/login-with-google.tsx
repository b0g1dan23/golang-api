'use client';

import { FcGoogle } from "react-icons/fc"
import { Button } from "./ui/button"
import { useSearchParams } from "next/navigation";

const LoginGoogleButton = () => {
    const searchParams = useSearchParams();
    const mode = searchParams.get('mode');

    return (
        <Button variant="outline" className="w-full" type="button">
            <FcGoogle /> {mode === 'signup' ? "Sign up" : "Login"} with Google
        </Button>
    )
}
export default LoginGoogleButton