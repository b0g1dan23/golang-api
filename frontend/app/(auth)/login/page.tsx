import { LoginForm } from "@/components/login-form";
import LoginGoogleButton from "@/components/login-with-google";
import Logo from "@/components/ui/Logo";
import { LoginFormSkeleton } from "@/components/skeletons/LoginFormSkeleton";
import { Suspense } from "react";
import { LoginGoogleButtonSkeleton } from "@/components/skeletons/LoginGoogleButtonSkeleton";

export default function Page() {
  return (
    <div className="max-w-3/4 max-lg:max-w-full max-lg:px-4 w-full">
      <Logo className="mb-6" />
      <Suspense fallback={<LoginFormSkeleton />}>
        <LoginForm />
      </Suspense>
      <div className="flex items-center justify-center gap-4 my-4">
        <hr className="w-full" />
        <span>or</span>
        <hr className="w-full" />
      </div>
      <Suspense fallback={<LoginGoogleButtonSkeleton />}>
        <LoginGoogleButton />
      </Suspense>
    </div>
  );
}
