import { LoginForm } from "@/components/login-form";
import LoginGoogleButton from "@/components/login-with-google";
import Logo from "@/components/ui/Logo";

export default function Page() {
  return (
    <div className="max-w-3/4 max-lg:max-w-full max-lg:px-4 w-full">
      <Logo className="mb-6" />
      <LoginForm />
      <div className="flex items-center justify-center gap-4 my-4">
        <hr className="w-full" />
        <span>or</span>
        <hr className="w-full" />
      </div>
      <LoginGoogleButton />
    </div>
  );
}
