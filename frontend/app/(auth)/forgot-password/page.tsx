import { ForgotPWForm } from "@/components/forgot-pw-form"
import Logo from "@/components/ui/Logo"

const page = () => {
    return (
        <div className="max-w-3/4 max-lg:max-w-full max-lg:px-4 w-full">
            <Logo className="mb-6" />
            <ForgotPWForm />
        </div>
    )
}
export default page