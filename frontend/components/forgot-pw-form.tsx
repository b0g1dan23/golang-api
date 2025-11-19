'use client';

import { FormEvent, useState } from "react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "./ui/card";
import { cn } from "@/lib/utils";
import { Field, FieldGroup, FieldLabel } from "./ui/field";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { IoMdArrowBack } from "react-icons/io";
import Link from "next/link";

export function ForgotPWForm({
    className,
    ...props
}: React.ComponentProps<"div">) {
    const [email, setEmail] = useState('')

    const handleSubmit = (ev: FormEvent<HTMLFormElement>) => {
        ev.preventDefault();

        toast.success('Password reset request sent!', {
            description: `If an account with the email ${email} exists, a password reset link will be sent.`,
        });
    }

    return (
        <div className={cn("flex flex-col gap-6", className)} {...props}>
            <motion.div
                initial={{ opacity: 0, y: 40 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4 }}>
                <Card>
                    <CardHeader>
                        <CardTitle>Forgot password</CardTitle>
                        <CardDescription>
                            Enter your email below to reset your password
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form onSubmit={handleSubmit}>
                            <FieldGroup>
                                <Field>
                                    <FieldLabel htmlFor="email">Email</FieldLabel>
                                    <Input
                                        id="email"
                                        type="email"
                                        placeholder="Enter your email"
                                        value={email}
                                        onChange={(e) => setEmail(e.target.value)}
                                        required
                                    />
                                </Field>
                                <Field>
                                    <Button type="submit">Send request</Button>
                                </Field>
                            </FieldGroup>
                        </form>
                    </CardContent>
                    <CardFooter className="justify-center flex-col gap-4">
                        <CardDescription>
                            <p>You will be sent a password reset link if the email is registered.</p>
                        </CardDescription>

                    </CardFooter>
                </Card>
            </motion.div>
            <Link href='/login' className="w-full" >
                <Button variant='outline' className="w-full">
                    <IoMdArrowBack />Go back to login
                </Button>
            </Link>
        </div >
    )
}