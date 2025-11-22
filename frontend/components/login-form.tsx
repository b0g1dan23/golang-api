'use client'

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import Link from "next/link"
import { FormEvent, useState } from "react"
import { toast } from 'sonner'
import { useRouter, useSearchParams } from "next/navigation"
import { motion, AnimatePresence } from "framer-motion";
import z from "zod"

const loginSchema = z.object({
  email: z.email("Invalid email address"),
  password: z.string().regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+={}[\]|\\:;"'<>,.?/~`]).{8,}$/, "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character."),
})

const signupSchema = loginSchema.extend({
  firstName: z.string().min(1, "First name is required"),
  lastName: z.string().min(1, "Last name is required"),
})

export function LoginForm({
  className,
  ...props
}: React.ComponentProps<"div">) {
  const [email, setEmail] = useState('')
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [password, setPassword] = useState('')
  const searchParams = useSearchParams();
  const mode = searchParams.get('mode');
  const router = useRouter();

  const handleSubmit = async (ev: FormEvent<HTMLFormElement>) => {
    ev.preventDefault();

    try {
      if (mode === 'signup') {
        signupSchema.parse({ firstName, lastName, email, password });
        // Proceed with signup logic
        const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/register`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          credentials: 'include',
          body: JSON.stringify({ firstname: firstName, lastname: lastName, email, password })
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || 'Server error');
        }

        toast.success('Signup successful!');
        router.push('/app');
      } else {
        loginSchema.parse({ email, password });

        const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/login`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          credentials: 'include',
          body: JSON.stringify({ email, password })
        })

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || 'Server error');
        }

        toast.success('Login successful!');
        router.push('/app');
      }
    } catch (err) {
      if (err instanceof z.ZodError) {
        if (Array.isArray(err.issues)) {
          err.issues.forEach((issue) => {
            toast.error(issue.message);
          })
          return;
        }
      }
      const e = err as Error;
      toast.error(e.message);
      return;
    }
  }

  return (
    <div className={cn("flex flex-col gap-6", className)} {...props}>
      <Card>
        <CardHeader>
          <CardTitle>Login to your account</CardTitle>
          <CardDescription>
            Enter your email below to login to your account
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit}>
            <FieldGroup>
              <AnimatePresence mode="wait">
                {mode === 'signup' && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.3 }}
                    className="grid grid-cols-2 gap-8"
                  >
                    <Field>
                      <FieldLabel htmlFor="firstname">First name</FieldLabel>
                      <Input
                        id="firstname"
                        type="text"
                        placeholder="Enter your first name"
                        value={firstName}
                        onChange={(e) => setFirstName(e.target.value)}
                        required
                      />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="lastname">Last name</FieldLabel>
                      <Input
                        id="lastname"
                        type="text"
                        placeholder="Enter your last name"
                        value={lastName}
                        onChange={(e) => setLastName(e.target.value)}
                        required
                      />
                    </Field>
                  </motion.div>
                )}
              </AnimatePresence>
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
                <FieldLabel htmlFor="password">Password</FieldLabel>
                <Input
                  id="password"
                  type="password"
                  placeholder="Enter your password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)} />
                <FieldDescription>
                  <Link href={'/forgot-password'}>
                    Forgot your password?</Link>
                </FieldDescription>
              </Field>
              <Field>
                <Button type="submit">Login</Button>
              </Field>
            </FieldGroup>
          </form>
        </CardContent>
        <CardFooter className="justify-center">
          {mode === 'signup' ? (
            <p>Already have an account? <Link href={'/login'} className="underline">Log in</Link></p>
          ) :
            <p>Don&apos;t have an account? <Link href={'/login?mode=signup'} className="underline">Sign up</Link></p>
          }
        </CardFooter>
      </Card>
    </div >
  )
}
