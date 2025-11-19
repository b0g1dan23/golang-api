import { Card, CardContent, CardFooter, CardHeader } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"

export function LoginFormSkeleton() {
    return (
        <div className="flex flex-col gap-6">
            <Card>
                <CardHeader className="space-y-1">
                    <Skeleton className="h-7 w-52" />
                    <Skeleton className="h-5 w-80" />
                </CardHeader>
                <CardContent>
                    <div className="flex flex-col gap-6">
                        <div className="flex flex-col gap-2">
                            <Skeleton className="h-3.5 w-12" />
                            <Skeleton className="h-10 w-full" />
                        </div>
                        <div className="flex flex-col gap-2">
                            <Skeleton className="h-3.5 w-16" />
                            <Skeleton className="h-10 w-full" />
                            <Skeleton className="h-3.5 w-36 mt-1.5" />
                        </div>
                        <Skeleton className="h-10 w-full mt-2" />
                    </div>
                </CardContent>
                <CardFooter className="justify-center pt-2">
                    <Skeleton className="h-5 w-60" />
                </CardFooter>
            </Card>
        </div>
    )
}
