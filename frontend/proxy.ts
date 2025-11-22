import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export async function proxy(request: NextRequest) {
    const cookies = request.cookies;

    const authToken =
        cookies.get("__Secure-auth_token")?.value ||
        cookies.get("auth_token")?.value;

    const refreshToken =
        cookies.get("__Host-refresh_token")?.value ||
        cookies.get("refresh_token")?.value;

    const url = request.nextUrl.clone();
    const isAppRoute = url.pathname.startsWith('/app');
    const isLoginRoute = url.pathname.startsWith('/login');

    if (isAppRoute && !authToken) {
        if (refreshToken) {
            try {
                const refreshRes = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/refresh`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        Cookie: `refresh_token=${refreshToken}`,
                    },
                    credentials: 'include',
                })

                if (refreshRes.ok) {
                    const setCookieHeader = refreshRes.headers.get('set-cookie');
                    const response = NextResponse.next();

                    if (setCookieHeader) {
                        response.headers.set('set-cookie', setCookieHeader);
                    }

                    return response;
                }
            } catch (err) {
                return NextResponse.redirect(new URL('/login', request.url));
            }
        }

        return NextResponse.redirect(new URL('/login', request.url));
    }

    if (isLoginRoute && authToken) {
        url.pathname = '/';
        return NextResponse.redirect(url);
    }

    if (isLoginRoute && !authToken && refreshToken) {
        try {
            const refreshRes = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/refresh`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Cookie: `refresh_token=${refreshToken}`,
                },
                credentials: 'include',
            })

            if (!refreshRes.ok) {
                return NextResponse.next();
            }

            const setCookieHeader = refreshRes.headers.get('set-cookie');

            const response = NextResponse.redirect(url);

            if (setCookieHeader) {
                response.headers.set('set-cookie', setCookieHeader);
            }

            return response;
        } catch (err) {
            return NextResponse.next();
        }
    }

    return NextResponse.next();
}

export const config = {
    matcher: ["/login", "/login/:path*", "/app", "/app/:path*"],
};