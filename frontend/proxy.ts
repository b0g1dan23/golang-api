import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { ServerClient } from './sdk/backend/server-client';

export async function proxy(request: NextRequest) {
    const server = new ServerClient();
    const { accessToken, refreshToken } = await server.getTokens();

    const url = request.nextUrl.clone();
    const isAppRoute = url.pathname.startsWith('/app');
    const isLoginRoute = url.pathname.startsWith('/login');

    if (isAppRoute && !accessToken) {
        if (!refreshToken) {
            return NextResponse.redirect(new URL('/login', request.url));
        }

        const refreshRes = await server.auth.refreshTokens();

        if (!refreshRes.ok) {
            return NextResponse.redirect(new URL('/login', request.url));
        }
        const response = NextResponse.next();
        const setCookie = refreshRes.headers.get('set-cookie');
        if (setCookie) {
            response.headers.set('set-cookie', setCookie);
        }
        return response;
    }

    if (isLoginRoute && accessToken) {
        url.pathname = '/';
        return NextResponse.redirect(url);
    }

    if (isLoginRoute && !accessToken && refreshToken) {
        const refreshRes = await server.auth.refreshTokens();

        if (!refreshRes.ok) {
            return NextResponse.next();
        }

        const response = NextResponse.redirect(url);
        const setCookie = refreshRes.headers.get('set-cookie');
        if (setCookie)
            response.headers.set('set-cookie', setCookie);
        return response;
    }

    return NextResponse.next();
}

export const config = {
    matcher: ["/login", "/login/:path*", "/app", "/app/:path*"],
};