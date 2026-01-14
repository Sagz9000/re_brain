import { NextResponse } from 'next/server';

export const maxDuration = 300; // 5 minutes timeout for Vercel/Next.js

export async function POST(req: Request) {
    const body = await req.json();

    // Use internal docker network URL if valid, else localhost fallback
    const API_BASE = process.env.INTERNAL_API_URL || 'http://re-api2:8000';

    try {
        const res = await fetch(`${API_BASE}/chat`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(body),
            // Explicitly set a long timeout signal if needed, 
            // though standard fetch in Node doesn't default to 10s like browsers might.
            // But we can mostly rely on the server keeping it open.
        });

        if (!res.ok) {
            return NextResponse.json(
                { error: `Backend error: ${res.status} ${res.statusText}` },
                { status: res.status }
            );
        }

        const data = await res.json();
        return NextResponse.json(data);

    } catch (error: any) {
        console.error("Proxy Error:", error);
        return NextResponse.json(
            { error: `Proxy failed: ${error.message}` },
            { status: 500 }
        );
    }
}
