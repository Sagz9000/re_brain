export const getApiUrl = () => {
    // 1. Client-side (Browser)
    if (typeof window !== 'undefined') {
        // If an explicit override is provided via env (baked in at build time)
        const envUrl = process.env.NEXT_PUBLIC_API_URL;
        if (envUrl && envUrl.trim().length > 0) {
            console.log("re-Brain: Using explicit API URL:", envUrl);
            return envUrl;
        }

        // Default to relative /api to use Next.js proxying (next.config.js)
        console.log("re-Brain: Using proxied API URL: /api");
        return '/api';
    }

    // 2. Server-side (SSR) or Fallback
    return process.env.INTERNAL_API_URL || process.env.NEXT_PUBLIC_API_URL || 'http://re-api2:8000';
};

export const API_URL = getApiUrl();
