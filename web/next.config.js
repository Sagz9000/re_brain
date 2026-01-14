/** @type {import('next').NextConfig} */
const nextConfig = {
    async rewrites() {
        return [
            {
                source: '/api/:path*',
                destination: (process.env.INTERNAL_API_URL || 'http://re-api2:8000') + '/:path*',
            },
        ];
    },
    output: 'standalone',
};

module.exports = nextConfig;
