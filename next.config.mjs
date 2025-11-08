/** @type {import('next').NextConfig} */
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const nextConfig = {
  experimental: {},
  webpack: (config) => {
    config.resolve.alias['@/src'] = path.join(__dirname, 'src');
    return config;
  },
};

export default nextConfig;
