import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            '@': resolve(__dirname, './src'),
        },
    },
    define: {
        // Polyfill for Stellar SDK
        'process.env': {},
        global: 'globalThis',
    },
    optimizeDeps: {
        exclude: ['falcon-wasm'],
        esbuildOptions: {
            define: {
                global: 'globalThis',
            },
        },
    },
    server: {
        fs: {
            // Allow serving files from the falcon/pkg directory
            allow: ['..'],
        },
    },
});
