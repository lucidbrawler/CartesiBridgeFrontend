// astro.config.mjs
import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

export default defineConfig({
  integrations: [react()],
  vite: {
    plugins: [
      nodePolyfills({
        // Buffer is the main one needed for ethers.js
        globals: {
          Buffer: true,  // Enables Buffer global
          global: true,
          process: true,
        },
      }),
    ],
    server: {
      proxy: {
        '/rollup': {
          target: 'http://127.0.0.1:8080',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/rollup/, ''),
        },
      },
    },
  },
});