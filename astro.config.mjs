// astro.config.mjs
import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import { nodePolyfills } from 'vite-plugin-node-polyfills';
import viteCommonjs from 'vite-plugin-commonjs';
import netlify from '@astrojs/netlify';

export default defineConfig({
  output: 'server',
  integrations: [react()],
  adapter: netlify({
    functionPerRoute: false,
    cacheOnDemandPages: true,
  }),
  vite: {
    plugins: [
      viteCommonjs(),
      nodePolyfills({
        globals: {
          Buffer: true,
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
    build: {
      commonjsOptions: {
        transformMixedEsModules: true
      }
    }
  },
});