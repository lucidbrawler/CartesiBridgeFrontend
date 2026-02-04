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
    resolve: {
      alias: {
        crypto: 'crypto-browserify',
        stream: 'stream-browserify',
      },
    },
    ssr: {
      noExternal: ['crypto-browserify', 'stream-browserify'],
    },
       optimizeDeps: {
      esbuildOptions: {
        define: {
          global: 'globalThis',
        },
      },
    },
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