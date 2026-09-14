import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    proxy: {
      '/api': {
        target: loadEnv(mode, '.', 'GUARD_').GUARD_API_TARGET || 'http://127.0.0.1:8765',
        changeOrigin: false,
      },
    },
  },
  build: { outDir: 'dist', sourcemap: false },
}));
