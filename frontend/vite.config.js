import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.SECURE_SMTP_DEV_API_TARGET || 'http://localhost:8000',
        changeOrigin: true,
      },
      '/ws': {
        target: (process.env.SECURE_SMTP_DEV_API_TARGET || 'http://localhost:8000').replace(/^http/, 'ws'),
        ws: true,
      },
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('@clerk')) return 'vendor-clerk';
            if (id.includes('recharts') || id.includes('d3')) return 'vendor-charts';
            if (id.includes('react') || id.includes('react-router')) return 'vendor-react';
            return 'vendor';
          }
        },
      },
    },
  },
})
