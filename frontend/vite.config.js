import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    allowedHosts: ['.loca.lt', '.lhr.life'],
    proxy: {
      '/api': 'http://localhost:3000'
    }
  },
  preview: {
    host: true,
    allowedHosts: ['.loca.lt', '.lhr.life'],
    proxy: {
      '/api': 'http://localhost:3000'
    }
  }
})
