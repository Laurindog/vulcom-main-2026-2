
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: './',
  server: {
    headers: {
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';"
    }
  }
})
