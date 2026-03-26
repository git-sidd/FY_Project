import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Essential for Electron to load local files properly:
  // Instead of absolute path /assets, Vite will output relative paths
  base: './',
  build: {
    outDir: 'dist'
  }
})
