import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

// Wails 会把 frontend/dist 整个嵌入二进制，因此：
//  - base 用相对路径，避免 WebView2 在老版本下解析绝对路径出错；
//  - 关闭 sourcemap，减少打包体积，也避免源码结构随构建产物外泄。
export default defineConfig({
  base: './',
  plugins: [vue(), tailwindcss()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2022',
    chunkSizeWarningLimit: 1500,
  },
  server: {
    port: 34115,
    strictPort: false,
  },
})
