import { createApp } from 'vue'
import AppRoot from './App.vue'
import './style.css'

// 在挂载前先把主题属性写好，避免首帧闪白。
// 初始值取系统偏好，随后 initVault 会用后端设置覆盖。
const prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches
document.documentElement.setAttribute('data-theme', prefersLight ? 'light' : 'dark')

// 禁用页面级拖放，防止把文件拖进 WebView 触发导航。
window.addEventListener('dragover', (e) => e.preventDefault())
window.addEventListener('drop', (e) => e.preventDefault())

createApp(AppRoot).mount('#app')
