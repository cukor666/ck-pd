/// <reference types="vite/client" />

// .vue 单文件组件的类型声明，供 vue-tsc 正确解析 SFC 导入。
declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<Record<string, unknown>, Record<string, unknown>, unknown>
  export default component
}
