/**
 * 轻量提示（Toast）状态。
 *
 * 约定：提示内容不得包含密码、TOTP 密钥等敏感信息——它们会被渲染到
 * DOM 中，属于需要避免的暴露面。
 */
import { reactive } from 'vue'

export type ToastKind = 'info' | 'success' | 'warn' | 'error'

export interface Toast {
  id: number
  kind: ToastKind
  message: string
  /** 自动消失时长（毫秒），0 表示需要手动关闭。 */
  ttl: number
}

const state = reactive<{ items: Toast[] }>({ items: [] })

let seq = 0

/** 推入一条提示。 */
export function pushToast(message: string, kind: ToastKind = 'info', ttl = 4000): number {
  const id = ++seq
  state.items.push({ id, kind, message, ttl })
  if (ttl > 0) {
    window.setTimeout(() => dismissToast(id), ttl)
  }
  return id
}

/** 关闭指定提示。 */
export function dismissToast(id: number): void {
  const idx = state.items.findIndex((t) => t.id === id)
  if (idx >= 0) state.items.splice(idx, 1)
}

/** 清空全部提示。 */
export function clearToasts(): void {
  state.items.splice(0, state.items.length)
}

export const toast = {
  info: (m: string) => pushToast(m, 'info'),
  success: (m: string) => pushToast(m, 'success'),
  warn: (m: string) => pushToast(m, 'warn', 6000),
  error: (m: string) => pushToast(m, 'error', 8000),
}

export function useToasts() {
  return { state, pushToast, dismissToast, clearToasts, toast }
}
