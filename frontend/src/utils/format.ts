/**
 * 格式化与安全提示相关的纯函数工具。
 *
 * 说明：本文件只做展示层格式化，不参与任何密码学逻辑。
 */

/** 把 Unix 秒格式化为本地日期时间。 */
export function formatDateTime(unixSeconds: number): string {
  if (!unixSeconds) return '—'
  const d = new Date(unixSeconds * 1000)
  if (Number.isNaN(d.getTime())) return '—'
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(
    d.getMinutes(),
  )}`
}

/** 把 Unix 秒格式化为相对时间（"3 天前"）。 */
export function formatRelative(unixSeconds: number): string {
  if (!unixSeconds) return '—'
  const diff = Date.now() / 1000 - unixSeconds
  if (diff < 0) return '刚刚'
  if (diff < 60) return '刚刚'
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`
  if (diff < 86400 * 30) return `${Math.floor(diff / 86400)} 天前`
  if (diff < 86400 * 365) return `${Math.floor(diff / (86400 * 30))} 个月前`
  return `${Math.floor(diff / (86400 * 365))} 年前`
}

/** 从 URL 中提取主机名，供列表展示与图标字母使用。 */
export function hostOf(url: string): string {
  if (!url) return ''
  const trimmed = url.trim()
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
    return new URL(withScheme).host.replace(/^www\./, '')
  } catch {
    return trimmed.replace(/^https?:\/\//, '').split('/')[0] ?? ''
  }
}

/**
 * 规范化用户输入的 URL。
 * 仅接受 http / https，避免把 javascript: 之类的协议交给系统浏览器打开。
 */
export function normalizeUrl(url: string): string | null {
  const trimmed = url.trim()
  if (!trimmed) return null
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  try {
    const parsed = new URL(withScheme)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
    return parsed.toString()
  } catch {
    return null
  }
}

/** 取标题首字符作为列表头像文字。 */
export function initialOf(text: string): string {
  const t = text.trim()
  if (!t) return '?'
  const first = Array.from(t)[0]
  return first ? first.toUpperCase() : '?'
}

/** 基于字符串生成稳定的头像配色索引。 */
export function hueOf(text: string): number {
  let h = 0
  for (let i = 0; i < text.length; i++) {
    h = (h * 31 + text.charCodeAt(i)) % 360
  }
  return h
}

/** 强度分值与中文标签。 */
export const STRENGTH_LABELS = ['极弱', '弱', '一般', '强', '极强'] as const

/** 强度分值对应的颜色变量。 */
export function strengthColor(score: number): string {
  switch (score) {
    case 0:
      return 'var(--app-danger)'
    case 1:
      return 'oklch(0.68 0.18 45)'
    case 2:
      return 'var(--app-warn)'
    case 3:
      return 'oklch(0.72 0.15 155)'
    default:
      return 'var(--app-ok)'
  }
}

/** 严重程度对应的中文与颜色。 */
export function severityMeta(severity: string): { label: string; color: string } {
  switch (severity) {
    case 'high':
      return { label: '高危', color: 'var(--app-danger)' }
    case 'medium':
      return { label: '中等', color: 'var(--app-warn)' }
    default:
      return { label: '提示', color: 'var(--app-text-muted)' }
  }
}

/** 风险类型的中文名称。 */
export function issueKindLabel(kind: string): string {
  switch (kind) {
    case 'weak':
      return '弱密码'
    case 'reused':
      return '重复使用'
    case 'empty':
      return '未设置密码'
    case 'old':
      return '长期未更新'
    case 'short':
      return '长度偏短'
    default:
      return '风险项'
  }
}

/** 隐藏敏感文本的占位符。 */
export function maskSecret(length: number): string {
  const n = Math.min(Math.max(length, 8), 24)
  return '•'.repeat(n)
}

/** 把字节数格式化为可读大小。 */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

/** 复制文本到剪贴板（用于非敏感字段，如用户名/网址）。 */
export async function copyPlainText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}
