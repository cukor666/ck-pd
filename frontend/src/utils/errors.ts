/**
 * 错误处理与敏感数据清理工具。
 *
 * 安全约定：
 *  - 后端返回的错误信息已经做过脱敏，这里只做展示层包装；
 *  - 任何临时承载明文密码的 Uint8Array 必须在 finally 中清零。
 */

/** 把任意抛出物转换为中文提示文案。 */
export function errorMessage(err: unknown): string {
  if (err == null) return '发生未知错误'
  if (typeof err === 'string') return err
  if (err instanceof Error) return err.message || '发生未知错误'
  if (typeof err === 'object' && 'message' in err) {
    const m = (err as { message?: unknown }).message
    if (typeof m === 'string' && m) return m
  }
  try {
    const s = String(err)
    return s === '[object Object]' ? '发生未知错误' : s
  } catch {
    return '发生未知错误'
  }
}

/**
 * 把字符串编码为字节数组。
 * 调用方负责在使用后调用 zeroBytes 清零。
 */
export function toBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

/**
 * 清零字节数组。
 *
 * 注意：这只是尽力而为——JS 引擎可能在 GC 前复制过该缓冲区，
 * 因此它的作用是缩短敏感数据在内存中的存活窗口，而不是保证擦除。
 * 真正的安全边界在 Go 侧：前端从不持有长期存活的密钥。
 */
export function zeroBytes(buf: Uint8Array | null | undefined): void {
  if (!buf) return
  buf.fill(0)
}

/**
 * 在回调执行期间持有敏感字节，结束后无条件清零。
 * 用于把主密码交给 Go 绑定的场景。
 */
export async function withSecret<T>(
  secret: string,
  fn: (bytes: Uint8Array) => Promise<T>,
): Promise<T> {
  const bytes = toBytes(secret)
  try {
    return await fn(bytes)
  } finally {
    zeroBytes(bytes)
  }
}

/** 等待若干毫秒。 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
