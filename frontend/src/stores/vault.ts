/**
 * 全局状态：保险库会话、条目列表、筛选与设置。
 *
 * 安全设计要点：
 *  1. 前端状态里永远不保存明文密码。密码只通过 CopyEntryField 在 Go 侧
 *     直接写入剪贴板，或通过 RevealPassword 按需返回给某个组件并在
 *     组件卸载 / 锁定时立即丢弃。
 *  2. 保险库被 Go 侧锁定（闲置、最小化、手动）时，通过事件通知前端，
 *     前端立刻清空所有列表数据，避免锁定后界面仍显示条目信息。
 *  3. 前端也实现了本地闲置倒计时作为「深度防御」：即使 Go 看门狗的
 *     事件丢失，界面也会在超时后主动清空并回到解锁页。
 */
import { computed, reactive, readonly } from 'vue'
import * as App from '../../wailsjs/go/main/App'
import { BrowserOpenURL, EventsOn } from '../../wailsjs/runtime/runtime'
import type { main, vault, gen, strength } from '../../wailsjs/go/models'
import { errorMessage, withSecret } from '../utils/errors'

export type SecurityFilter = 'all' | 'weak' | 'reused' | 'empty'
export type NavMode = 'all' | 'favorites' | 'security' | 'generator' | 'settings'

export interface EditorRequest {
  /** 为 null 表示新建条目。 */
  id: string | null
  /** 新建时可直接预填密码（来自生成器）。 */
  presetPassword?: string
}

interface VaultState {
  ready: boolean
  locked: boolean
  configured: boolean
  busy: boolean
  /** 当前界面的顶层模式。 */
  nav: NavMode
  entries: vault.Summary[]
  tags: string[]
  status: vault.Status | null
  appInfo: main.AppInfo | null
  settings: main.Settings | null
  search: string
  activeTag: string
  securityFilter: SecurityFilter
  selectedId: string | null
  detail: vault.Detail | null
  editor: EditorRequest | null
  security: vault.Report | null
  securityLoading: boolean
  /** 复制后的提示（例如「已复制，30 秒后自动清除」）。 */
  clipboardNotice: { text: string; at: number } | null
}

const state = reactive<VaultState>({
  ready: false,
  locked: true,
  configured: false,
  busy: false,
  nav: 'all',
  entries: [],
  tags: [],
  status: null,
  appInfo: null,
  settings: null,
  search: '',
  activeTag: '',
  securityFilter: 'all',
  selectedId: null,
  detail: null,
  editor: null,
  security: null,
  securityLoading: false,
  clipboardNotice: null,
})

// ---------------------------------------------------------------------------
// 主题
// ---------------------------------------------------------------------------

let themeMedia: MediaQueryList | null = null

/** 应用主题到 <html data-theme>。 */
export function applyTheme(mode: string): void {
  const root = document.documentElement
  const resolved =
    mode === 'system'
      ? (themeMedia?.matches ?? window.matchMedia('(prefers-color-scheme: light)').matches)
        ? 'light'
        : 'dark'
      : mode
  root.setAttribute('data-theme', resolved === 'light' ? 'light' : 'dark')
}

/** 监听系统主题变化，仅在 mode 为 system 时生效。 */
function watchSystemTheme(): void {
  themeMedia = window.matchMedia('(prefers-color-scheme: light)')
  themeMedia.addEventListener('change', () => {
    if ((state.settings?.theme ?? 'system') === 'system') applyTheme('system')
  })
}

// ---------------------------------------------------------------------------
// 闲置与自动锁定（前端侧深度防御）
// ---------------------------------------------------------------------------

let lastFrontendActivity = Date.now()
let watchdogTimer: number | null = null
let pingTimer: number | null = null

/** 记录一次用户活动。 */
export function markActivity(): void {
  lastFrontendActivity = Date.now()
  void App.NotifyActivity().catch(() => undefined)
}

/**
 * 启动前端看门狗与心跳。
 *
 * 心跳（Ping）会让 Go 侧刷新活动时间，因此只要用户真的在操作界面，
 * 后端就不会误判闲置；反过来当前端长时间没有活动时，前端自己也会
 * 主动调用 Lock，形成两道防线。
 */
function startWatchdog(): void {
  stopWatchdog()

  // 每 20 秒向 Go 侧确认一次「用户仍在活动」，同时同步解锁状态。
  pingTimer = window.setInterval(async () => {
    try {
      const unlocked = await App.Ping()
      if (!unlocked && !state.locked) {
        await handleLocked('会话已失效')
      }
    } catch {
      // 心跳失败不打断用户操作；下一次 tick 会重试。
    }
  }, 20_000)

  // 每 15 秒检查一次前端侧的闲置时长。
  watchdogTimer = window.setInterval(async () => {
    if (state.locked) return
    const limitMs = (state.settings?.autoLockMinutes ?? 0) * 60_000
    if (limitMs <= 0) return
    if (Date.now() - lastFrontendActivity >= limitMs) {
      try {
        await App.Lock()
      } catch {
        // 忽略：即便调用失败，Go 看门狗也会独立完成锁定。
      }
      await handleLocked('界面长时间无操作，已锁定')
    }
  }, 15_000)
}

function stopWatchdog(): void {
  if (pingTimer !== null) {
    window.clearInterval(pingTimer)
    pingTimer = null
  }
  if (watchdogTimer !== null) {
    window.clearInterval(watchdogTimer)
    watchdogTimer = null
  }
}

// ---------------------------------------------------------------------------
// 锁定处理
// ---------------------------------------------------------------------------

/**
 * 统一处理锁定：清空所有解密后的状态，回到解锁界面。
 *
 * 这里会同时清空 detail（含备注）与 entries（含用户名等元数据），
 * 避免用户离开工位后屏幕上仍留有账号信息。
 */
async function handleLocked(_reason: string): Promise<void> {
  state.locked = true
  state.entries = []
  state.tags = []
  state.detail = null
  state.selectedId = null
  state.search = ''
  state.activeTag = ''
  state.security = null
  state.securityFilter = 'all'
  state.nav = 'all'
  state.editor = null
  state.clipboardNotice = null
  stopWatchdog()
}

// ---------------------------------------------------------------------------
// 数据加载
// ---------------------------------------------------------------------------

/** 刷新保险库状态与条目列表。 */
async function refresh(): Promise<void> {
  const status = await App.GetStatus()
  state.status = status
  state.configured = status.configured
  state.locked = !status.unlocked

  if (!status.unlocked) {
    state.entries = []
    state.tags = []
    state.detail = null
    state.security = null
    return
  }

  const [entries, tags] = await Promise.all([App.ListEntries(), App.GetAllTags()])
  state.entries = entries ?? []
  state.tags = tags ?? []

  // 若当前选中的条目已被删除，清空详情。
  if (state.selectedId && !state.entries.some((e) => e.id === state.selectedId)) {
    state.selectedId = null
    state.detail = null
  }
}

/** 加载应用信息与设置（不依赖解锁状态）。 */
async function loadAppInfo(): Promise<void> {
  const info = await App.GetAppInfo()
  state.appInfo = info
  state.settings = info.settings
  applyTheme(info.settings.theme)
}

/** 初始化：订阅后端事件并加载基础数据。 */
export async function initVault(): Promise<void> {
  watchSystemTheme()

  // 后端锁定事件：无论何种原因（手动 / 闲置 / 最小化 / 恢复备份）都清空界面。
  // 这里使用静态导入，避免同一模块既静态又动态引入造成打包警告。
  EventsOn('vault:locked', () => {
    void handleLocked('保险库已锁定')
  })
  EventsOn('vault:auto-locked', (payload: { message?: string }) => {
    if (payload?.message) {
      state.clipboardNotice = { text: payload.message, at: Date.now() }
    }
  })
  EventsOn('clipboard:cleared', (payload: { message?: string }) => {
    state.clipboardNotice = {
      text: payload?.message ?? '剪贴板已清除',
      at: Date.now(),
    }
  })

  // 用户活动监听：keydown 等事件在 App.vue 中也用于快捷键，
  // 这里只负责刷新活动时间。
  const activityEvents: (keyof WindowEventMap)[] = ['mousedown', 'keydown', 'wheel', 'mousemove']
  activityEvents.forEach((evt) =>
    window.addEventListener(evt, () => markActivity(), { passive: true }),
  )

  // 窗口失焦 / 最小化时按设置锁定（由 Go 侧判断设置是否开启）。
  window.addEventListener('blur', () => {
    void App.LockIfBlurred().catch(() => undefined)
  })
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      void App.LockIfMinimized().catch(() => undefined)
    }
  })

  try {
    await loadAppInfo()
    await refresh()
    if (!state.locked) startWatchdog()
  } finally {
    state.ready = true
  }

  window.addEventListener('beforeunload', () => {
    stopWatchdog()
  })
}

// ---------------------------------------------------------------------------
// 解锁 / 创建 / 锁定
// ---------------------------------------------------------------------------

/** 创建保险库。 */
async function createVault(password: string): Promise<void> {
  state.busy = true
  try {
    await withSecret(password, (bytes) => App.CreateVault(Array.from(bytes)))
    await loadAppInfo()
    await refresh()
    startWatchdog()
  } finally {
    state.busy = false
  }
}

/** 解锁保险库。 */
async function unlock(password: string): Promise<void> {
  state.busy = true
  try {
    await withSecret(password, (bytes) => App.Unlock(Array.from(bytes)))
    await refresh()
    startWatchdog()
  } finally {
    state.busy = false
  }
}

/** 手动锁定。 */
async function lock(): Promise<void> {
  try {
    await App.Lock()
  } finally {
    await handleLocked('已手动锁定')
  }
}

// ---------------------------------------------------------------------------
// 条目操作
// ---------------------------------------------------------------------------

/** 选中一个条目并加载详情。 */
async function selectEntry(id: string | null): Promise<void> {
  state.selectedId = id
  if (!id) {
    state.detail = null
    return
  }
  state.detail = await App.GetEntry(id)
  if (state.nav === 'security') state.nav = 'all'
}

/** 保存条目（新建或更新）。 */
async function saveEntry(input: vault.EntryInput): Promise<string> {
  const id = await App.SaveEntry(input)
  await refresh()
  state.selectedId = id
  state.detail = await App.GetEntry(id)
  state.editor = null
  return id
}

/** 删除条目。 */
async function deleteEntry(id: string): Promise<void> {
  await App.DeleteEntry(id)
  if (state.selectedId === id) {
    state.selectedId = null
    state.detail = null
  }
  if (state.security) state.security = null
  await refresh()
}

/** 切换收藏。 */
async function toggleFavorite(id: string): Promise<void> {
  await App.ToggleFavorite(id)
  await refresh()
  if (state.selectedId === id) {
    state.detail = await App.GetEntry(id)
  }
  if (state.security) state.security = null
}

/**
 * 复制字段到剪贴板。
 *
 * 密码类字段的明文完全不出 Go 进程：这里只传条目 id 与字段名，
 * 由后端读取明文并直接写入系统剪贴板。
 */
async function copyField(id: string, field: 'password' | 'username' | 'url' | 'totp'): Promise<void> {
  const res = await App.CopyEntryField(id, field)
  state.clipboardNotice = { text: res.message, at: Date.now() }
}

/** 立即清空剪贴板。 */
async function clearClipboard(): Promise<boolean> {
  const done = await App.ClearClipboard()
  state.clipboardNotice = {
    text: done ? '剪贴板已清空' : '剪贴板内容不是本程序写入的，未做修改',
    at: Date.now(),
  }
  return done
}

/** 在系统浏览器中打开条目的网址。 */
function openUrl(url: string): void {
  BrowserOpenURL(url)
}

// ---------------------------------------------------------------------------
// 安全体检
// ---------------------------------------------------------------------------

/** 运行安全体检。 */
async function runSecurityCheck(): Promise<void> {
  state.securityLoading = true
  try {
    state.security = await App.AnalyzeSecurity()
  } finally {
    state.securityLoading = false
  }
}

// ---------------------------------------------------------------------------
// 设置
// ---------------------------------------------------------------------------

/** 保存设置。 */
async function saveSettings(patch: Partial<main.Settings>): Promise<void> {
  if (!state.settings) return
  const merged = { ...state.settings, ...patch } as main.Settings
  const saved = await App.SaveSettings(merged)
  state.settings = saved
  if (patch.theme !== undefined) applyTheme(saved.theme)
}

// ---------------------------------------------------------------------------
// 派生数据
// ---------------------------------------------------------------------------

/** 是否配置了自动锁定。 */
const autoLockEnabled = computed(() => (state.settings?.autoLockMinutes ?? 0) > 0)

/** 当前应展示的条目列表（已应用搜索、标签、安全筛选与排序）。 */
const visibleEntries = computed(() => {
  const q = state.search.trim().toLowerCase()
  let list = state.entries.slice()

  if (state.nav === 'favorites') {
    list = list.filter((e) => e.favorite)
  }

  if (state.activeTag) {
    list = list.filter((e) => (e.tags ?? []).includes(state.activeTag))
  }

  switch (state.securityFilter) {
    case 'weak':
      list = list.filter((e) => e.passwordWeak)
      break
    case 'reused':
      list = list.filter((e) => e.passwordReusedCount > 1)
      break
    case 'empty':
      list = list.filter((e) => e.passwordEmpty)
      break
    default:
      break
  }

  if (q) {
    // 搜索范围刻意不包含密码本身——前端根本拿不到密码。
    list = list.filter((e) => {
      const haystack = [e.title, e.username, e.url, ...(e.tags ?? [])].join(' ').toLowerCase()
      return haystack.includes(q)
    })
  }

  const mode = state.settings?.sortMode ?? 'updated'
  list.sort((a, b) => {
    // 收藏条目始终置顶，其余按所选模式排序。
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1
    switch (mode) {
      case 'title':
        return a.title.localeCompare(b.title, 'zh-Hans-CN')
      case 'created':
        return b.created - a.created
      default:
        return b.updated - a.updated
    }
  })

  return list
})

/** 风险条目数量，用于侧边栏角标。 */
const riskCount = computed(
  () =>
    state.entries.filter((e) => e.passwordWeak || e.passwordReusedCount > 1 || e.passwordEmpty)
      .length,
)

/** 收藏数量。 */
const favoriteCount = computed(() => state.entries.filter((e) => e.favorite).length)

// ---------------------------------------------------------------------------
// 对外接口
// ---------------------------------------------------------------------------

export function useVault() {
  return {
    state,
    // 只读派生数据
    visibleEntries,
    riskCount,
    favoriteCount,
    autoLockEnabled,
    // 生命周期
    initVault,
    refresh,
    createVault,
    unlock,
    lock,
    // 条目
    selectEntry,
    saveEntry,
    deleteEntry,
    toggleFavorite,
    copyField,
    clearClipboard,
    openUrl,
    // 安全
    runSecurityCheck,
    // 设置
    saveSettings,
    // 通用
    markActivity,
    setNav(nav: NavMode) {
      state.nav = nav
      if (nav === 'security' && !state.security) void runSecurityCheck()
      if (nav !== 'security') state.securityFilter = 'all'
    },
    openEditor(req: EditorRequest) {
      state.editor = req
    },
    closeEditor() {
      state.editor = null
    },
    setSearch(v: string) {
      state.search = v
    },
    setActiveTag(tag: string) {
      state.activeTag = tag
    },
    setSecurityFilter(f: SecurityFilter) {
      state.securityFilter = f
      state.nav = f === 'all' ? 'all' : 'security'
      if (state.nav === 'security' && !state.security) void runSecurityCheck()
    },
    dismissClipboardNotice() {
      state.clipboardNotice = null
    },
  }
}

/** 只读状态视图，供不希望误改状态的组件使用。 */
export const readonlyState = readonly(state)

/** 供错误提示统一使用的包装，避免每个调用点重复 try/catch。 */
export async function safe<T>(fn: () => Promise<T>): Promise<T | null> {
  try {
    return await fn()
  } catch (err) {
    throw new Error(errorMessage(err))
  }
}

/** 生成器选项类型别名，便于组件引用。 */
export type GeneratorOptions = gen.Options
/** 强度评估结果类型别名。 */
export type StrengthResult = strength.Result
