<script setup lang="ts">
/**
 * 主界面外壳：侧边栏导航 + 条目列表 + 详情区，并注册全局快捷键。
 *
 * 快捷键：
 *   Ctrl/Cmd + K  聚焦搜索
 *   Ctrl/Cmd + N  新建条目
 *   Ctrl/Cmd + L  立即锁定
 *   Esc           清空搜索 / 取消选中
 */
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useVault, type NavMode } from '../stores/vault'
import { toast } from '../stores/toast'
import EntryList from './EntryList.vue'
import EntryDetail from './EntryDetail.vue'
import SecurityPanel from './SecurityPanel.vue'
import SettingsPanel from './SettingsPanel.vue'
import PasswordGeneratorPanel from './PasswordGeneratorPanel.vue'

const vault = useVault()

const listRef = ref<InstanceType<typeof EntryList> | null>(null)

const navItems: { key: NavMode; label: string; icon: string }[] = [
  { key: 'all', label: '全部条目', icon: 'list' },
  { key: 'favorites', label: '收藏', icon: 'star' },
  { key: 'security', label: '安全体检', icon: 'shield' },
  { key: 'generator', label: '密码生成器', icon: 'spark' },
  { key: 'settings', label: '设置', icon: 'gear' },
]

const nav = computed(() => vault.state.nav)

/** 中间栏是否显示条目列表（体检/生成器/设置页不需要）。 */
const showList = computed(() => nav.value === 'all' || nav.value === 'favorites')

/** 右侧详情是否需要显示（体检/生成器/设置占满右侧）。 */
const showDetail = computed(() => showList.value)

const clipboardNotice = computed(() => vault.state.clipboardNotice)

async function doLock(): Promise<void> {
  await vault.lock()
  toast.info('保险库已锁定')
}

function onKeydown(e: KeyboardEvent): void {
  const mod = e.ctrlKey || e.metaKey
  if (mod && e.key.toLowerCase() === 'k') {
    e.preventDefault()
    vault.setNav('all')
    // 等待渲染出列表后再聚焦搜索框。
    window.setTimeout(() => listRef.value?.focusSearch(), 0)
  } else if (mod && e.key.toLowerCase() === 'n') {
    e.preventDefault()
    vault.openEditor({ id: null })
  } else if (mod && e.key.toLowerCase() === 'l') {
    e.preventDefault()
    void doLock()
  } else if (e.key === 'Escape') {
    if (vault.state.editor) {
      vault.closeEditor()
    } else if (vault.state.search) {
      vault.setSearch('')
    } else if (vault.state.selectedId) {
      void vault.selectEntry(null)
    }
  }
}

onMounted(() => window.addEventListener('keydown', onKeydown))
onUnmounted(() => window.removeEventListener('keydown', onKeydown))

const navIconPaths: Record<string, string> = {
  list: 'M4 6h16M4 12h16M4 18h10',
  star: 'M12 3.6l2.6 5.3 5.8.8-4.2 4.1 1 5.8-5.2-2.7-5.2 2.7 1-5.8L3.6 9.7l5.8-.8z',
  shield: 'M12 3l7 3v6c0 4.2-2.9 7.6-7 9-4.1-1.4-7-4.8-7-9V6z',
  spark: 'M12 3v4M12 17v4M3 12h4M17 12h4M6.3 6.3l2.8 2.8M14.9 14.9l2.8 2.8M17.7 6.3l-2.8 2.8M9.1 14.9l-2.8 2.8',
  gear: 'M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zM19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2v.2a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-2.9-1.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1A1.7 1.7 0 0 0 3 15h-.2a2 2 0 1 1 0-4h.1A1.7 1.7 0 0 0 4.2 8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1A1.7 1.7 0 0 0 9.9 4V3.8a2 2 0 1 1 4 0V4a1.7 1.7 0 0 0 2.9 1.2l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0 1.2 2.9h.2a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z',
}

function badgeFor(key: NavMode): number {
  if (key === 'all') return vault.state.entries.length
  if (key === 'favorites') return vault.favoriteCount.value
  if (key === 'security') return vault.riskCount.value
  return 0
}

async function copyAllTagsTitle(tag: string): Promise<void> {
  vault.setActiveTag(vault.state.activeTag === tag ? '' : tag)
  vault.setNav('all')
}
</script>

<template>
  <div class="flex h-full min-h-0">
    <!-- 侧边栏 -->
    <aside
      class="flex w-60 shrink-0 flex-col border-r"
      style="border-color: var(--app-border); background: var(--app-bg-elevated)"
    >
      <!-- 品牌 -->
      <div class="flex items-center gap-2.5 px-4 py-4">
        <div
          class="flex h-9 w-9 items-center justify-center rounded-xl"
          style="background: color-mix(in oklab, var(--app-accent) 18%, transparent)"
        >
          <svg
            viewBox="0 0 24 24"
            class="h-5 w-5"
            fill="none"
            stroke="var(--app-accent)"
            stroke-width="1.7"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <rect x="4" y="10.5" width="16" height="10" rx="2.5" />
            <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
          </svg>
        </div>
        <div class="min-w-0">
          <div class="truncate text-sm font-semibold">ck-pd</div>
          <div class="truncate text-[11px] text-muted">本地加密密码库</div>
        </div>
      </div>

      <!-- 导航 -->
      <nav class="px-2">
        <button
          v-for="item in navItems"
          :key="item.key"
          class="mb-0.5 flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-colors"
          :style="
            nav === item.key
              ? {
                  background: 'color-mix(in oklab, var(--app-accent) 18%, transparent)',
                  color: 'var(--app-accent)',
                }
              : {}
          "
          :class="nav === item.key ? 'font-medium' : ''"
          @click="vault.setNav(item.key)"
        >
          <svg
            viewBox="0 0 24 24"
            class="h-4 w-4 shrink-0"
            fill="none"
            stroke="currentColor"
            stroke-width="1.7"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <path :d="navIconPaths[item.icon]" />
          </svg>
          <span class="flex-1 text-left">{{ item.label }}</span>
          <span
            v-if="badgeFor(item.key) > 0"
            class="rounded-full px-1.5 py-0.5 text-[10px] font-medium"
            :style="{
              background:
                item.key === 'security'
                  ? 'color-mix(in oklab, var(--app-danger) 22%, transparent)'
                  : 'color-mix(in oklab, var(--app-text) 12%, transparent)',
              color: item.key === 'security' ? 'var(--app-danger)' : 'var(--app-text-muted)',
            }"
          >
            {{ badgeFor(item.key) }}
          </span>
        </button>
      </nav>

      <!-- 标签 -->
      <div v-if="vault.state.tags.length" class="mt-4 min-h-0 flex-1 overflow-y-auto px-4">
        <div class="mb-2 text-[11px] font-medium tracking-wide text-muted uppercase">标签</div>
        <div class="flex flex-wrap gap-1.5">
          <button
            v-for="t in vault.state.tags"
            :key="t"
            class="chip cursor-pointer"
            :style="
              vault.state.activeTag === t
                ? { borderColor: 'var(--app-accent)', color: 'var(--app-accent)' }
                : {}
            "
            @click="copyAllTagsTitle(t)"
          >
            {{ t }}
          </button>
        </div>
      </div>
      <div v-else class="flex-1" />

      <!-- 底部操作 -->
      <div class="space-y-2 border-t p-3" style="border-color: var(--app-border)">
        <div v-if="clipboardNotice" class="rounded-lg px-2.5 py-2 text-[11px]" style="background: var(--app-bg-panel)">
          <p>{{ clipboardNotice.text }}</p>
          <button class="mt-1 text-muted underline" @click="vault.dismissClipboardNotice()">
            知道了
          </button>
        </div>

        <button class="btn btn-primary w-full" @click="vault.openEditor({ id: null })">
          <svg
            viewBox="0 0 24 24"
            class="h-4 w-4"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
          >
            <path d="M12 5v14M5 12h14" />
          </svg>
          新建条目
        </button>

        <button class="btn btn-ghost w-full" @click="doLock">
          <svg
            viewBox="0 0 24 24"
            class="h-4 w-4"
            fill="none"
            stroke="currentColor"
            stroke-width="1.7"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <rect x="4" y="10.5" width="16" height="10" rx="2.5" />
            <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
          </svg>
          立即锁定
          <kbd class="ml-auto text-[10px] text-muted">Ctrl+L</kbd>
        </button>

        <p v-if="vault.autoLockEnabled.value" class="text-center text-[10px] text-muted">
          闲置 {{ vault.state.settings?.autoLockMinutes }} 分钟自动锁定
        </p>
      </div>
    </aside>

    <!-- 条目列表 -->
    <section
      v-if="showList"
      class="flex w-[330px] shrink-0 flex-col border-r"
      style="border-color: var(--app-border); background: var(--app-bg-panel)"
    >
      <EntryList ref="listRef" />
    </section>

    <!-- 右侧内容 -->
    <main class="min-w-0 flex-1" style="background: var(--app-bg)">
      <EntryDetail v-if="showDetail" />
      <SecurityPanel v-else-if="nav === 'security'" />
      <div v-else-if="nav === 'generator'" class="min-h-0 flex-1 overflow-y-auto p-5">
        <h2 class="mb-4 text-lg font-semibold">密码生成器</h2>
        <div class="mx-auto max-w-2xl">
          <PasswordGeneratorPanel />
        </div>
      </div>
      <SettingsPanel v-else-if="nav === 'settings'" />
    </main>
  </div>
</template>
