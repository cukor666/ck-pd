<script setup lang="ts">
/**
 * 条目列表：包含搜索框、安全筛选与条目卡片。
 *
 * 列表中只展示非敏感字段（标题、用户名、网址、标签），
 * 密码长度与风险标记来自后端的非敏感视图。
 */
import { computed, ref } from 'vue'
import { useVault, type SecurityFilter } from '../stores/vault'
import { formatRelative, hostOf, hueOf, initialOf } from '../utils/format'

const vault = useVault()
const searchInput = ref<HTMLInputElement | null>(null)

const filters: { key: SecurityFilter; label: string }[] = [
  { key: 'all', label: '全部' },
  { key: 'weak', label: '弱密码' },
  { key: 'reused', label: '重复使用' },
  { key: 'empty', label: '未设置' },
]

const entries = vault.visibleEntries

const emptyHint = computed(() => {
  if (vault.state.search.trim()) return '没有匹配的条目'
  if (vault.state.activeTag) return `标签「${vault.state.activeTag}」下没有条目`
  if (vault.state.nav === 'favorites') return '还没有收藏的条目'
  if (vault.state.securityFilter !== 'all') return '该风险类型下没有条目'
  return '保险库还是空的，点击右上角「新建」添加第一个条目'
})

function riskLabel(e: { passwordWeak: boolean; passwordReusedCount: number; passwordEmpty: boolean }): string {
  if (e.passwordEmpty) return '未设置密码'
  if (e.passwordReusedCount > 1) return `与另外 ${e.passwordReusedCount - 1} 个条目重复`
  if (e.passwordWeak) return '弱密码'
  return ''
}

/** 暴露给父组件用于聚焦搜索框（快捷键 Ctrl+K）。 */
defineExpose({
  focusSearch: () => searchInput.value?.focus(),
})
</script>

<template>
  <div class="flex h-full min-h-0 flex-col">
    <!-- 搜索 -->
    <div class="border-b px-3 py-2.5" style="border-color: var(--app-border)">
      <div class="relative">
        <svg
          viewBox="0 0 24 24"
          class="pointer-events-none absolute top-1/2 left-2.5 h-4 w-4 -translate-y-1/2 text-muted"
          fill="none"
          stroke="currentColor"
          stroke-width="1.7"
          stroke-linecap="round"
        >
          <circle cx="11" cy="11" r="6.5" />
          <path d="M16 16l4.5 4.5" />
        </svg>
        <input
          ref="searchInput"
          :value="vault.state.search"
          class="field pl-8"
          placeholder="搜索标题、用户名、网址、标签…"
          spellcheck="false"
          @input="vault.setSearch(($event.target as HTMLInputElement).value)"
        />
        <button
          v-if="vault.state.search"
          class="icon-btn absolute top-1/2 right-1 h-7 w-7 -translate-y-1/2"
          title="清空搜索"
          @click="vault.setSearch('')"
        >
          <svg viewBox="0 0 20 20" class="h-3.5 w-3.5" fill="none" stroke="currentColor" stroke-width="1.8">
            <path d="M5 5l10 10M15 5L5 15" stroke-linecap="round" />
          </svg>
        </button>
      </div>

      <!-- 风险筛选 -->
      <div class="mt-2 flex flex-wrap gap-1.5">
        <button
          v-for="f in filters"
          :key="f.key"
          class="chip cursor-pointer"
          :style="
            vault.state.securityFilter === f.key
              ? {
                  borderColor: 'var(--app-accent)',
                  color: 'var(--app-accent)',
                  background: 'color-mix(in oklab, var(--app-accent) 12%, transparent)',
                }
              : {}
          "
          @click="vault.setSecurityFilter(f.key)"
        >
          {{ f.label }}
        </button>
        <button
          v-if="vault.state.activeTag"
          class="chip cursor-pointer"
          :style="{ borderColor: 'var(--app-accent)', color: 'var(--app-accent)' }"
          @click="vault.setActiveTag('')"
        >
          标签：{{ vault.state.activeTag }} ✕
        </button>
      </div>
    </div>

    <!-- 列表 -->
    <div class="min-h-0 flex-1 overflow-y-auto">
      <div v-if="!entries.length" class="p-6 text-center text-sm text-muted">
        {{ emptyHint }}
      </div>

      <ul v-else class="p-2">
        <li v-for="e in entries" :key="e.id">
          <button
            class="mb-1 w-full rounded-lg px-2.5 py-2 text-left transition-colors"
            :style="
              vault.state.selectedId === e.id
                ? { background: 'color-mix(in oklab, var(--app-accent) 16%, transparent)' }
                : {}
            "
            @mouseenter="
              ($event.currentTarget as HTMLElement).style.background =
                vault.state.selectedId === e.id
                  ? 'color-mix(in oklab, var(--app-accent) 16%, transparent)'
                  : 'color-mix(in oklab, var(--app-text) 6%, transparent)'
            "
            @mouseleave="
              ($event.currentTarget as HTMLElement).style.background =
                vault.state.selectedId === e.id
                  ? 'color-mix(in oklab, var(--app-accent) 16%, transparent)'
                  : ''
            "
            @click="vault.selectEntry(e.id)"
          >
            <div class="flex items-center gap-2.5">
              <!-- 头像：用标题首字符 + 稳定配色 -->
              <span
                class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-sm font-semibold"
                :style="{
                  background: `oklch(0.45 0.09 ${hueOf(e.title || e.id)})`,
                  color: 'white',
                }"
              >
                {{ initialOf(e.title) }}
              </span>

              <div class="min-w-0 flex-1">
                <div class="flex items-center gap-1.5">
                  <span class="truncate font-medium">{{ e.title || '未命名条目' }}</span>
                  <svg
                    v-if="e.favorite"
                    viewBox="0 0 24 24"
                    class="h-3.5 w-3.5 shrink-0"
                    fill="var(--app-warn)"
                    stroke="var(--app-warn)"
                    stroke-width="1.4"
                  >
                    <path
                      d="M12 3.6l2.6 5.3 5.8.8-4.2 4.1 1 5.8-5.2-2.7-5.2 2.7 1-5.8L3.6 9.7l5.8-.8z"
                      stroke-linejoin="round"
                    />
                  </svg>
                  <span
                    v-if="e.hasTotp"
                    class="chip shrink-0 px-1.5 py-0 text-[10px]"
                    title="已配置两步验证"
                  >
                    2FA
                  </span>
                </div>
                <div class="flex items-center gap-1.5 text-xs text-muted">
                  <span class="truncate">{{ e.username || hostOf(e.url) || '—' }}</span>
                </div>
              </div>

              <!-- 风险标记 -->
              <div class="flex shrink-0 items-center gap-1">
                <svg
                  v-if="e.passwordWeak || e.passwordReusedCount > 1 || e.passwordEmpty"
                  viewBox="0 0 24 24"
                  class="h-4 w-4"
                  fill="none"
                  :stroke="e.passwordEmpty || e.passwordReusedCount > 1 ? 'var(--app-danger)' : 'var(--app-warn)'"
                  stroke-width="1.7"
                  stroke-linecap="round"
                >
                  <path d="M12 4.5l8.5 15h-17z" stroke-linejoin="round" />
                  <path d="M12 10v4M12 16.6v.2" />
                </svg>
                <span class="text-[10px] text-muted">{{ formatRelative(e.updated) }}</span>
              </div>
            </div>

            <p
              v-if="riskLabel(e)"
              class="mt-1 pl-[42px] text-[11px]"
              :style="{
                color:
                  e.passwordEmpty || e.passwordReusedCount > 1
                    ? 'var(--app-danger)'
                    : 'var(--app-warn)',
              }"
            >
              {{ riskLabel(e) }}
            </p>
          </button>
        </li>
      </ul>
    </div>

    <footer
      class="border-t px-3 py-2 text-xs text-muted"
      style="border-color: var(--app-border)"
    >
      共 {{ vault.state.entries.length }} 条，当前显示 {{ entries.length }} 条
    </footer>
  </div>
</template>
