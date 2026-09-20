<script setup lang="ts">
/**
 * 条目详情面板：展示条目信息并提供复制 / 显示 / 动态验证码操作。
 *
 * 明文密码处理：
 *  - 只有用户点击「显示」且（按设置）通过二次确认后，才调用 RevealPassword；
 *  - 返回的明文保存在本组件的局部 ref 中，切换条目、锁定或卸载时立即清空；
 *  - 「复制密码」完全不经过前端：由 Go 直接写入系统剪贴板。
 */
import { computed, onUnmounted, ref, watch } from 'vue'
import * as App from '../../wailsjs/go/main/App'
import type { main } from '../../wailsjs/go/models'
import { useVault } from '../stores/vault'
import { toast } from '../stores/toast'
import { errorMessage } from '../utils/errors'
import { formatDateTime, formatRelative, hostOf, hueOf, initialOf, maskSecret, normalizeUrl } from '../utils/format'
import ConfirmDialog from './ConfirmDialog.vue'

const vault = useVault()

const revealed = ref('')
const revealGeneration = ref(0)
const totp = ref<main.TOTPResult | null>(null)
const totpBusy = ref(false)
const totpRemaining = ref(0)
const confirmReveal = ref(false)
const confirmDelete = ref(false)
const busy = ref(false)

const detail = computed(() => vault.state.detail)

let totpTimer: number | null = null

/** 清空所有按需取回的敏感数据。 */
function clearSecrets(): void {
  revealed.value = ''
  totp.value = null
  totpRemaining.value = 0
}

/** 切换/关闭条目、以及保险库锁定时，必须丢弃明文。 */
watch(
  () => vault.state.selectedId,
  () => {
    clearSecrets()
    stopTotpTicker()
  },
)

watch(
  () => vault.state.locked,
  (locked) => {
    if (locked) clearSecrets()
  },
)

onUnmounted(() => {
  clearSecrets()
  stopTotpTicker()
})

// ---------------------------------------------------------------------------
// 显示密码
// ---------------------------------------------------------------------------

async function doReveal(): Promise<void> {
  const d = detail.value
  if (!d) return
  try {
    const res = await App.RevealPassword(d.id)
    // 校验解锁代数：若期间发生过锁定，返回的数据必须丢弃。
    const current = await App.CurrentGeneration()
    if (res.generation !== current || vault.state.locked) {
      clearSecrets()
      toast.warn('保险库状态已变化，已丢弃本次读取结果')
      return
    }
    revealed.value = res.value
    revealGeneration.value = res.generation
  } catch (err) {
    toast.error(errorMessage(err))
  }
}

function onRevealClick(): void {
  if (revealed.value) {
    revealed.value = ''
    return
  }
  if (vault.state.settings?.revealNeedsConfirm) {
    confirmReveal.value = true
    return
  }
  void doReveal()
}

// ---------------------------------------------------------------------------
// 复制（全部在 Go 侧完成）
// ---------------------------------------------------------------------------

async function copy(field: 'password' | 'username' | 'url' | 'totp'): Promise<void> {
  const d = detail.value
  if (!d) return
  try {
    await vault.copyField(d.id, field)
  } catch (err) {
    toast.error(errorMessage(err))
  }
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

function stopTotpTicker(): void {
  if (totpTimer !== null) {
    window.clearInterval(totpTimer)
    totpTimer = null
  }
}

/** 加载验证码，并在剩余秒数归零后自动刷新。 */
async function loadTOTP(): Promise<void> {
  const d = detail.value
  if (!d?.hasTotp) {
    totp.value = null
    stopTotpTicker()
    return
  }
  totpBusy.value = true
  try {
    const res = await App.GetTOTPCode(d.id)
    // 同样校验解锁代数，避免锁定后把验证码留在界面上。
    if (vault.state.locked) {
      totp.value = null
      return
    }
    totp.value = res
    totpRemaining.value = res.remaining
    stopTotpTicker()
    totpTimer = window.setInterval(() => {
      totpRemaining.value -= 1
      if (totpRemaining.value <= 0) {
        void loadTOTP()
      }
    }, 1000)
  } catch (err) {
    toast.error(errorMessage(err))
    totp.value = null
  } finally {
    totpBusy.value = false
  }
}

/** 剩余时间进度百分比，用于环形/条形指示。 */
const totpPercent = computed(() => {
  const period = totp.value?.period ?? 30
  return Math.max(0, Math.min(100, (totpRemaining.value / period) * 100))
})

// ---------------------------------------------------------------------------
// 其他操作
// ---------------------------------------------------------------------------

function openSite(): void {
  const d = detail.value
  if (!d?.url) return
  const safe = normalizeUrl(d.url)
  if (!safe) {
    toast.error('该条目的网址不是有效的 http/https 链接')
    return
  }
  vault.openUrl(safe)
}

async function toggleFavorite(): Promise<void> {
  const d = detail.value
  if (!d) return
  busy.value = true
  try {
    await vault.toggleFavorite(d.id)
  } catch (err) {
    toast.error(errorMessage(err))
  } finally {
    busy.value = false
  }
}

async function remove(): Promise<void> {
  const d = detail.value
  if (!d) return
  busy.value = true
  try {
    await vault.deleteEntry(d.id)
    toast.success('条目已删除')
    confirmDelete.value = false
  } catch (err) {
    toast.error(errorMessage(err))
  } finally {
    busy.value = false
  }
}

/** 复制用户名或网址（非敏感，走系统剪贴板 API 即可）。 */
async function copyPlain(value: string, label: string): Promise<void> {
  if (!value) return
  try {
    await navigator.clipboard.writeText(value)
    toast.success(`已复制${label}`)
  } catch {
    toast.error('复制失败，请手动选择文本')
  }
}
</script>

<template>
  <div class="flex h-full min-h-0 flex-col">
    <!-- 空状态 -->
    <div v-if="!detail" class="flex flex-1 items-center justify-center p-8 text-center">
      <div>
        <svg
          viewBox="0 0 24 24"
          class="mx-auto mb-3 h-10 w-10 text-muted"
          fill="none"
          stroke="currentColor"
          stroke-width="1.4"
          stroke-linecap="round"
        >
          <rect x="4" y="10.5" width="16" height="10" rx="2.5" />
          <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
        </svg>
        <p class="text-sm text-muted">从左侧选择一个条目查看详情</p>
        <p class="mt-1 text-xs text-muted">快捷键：Ctrl+K 搜索，Ctrl+N 新建</p>
      </div>
    </div>

    <template v-else>
      <!-- 头部 -->
      <header class="border-b px-5 py-4" style="border-color: var(--app-border)">
        <div class="flex items-start gap-3">
          <span
            class="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl text-lg font-semibold"
            :style="{
              background: `oklch(0.45 0.09 ${hueOf(detail.title || detail.id)})`,
              color: 'white',
            }"
          >
            {{ initialOf(detail.title) }}
          </span>
          <div class="min-w-0 flex-1">
            <h2 class="truncate text-lg font-semibold">{{ detail.title || '未命名条目' }}</h2>
            <p class="truncate text-xs text-muted">
              {{ hostOf(detail.url) || '未填写网址' }} · 更新于 {{ formatRelative(detail.updated) }}
            </p>
          </div>
          <div class="flex shrink-0 items-center gap-1">
            <button
              class="icon-btn"
              :title="detail.favorite ? '取消收藏' : '收藏'"
              :disabled="busy"
              @click="toggleFavorite"
            >
              <svg
                viewBox="0 0 24 24"
                class="h-4 w-4"
                :fill="detail.favorite ? 'var(--app-warn)' : 'none'"
                :stroke="detail.favorite ? 'var(--app-warn)' : 'currentColor'"
                stroke-width="1.6"
              >
                <path
                  d="M12 3.6l2.6 5.3 5.8.8-4.2 4.1 1 5.8-5.2-2.7-5.2 2.7 1-5.8L3.6 9.7l5.8-.8z"
                  stroke-linejoin="round"
                />
              </svg>
            </button>
            <button class="icon-btn" title="编辑" @click="vault.openEditor({ id: detail.id })">
              <svg
                viewBox="0 0 24 24"
                class="h-4 w-4"
                fill="none"
                stroke="currentColor"
                stroke-width="1.6"
                stroke-linecap="round"
                stroke-linejoin="round"
              >
                <path d="M4 20h4l10-10-4-4L4 16v4z" />
                <path d="M13.5 6.5l4 4" />
              </svg>
            </button>
            <button class="icon-btn" title="删除" @click="confirmDelete = true">
              <svg
                viewBox="0 0 24 24"
                class="h-4 w-4"
                fill="none"
                stroke="var(--app-danger)"
                stroke-width="1.6"
                stroke-linecap="round"
                stroke-linejoin="round"
              >
                <path d="M5 7h14M10 7V5h4v2M6.5 7l.8 12h9.4l.8-12" />
              </svg>
            </button>
          </div>
        </div>

        <!-- 风险提示 -->
        <div
          v-if="detail.passwordEmpty || detail.passwordWeak || detail.passwordReusedCount > 1"
          class="mt-3 rounded-lg px-3 py-2 text-xs"
          :style="{
            color:
              detail.passwordEmpty || detail.passwordReusedCount > 1
                ? 'var(--app-danger)'
                : 'var(--app-warn)',
            background:
              detail.passwordEmpty || detail.passwordReusedCount > 1
                ? 'color-mix(in oklab, var(--app-danger) 12%, transparent)'
                : 'color-mix(in oklab, var(--app-warn) 14%, transparent)',
          }"
        >
          <span v-if="detail.passwordEmpty">此条目尚未保存密码。</span>
          <span v-else-if="detail.passwordReusedCount > 1">
            该密码与另外 {{ detail.passwordReusedCount - 1 }} 个条目重复，建议为每个站点使用独立密码。
          </span>
          <span v-else>此密码强度偏低，建议点击「编辑」并使用生成器更换。</span>
        </div>
      </header>

      <!-- 内容 -->
      <div class="min-h-0 flex-1 space-y-4 overflow-y-auto p-5">
        <!-- 密码 -->
        <section class="panel p-3.5">
          <div class="mb-2 flex items-center justify-between">
            <span class="text-xs font-medium text-muted">密码</span>
            <span class="text-xs text-muted">{{ detail.passwordLength }} 位</span>
          </div>
          <div class="flex items-center gap-2">
            <div class="mono selectable flex-1 overflow-x-auto text-base whitespace-nowrap">
              {{ revealed || maskSecret(detail.passwordLength) }}
            </div>
            <button
              class="icon-btn"
              :title="revealed ? '隐藏密码' : '显示密码'"
              :disabled="detail.passwordEmpty"
              @click="onRevealClick"
            >
              <svg
                viewBox="0 0 24 24"
                class="h-4 w-4"
                fill="none"
                stroke="currentColor"
                stroke-width="1.6"
                stroke-linecap="round"
              >
                <path v-if="revealed" d="M3 3l18 18M10.6 10.6a2 2 0 0 0 2.8 2.8" />
                <path d="M2.5 12S6 5.5 12 5.5c1.6 0 3 .5 4.3 1.3M21.5 12s-1.6 3-4.4 4.6" />
              </svg>
            </button>
            <button
              class="btn btn-primary px-3 py-1.5 text-sm"
              :disabled="detail.passwordEmpty"
              title="密码由后端直接写入剪贴板，不会经过界面"
              @click="copy('password')"
            >
              复制密码
            </button>
          </div>
          <p v-if="revealed" class="mt-2 text-xs" style="color: var(--app-warn)">
            密码已显示在界面上，请注意周围环境；切换条目或锁定时会自动隐藏。
          </p>
          <p v-else class="mt-2 text-xs text-muted">
            复制操作在后台完成，明文密码不会出现在界面或前端存储中。
          </p>
        </section>

        <!-- 动态验证码 -->
        <section v-if="detail.hasTotp" class="panel p-3.5">
          <div class="mb-2 flex items-center justify-between">
            <span class="text-xs font-medium text-muted">
              两步验证码
              <span v-if="detail.totpIssuer"> · {{ detail.totpIssuer }}</span>
            </span>
            <span class="text-xs text-muted">
              {{ detail.totpAlgorithm || 'SHA1' }} / {{ detail.totpDigits || 6 }} 位
            </span>
          </div>

          <div v-if="totp" class="flex items-center gap-3">
            <span class="mono selectable text-2xl font-semibold tracking-[0.2em]">
              {{ totp.code.slice(0, Math.ceil(totp.code.length / 2)) }}
              {{ totp.code.slice(Math.ceil(totp.code.length / 2)) }}
            </span>
            <div class="min-w-[90px] flex-1">
              <div class="h-1.5 overflow-hidden rounded-full" style="background: var(--app-border)">
                <div
                  class="h-full rounded-full transition-[width] duration-1000 ease-linear"
                  :style="{
                    width: `${totpPercent}%`,
                    background: totpRemaining <= 5 ? 'var(--app-danger)' : 'var(--app-accent)',
                  }"
                />
              </div>
              <p class="mt-1 text-xs text-muted">{{ totpRemaining }} 秒后刷新</p>
            </div>
            <button class="btn btn-ghost px-3 py-1.5 text-sm" @click="copy('totp')">复制</button>
          </div>

          <button
            v-else
            class="btn btn-ghost w-full"
            :disabled="totpBusy"
            @click="loadTOTP"
          >
            {{ totpBusy ? '正在生成…' : '显示验证码' }}
          </button>
        </section>

        <!-- 用户名 -->
        <section class="panel p-3.5">
          <div class="mb-1.5 text-xs font-medium text-muted">用户名 / 账号</div>
          <div class="flex items-center gap-2">
            <span class="selectable flex-1 truncate">{{ detail.username || '—' }}</span>
            <button
              class="icon-btn"
              title="复制用户名"
              :disabled="!detail.username"
              @click="copyPlain(detail.username, '用户名')"
            >
              <svg
                viewBox="0 0 24 24"
                class="h-4 w-4"
                fill="none"
                stroke="currentColor"
                stroke-width="1.6"
                stroke-linecap="round"
                stroke-linejoin="round"
              >
                <rect x="9" y="9" width="11" height="11" rx="2" />
                <path d="M15 5.5A2.5 2.5 0 0 0 12.5 3H6a2 2 0 0 0-2 2v7a2.5 2.5 0 0 0 2.5 2.5" />
              </svg>
            </button>
          </div>
        </section>

        <!-- 网址 -->
        <section class="panel p-3.5">
          <div class="mb-1.5 text-xs font-medium text-muted">网址</div>
          <div class="flex items-center gap-2">
            <span class="selectable flex-1 truncate text-sm">{{ detail.url || '—' }}</span>
            <button
              class="icon-btn"
              title="复制网址"
              :disabled="!detail.url"
              @click="copyPlain(detail.url, '网址')"
            >
              <svg
                viewBox="0 0 24 24"
                class="h-4 w-4"
                fill="none"
                stroke="currentColor"
                stroke-width="1.6"
                stroke-linecap="round"
                stroke-linejoin="round"
              >
                <rect x="9" y="9" width="11" height="11" rx="2" />
                <path d="M15 5.5A2.5 2.5 0 0 0 12.5 3H6a2 2 0 0 0-2 2v7a2.5 2.5 0 0 0 2.5 2.5" />
              </svg>
            </button>
            <button class="btn btn-ghost px-3 py-1.5 text-sm" :disabled="!detail.url" @click="openSite">
              打开
            </button>
          </div>
        </section>

        <!-- 标签 -->
        <section v-if="detail.tags?.length" class="panel p-3.5">
          <div class="mb-2 text-xs font-medium text-muted">标签</div>
          <div class="flex flex-wrap gap-1.5">
            <button
              v-for="t in detail.tags"
              :key="t"
              class="chip cursor-pointer"
              @click="vault.setActiveTag(t)"
            >
              {{ t }}
            </button>
          </div>
        </section>

        <!-- 备注 -->
        <section v-if="detail.notes" class="panel p-3.5">
          <div class="mb-1.5 text-xs font-medium text-muted">备注</div>
          <p class="selectable text-sm whitespace-pre-wrap">{{ detail.notes }}</p>
        </section>

        <!-- 元信息 -->
        <section class="panel p-3.5 text-xs text-muted">
          <div class="flex justify-between py-0.5">
            <span>创建时间</span><span>{{ formatDateTime(detail.created) }}</span>
          </div>
          <div class="flex justify-between py-0.5">
            <span>更新时间</span><span>{{ formatDateTime(detail.updated) }}</span>
          </div>
        </section>
      </div>
    </template>

    <!-- 二次确认：显示明文密码 -->
    <ConfirmDialog
      v-if="confirmReveal"
      title="确认显示明文密码"
      message="密码将以明文显示在屏幕上，请确认周围没有他人或录屏。"
      confirm-text="显示"
      @confirm="
        confirmReveal = false;
        void doReveal()
      "
      @cancel="confirmReveal = false"
    />

    <!-- 二次确认：删除条目 -->
    <ConfirmDialog
      v-if="confirmDelete"
      title="删除条目"
      :message="`确定要删除「${detail?.title || '未命名条目'}」吗？此操作不可撤销。`"
      confirm-text="删除"
      danger
      require-text="删除"
      @confirm="remove"
      @cancel="confirmDelete = false"
    />
  </div>
</template>
