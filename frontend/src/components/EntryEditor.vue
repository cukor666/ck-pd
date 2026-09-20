<script setup lang="ts">
/**
 * 条目编辑器（新建 / 编辑）。
 *
 * 密码处理约定：
 *  - 编辑已有条目时默认不显示密码，只显示长度与「保留原密码」提示；
 *    用户点击「更换」后才进入新密码输入模式，避免无谓地把明文拉进界面。
 *  - 所有输入的明文只存在于本组件的局部 ref 中，关闭时立即清空。
 */
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import * as App from '../../wailsjs/go/main/App'
import { vault, strength } from '../../wailsjs/go/models'
import { useVault } from '../stores/vault'
import { toast } from '../stores/toast'
import { errorMessage } from '../utils/errors'
import { normalizeUrl } from '../utils/format'
import StrengthMeter from './StrengthMeter.vue'
import PasswordGeneratorPanel from './PasswordGeneratorPanel.vue'

const vaultStore = useVault()

const props = defineProps<{
  /** 为 null 表示新建。 */
  entryId: string | null
  /** 新建时可预填密码（例如来自生成器）。 */
  presetPassword?: string
}>()

const emit = defineEmits<{ (e: 'close'): void; (e: 'saved', id: string): void }>()

// 表单字段
const title = ref('')
const username = ref('')
const url = ref('')
const notes = ref('')
const tagsText = ref('')
const favorite = ref(false)

// 密码字段
const password = ref('')
const revealPassword = ref(false)
const changePassword = ref(false)
const strengthResult = ref<strength.Result | null>(null)
const generation = ref(0)

// TOTP
const totpEnabled = ref(false)
const totpSecret = ref('')
const totpAlgorithm = ref('SHA1')
const totpDigits = ref(6)
const totpPeriod = ref(30)
const totpIssuer = ref('')
const totpAccount = ref('')
const totpUri = ref('')
const hasExistingTotp = ref(false)

const loading = ref(true)
const saving = ref(false)
const errorText = ref('')

const isNew = computed(() => !props.entryId)
const titleInput = ref<HTMLInputElement | null>(null)

const dialogTitle = computed(() => (isNew.value ? '新建条目' : '编辑条目'))

/** 已存在条目的密码长度提示（不泄露内容）。 */
const existingPasswordLength = ref(0)

onMounted(async () => {
  if (props.entryId) {
    try {
      const d = await App.GetEntry(props.entryId)
      title.value = d.title
      username.value = d.username
      url.value = d.url
      notes.value = d.notes
      tagsText.value = (d.tags ?? []).join('，')
      favorite.value = d.favorite
      existingPasswordLength.value = d.passwordLength
      hasExistingTotp.value = d.hasTotp
      totpEnabled.value = d.hasTotp
      totpIssuer.value = d.totpIssuer ?? ''
      totpAccount.value = d.totpAccount ?? ''
      totpAlgorithm.value = d.totpAlgorithm || 'SHA1'
      totpDigits.value = d.totpDigits || 6
      totpPeriod.value = d.totpPeriod || 30
    } catch (err) {
      errorText.value = errorMessage(err)
    }
  } else if (props.presetPassword) {
    password.value = props.presetPassword
    changePassword.value = true
    generation.value = 1
  }
  loading.value = false
  titleInput.value?.focus()
  window.addEventListener('keydown', onKeydown)
})

onUnmounted(() => {
  window.removeEventListener('keydown', onKeydown)
  // 关闭时清空所有承载明文/密钥的局部状态。
  password.value = ''
  totpSecret.value = ''
  totpUri.value = ''
})

function onKeydown(e: KeyboardEvent): void {
  if (e.key === 'Escape') {
    e.stopPropagation()
    close()
  }
}

function close(): void {
  password.value = ''
  totpSecret.value = ''
  emit('close')
}

// 密码强度：仅在用户输入新密码时评估。
let evalTimer: number | null = null
watch(password, (value) => {
  generation.value++
  if (evalTimer !== null) window.clearTimeout(evalTimer)
  if (!value) {
    strengthResult.value = null
    return
  }
  evalTimer = window.setTimeout(async () => {
    try {
      strengthResult.value = await App.EvaluateStrength(value)
    } catch {
      strengthResult.value = null
    }
  }, 180)
})

/** 从生成器面板接收新生成的密码。 */
function onGenerated(value: string): void {
  password.value = value
  changePassword.value = true
  revealPassword.value = true
}

/** 解析粘贴的 otpauth:// URI。 */
async function applyUri(): Promise<void> {
  const raw = totpUri.value.trim()
  if (!raw) return
  try {
    const parsed = await App.ParseTOTPURI(raw)
    totpSecret.value = parsed.secret
    totpAlgorithm.value = parsed.algorithm
    totpDigits.value = parsed.digits
    totpPeriod.value = parsed.period
    if (parsed.issuer) totpIssuer.value = parsed.issuer
    if (parsed.account) totpAccount.value = parsed.account
    totpEnabled.value = true
    totpUri.value = ''
    toast.success('已从 otpauth 链接解析出验证码参数')
  } catch (err) {
    toast.error(errorMessage(err))
  }
}

/** 解析标签输入：支持中英文逗号、空格与分号分隔。 */
function parseTags(): string[] {
  return tagsText.value
    .split(/[,，;；\s]+/)
    .map((t) => t.trim())
    .filter(Boolean)
    .slice(0, 16)
}

async function save(): Promise<void> {
  errorText.value = ''
  if (!title.value.trim()) {
    errorText.value = '请填写标题'
    return
  }

  // URL 校验：只允许 http/https，避免把危险协议交给系统浏览器。
  let safeUrl = url.value.trim()
  if (safeUrl) {
    const normalized = normalizeUrl(safeUrl)
    if (!normalized) {
      errorText.value = '网址格式不正确，仅支持 http:// 或 https:// 链接'
      return
    }
    safeUrl = normalized
  }

  const input = new vault.EntryInput({
    id: props.entryId ?? '',
    title: title.value.trim(),
    username: username.value.trim(),
    url: safeUrl,
    notes: notes.value,
    tags: parseTags(),
    favorite: favorite.value,
    // 新建时没有原密码可保留，必须提交当前值。
    keepPassword: !isNew.value && !changePassword.value,
    password: changePassword.value || isNew.value ? password.value : '',
    clearTotp: !totpEnabled.value,
    totpSecret: totpEnabled.value ? totpSecret.value.trim() : '',
    totpAlgorithm: totpEnabled.value ? totpAlgorithm.value : 'SHA1',
    totpDigits: totpEnabled.value ? totpDigits.value : 6,
    totpPeriod: totpEnabled.value ? totpPeriod.value : 30,
    totpIssuer: totpIssuer.value.trim(),
    totpAccount: totpAccount.value.trim(),
  })

  saving.value = true
  try {
    const id = await vaultStore.saveEntry(input)
    password.value = ''
    totpSecret.value = ''
    toast.success(isNew.value ? '条目已创建' : '条目已保存')
    emit('saved', id)
  } catch (err) {
    errorText.value = errorMessage(err)
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div
    class="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto p-6"
    style="background: rgb(0 0 0 / 0.55)"
    @mousedown.self="close"
  >
    <div class="panel card-shadow my-auto w-full max-w-2xl">
      <!-- 标题栏 -->
      <header
        class="flex items-center justify-between border-b px-5 py-3.5"
        style="border-color: var(--app-border)"
      >
        <h2 class="text-base font-semibold">{{ dialogTitle }}</h2>
        <button class="icon-btn" title="关闭 (Esc)" @click="close">
          <svg viewBox="0 0 20 20" class="h-4 w-4" fill="none" stroke="currentColor" stroke-width="1.8">
            <path d="M5 5l10 10M15 5L5 15" stroke-linecap="round" />
          </svg>
        </button>
      </header>

      <div v-if="loading" class="p-8 text-center text-sm text-muted">正在读取条目…</div>

      <form v-else class="space-y-4 p-5" @submit.prevent="save">
        <!-- 标题 + 收藏 -->
        <div class="flex items-end gap-3">
          <div class="flex-1">
            <label for="e-title" class="mb-1.5 block text-sm font-medium">标题 *</label>
            <input
              id="e-title"
              ref="titleInput"
              v-model="title"
              class="field"
              placeholder="例如：GitHub"
              maxlength="256"
            />
          </div>
          <label
            class="btn btn-ghost cursor-pointer select-none"
            :title="favorite ? '取消收藏' : '加入收藏'"
          >
            <input v-model="favorite" type="checkbox" class="hidden" />
            <svg
              viewBox="0 0 24 24"
              class="h-4 w-4"
              :fill="favorite ? 'var(--app-warn)' : 'none'"
              :stroke="favorite ? 'var(--app-warn)' : 'currentColor'"
              stroke-width="1.6"
            >
              <path
                d="M12 3.6l2.6 5.3 5.8.8-4.2 4.1 1 5.8-5.2-2.7-5.2 2.7 1-5.8L3.6 9.7l5.8-.8z"
                stroke-linejoin="round"
              />
            </svg>
            {{ favorite ? '已收藏' : '收藏' }}
          </label>
        </div>

        <!-- 用户名 -->
        <div>
          <label for="e-user" class="mb-1.5 block text-sm font-medium">用户名 / 账号</label>
          <input
            id="e-user"
            v-model="username"
            class="field"
            placeholder="user@example.com"
            autocomplete="off"
            spellcheck="false"
            maxlength="512"
          />
        </div>

        <!-- 密码 -->
        <div>
          <div class="mb-1.5 flex items-center justify-between">
            <label for="e-pw" class="text-sm font-medium">密码</label>
            <div class="flex items-center gap-1">
              <button
                v-if="!isNew && !changePassword"
                type="button"
                class="btn btn-ghost px-2 py-1 text-xs"
                @click="changePassword = true"
              >
                更换密码
              </button>
              <button
                type="button"
                class="icon-btn"
                :title="revealPassword ? '隐藏密码' : '显示密码'"
                @click="revealPassword = !revealPassword"
              >
                <svg
                  viewBox="0 0 24 24"
                  class="h-4 w-4"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="1.6"
                  stroke-linecap="round"
                >
                  <path v-if="revealPassword" d="M3 3l18 18M10.6 10.6a2 2 0 0 0 2.8 2.8" />
                  <path d="M2.5 12S6 5.5 12 5.5c1.6 0 3 .5 4.3 1.3M21.5 12s-1.6 3-4.4 4.6" />
                </svg>
              </button>
            </div>
          </div>

          <!-- 保留原密码 -->
          <div
            v-if="!isNew && !changePassword"
            class="field flex items-center justify-between text-sm text-muted"
          >
            <span class="mono">{{ '•'.repeat(Math.min(existingPasswordLength, 24) || 8) }}</span>
            <span class="text-xs">保留原密码（{{ existingPasswordLength }} 位）</span>
          </div>

          <template v-else>
            <input
              id="e-pw"
              v-model="password"
              :type="revealPassword ? 'text' : 'password'"
              class="field mono"
              placeholder="输入或生成新密码"
              autocomplete="new-password"
              spellcheck="false"
            />
            <div class="mt-2">
              <StrengthMeter v-if="strengthResult" :result="strengthResult" :compact="true" />
            </div>
            <button
              v-if="!isNew && changePassword"
              type="button"
              class="mt-2 text-xs text-muted underline"
              @click="
                changePassword = false;
                password = '';
                strengthResult = null
              "
            >
              取消更换，保留原密码
            </button>
          </template>
        </div>

        <!-- 生成器（可折叠，只在需要新密码时有意义） -->
        <details class="panel overflow-hidden">
          <summary
            class="cursor-pointer px-3.5 py-2.5 text-sm font-medium select-none"
            style="background: var(--app-bg-elevated)"
          >
            密码生成器
          </summary>
          <div class="p-3.5">
            <PasswordGeneratorPanel
              :key="generation"
              compact
              :apply-label="'使用此密码'"
              @use="onGenerated"
            />
          </div>
        </details>

        <!-- 网址 -->
        <div>
          <label for="e-url" class="mb-1.5 block text-sm font-medium">网址</label>
          <input
            id="e-url"
            v-model="url"
            class="field"
            placeholder="https://example.com"
            autocomplete="off"
            spellcheck="false"
            maxlength="1024"
          />
        </div>

        <!-- 标签 -->
        <div>
          <label for="e-tags" class="mb-1.5 block text-sm font-medium">标签</label>
          <input
            id="e-tags"
            v-model="tagsText"
            class="field"
            placeholder="用逗号分隔，例如：工作，重要"
          />
        </div>

        <!-- TOTP -->
        <div class="panel overflow-hidden">
          <label
            class="flex cursor-pointer items-center justify-between px-3.5 py-2.5"
            style="background: var(--app-bg-elevated)"
          >
            <span class="text-sm font-medium">两步验证（TOTP）</span>
            <input v-model="totpEnabled" type="checkbox" class="h-4 w-4 cursor-pointer" />
          </label>

          <div v-if="totpEnabled" class="space-y-3 p-3.5">
            <div v-if="hasExistingTotp && !totpSecret">
              <p class="text-xs text-muted">
                已配置验证码密钥（出于安全考虑不会回显）。留空表示保持不变。
              </p>
            </div>
            <div>
              <label for="e-totp-uri" class="mb-1.5 block text-sm font-medium">
                粘贴 otpauth 链接（可选）
              </label>
              <div class="flex gap-2">
                <input
                  id="e-totp-uri"
                  v-model="totpUri"
                  class="field mono text-xs"
                  placeholder="otpauth://totp/..."
                  spellcheck="false"
                />
                <button type="button" class="btn btn-ghost" @click="applyUri">解析</button>
              </div>
            </div>
            <div>
              <label for="e-totp-secret" class="mb-1.5 block text-sm font-medium">
                Base32 密钥{{ hasExistingTotp ? '（留空保持不变）' : '' }}
              </label>
              <input
                id="e-totp-secret"
                v-model="totpSecret"
                class="field mono"
                placeholder="JBSWY3DPEHPK3PXP"
                autocomplete="off"
                spellcheck="false"
              />
              <p class="mt-1 text-xs text-muted">
                仅接受 Base32 字符（A–Z、2–7），程序不会自动替换字符。
              </p>
            </div>
            <div class="grid grid-cols-3 gap-3">
              <div>
                <label for="e-totp-algo" class="mb-1.5 block text-xs text-muted">算法</label>
                <select id="e-totp-algo" v-model="totpAlgorithm" class="field">
                  <option value="SHA1">SHA1</option>
                  <option value="SHA256">SHA256</option>
                  <option value="SHA512">SHA512</option>
                </select>
              </div>
              <div>
                <label for="e-totp-digits" class="mb-1.5 block text-xs text-muted">位数</label>
                <select id="e-totp-digits" v-model.number="totpDigits" class="field">
                  <option :value="6">6</option>
                  <option :value="7">7</option>
                  <option :value="8">8</option>
                </select>
              </div>
              <div>
                <label for="e-totp-period" class="mb-1.5 block text-xs text-muted">周期（秒）</label>
                <input
                  id="e-totp-period"
                  v-model.number="totpPeriod"
                  type="number"
                  min="10"
                  max="300"
                  class="field"
                />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label for="e-totp-issuer" class="mb-1.5 block text-xs text-muted">发行方</label>
                <input id="e-totp-issuer" v-model="totpIssuer" class="field" placeholder="GitHub" />
              </div>
              <div>
                <label for="e-totp-account" class="mb-1.5 block text-xs text-muted">账号</label>
                <input
                  id="e-totp-account"
                  v-model="totpAccount"
                  class="field"
                  placeholder="alice@example.com"
                />
              </div>
            </div>
          </div>
        </div>

        <!-- 备注 -->
        <div>
          <label for="e-notes" class="mb-1.5 block text-sm font-medium">备注</label>
          <textarea
            id="e-notes"
            v-model="notes"
            class="field resize-y"
            rows="3"
            placeholder="安全提示、恢复码等（同样会被加密）"
            maxlength="16384"
          />
        </div>

        <p
          v-if="errorText"
          class="rounded-lg px-3 py-2 text-sm"
          style="
            color: var(--app-danger);
            background: color-mix(in oklab, var(--app-danger) 12%, transparent);
          "
        >
          {{ errorText }}
        </p>

        <div class="flex justify-end gap-2 pt-1">
          <button type="button" class="btn btn-ghost" @click="close">取消</button>
          <button type="submit" class="btn btn-primary" :disabled="saving">
            {{ saving ? '正在保存…' : '保存' }}
          </button>
        </div>
      </form>
    </div>
  </div>
</template>
