<script setup lang="ts">
/**
 * 密码生成器面板。
 *
 * 生成完全在 Go 侧完成（crypto/rand + 拒绝采样），前端只负责参数与展示。
 * 生成的密码默认以明文显示，因为用户需要确认；离开本面板时立即清空。
 */
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import * as App from '../../wailsjs/go/main/App'
import type { gen, strength } from '../../wailsjs/go/models'
import { toast } from '../stores/toast'
import { errorMessage } from '../utils/errors'
import StrengthMeter from './StrengthMeter.vue'

const props = withDefaults(
  defineProps<{
    /** 紧凑模式用于嵌入编辑器。 */
    compact?: boolean
    /** 应用按钮文案；未提供时不显示应用按钮。 */
    applyLabel?: string
  }>(),
  { compact: false, applyLabel: '' },
)

const emit = defineEmits<{ (e: 'use', value: string): void }>()

const opts = reactive<gen.Options>({
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: true,
  noRepeating: false,
  requireEachClass: true,
})

const password = ref('')
const strengthResult = ref<strength.Result | null>(null)
const revealed = ref(false)
const busy = ref(false)
const errorText = ref('')

const classCount = computed(
  () => [opts.lowercase, opts.uppercase, opts.digits, opts.symbols].filter(Boolean).length,
)

const canGenerate = computed(() => classCount.value > 0 && opts.length >= 4)

async function generate(): Promise<void> {
  if (!canGenerate.value) {
    errorText.value = '至少需要选择一种字符类型'
    return
  }
  busy.value = true
  errorText.value = ''
  try {
    const pw = await App.GeneratePassword(opts)
    password.value = pw
    revealed.value = true
    strengthResult.value = await App.EvaluateStrength(pw)
  } catch (err) {
    errorText.value = errorMessage(err)
  } finally {
    busy.value = false
  }
}

/** 生成单词口令，适合需要手抄的场景（如主密码）。 */
async function generatePassphrase(): Promise<void> {
  busy.value = true
  errorText.value = ''
  try {
    const pw = await App.GeneratePassphrase(5, '-')
    password.value = pw
    revealed.value = true
    strengthResult.value = await App.EvaluateStrength(pw)
  } catch (err) {
    errorText.value = errorMessage(err)
  } finally {
    busy.value = false
  }
}

async function copyToClipboard(): Promise<void> {
  if (!password.value) return
  try {
    await navigator.clipboard.writeText(password.value)
    toast.success('已复制生成的密码，请尽快粘贴到目标位置')
  } catch {
    toast.error('复制失败，请手动选择文本')
  }
}

function apply(): void {
  if (!password.value) return
  emit('use', password.value)
}

// 任意参数变化都让已生成的密码失效，避免用户以为改参数后密码同步变了。
watch(
  () => [
    opts.length,
    opts.lowercase,
    opts.uppercase,
    opts.digits,
    opts.symbols,
    opts.excludeAmbiguous,
    opts.noRepeating,
    opts.requireEachClass,
  ],
  () => {
    if (password.value) {
      password.value = ''
      strengthResult.value = null
    }
  },
)

onMounted(() => void generate())

onUnmounted(() => {
  // 离开时丢弃明文。
  password.value = ''
})

const toggles = [
  { key: 'lowercase' as const, label: '小写字母', hint: 'a-z' },
  { key: 'uppercase' as const, label: '大写字母', hint: 'A-Z' },
  { key: 'digits' as const, label: '数字', hint: '0-9' },
  { key: 'symbols' as const, label: '符号', hint: '!@#$%' },
]
</script>

<template>
  <div :class="props.compact ? 'space-y-3' : 'space-y-5'">
    <!-- 生成结果 -->
    <div v-if="!props.compact" class="panel p-4">
      <div class="flex items-center gap-2">
        <div
          class="field mono flex min-h-[42px] flex-1 items-center overflow-x-auto whitespace-nowrap"
          :class="{ 'text-muted': !password }"
        >
          {{ password ? (revealed ? password : '•'.repeat(password.length)) : '点击下方按钮生成密码' }}
        </div>
        <button
          class="icon-btn h-[38px] w-[38px]"
          :title="revealed ? '隐藏' : '显示'"
          :disabled="!password"
          @click="revealed = !revealed"
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
          class="icon-btn h-[38px] w-[38px]"
          title="复制到剪贴板"
          :disabled="!password"
          @click="copyToClipboard"
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
      <div v-if="strengthResult" class="mt-3">
        <StrengthMeter :result="strengthResult" />
      </div>
      <p v-if="password" class="mt-2 text-xs" style="color: var(--app-warn)">
        提示：此密码显示在界面上，复制并保存后建议清空剪贴板。
      </p>
    </div>

    <!-- 紧凑模式下的结果行 -->
    <div v-else class="flex items-center gap-2">
      <div class="field mono flex-1 overflow-x-auto whitespace-nowrap text-sm">
        {{ password || '—' }}
      </div>
      <button class="icon-btn" title="复制" :disabled="!password" @click="copyToClipboard">
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
      <button class="btn btn-ghost" :disabled="busy" @click="generate">重新生成</button>
      <button v-if="props.applyLabel" class="btn btn-primary" :disabled="!password" @click="apply">
        {{ props.applyLabel }}
      </button>
    </div>

    <!-- 参数 -->
    <div class="space-y-4">
      <div>
        <div class="mb-1.5 flex items-center justify-between">
          <label for="gen-len" class="text-sm font-medium">长度</label>
          <span class="mono text-sm">{{ opts.length }}</span>
        </div>
        <input
          id="gen-len"
          v-model.number="opts.length"
          type="range"
          min="8"
          max="64"
          class="w-full accent-[var(--app-accent)]"
        />
      </div>

      <div class="grid grid-cols-2 gap-2">
        <label
          v-for="t in toggles"
          :key="t.key"
          class="flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-sm"
          style="border-color: var(--app-border)"
        >
          <input v-model="opts[t.key]" type="checkbox" class="h-4 w-4 cursor-pointer" />
          <span class="flex-1">{{ t.label }}</span>
          <span class="mono text-xs text-muted">{{ t.hint }}</span>
        </label>
      </div>

      <div class="space-y-2">
        <label class="flex cursor-pointer items-center gap-2 text-sm">
          <input v-model="opts.excludeAmbiguous" type="checkbox" class="h-4 w-4 cursor-pointer" />
          排除易混淆字符（i l 1 I o O 0 等）
        </label>
        <label class="flex cursor-pointer items-center gap-2 text-sm">
          <input v-model="opts.requireEachClass" type="checkbox" class="h-4 w-4 cursor-pointer" />
          每类字符至少出现一次
        </label>
        <label class="flex cursor-pointer items-center gap-2 text-sm">
          <input v-model="opts.noRepeating" type="checkbox" class="h-4 w-4 cursor-pointer" />
          不允许重复字符
        </label>
      </div>

      <p v-if="errorText" class="text-sm" style="color: var(--app-danger)">{{ errorText }}</p>

      <div v-if="!props.compact" class="flex gap-2">
        <button class="btn btn-primary flex-1" :disabled="busy || !canGenerate" @click="generate">
          生成随机密码
        </button>
        <button class="btn btn-ghost" :disabled="busy" @click="generatePassphrase">
          生成单词口令
        </button>
        <button
          v-if="props.applyLabel"
          class="btn btn-ghost"
          :disabled="!password"
          @click="apply"
        >
          {{ props.applyLabel }}
        </button>
      </div>

      <p v-if="!props.compact" class="text-xs text-muted">
        随机性来自操作系统的密码学安全随机源，并使用拒绝采样消除取模偏差。
      </p>
    </div>
  </div>
</template>
