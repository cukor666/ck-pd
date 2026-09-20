<script setup lang="ts">
/**
 * 解锁界面：涵盖「首次创建保险库」与「解锁已有保险库」两种形态。
 *
 * 安全相关实现细节：
 *  - 密码输入框为 type=password 且关闭自动填充与拼写检查；
 *  - 创建流程要求二次确认，并用后端返回的强度评估实时提示；
 *  - 解锁失败只提示通用错误，不回显密码，也不记录任何日志。
 */
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import * as App from '../../wailsjs/go/main/App'
import type { strength } from '../../wailsjs/go/models'
import { useVault } from '../stores/vault'
import { toast } from '../stores/toast'
import { errorMessage } from '../utils/errors'
import StrengthMeter from './StrengthMeter.vue'

const vault = useVault()

const password = ref('')
const confirm = ref('')
const showPassword = ref(false)
const errorText = ref('')
const submitting = ref(false)
const strengthResult = ref<strength.Result | null>(null)

const creating = computed(() => !vault.state.configured)
const busy = computed(() => submitting.value || vault.state.busy)

const passwordInput = ref<HTMLInputElement | null>(null)

onMounted(() => {
  passwordInput.value?.focus()
  window.addEventListener('keydown', onKeydown)
})

onUnmounted(() => {
  window.removeEventListener('keydown', onKeydown)
  // 离开解锁界面时丢弃输入内容。
  password.value = ''
  confirm.value = ''
})

function onKeydown(e: KeyboardEvent): void {
  if (e.key === 'Enter' && !busy.value) void submit()
}

// 仅在创建模式下实时评估强度；解锁模式不评估，避免把密码送去多做一次处理。
let evalTimer: number | null = null
watch(password, (value) => {
  if (!creating.value) {
    strengthResult.value = null
    return
  }
  if (evalTimer !== null) window.clearTimeout(evalTimer)
  if (!value) {
    strengthResult.value = null
    return
  }
  // 稍作防抖，避免每次按键都跨进程调用。
  evalTimer = window.setTimeout(async () => {
    try {
      strengthResult.value = await App.EvaluateStrength(value)
    } catch {
      strengthResult.value = null
    }
  }, 180)
})

const canSubmit = computed(() => {
  if (busy.value) return false
  if (!password.value) return false
  if (creating.value) {
    return password.value === confirm.value && (strengthResult.value?.score ?? 0) >= 2
  }
  return true
})

const hint = computed(() => {
  if (creating.value) {
    if (!password.value) return '主密码用于加密整个保险库，请使用较长且唯一的随机口令。'
    if (strengthResult.value && strengthResult.value.score < 2) {
      return '主密码强度不足，至少需要「一般」及以上才能创建。'
    }
    if (confirm.value && password.value !== confirm.value) return '两次输入不一致。'
    return '主密码无法找回：一旦遗忘，保险库中的数据将无法解密。'
  }
  return '输入主密码以解锁。解锁后密钥仅保存在内存中，不会写入磁盘。'
})

async function submit(): Promise<void> {
  if (!canSubmit.value) return
  errorText.value = ''
  submitting.value = true
  const used = password.value
  try {
    if (creating.value) {
      await vault.createVault(used)
      toast.success('保险库已创建')
    } else {
      await vault.unlock(used)
      toast.success('已解锁')
    }
    // 成功后立刻从界面状态中移除密码。
    password.value = ''
    confirm.value = ''
    strengthResult.value = null
  } catch (err) {
    errorText.value = errorMessage(err)
    password.value = ''
    showPassword.value = false
    passwordInput.value?.focus()
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div class="flex h-full items-center justify-center p-8">
    <div class="w-full max-w-[420px]">
      <!-- 品牌区 -->
      <div class="mb-7 text-center">
        <div
          class="mx-auto mb-3 flex h-14 w-14 items-center justify-center rounded-2xl"
          style="background: color-mix(in oklab, var(--app-accent) 18%, transparent)"
        >
          <svg
            viewBox="0 0 24 24"
            class="h-7 w-7"
            fill="none"
            stroke="var(--app-accent)"
            stroke-width="1.6"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <rect x="4" y="10.5" width="16" height="10" rx="2.5" />
            <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
            <circle cx="12" cy="15.5" r="1.4" />
          </svg>
        </div>
        <h1 class="text-xl font-semibold">
          {{ creating ? '创建你的保险库' : 'ck-pd 密码管理器' }}
        </h1>
        <p class="mt-1 text-sm text-muted">
          {{
            creating
              ? '所有数据都在本地加密保存，不会上传到任何服务器。'
              : '本地加密保险库已就绪，请输入主密码解锁。'
          }}
        </p>
      </div>

      <form class="panel card-shadow space-y-4 p-5" @submit.prevent="submit">
        <div>
          <label for="master" class="mb-1.5 block text-sm font-medium">主密码</label>
          <div class="relative">
            <input
              id="master"
              ref="passwordInput"
              v-model="password"
              :type="showPassword ? 'text' : 'password'"
              class="field pr-10"
              :placeholder="creating ? '建议 16 位以上随机口令' : '请输入主密码'"
              autocomplete="off"
              autocapitalize="off"
              autocorrect="off"
              spellcheck="false"
              :disabled="busy"
            />
            <button
              type="button"
              class="icon-btn absolute top-1/2 right-1 -translate-y-1/2"
              :title="showPassword ? '隐藏' : '显示'"
              tabindex="-1"
              @click="showPassword = !showPassword"
            >
              <svg
                viewBox="0 0 24 24"
                class="h-4 w-4"
                fill="none"
                stroke="currentColor"
                stroke-width="1.6"
                stroke-linecap="round"
              >
                <path v-if="showPassword" d="M3 3l18 18M10.6 10.6a2 2 0 0 0 2.8 2.8" />
                <path
                  d="M2.5 12S6 5.5 12 5.5c1.6 0 3 .5 4.3 1.3M21.5 12s-1.6 3-4.4 4.6"
                />
              </svg>
            </button>
          </div>
        </div>

        <!-- 创建模式：强度条 + 二次确认 -->
        <template v-if="creating">
          <StrengthMeter v-if="strengthResult" :result="strengthResult" />
          <div>
            <label for="confirm" class="mb-1.5 block text-sm font-medium">确认主密码</label>
            <input
              id="confirm"
              v-model="confirm"
              :type="showPassword ? 'text' : 'password'"
              class="field"
              placeholder="再次输入主密码"
              autocomplete="off"
              spellcheck="false"
              :disabled="busy"
            />
          </div>
        </template>

        <p class="text-xs text-muted">{{ hint }}</p>

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

        <button type="submit" class="btn btn-primary w-full" :disabled="!canSubmit">
          <svg
            v-if="busy"
            class="h-4 w-4 animate-spin"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2.5"
          >
            <path d="M12 3a9 9 0 1 0 9 9" stroke-linecap="round" />
          </svg>
          {{
            busy
              ? creating
                ? '正在创建…'
                : '正在解锁…'
              : creating
                ? '创建保险库'
                : '解锁'
          }}
        </button>

        <p v-if="creating" class="text-center text-xs text-muted">
          密钥派生使用 Argon2id（64 MiB / 3 轮），创建过程约需 0.3 秒。
        </p>
        <p v-else class="text-center text-xs text-muted">
          忘记主密码？可从设置中的加密备份恢复，见项目 README。
        </p>
      </form>
    </div>
  </div>
</template>
