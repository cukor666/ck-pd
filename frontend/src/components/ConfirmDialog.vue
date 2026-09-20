<script setup lang="ts">
/**
 * 确认对话框：用于删除条目、关闭自动清除等破坏性或高影响操作。
 */
import { onMounted, onUnmounted, ref } from 'vue'

const props = withDefaults(
  defineProps<{
    title: string
    message: string
    confirmText?: string
    cancelText?: string
    /** 危险操作使用红色确认按钮。 */
    danger?: boolean
    /** 需要用户输入指定文本才能确认（用于不可逆操作）。 */
    requireText?: string
  }>(),
  { confirmText: '确认', cancelText: '取消', danger: false, requireText: '' },
)

const emit = defineEmits<{ (e: 'confirm'): void; (e: 'cancel'): void }>()

const typed = ref('')
const canConfirm = ref(props.requireText === '')
const confirmBtn = ref<HTMLButtonElement | null>(null)

function onInput(): void {
  canConfirm.value = props.requireText === '' || typed.value.trim() === props.requireText
}

function onKeydown(e: KeyboardEvent): void {
  if (e.key === 'Escape') {
    e.stopPropagation()
    emit('cancel')
  } else if (e.key === 'Enter' && canConfirm.value) {
    e.stopPropagation()
    emit('confirm')
  }
}

onMounted(() => {
  confirmBtn.value?.focus()
  window.addEventListener('keydown', onKeydown, true)
})
onUnmounted(() => window.removeEventListener('keydown', onKeydown, true))
</script>

<template>
  <div
    class="fixed inset-0 z-50 flex items-center justify-center p-6"
    style="background: rgb(0 0 0 / 0.55)"
    @mousedown.self="emit('cancel')"
  >
    <div class="panel card-shadow w-full max-w-md p-5">
      <h3 class="text-base font-semibold">{{ title }}</h3>
      <p class="mt-2 text-sm text-muted">{{ message }}</p>

      <div v-if="props.requireText" class="mt-4">
        <label class="mb-1 block text-xs text-muted">
          请输入 <span class="mono font-semibold">{{ props.requireText }}</span> 以继续
        </label>
        <input
          v-model="typed"
          class="field mono"
          autocomplete="off"
          spellcheck="false"
          @input="onInput"
        />
      </div>

      <div class="mt-5 flex justify-end gap-2">
        <button class="btn btn-ghost" @click="emit('cancel')">{{ props.cancelText }}</button>
        <button
          ref="confirmBtn"
          class="btn"
          :class="props.danger ? 'btn-danger' : 'btn-primary'"
          :disabled="!canConfirm"
          @click="emit('confirm')"
        >
          {{ props.confirmText }}
        </button>
      </div>
    </div>
  </div>
</template>
