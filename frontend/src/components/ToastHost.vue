<script setup lang="ts">
/**
 * Toast 容器：渲染 stores/toast.ts 中的提示队列。
 */
import { useToasts } from '../stores/toast'

const { state, dismissToast } = useToasts()

const colorOf: Record<string, string> = {
  info: 'var(--app-accent)',
  success: 'var(--app-ok)',
  warn: 'var(--app-warn)',
  error: 'var(--app-danger)',
}
</script>

<template>
  <div class="pointer-events-none fixed right-4 bottom-4 z-[60] flex w-80 flex-col gap-2">
    <TransitionGroup
      enter-active-class="transition duration-200 ease-out"
      enter-from-class="translate-y-2 opacity-0"
      leave-active-class="transition duration-150 ease-in"
      leave-to-class="opacity-0"
    >
      <div
        v-for="item in state.items"
        :key="item.id"
        class="panel card-shadow pointer-events-auto flex items-start gap-2 p-3"
      >
        <span
          class="mt-1.5 h-2 w-2 shrink-0 rounded-full"
          :style="{ background: colorOf[item.kind] ?? 'var(--app-accent)' }"
        />
        <p class="flex-1 text-sm leading-snug">{{ item.message }}</p>
        <button
          class="icon-btn h-6 w-6 shrink-0 text-muted"
          title="关闭"
          @click="dismissToast(item.id)"
        >
          <svg viewBox="0 0 20 20" class="h-3.5 w-3.5" fill="none" stroke="currentColor" stroke-width="1.8">
            <path d="M5 5l10 10M15 5L5 15" stroke-linecap="round" />
          </svg>
        </button>
      </div>
    </TransitionGroup>
  </div>
</template>
