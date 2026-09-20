<script setup lang="ts">
/**
 * 强度条：展示强度评估结果。
 *
 * 只接收已经算好的评估结果，不自行计算，避免同一份密码在多个组件
 * 里出现额外副本。
 */
import { computed } from 'vue'
import type { strength } from '../../wailsjs/go/models'
import { strengthColor } from '../utils/format'

const props = withDefaults(
  defineProps<{
    result: strength.Result | null
    /** 紧凑模式只显示进度条与标签。 */
    compact?: boolean
    /** 是否展示警告与建议列表。 */
    showAdvice?: boolean
  }>(),
  { compact: false, showAdvice: true },
)

const score = computed(() => Math.max(0, Math.min(4, props.result?.score ?? 0)))
const percent = computed(() => ((score.value + 1) / 5) * 100)
const color = computed(() => strengthColor(score.value))
const label = computed(() => props.result?.label ?? '未评估')
const entropy = computed(() => props.result?.entropyBits ?? 0)
</script>

<template>
  <div class="space-y-1.5">
    <div class="flex items-center gap-2">
      <div class="h-1.5 flex-1 overflow-hidden rounded-full" style="background: var(--app-border)">
        <div
          class="h-full rounded-full transition-all duration-300"
          :style="{ width: `${percent}%`, background: color }"
        />
      </div>
      <span class="shrink-0 text-xs font-medium" :style="{ color }">{{ label }}</span>
      <span v-if="!compact && result" class="shrink-0 text-xs text-muted">
        ≈{{ entropy.toFixed(0) }} bit
      </span>
    </div>

    <template v-if="!compact && showAdvice && result">
      <p v-if="result.warnings.length" class="text-xs" :style="{ color: 'var(--app-warn)' }">
        {{ result.warnings[0] }}
      </p>
      <p
        v-else-if="result.suggestions.length"
        class="text-xs text-muted"
      >
        {{ result.suggestions[0] }}
      </p>
      <p v-if="result.guesses" class="text-xs text-muted">
        暴力枚举难度：{{ result.guesses }}
      </p>
    </template>
  </div>
</template>
