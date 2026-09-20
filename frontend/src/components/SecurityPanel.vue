<script setup lang="ts">
/**
 * 安全体检面板：展示后端返回的风险报告。
 *
 * 报告只包含"哪些条目有问题"，不含任何密码内容，因此可以安全渲染。
 */
import { computed } from 'vue'
import { useVault } from '../stores/vault'
import { formatDateTime, issueKindLabel, severityMeta } from '../utils/format'

const vault = useVault()

const report = computed(() => vault.state.security)

const stats = computed(() => {
  const r = report.value
  return [
    { label: '条目总数', value: r?.total ?? 0, color: 'var(--app-text)' },
    { label: '弱密码', value: r?.weak ?? 0, color: (r?.weak ?? 0) > 0 ? 'var(--app-danger)' : 'var(--app-ok)' },
    {
      label: '重复使用',
      value: r?.reused ?? 0,
      color: (r?.reused ?? 0) > 0 ? 'var(--app-danger)' : 'var(--app-ok)',
    },
    {
      label: '未设置密码',
      value: r?.empty ?? 0,
      color: (r?.empty ?? 0) > 0 ? 'var(--app-warn)' : 'var(--app-ok)',
    },
    { label: '强密码', value: r?.strong ?? 0, color: 'var(--app-ok)' },
    {
      label: '一年未更新',
      value: r?.aging ?? 0,
      color: (r?.aging ?? 0) > 0 ? 'var(--app-warn)' : 'var(--app-ok)' ,
    },
  ]
})

/** 风险类型聚合，便于按类别折叠查看。 */
const issueKind = (kind: string): string => issueKindLabel(kind)
</script>

<template>
  <div class="min-h-0 flex-1 overflow-y-auto p-5">
    <header class="mb-4 flex items-start justify-between gap-4">
      <div>
        <h2 class="text-lg font-semibold">安全体检</h2>
        <p class="mt-0.5 text-xs text-muted">
          检查弱密码、重复使用、未设置与长期未更新的条目。
          <span v-if="report">上次检查：{{ formatDateTime(report.checkedAt) }}</span>
        </p>
      </div>
      <button
        class="btn btn-ghost shrink-0"
        :disabled="vault.state.securityLoading"
        @click="vault.runSecurityCheck()"
      >
        {{ vault.state.securityLoading ? '正在检查…' : '重新检查' }}
      </button>
    </header>

    <div v-if="!report" class="panel p-8 text-center text-sm text-muted">
      点击「重新检查」开始扫描保险库。
    </div>

    <template v-else>
      <!-- 统计卡片 -->
      <div class="mb-5 grid grid-cols-3 gap-3 lg:grid-cols-6">
        <div v-for="s in stats" :key="s.label" class="panel px-3 py-2.5">
          <div class="text-xl font-semibold" :style="{ color: s.color }">{{ s.value }}</div>
          <div class="mt-0.5 text-xs text-muted">{{ s.label }}</div>
        </div>
      </div>

      <!-- 说明 -->
      <p class="mb-4 rounded-lg px-3 py-2 text-xs text-muted" style="background: var(--app-bg-elevated)">
        强度评估模型：{{ report.model }}。内置弱密码字典包含 {{ report.dictSize }} 条常见口令。
        分值为估算值，用于发现明显风险，不代表绝对安全等级。
      </p>

      <!-- 无风险 -->
      <div
        v-if="!report.issues.length"
        class="panel p-8 text-center"
        style="border-color: color-mix(in oklab, var(--app-ok) 45%, transparent)"
      >
        <svg
          viewBox="0 0 24 24"
          class="mx-auto mb-3 h-10 w-10"
          fill="none"
          stroke="var(--app-ok)"
          stroke-width="1.6"
          stroke-linecap="round"
          stroke-linejoin="round"
        >
          <path d="M12 3l7 3v6c0 4.2-2.9 7.6-7 9-4.1-1.4-7-4.8-7-9V6z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
        <p class="text-sm font-medium" style="color: var(--app-ok)">未发现明显风险</p>
        <p class="mt-1 text-xs text-muted">所有条目都已设置强度足够的独立密码。</p>
      </div>

      <!-- 风险列表 -->
      <ul v-else class="space-y-2">
        <li v-for="(issue, idx) in report.issues" :key="`${issue.entryId}-${issue.kind}-${idx}`">
          <button
            class="panel w-full px-3.5 py-3 text-left transition-colors"
            @mouseenter="
              ($event.currentTarget as HTMLElement).style.borderColor =
                severityMeta(issue.severity).color
            "
            @mouseleave="($event.currentTarget as HTMLElement).style.borderColor = ''"
            @click="vault.selectEntry(issue.entryId)"
          >
            <div class="flex items-start gap-2.5">
              <span
                class="mt-0.5 h-2 w-2 shrink-0 rounded-full"
                :style="{ background: severityMeta(issue.severity).color }"
              />
              <div class="min-w-0 flex-1">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="font-medium">{{ issue.entryTitle || '未命名条目' }}</span>
                  <span class="chip">{{ issueKind(issue.kind) }}</span>
                  <span
                    class="chip"
                    :style="{
                      borderColor: severityMeta(issue.severity).color,
                      color: severityMeta(issue.severity).color,
                    }"
                  >
                    {{ severityMeta(issue.severity).label }}
                  </span>
                </div>
                <p class="mt-1 text-sm">{{ issue.title }}</p>
                <p class="mt-0.5 text-xs text-muted">{{ issue.detail }}</p>
              </div>
              <svg
                viewBox="0 0 24 24"
                class="mt-1 h-4 w-4 shrink-0 text-muted"
                fill="none"
                stroke="currentColor"
                stroke-width="1.7"
                stroke-linecap="round"
              >
                <path d="M9 5l7 7-7 7" />
              </svg>
            </div>
          </button>
        </li>
      </ul>

      <p v-if="report.issues.length >= 300" class="mt-3 text-xs text-muted">
        仅显示前 300 条风险提示，修复后重新检查可看到更多结果。
      </p>
    </template>
  </div>
</template>
