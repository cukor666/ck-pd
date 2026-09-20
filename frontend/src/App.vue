<script setup lang="ts">
/**
 * 应用根组件。
 *
 * 只负责三件事：
 *  1. 初始化会话（订阅后端事件、加载设置与状态）；
 *  2. 根据锁定状态在「解锁界面」与「主界面」之间切换；
 *  3. 挂载全局浮层（条目编辑器、通知）。
 *
 * 注意：这里不持有任何密码或密钥，敏感数据的生命周期严格限制在
 * 使用它的子组件内部。
 */
import { computed, onMounted, ref } from 'vue'
import { useVault } from './stores/vault'
import { toast } from './stores/toast'
import { errorMessage } from './utils/errors'
import UnlockScreen from './components/UnlockScreen.vue'
import MainShell from './components/MainShell.vue'
import EntryEditor from './components/EntryEditor.vue'
import ToastHost from './components/ToastHost.vue'

const vault = useVault()
const initError = ref('')

const showUnlock = computed(() => vault.state.ready && vault.state.locked)
const showMain = computed(() => vault.state.ready && !vault.state.locked)
const editorRequest = computed(() => vault.state.editor)

onMounted(async () => {
  try {
    await vault.initVault()
  } catch (err) {
    initError.value = errorMessage(err)
    toast.error(`初始化失败：${initError.value}`)
  }
})
</script>

<template>
  <div class="h-full min-h-0">
    <!-- 加载中 -->
    <div v-if="!vault.state.ready" class="flex h-full items-center justify-center">
      <div class="flex flex-col items-center gap-3">
        <svg
          class="h-7 w-7 animate-spin"
          viewBox="0 0 24 24"
          fill="none"
          stroke="var(--app-accent)"
          stroke-width="2.4"
        >
          <path d="M12 3a9 9 0 1 0 9 9" stroke-linecap="round" />
        </svg>
        <p class="text-sm text-muted">正在初始化…</p>
        <p v-if="initError" class="max-w-sm text-center text-xs" style="color: var(--app-danger)">
          {{ initError }}
        </p>
      </div>
    </div>

    <!-- 解锁 / 创建 -->
    <UnlockScreen v-else-if="showUnlock" />

    <!-- 主界面 -->
    <MainShell v-else-if="showMain" />

    <!-- 条目编辑器 -->
    <EntryEditor
      v-if="editorRequest"
      :key="editorRequest.id ?? 'new'"
      :entry-id="editorRequest.id"
      :preset-password="editorRequest.presetPassword"
      @close="vault.closeEditor()"
    />

    <!-- 全局通知 -->
    <ToastHost />
  </div>
</template>
