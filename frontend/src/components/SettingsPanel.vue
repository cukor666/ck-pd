<script setup lang="ts">
/**
 * 设置面板：安全偏好、备份恢复、主密码更换与关于信息。
 *
 * 备份与主密码相关的操作都会重新派生密钥，属于敏感流程：
 *  - 备份口令、主密码只在本组件局部 ref 中存在，提交后立即清空；
 *  - 更换主密码需要二次确认，且不会重新加密条目（只重新包裹密钥）。
 */
import { computed, onUnmounted, ref } from 'vue'
import * as App from '../../wailsjs/go/main/App'
import type { strength, vault as vaultModels } from '../../wailsjs/go/models'
import { useVault } from '../stores/vault'
import { toast } from '../stores/toast'
import { errorMessage, withSecret } from '../utils/errors'
import { formatBytes, formatDateTime } from '../utils/format'
import StrengthMeter from './StrengthMeter.vue'
import ConfirmDialog from './ConfirmDialog.vue'

const vault = useVault()

const lockOptions = [
  { value: 0, label: '不自动锁定（不推荐）' },
  { value: 1, label: '1 分钟' },
  { value: 5, label: '5 分钟' },
  { value: 15, label: '15 分钟' },
  { value: 30, label: '30 分钟' },
  { value: 60, label: '1 小时' },
]

const clipOptions = [
  { value: 0, label: '不自动清除' },
  { value: 15, label: '15 秒' },
  { value: 30, label: '30 秒' },
  { value: 60, label: '1 分钟' },
  { value: 120, label: '2 分钟' },
]

const themeOptions = [
  { value: 'system', label: '跟随系统' },
  { value: 'dark', label: '深色' },
  { value: 'light', label: '浅色' },
]

const sortOptions = [
  { value: 'updated', label: '最近更新' },
  { value: 'title', label: '标题' },
  { value: 'created', label: '创建时间' },
]

// --- 主密码更换 ---
const oldPassword = ref('')
const newPassword = ref('')
const newPassword2 = ref('')
const newStrength = ref<strength.Result | null>(null)
const confirmChangePassword = ref(false)
const changingPassword = ref(false)

// --- 备份 ---
const backupPath = ref('')
const backupPassword = ref('')
const backupPassword2 = ref('')
const backupBusy = ref(false)
const lastBackup = ref<vaultModels.BackupResult | null>(null)

// --- 恢复 ---
const restorePath = ref('')
const restorePassword = ref('')
const restoreInfo = ref<vaultModels.BackupInfo | null>(null)
const restoreBusy = ref(false)
const confirmRestore = ref(false)

const info = computed(() => vault.state.appInfo)
const settings = computed(() => vault.state.settings)

onUnmounted(() => {
  clearSecrets()
})

/** 清空所有敏感输入。 */
function clearSecrets(): void {
  oldPassword.value = ''
  newPassword.value = ''
  newPassword2.value = ''
  backupPassword.value = ''
  backupPassword2.value = ''
  restorePassword.value = ''
  newStrength.value = null
}

// ---------------------------------------------------------------------------
// 设置项
// ---------------------------------------------------------------------------

async function update(patch: Record<string, unknown>): Promise<void> {
  try {
    await vault.saveSettings(patch)
  } catch (err) {
    toast.error(errorMessage(err))
  }
}

// ---------------------------------------------------------------------------
// 主密码
// ---------------------------------------------------------------------------

let evalTimer: number | null = null
function onNewPasswordInput(): void {
  if (evalTimer !== null) window.clearTimeout(evalTimer)
  if (!newPassword.value) {
    newStrength.value = null
    return
  }
  evalTimer = window.setTimeout(async () => {
    try {
      newStrength.value = await App.EvaluateStrength(newPassword.value)
    } catch {
      newStrength.value = null
    }
  }, 180)
}

const canChangePassword = computed(
  () =>
    !!oldPassword.value &&
    newPassword.value.length >= 8 &&
    newPassword.value === newPassword2.value &&
    (newStrength.value?.score ?? 0) >= 2 &&
    !changingPassword.value,
)

async function changePassword(): Promise<void> {
  confirmChangePassword.value = false
  changingPassword.value = true
  const oldPw = oldPassword.value
  const newPw = newPassword.value
  try {
    // 两个密码分别编码、分别清零，避免在 JS 堆上留下长期副本。
    const oldBytes = new TextEncoder().encode(oldPw)
    const newBytes = new TextEncoder().encode(newPw)
    try {
      await App.ChangeMasterPassword(Array.from(oldBytes), Array.from(newBytes))
    } finally {
      oldBytes.fill(0)
      newBytes.fill(0)
    }
    toast.success('主密码已更新，请牢记新密码')
    clearSecrets()
  } catch (err) {
    toast.error(errorMessage(err))
    oldPassword.value = ''
  } finally {
    changingPassword.value = false
  }
}

// ---------------------------------------------------------------------------
// 备份
// ---------------------------------------------------------------------------

async function choosePath(): Promise<void> {
  try {
    const p = await App.ChooseBackupPath()
    if (p) backupPath.value = p
  } catch (err) {
    toast.error(errorMessage(err))
  }
}

async function useDefaultPath(): Promise<void> {
  try {
    backupPath.value = await App.SuggestBackupPath()
  } catch (err) {
    toast.error(errorMessage(err))
  }
}

const canExport = computed(() => {
  if (!backupPath.value.trim() || backupBusy.value) return false
  if (!backupPassword.value) return true
  return (
    backupPassword.value.length >= 8 && backupPassword.value === backupPassword2.value
  )
})

async function doExport(): Promise<void> {
  backupBusy.value = true
  try {
    const pw = backupPassword.value
    const result = pw
      ? await withSecret(pw, (bytes) =>
          App.ExportBackup(backupPath.value.trim(), Array.from(bytes)),
        )
      : await App.ExportBackup(backupPath.value.trim(), [])
    lastBackup.value = result
    backupPassword.value = ''
    backupPassword2.value = ''
    toast.success(
      result.protected
        ? '已导出受口令保护的加密备份'
        : '已导出加密备份（使用主密码解锁）',
    )
  } catch (err) {
    toast.error(errorMessage(err))
  } finally {
    backupBusy.value = false
  }
}

// ---------------------------------------------------------------------------
// 恢复
// ---------------------------------------------------------------------------

async function chooseRestoreFile(): Promise<void> {
  try {
    const p = await App.ChooseBackupFile()
    if (!p) return
    restorePath.value = p
    restoreInfo.value = await App.DescribeBackup(p)
    if (!restoreInfo.value.protected) {
      toast.info('该备份未受额外口令保护，恢复后使用原主密码解锁')
    }
  } catch (err) {
    toast.error(errorMessage(err))
  }
}

const needsRestorePassword = computed(() => restoreInfo.value?.protected === true)
const canRestore = computed(
  () =>
    !!restorePath.value.trim() &&
    !restoreBusy.value &&
    (!needsRestorePassword.value || restorePassword.value.length > 0),
)

async function doRestore(): Promise<void> {
  confirmRestore.value = false
  restoreBusy.value = true
  try {
    const pw = restorePassword.value
    const result = pw
      ? await withSecret(pw, (bytes) => App.ImportBackup(restorePath.value.trim(), Array.from(bytes)))
      : await App.ImportBackup(restorePath.value.trim(), [])
    restorePassword.value = ''
    toast.success(`已从备份恢复（${formatBytes(result.containerBytes)}），请用对应主密码解锁`)
    // 恢复后 Go 侧会锁定保险库，前端状态由事件清空。
  } catch (err) {
    toast.error(errorMessage(err))
  } finally {
    restoreBusy.value = false
  }
}
</script>

<template>
  <div class="min-h-0 flex-1 overflow-y-auto p-5">
    <h2 class="mb-4 text-lg font-semibold">设置</h2>

    <div class="mx-auto max-w-2xl space-y-5">
      <!-- 自动锁定 -->
      <section class="panel p-4">
        <h3 class="mb-1 font-medium">自动锁定</h3>
        <p class="mb-3 text-xs text-muted">
          锁定后内存中的密钥会被清零，必须重新输入主密码。闲置判定由后端看门狗执行，
          不依赖界面是否响应。
        </p>

        <div class="space-y-3">
          <div class="flex items-center justify-between gap-4">
            <label for="s-lock" class="text-sm">闲置超时</label>
            <select
              id="s-lock"
              class="field max-w-[220px]"
              :value="settings?.autoLockMinutes ?? 5"
              @change="update({ autoLockMinutes: Number(($event.target as HTMLSelectElement).value) })"
            >
              <option v-for="o in lockOptions" :key="o.value" :value="o.value">{{ o.label }}</option>
            </select>
          </div>

          <label class="flex cursor-pointer items-center justify-between gap-4">
            <span class="text-sm">
              窗口最小化时锁定
              <span class="block text-xs text-muted">离开工位时最有效的一道防线</span>
            </span>
            <input
              type="checkbox"
              class="h-4 w-4 cursor-pointer"
              :checked="settings?.lockOnMinimize ?? true"
              @change="update({ lockOnMinimize: ($event.target as HTMLInputElement).checked })"
            />
          </label>

          <label class="flex cursor-pointer items-center justify-between gap-4">
            <span class="text-sm">
              窗口失去焦点时锁定
              <span class="block text-xs text-muted">
                更严格，但复制密码后切换到浏览器会立刻锁定
              </span>
            </span>
            <input
              type="checkbox"
              class="h-4 w-4 cursor-pointer"
              :checked="settings?.lockOnBlur ?? false"
              @change="update({ lockOnBlur: ($event.target as HTMLInputElement).checked })"
            />
          </label>
        </div>
      </section>

      <!-- 剪贴板 -->
      <section class="panel p-4">
        <h3 class="mb-1 font-medium">剪贴板</h3>
        <p class="mb-3 text-xs text-muted">
          复制密码后自动清空剪贴板，降低其它程序读取剪贴板导致泄露的风险。
        </p>

        <div class="flex items-center justify-between gap-4">
          <label for="s-clip" class="text-sm">自动清除时间</label>
          <select
            id="s-clip"
            class="field max-w-[220px]"
            :value="settings?.clipboardClearSeconds ?? 30"
            @change="
              update({ clipboardClearSeconds: Number(($event.target as HTMLSelectElement).value) })
            "
          >
            <option v-for="o in clipOptions" :key="o.value" :value="o.value">{{ o.label }}</option>
          </select>
        </div>

        <label class="mt-3 flex cursor-pointer items-center justify-between gap-4">
          <span class="text-sm">
            显示明文密码前二次确认
            <span class="block text-xs text-muted">防止在他人可见时误点显示</span>
          </span>
          <input
            type="checkbox"
            class="h-4 w-4 cursor-pointer"
            :checked="settings?.revealNeedsConfirm ?? false"
            @change="update({ revealNeedsConfirm: ($event.target as HTMLInputElement).checked })"
          />
        </label>

        <button class="btn btn-ghost mt-3 w-full" @click="vault.clearClipboard()">
          立即清空剪贴板
        </button>
      </section>

      <!-- 外观 -->
      <section class="panel p-4">
        <h3 class="mb-3 font-medium">外观与列表</h3>
        <div class="space-y-3">
          <div class="flex items-center justify-between gap-4">
            <label for="s-theme" class="text-sm">主题</label>
            <select
              id="s-theme"
              class="field max-w-[220px]"
              :value="settings?.theme ?? 'system'"
              @change="update({ theme: ($event.target as HTMLSelectElement).value })"
            >
              <option v-for="o in themeOptions" :key="o.value" :value="o.value">{{ o.label }}</option>
            </select>
          </div>
          <div class="flex items-center justify-between gap-4">
            <label for="s-sort" class="text-sm">列表排序</label>
            <select
              id="s-sort"
              class="field max-w-[220px]"
              :value="settings?.sortMode ?? 'updated'"
              @change="update({ sortMode: ($event.target as HTMLSelectElement).value })"
            >
              <option v-for="o in sortOptions" :key="o.value" :value="o.value">{{ o.label }}</option>
            </select>
          </div>
        </div>
      </section>

      <!-- 备份 -->
      <section class="panel p-4">
        <h3 class="mb-1 font-medium">加密备份</h3>
        <p class="mb-3 text-xs text-muted">
          导出的文件本身就是加密容器。若再设置备份口令，会在外层用
          Argon2id + XChaCha20-Poly1305 额外加密一次，可安全地放到云盘。
        </p>

        <div class="space-y-3">
          <div>
            <label for="s-backup-path" class="mb-1.5 block text-sm">保存位置</label>
            <div class="flex gap-2">
              <input
                id="s-backup-path"
                v-model="backupPath"
                class="field mono text-xs"
                placeholder="点击「选择」或使用默认路径"
                spellcheck="false"
              />
              <button class="btn btn-ghost shrink-0" @click="choosePath">选择</button>
              <button class="btn btn-ghost shrink-0" @click="useDefaultPath">默认</button>
            </div>
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div>
              <label for="s-backup-pw" class="mb-1.5 block text-sm">备份口令（可选）</label>
              <input
                id="s-backup-pw"
                v-model="backupPassword"
                type="password"
                class="field"
                placeholder="留空则仅用主密码保护"
                autocomplete="new-password"
              />
            </div>
            <div>
              <label for="s-backup-pw2" class="mb-1.5 block text-sm">确认口令</label>
              <input
                id="s-backup-pw2"
                v-model="backupPassword2"
                type="password"
                class="field"
                :disabled="!backupPassword"
                autocomplete="new-password"
              />
            </div>
          </div>

          <p v-if="backupPassword && backupPassword !== backupPassword2" class="text-xs" style="color: var(--app-warn)">
            两次输入的口令不一致。
          </p>

          <button class="btn btn-primary w-full" :disabled="!canExport" @click="doExport">
            {{ backupBusy ? '正在导出…' : '导出加密备份' }}
          </button>

          <p v-if="lastBackup" class="rounded-lg px-3 py-2 text-xs" style="background: var(--app-bg-elevated)">
            已导出到 <span class="mono selectable">{{ lastBackup.path }}</span>
            （{{ formatBytes(lastBackup.bytes) }}，{{ lastBackup.protected ? '受口令保护' : '主密码保护' }}）
          </p>
        </div>
      </section>

      <!-- 恢复 -->
      <section class="panel p-4">
        <h3 class="mb-1 font-medium">从备份恢复</h3>
        <p class="mb-3 text-xs text-muted">
          恢复会覆盖当前保险库文件。程序会在覆盖前自动生成一份当前内容的快照
          （文件名后缀 <span class="mono">.before-restore-时间</span>），恢复后需要重新解锁。
        </p>

        <div class="space-y-3">
          <div class="flex gap-2">
            <input
              :value="restorePath"
              class="field mono text-xs"
              placeholder="选择 .ckpd-backup 文件"
              readonly
            />
            <button class="btn btn-ghost shrink-0" @click="chooseRestoreFile">选择文件</button>
          </div>

          <div v-if="restoreInfo">
            <p class="text-xs text-muted">
              版本信息：{{ restoreInfo.protected ? '受口令保护' : '未受额外口令保护' }} ·
              容器大小 {{ formatBytes(restoreInfo.containerBytes) }}
              <span v-if="restoreInfo.createdAt"> · 创建于 {{ formatDateTime(restoreInfo.createdAt) }}</span>
            </p>
          </div>

          <div v-if="needsRestorePassword">
            <label for="s-restore-pw" class="mb-1.5 block text-sm">备份口令</label>
            <input
              id="s-restore-pw"
              v-model="restorePassword"
              type="password"
              class="field"
              placeholder="请输入导出时设置的备份口令"
              autocomplete="off"
            />
          </div>

          <button
            class="btn btn-danger w-full"
            :disabled="!canRestore"
            @click="confirmRestore = true"
          >
            {{ restoreBusy ? '正在恢复…' : '从此备份恢复' }}
          </button>
        </div>
      </section>

      <!-- 主密码 -->
      <section class="panel p-4">
        <h3 class="mb-1 font-medium">更换主密码</h3>
        <p class="mb-3 text-xs text-muted">
          更换主密码只会重新加密数据密钥，条目数据不需要重写，因此速度很快且不会丢失内容。
        </p>

        <div class="space-y-3">
          <div>
            <label for="s-old-pw" class="mb-1.5 block text-sm">当前主密码</label>
            <input
              id="s-old-pw"
              v-model="oldPassword"
              type="password"
              class="field"
              autocomplete="current-password"
            />
          </div>
          <div>
            <label for="s-new-pw" class="mb-1.5 block text-sm">新主密码</label>
            <input
              id="s-new-pw"
              v-model="newPassword"
              type="password"
              class="field"
              autocomplete="new-password"
              @input="onNewPasswordInput"
            />
            <div v-if="newStrength" class="mt-2">
              <StrengthMeter :result="newStrength" />
            </div>
          </div>
          <div>
            <label for="s-new-pw2" class="mb-1.5 block text-sm">确认新主密码</label>
            <input
              id="s-new-pw2"
              v-model="newPassword2"
              type="password"
              class="field"
              autocomplete="new-password"
            />
          </div>

          <button
            class="btn btn-primary w-full"
            :disabled="!canChangePassword"
            @click="confirmChangePassword = true"
          >
            {{ changingPassword ? '正在更新…' : '更新主密码' }}
          </button>
        </div>
      </section>

      <!-- 关于 -->
      <section v-if="info" class="panel p-4">
        <h3 class="mb-3 font-medium">关于</h3>
        <div class="space-y-2 text-xs text-muted">
          <div class="flex justify-between gap-4">
            <span>版本</span><span class="mono">{{ info.version }}</span>
          </div>
          <div class="flex justify-between gap-4">
            <span>平台</span><span>{{ info.platform }}</span>
          </div>
          <div class="flex justify-between gap-4">
            <span>保险库文件</span>
            <span class="mono selectable truncate" :title="info.vaultPath">{{ info.vaultPath }}</span>
          </div>
          <div class="flex justify-between gap-4">
            <span>配置目录</span>
            <span class="mono selectable truncate" :title="info.settingsPath">{{ info.settingsPath }}</span>
          </div>
          <div class="flex justify-between gap-4">
            <span>运行模式</span><span>{{ info.portable ? '便携模式' : '用户配置目录' }}</span>
          </div>
          <div class="flex justify-between gap-4">
            <span>KDF 参数</span>
            <span class="mono">
              Argon2id / {{ vault.state.status?.kdfMemoryKiB ?? 0 }} KiB /
              {{ vault.state.status?.kdfIterations ?? 0 }} 轮 /
              并行 {{ vault.state.status?.kdfParallelism ?? 0 }}
            </span>
          </div>
          <div class="flex justify-between gap-4">
            <span>数据修订号</span><span class="mono">{{ vault.state.status?.revision ?? 0 }}</span>
          </div>
        </div>
        <p class="mt-3 text-xs text-muted">
          加密方案：Argon2id 派生密钥 → XChaCha20-Poly1305 包裹数据密钥 →
          数据密钥以 XChaCha20-Poly1305 加密条目数据。密钥只在解锁期间存在于内存。
        </p>
      </section>
    </div>

    <ConfirmDialog
      v-if="confirmChangePassword"
      title="确认更换主密码"
      message="更换后旧主密码将立即失效。请确保新主密码已妥善记录，且不要与其它服务重复使用。"
      confirm-text="确认更换"
      @confirm="changePassword"
      @cancel="confirmChangePassword = false"
    />

    <ConfirmDialog
      v-if="confirmRestore"
      title="确认从备份恢复"
      message="当前保险库将被备份文件中的内容覆盖。程序会自动保存一份当前文件的快照，但恢复后需要重新解锁。"
      confirm-text="确认恢复"
      danger
      require-text="恢复"
      @confirm="doRestore"
      @cancel="confirmRestore = false"
    />
  </div>
</template>
