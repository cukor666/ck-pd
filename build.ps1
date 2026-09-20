#!/usr/bin/env pwsh
#
# ck-pd 一键构建脚本（Windows / PowerShell）
#
# 为什么需要这个脚本，而不直接用 `wails build`？
# ---------------------------------------------------------------
# Wails CLI 的绑定生成与打包阶段使用内置的 Go 包加载器。当本机 Go 工具链
# 版本明显新于该 Wails 版本时，会报：
#     internal error: package "errors" without types was imported from "..."
# 这是 Wails 内置 loader 与新版 Go 标准库导出数据格式不兼容导致的，
# 与项目代码无关（`go build ./...` 与 `go test ./...` 均可正常通过）。
#
# 绑定本身可以用 `wails generate module` 正常生成，因此这里的做法是：
#   1. 构建前端（vue-tsc 类型检查 + vite build）；
#   2. 用 `wails generate module` 重新生成 TS 绑定；
#   3. 直接用 `go build` 产出带 windowsgui 子系统的 GUI 可执行文件。
#
# 若你的 Wails CLI 版本已支持当前 Go 工具链，也可以直接 `wails build`。

[CmdletBinding()]
param(
    # 跳过前端构建（仅重新编译 Go 部分时使用）
    [switch]$SkipFrontend,
    # 跳过绑定生成
    [switch]$SkipBindings,
    # 构建后立即启动
    [switch]$Run,
    # 输出文件名
    [string]$OutputName = 'ck-pd.exe'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Assert-LastExit([string]$What) {
    if ($LASTEXITCODE -ne 0) {
        throw "$What 失败（退出码 $LASTEXITCODE）"
    }
}

# ---------------------------------------------------------------------------
# 1. 前端构建
# ---------------------------------------------------------------------------
if (-not $SkipFrontend) {
    Write-Step "构建前端（Vue 3 + TypeScript + TailwindCSS）"
    Push-Location 'frontend'
    try {
        pnpm install --frozen-lockfile 2>&1 | Out-Host
        # 没有 lockfile 时不因 --frozen-lockfile 失败而中断
        if ($LASTEXITCODE -ne 0) {
            Write-Host "锁文件校验失败，回退为普通安装" -ForegroundColor Yellow
            pnpm install 2>&1 | Out-Host
            Assert-LastExit 'pnpm install'
        }
        pnpm run build 2>&1 | Out-Host
        Assert-LastExit '前端构建'
    }
    finally {
        Pop-Location
    }
}

# ---------------------------------------------------------------------------
# 2. 重新生成 Wails TypeScript 绑定
# ---------------------------------------------------------------------------
if (-not $SkipBindings) {
    Write-Step "生成 TypeScript 绑定"

    # wails CLI 常常装在 $GOPATH\bin 而不在 PATH 上，因此这里依次探测：
    #   1. PATH 中的 wails
    #   2. $env:GOPATH\bin\wails.exe
    #   3. `go env GOPATH` 返回的目录下的 bin
    $wailsPath = $null
    $cmd = Get-Command wails -ErrorAction SilentlyContinue
    if ($cmd) {
        $wailsPath = $cmd.Source
    }
    else {
        $candidates = @()
        if ($env:GOPATH) { $candidates += (Join-Path $env:GOPATH 'bin/wails.exe') }
        $goPath = (& go env GOPATH 2>$null)
        if ($LASTEXITCODE -eq 0 -and $goPath) {
            $candidates += (Join-Path $goPath.Trim() 'bin/wails.exe')
        }
        foreach ($c in $candidates) {
            if (Test-Path $c) { $wailsPath = $c; break }
        }
    }

    if ($wailsPath) {
        Write-Host "使用 wails: $wailsPath"
        & $wailsPath generate module 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Write-Host "绑定生成失败，沿用现有绑定继续构建" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "未找到 wails CLI，跳过绑定生成（沿用现有绑定）" -ForegroundColor Yellow
        Write-Host "安装方式：go install github.com/wailsapp/wails/v2/cmd/wails@latest" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 3. 后端测试（默认执行，保证不把失败的构建产物交出去）
# ---------------------------------------------------------------------------
Write-Step "运行后端测试"
go test ./... 2>&1 | Out-Host
Assert-LastExit '后端测试'

# ---------------------------------------------------------------------------
# 4. 编译可执行文件
# ---------------------------------------------------------------------------
Write-Step "编译可执行文件"
$binDir = Join-Path $root 'build/bin'
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
$outPath = Join-Path $binDir $OutputName

# -H windowsgui：以 GUI 子系统启动，避免弹出控制台窗口
# -w -s        ：去掉符号表与调试信息，减小体积
$ldflags = '-w -s -H windowsgui'
go build -tags 'desktop,production' -ldflags $ldflags -o $outPath . 2>&1 | Out-Host
Assert-LastExit '编译'

$size = [math]::Round((Get-Item $outPath).Length / 1MB, 2)
Write-Host ""
Write-Host "构建完成：$outPath ($size MB)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5. 可选：立即运行
# ---------------------------------------------------------------------------
if ($Run) {
    Write-Step "启动应用"
    Start-Process -FilePath $outPath
}
