// ck-pd 是一个本地优先的密码管理器。
//
// 架构约定：
//   - 所有密码学操作、明文密码与保险库密钥都只存在于 Go 进程内；
//     前端是纯展示层，只能通过绑定接口按需取回单个字段。
//   - 窗口关闭、进程退出、闲置超时、窗口最小化都会触发密钥清零。
package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "ck-pd 密码管理器",
		Width:     1200,
		Height:    800,
		MinWidth:  940,
		MinHeight: 620,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		// 使用与界面一致的深色背景，避免启动瞬间白屏闪烁。
		BackgroundColour: &options.RGBA{R: 15, G: 18, B: 26, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		OnBeforeClose:    app.beforeClose,
		Windows: &windows.Options{
			// 关闭 WebView2 的默认右键菜单与开发者工具，
			// 减少明文密码被从 DOM 中检出的机会。
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			DisableWindowIcon:    false,
		},
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("启动失败:", err.Error())
	}
}
