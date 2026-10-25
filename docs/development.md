# 开发与构建

## 环境

- Windows 10/11 x64，以及 Microsoft Edge WebView2 Runtime。
- Rust 1.90 或更高版本；Node.js 20.19+ 或 22.12+。
- 推荐使用 MSVC 加 Windows SDK，参见 [Tauri 前提条件](https://v2.tauri.app/start/prerequisites/)。也可以用 GNU 工具链，但需要完整的 LLVM-MinGW，因为编译 Tauri 资源要用到 `windres` 和 C 预处理器。

## 构建命令

所有步骤都通过 `scripts/Build.ps1` 执行。如果仓库里有 `.tools/`，脚本会优先使用其中的便携 Rust，否则使用 PATH 里的 Rust。

```powershell
./scripts/Build.ps1 -Action doctor    # 检查 Rust、Node、npm 和资源编译器
./scripts/Build.ps1 -Action test      # 后端测试
./scripts/Build.ps1 -Action desktop   # 前端构建与测试、桌面宿主测试与编译
./scripts/Build.ps1 -Action package   # 全部测试，生成安装程序
```

使用 GNU 工具链时需要再加上 `-ResourceToolsRoot <LLVM-MinGW 根目录>`。需要的话，还可以用 `-RustToolsRoot`、`-RustToolchain` 指定 Rust。这三个参数也可以分别通过环境变量 `WATCH_UNLOCK_RESOURCE_TOOLS`、`WATCH_UNLOCK_TOOL_ROOT`、`WATCH_UNLOCK_RUST_TOOLCHAIN` 设置。构建日志写在 `artifacts/build/`。

## 安装程序

`package` 按以下顺序执行：
1. 生成第三方许可清单（`scripts/Export-ThirdPartyNotices.ps1`）；
2. 运行全部测试，并编译后端的 release 版本；
3. 执行 `tauri build --bundles nsis`，生成 `dist/Watch Unlock_x.y.z_x64-setup.exe` 和 `SHA256SUMS.txt`。

第一次打包时，Tauri 会自动下载免费的 NSIS 工具，放在 Tauri 自己的缓存目录里。

安装程序的内容由 `apps/desktop/src-tauri/tauri.conf.json` 中的 `bundle.resources` 决定：
- 界面程序 `WatchUnlock.exe` 和 `WebView2Loader.dll`；
- 后台 `watchd.exe`、`watchd-supervisor.exe`；
- 登录组件 DLL；
- `LICENSE`、`NOTICE` 和 `licenses/`。

安装默认是“所有用户”模式，装到 `Program Files\Watch Unlock`。`apps/desktop/src-tauri/installer.nsh` 中的钩子负责以下工作：

| 时机 | 操作 |
| --- | --- |
| 安装前 | 停止旧的后台；把正在被 LogonUI 占用的旧 DLL 改名，重启后删除 |
| 安装后 | 在 HKLM 中注册 Credential Provider；在当前用户的 `Run` 项里写入开机自启 |
| 卸载时 | 停止后台，删除以上注册表项 |

用户数据（`%LOCALAPPDATA%\WatchUnlockWindows\`）在卸载时会保留。

登录组件只信任与它的 DLL 位于同一目录、并且该目录在 Program Files 之内的 `watchd.exe`。在开发目录里运行的后台可以扫描和保存配置，但无法真正解锁；要在真机上验证，请打包后运行 setup.exe。

## 开发界面

```powershell
cd apps/desktop
npm ci
npm run dev                       # 浏览器预览，不连接后端
$env:WATCH_UNLOCK_BACKEND = (Resolve-Path '../../backend/target/release/watchd.exe').Path
npm run tauri dev                 # 连接本机编译的 watchd
```

## 提交前

运行 `scripts/Check-Release.ps1`，不要强制添加被忽略的文件：`.tools/`、构建产物、日志、`.dpapi`、`.blob`。
