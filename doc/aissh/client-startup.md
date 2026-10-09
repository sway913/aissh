# 客户端开机自启

普通执行 `aisshc` 会检查本机自启任务：不存在就安装，已存在则检查运行状态；停止或禁用时尝试恢复，正常运行时直接退出，不启动第二个前台客户端。网络暂时不可用时由后台客户端持续重连。

首次安装、修复、更新和卸载需要管理员权限。Windows 请用“以管理员身份运行”的 PowerShell，Linux/macOS 使用 sudo。不要同时保留旧版前台 aisshc，首次安装前先 Ctrl+C 停止它。

```powershell
# Windows：管理员 PowerShell
.\aisshc.exe
.\aisshc.exe --service status
```

```sh
# Linux / macOS
sudo ./aisshc
./aisshc --service status
```

| 系统 | 自启机制 | 安装位置 | 日志 |
|---|---|---|---|
| Windows | 计划任务 `\aisshc`，开机触发，SYSTEM 运行，无需账户密码或用户登录 | `%ProgramData%\aissh` | `%ProgramData%\aissh\client.log`（管理员读取） |
| Linux | systemd `aisshc.service`，开机启动，退出后自动重启 | `/usr/local/lib/aissh` | `journalctl -u aisshc -f` |
| macOS | LaunchDaemon `com.builderopc.aisshc`，开机启动，退出后自动重启 | `/Library/Application Support/aissh` | 安装目录的 `client.log` |

Linux/macOS 以安装者的原始用户运行，`sudo` 的原用户由 `SUDO_USER` 识别；直接以 root 安装则使用 root。Windows SYSTEM 任务使用安装时保存的 SSH 账户名及硬件辅助哈希，避免账户切换导致设备身份变化；MAC 每次启动重新读取，MAC 改变仍会产生新设备。配置不保存系统密码、PIN、SSH 私钥或临时会话。Windows 安装目录仅允许 SYSTEM 和管理员写入。

程序复制到固定位置，删除下载目录或关闭终端不会影响运行。安装时的 `--server`、`--api-url`、`--ssh-port`、`--ca` 等参数会保存；自定义 CA 也会复制到安装目录。普通重复执行保留已安装配置，不覆盖参数。

## 更新与移除

下载新版后，以管理员权限运行：

```sh
./aisshc --service update
# Windows 使用 .\aisshc.exe --service update
```

更新停止旧进程、复制新二进制并重新启动。原始运行用户和状态目录保持不变；其他连接参数采用此次命令提供的值，省略则采用程序默认值。自建服务器更新时应再次传入自定义入口参数。

```sh
./aisshc --service uninstall
```

卸载停止客户端并移除自启任务，保留本机安装文件和后台设备授权。需要临时在终端运行而不安装自启时：

```sh
./aisshc --foreground
```

`--service-run` 是供系统任务使用的内部入口，加载固定安装目录中的配置，不执行安装流程。服务显示 running 只表示进程运行；设备联网、注册、隧道连接及目标 SSH 是否正常，应结合客户端日志和管理后台检查。

## Windows 硬件指纹采集失败

客户端优先从系统网卡接口读取 MAC；Windows 接口枚举失败或没有可用 MAC 时，会通过 PowerShell 的 CIM 网卡查询再尝试一次（最多等待 10 秒）。保留原有 MAC 优先级和设备 ID 算法。

仍无法获取时，会提示 `no usable MAC address found` 或具体的 Windows 查询错误。请检查网卡和驱动状态：

```powershell
Get-NetAdapter -IncludeHidden | Select-Object Name,Status,MacAddress
Get-CimInstance Win32_NetworkAdapter | Select-Object Name,MACAddress
```

客户端不会用随机数或计算机名替代 MAC 注册。安装自启失败的机器下载新版后，以管理员身份重新执行 `.\aisshc.exe`；已经安装的使用 `.\aisshc.exe --service update`。
