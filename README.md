# aissh

[![CI](https://github.com/sway913/aissh/actions/workflows/aissh-build.yml/badge.svg)](https://github.com/sway913/aissh/actions/workflows/aissh-build.yml)

[最新开发版二进制](https://github.com/sway913/aissh/releases/tag/aissh-latest) · [全部 Releases](https://github.com/sway913/aissh/releases)

基于 [fatedier/frp](https://github.com/fatedier/frp) 的个人远程 SSH 管理工具。两台电脑都不需要公网 IP；默认通过 `connect.builderopc.com` 中转，当前解析到香港服务器。

## 使用

在需要连接的两台电脑上分别启动：

```sh
./aisshc
```

无需填写服务器地址、token、设备私钥或 STCP 密钥。客户端自动识别硬件、注册设备、领取 24 小时临时会话，并每 10 秒同步后台权限。会话临近到期或服务器重启后会自动重新注册。客户端进程需要保持运行。

1. 在目标电脑开启系统 SSH 服务（默认 `127.0.0.1:22`）。
2. 启动两端的 `aisshc`，设备自动出现在后台。
3. 后台添加“电脑 A → 电脑 B”的访问权限。
4. 根据后台或 A 的日志显示的端口登录，例如：

```sh
ssh -p 22000 电脑B的用户名@127.0.0.1
```

新版客户端会自动读取运行它的系统账户名并上报后台，后台将目标用户名填入 SSH 命令。Windows 本机账户使用本地登录名，AD 域账户保留域前缀；显示的是运行客户端的账户，不保证该账户具有 SSH 登录权限。用户名不参与设备 ID 计算；不读取或上传系统密码、PIN 或 SSH 私钥。

SSH 账号、密码或 SSH 密钥由目标电脑的系统管理，aissh 仅管理隧道访问权限。SCP/SFTP 同样可用。目标 SSH 不在 22 端口时使用 `./aisshc --ssh-port 其他端口`。

## 设备识别与权限

- 优先使用具有全球管理地址的物理网卡 MAC，过滤常见虚拟/桥接接口；无此类地址时回退到本地管理 MAC。
- 按地址排序选择一个主 MAC，结合可读取的机器 UUID、主板序列号、Linux machine-id 等计算设备 ID。
- 额外硬件标识先哈希后上传；后台显示设备 ID、主 MAC、主机名、系统、当前运行账户、SSH 用户名及最近活动。
- 网卡、随机 MAC、系统重装或硬件标识读取权限变化可能改变设备 ID，需要重新授权。
- 后台可删除残留设备，同时移除该设备双向授权、临时会话并断开连接；运行中的客户端会重新注册，需要重新授权。禁用用于阻止设备继续注册，删除用于清理记录。
- 首次注册不分配任何访问权限。规则单向生效，双向访问需添加两条规则。
- 临时会话只保存在内存，每次启动注册替换该设备旧会话。禁用设备会使会话失效。
- 服务端对每条 STCP 连接检查设备与 ACL；撤销权限和禁用设备会关闭现有隧道连接，缓存旧 STCP 配置也不能重新访问。

这是按需求实现的硬件指纹自动注册，不提供设备私钥的持有证明。MAC 和硬件信息可被仿冒；知道完整指纹的人可冒充该设备。适用于个人受控设备，不用于要求强设备认证的多租户环境。

## 后台与服务端

默认端口：

| 端口 | 用途 |
|---|---|
| TCP 17000 | frp TLS 隧道 |
| HTTPS 443 | `sshapi.builderopc.com` 注册与配置，经 Cloudflare Tunnel |
| 127.0.0.1:17443 | 注册接口内部 TLS，仅本机监听 |
| 127.0.0.1:17500 | 管理页面，仅本机监听 |

后台可通过 https://aissh.builderopc.com 使用管理员凭证登录。也可通过 SSH 转发访问：

```sh
ssh -N -L 17500:127.0.0.1:17500 root@connect.builderopc.com
```

打开 `http://127.0.0.1:17500`。用户名为 `admin`，随机生成的密码保存在服务器 `/var/lib/aissh/admin-password`，不包含在仓库或日志中。

客户端默认通过 `https://sshapi.builderopc.com` 注册，无需指定端口。该域名使用 Cloudflare Tunnel；SSH 数据隧道使用仅 DNS 的 `connect.builderopc.com:17000`。换服务器时迁移 `/var/lib/aissh`，更新隧道域名 A 记录并迁移 Cloudflare Tunnel。

注册 HTTPS 使用系统可信 CA 验证公网证书；数据隧道使用客户端内置的私有信任根。`--api-url` 指定注册 HTTPS 入口，`--server` 指定隧道域名，`--ca` 仅指定隧道信任根。不提供旧 IP、直连注册端口或 `--api-port` 兼容方式。

部署说明见 [部署文档](doc/aissh/deployment.md)。

## 构建与测试

需要 Go 1.25 或更新版本。管理页面使用内嵌 HTML，无需 Node、数据库服务或单独前端构建。

```sh
make -f Makefile.aissh build
go test -race -tags noweb ./aissh/... ./client/... ./server/...
```

输出为 `bin/aisshs`、`bin/aisshc`。原版命令和构建方式仍可通过上游 `Makefile` 使用。

## 同步官方修复

保留完整 frp Git 历史、Apache-2.0 许可证和版权声明。Go module 及内部协议沿用 `github.com/fatedier/frp`，减少同步冲突。

自定义代码集中在 `aissh/`、`cmd/aisshs/`、`cmd/aisshc/`；服务端通过进程内插件和 visitor admission hook 接入权限。官方功能说明保留在 [原版 README](README.frp.md) 和 [中文文档](README_zh.md)。同步流程见 [上游同步指南](doc/aissh/upstream-sync.md)。

## 自动 CI 与二进制发布

- 提交到 `main`、创建指向 `main` 的 PR 或手动运行 Actions，自动执行格式检查、vet、竞态测试及 SSH 权限链路测试，并构建五个平台下载包。
- PR 和每次运行的二进制可在 Actions 的 Artifacts 下载，保留 14 天。
- `main` 的测试与全部平台构建成功后，自动更新 `aissh-latest` 开发版 Release，免登录即可下载。
- 推送 `aissh-vMAJOR.MINOR.PATCH` 标签会自动发布正式版本；带 `-rc.N` 的标签发布预发布版。
- 平台包括 Linux amd64/arm64、macOS Intel/Apple Silicon、Windows amd64。每个包包含 `aisshc`、`aisshs` 和使用说明，并附 `SHA256SUMS`。
- 发布使用仓库内置的 `GITHUB_TOKEN`，无需设置 PAT、服务器 SSH 密钥或原版 `GPR_TOKEN`；不会自动更新香港服务器上正在运行的服务。

正式发布步骤与本地打包方法见 [aissh 发布指南](doc/aissh/release.md)。
