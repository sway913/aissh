# aissh 部署

香港默认服务器：149.88.87.82。服务独立使用 17000/17443/17500，不占用已有 frps、MapLink 或 Xray 端口。

## 证书初始化与构建

生产服务器证书已与内置 `aissh/default-ca.pem` 对应。初次在新服务器部署时生成证书，再将公开证书打包到客户端：

```sh
go run ./cmd/aisshs --init-tls --host 149.88.87.82 --data-dir .aissh-server
cp .aissh-server/server.crt aissh/default-ca.pem
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -tags noweb -o bin/linux-amd64/aisshs ./cmd/aisshs
make -f Makefile.aissh build
```

已有证书不得覆盖。私钥文件为 `.aissh-server/server.key`，受 Git 忽略规则保护。备份服务器 `/var/lib/aissh`，包含证书、管理密码、设备及规则数据库。设备会话仅驻留内存，服务器重启后自动重新注册。

在新工作区克隆项目时，默认已包含生产信任公开证书，但没有生产私钥。不要直接生成一个不同证书后部署到生产；需要恢复服务器证书或完整更新客户端信任。

## 安装

将 Linux 服务端放在 `/usr/local/bin/aisshs`，证书与私钥放在 `/var/lib/aissh/server.crt` 和 `/var/lib/aissh/server.key`。以专用 `aissh` 系统用户运行，数据目录归其所有，权限 0700，私钥 0600。

安装仓库 `deploy/aisshs.service` 至 `/etc/systemd/system/aisshs.service`，然后执行：

```sh
systemctl daemon-reload
systemctl enable --now aisshs
systemctl status aisshs
```

放行 TCP 17000、17443；17500 仅监听回环地址，通过 SSH 端口转发访问。服务限制内存为 128 MB，适合当前资源紧张的服务器。无需更改现有服务。

## 管理与回滚

- 日志：`journalctl -u aisshs`。日志不输出管理密码或临时会话 token。
- 密码：`cat /var/lib/aissh/admin-password`，用户名 `admin`。
- 停止：`systemctl disable --now aisshs`，不影响已有 frps 和 MapLink。
- 更新：替换独立的 `/usr/local/bin/aisshs` 后重启 `aisshs`。设备会自动重新注册。
- 备份：停止 aisshs 后备份 `/var/lib/aissh`，私钥和设备隧道 secret 不应公开。

## 客户端

macOS、Linux、Windows 均支持。Windows 对应 `aisshc.exe`。客户端启动时自动注册；目标系统必须启用 SSH 服务。不要同时在同一台电脑启动多个 aisshc：新注册会取代旧会话。

当前权限配置最多约 10 秒同步，撤销在服务器立即生效，并有 1 秒周期检查作为兜底。授权撤销会中断已有 SSH 会话。客户端本地 visitor 端口从 22000 开始分配；若被其他程序占用，需要先释放对应端口。
