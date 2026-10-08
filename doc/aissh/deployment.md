# aissh 部署

注册入口：https://sshapi.builderopc.com；隧道域名：connect.builderopc.com，当前香港服务器 IP 为 149.88.87.82。服务独立使用 17000/17443/17500，不占用已有 frps、MapLink 或 Xray 端口。

## 证书初始化与构建

生产服务器证书已与内置 `aissh/default-ca.pem` 对应。初次在新服务器部署时生成证书，再将公开证书打包到客户端：

```sh
go run ./cmd/aisshs --init-tls --host connect.builderopc.com --data-dir .aissh-server
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

仅放行 TCP 17000；17443 和 17500 仅监听回环地址，通过 Cloudflare Tunnel 提供公网 HTTPS。服务限制内存为 128 MB，适合当前资源紧张的服务器。无需更改现有服务。

## 管理与回滚

- 日志：`journalctl -u aisshs`。日志不输出管理密码或临时会话 token。
- 密码：`cat /var/lib/aissh/admin-password`，用户名 `admin`。
- 停止：`systemctl disable --now aisshs`，不影响已有 frps 和 MapLink。
- 更新：替换独立的 `/usr/local/bin/aisshs` 后重启 `aisshs`。设备会自动重新注册。
- 备份：停止 aisshs 后备份 `/var/lib/aissh`，私钥和设备隧道 secret 不应公开。

## 客户端

macOS、Linux、Windows 均支持。Windows 对应 `aisshc.exe`。客户端普通执行时检查并安装开机自启，安装需要管理员权限；系统任务启动客户端后自动注册。详见 [自启说明](client-startup.md)。目标系统必须启用 SSH 服务。不要同时在同一台电脑启动多个 aisshc：新注册会取代旧会话。

当前权限配置最多约 10 秒同步，撤销在服务器立即生效，并有 1 秒周期检查作为兜底。授权撤销会中断已有 SSH 会话。客户端本地 visitor 端口从 22000 开始分配；若被其他程序占用，需要先释放对应端口。

## 默认域名与迁移

- 客户端入口 `connect.builderopc.com`：Cloudflare A 记录指向服务器公网 IPv4，代理关闭（仅 DNS）。TCP 17000 为 TLS 隧道。
- 管理后台 `https://aissh.builderopc.com`：通过现有 Cloudflare Tunnel 转发到回环管理服务，与客户端入口分开。
- 当前内置信任公开证书保持不变。生产服务端已用该信任根签发包含 `connect.builderopc.com` 和本机回环地址的叶证书，不再包含旧公网 IP。
- 叶证书到期前使用同一信任根签发并替换服务端证书即可，不需要重新发布客户端。根私钥只保存在受保护的离线目录或备份，不进入 Git。
- 迁移时备份 `/var/lib/aissh`，在新机器恢复同一证书、私钥、管理密码与设备数据库，安装 aisshs 并放行 17000，然后更新 `connect.builderopc.com` 的 A 记录。停止旧服务器上的 aisshs，避免设备连接到不同服务器；现有会话会重连，受 DNS 缓存影响不会瞬间切换。
- 注册和管理域名同时迁移 Cloudflare Tunnel；更换隧道 A 记录不会自动迁移 Tunnel。
- 自建服务器通过 `--api-url https://注册域名`、`--server 隧道域名` 和 `--ca` 配置。注册公网证书由系统 CA 验证，`--ca` 仅用于数据隧道。不兼容旧直连注册方式。

## Cloudflare Tunnel 注册入口

在现有 ingress 的兜底规则之前添加：

```yaml
  - hostname: sshapi.builderopc.com
    service: https://127.0.0.1:17443
    originRequest:
      originServerName: connect.builderopc.com
      caPool: /etc/cloudflared/aissh-ca.pem
```

将 `aissh/default-ca.pem` 安装到上述 CA 路径，保留源站证书校验。通过 `cloudflared tunnel route dns hk-tunnel sshapi.builderopc.com` 创建代理 DNS 记录，验证 ingress 后重启 cloudflared。仅转发设备接口，不转发管理页面。

注册限流仅在回环代理连接上接受 `CF-Connecting-IP`，避免所有客户端共享同一限流额度。新版本需要更新全部客户端并重启；设备 ID、授权关系和已分配 SSH 端口保持不变。
