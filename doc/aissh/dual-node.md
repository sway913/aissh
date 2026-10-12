# 内网优先与香港备用

香港是唯一权限写入端。Mac mini 的 `10.19.181.6` 是客户端连接的内网地址，**不需要是公网出口地址**。内网节点主动每 10 秒向 `https://sshapi.builderopc.com/v1/node/sync` 发起 HTTPS 请求，携带节点专用凭证，上报心跳和隧道状态并取回完整签名权限快照。香港无需反向连接内网，也无需知道 NAT 出口 IP。应允许 Mac mini 出站访问该域名 TCP 443。

客户端从香港发现节点并缓存公开节点元数据。两端升级后，同时连接香港和内网节点；旧客户端继续使用香港。只有路由层监听原有 `127.0.0.1:220xx` 端口。每个新 SSH 连接先尝试内网，连接及 SSH 标识合计 2 秒；失败再尝试香港，合计 5 秒。显式权限拒绝不重试其他节点。SSH 用户认证失败不切换线路，已建立的会话不迁移。

## 配置和密钥

`aisshs --federation-config /data/federation.json` 启用节点模式。配置不提交到 Git，不打包进客户端或镜像。

香港配置角色 `authority`、节点 ID `hongkong`、`nodes` 和 `nodeTokens`。启动生成独立的 `policy-signing.key`，使用 `--signing-public-key --data-dir /var/lib/aissh` 导出其公开验证密钥。每个内网节点使用不同的至少 32 字节随机凭证。

内网配置角色 `replica`、节点 ID `mac-mini`、`authorityURL`、`publicKey`、`token` 和 `nodes`。`nodes` 含节点 ID、名称、类型 `lan/public`、HTTPS 注册地址、隧道域名和端口、优先级以及公开 CA 证书 `caPEM`。配置应包含本节点。内网独立生成 TLS 私钥：

```sh
aisshs --init-tls --data-dir /data --host lan-connect.builderopc.com
```

只有 `server.crt` 的公开内容被香港分发；`server.key` 留在内网。节点凭证仅存香港和对应内网节点，完整权限快照含设备隧道秘密，仅通过节点专用认证接口发送，并以权限 0600 保存。

## 权限和故障行为

签名快照包含权限版本、签发时间和固定 24 小时到期时间。完整替换处理删除、撤销和禁用。拒绝无效签名、过期快照、版本回退和签发时间回退。原始签名快照原子持久化；重启不会重新计时。过期后拒绝注册和新隧道，并在一秒内回收现有授权连接。

已同步设备可在香港不可达时通过内网注册和重连。新设备需要香港登记。尚未收到撤销的离线节点可能继续使用最后签发的权限，最长 24 小时；恢复同步后回收撤销的连接。客户端收到香港的新权限后，不接受更旧的内网权限覆盖。设备在香港被禁用时，客户端关闭所有本地入口。

管理后台显示注册心跳、各节点实际 SSH 代理隧道、内网同步时间及权限剩余有效期。同步中断后，香港不能实时得知内网隧道状态，报告超过 30 秒显示未连接。

## Mac mini 部署

数据目录 `/Users/qihoo/aissh-server/data`，Compose 位于 `/Users/qihoo/aissh-server/compose.yaml`。仓库模板：`deploy/lan/compose.yaml` 和 `deploy/lan/Dockerfile`。默认 UID 502/GID 20 对应当前 Mac mini 的 qihoo 用户；其他主机应通过 `AISSH_UID/AISSH_GID` 设置实际目录所有者。镜像不含配置和密钥。

DNS：`lan-connect.builderopc.com A 10.19.181.6`，仅 DNS。公司 ACL：客户端到 `10.19.181.6` TCP 443/17000；不需要直达目标电脑 TCP 22。部分网络的 DNS 重绑定保护会过滤私网 A 记录，需在公司 DNS 允许此域名或设置内部解析；这与公网出口地址无关。

容器使用 `unless-stopped`、健康检查、只读镜像、数据卷和轮转日志。Docker Desktop 随登录启动；Mac mini 接通电源时不进入系统睡眠，显示器仍可休眠。重启后必须登录才能启动 Docker Desktop。参见 [Docker Desktop 启动设置](https://docs.docker.com/desktop/settings-and-maintenance/settings/) 和 [容器重启策略](https://docs.docker.com/engine/containers/start-containers-automatically/)。

## 发布和回滚

先备份香港二进制、设备数据库和配置，升级香港，再启动内网节点。内网健康且同步成功后升级试点客户端。启动服务配置继续使用原有 StateDir；新 `nodes.json` 位于该目录，仅包含公开信息。

回滚时香港停止下发内网节点（保留香港节点），客户端下次获取配置后停止内网连接；回退香港旧二进制和客户端旧二进制可恢复单节点模式。不要回退正在使用的设备数据库，以免意外恢复已撤销权限；数据库备份用于灾难恢复。

验收：race 测试包含真实 TLS/STCP/SSH 内网优先、目标仅公网时备用路径、权限拒绝不跨节点重试，以及签名、快照回退、撤销与重启到期测试。公司跨网访问及 Docker Desktop 登录后恢复需在真实环境验收。
