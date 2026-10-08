# aissh

aissh 基于 [fatedier/frp](https://github.com/fatedier/frp)，面向两台非公网电脑之间的远程 SSH 访问。

计划在香港服务器部署集中管理后台，管理设备、访问权限和 SSH 隧道。当前仓库完成了上游代码迁移与独立构建入口；集中管理后台、设备注册和权限管理尚未实现。现有 frps/frpc Dashboard 是上游自带界面。

## 构建与使用

需要 Go 1.25 或更新版本。

```sh
make -f Makefile.aissh build
./bin/aisshs -c conf/frps.toml
./bin/aisshc -c conf/frpc.toml
```

- `aisshs`：运行在公网服务器上的服务端。
- `aisshc`：运行在内网电脑上的客户端或 visitor。
- SSH 服务仍由目标电脑的 OpenSSH 等程序提供；推荐先使用 STCP 私密代理实现访问。
- 当前配置格式、默认配置文件名、协议及版本号沿用 frp。运行客户端时请显式传入 `-c`。
- 无前端构建产物时，以上命令构建不包含 Dashboard 的二进制。包含现有 Dashboard：先执行 `make -f Makefile.aissh web`，再执行构建命令。

## 保持上游可同步

保留 frp 的完整 Git 历史、Apache-2.0 许可证和原作者版权声明。底层 Go module 仍为 `github.com/fatedier/frp`，避免批量改写 import 给以后同步带来冲突。本项目的仓库地址为 `github.com/sway913/aissh`。

- `origin`：aissh 自有仓库。
- `upstream`：frp 官方仓库。
- `main`：aissh 主分支。

具体步骤见 [上游同步指南](doc/aissh/upstream-sync.md)。官方功能说明保留在 [原版 README](README.frp.md) 和 [中文文档](README_zh.md)。

## 自定义开发约定

新管理后台及其设备管理、权限管理接口优先放在独立的 `aissh/` 目录。需要接入底层时使用尽量小的适配改动，避免批量重命名上游目录、配置字段和协议。与上游有关的缺陷修复和 aissh 自定义功能分别提交。

原版发布工作流保留供参考，但仅允许在官方仓库运行；aissh 发布与部署流程另行配置。
