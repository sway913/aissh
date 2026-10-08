# aissh CI 和发布

独立工作流：`.github/workflows/aissh-build.yml`。原版 frp GoReleaser、Docker 发布仍限制在官方仓库运行，不用于 aissh。

## 自动触发

| 操作 | 结果 |
|---|---|
| 推送 main | CI → 五个平台打包 → 更新 aissh-latest 开发版 Release |
| 指向 main 的 PR | CI → 五个平台 Artifacts，不发布 Release |
| 手动运行工作流（main） | 重跑 CI、打包和最新开发版发布 |
| 推送 aissh-v0.1.0 等标签 | CI → 五个平台打包 → 正式 Release |
| 推送 aissh-v0.1.0-rc.1 等标签 | 同上，但标记为预发布版 |

工作流不部署服务器，发布包仅包含明确列出的程序、LICENSE、文档、版本信息和 Linux systemd 模板。公开服务器信任证书已嵌入程序；不包含服务器私钥、管理密码、设备数据库、临时 token 或本机运行数据。

## 下载与版本

开发版入口：https://github.com/sway913/aissh/releases/tag/aissh-latest

开发版标签跟随最新成功构建的 main 提交移动。正式标签不移动，版本号采用 aissh 自己的版本序列，不沿用 frp 的 0.71.0。`aisshc --version` 和 `aisshs --version` 可查看产品版本与完整提交 SHA；压缩包内 `build-info.json` 记录相同来源信息。

Linux/macOS 为 `.tar.gz`，Windows 为 `.zip`，每个平台都包含客户端和服务端。校验下载文件：

```sh
sha256sum --check SHA256SUMS --ignore-missing
# macOS 可使用 shasum -a 256 比对 SHA256SUMS。
```

## 正式版本

确认目标提交并推送带 aissh 前缀的标签，例如：

```sh
git switch main
git pull --ff-only origin main
git tag -a aissh-v0.1.0 -m 'aissh v0.1.0'
git push origin aissh-v0.1.0
```

全部测试和平台构建成功后，自动创建 Release 并上传二进制与 SHA256SUMS。正式版本先上传到草稿，上传完成后发布；开发版重复运行会替换同名资产。失败时先检查 Actions 日志，再重跑失败任务。无需提前手工创建 Release。

GitHub Actions 必须在仓库启用。只有发布任务申请 `contents: write`，测试及打包任务只申请读取权限。内置 GITHUB_TOKEN 用于创建 Release 和更新开发标签；无需自建 PAT 或部署凭据。

## 本地打包

需要 Go 1.25+ 和 Python 3.11+：

```sh
python3 hack/aissh-package.py --os linux --arch amd64 --version v0.1.0
python3 hack/aissh-package.py --os darwin --arch arm64 --version dev
python3 hack/aissh-package.py --os windows --arch amd64 --version dev
```

输出默认位于 `dist/aissh/`，并生成每个压缩包的 `.sha256` 文件。构建时注入产品版本和提交；默认服务器及其公开信任证书保持一致。
