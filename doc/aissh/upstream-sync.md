# 同步官方 frp

初始上游基线：`d20a2329`（完整历史已保留）。上游开发分支为 `dev`；此分支可能包含未发布变更。生产发布应选择经过验证的官方 release/tag，避免把上游开发分支的每次更新直接部署到香港服务器。

## 新克隆的仓库

Git remote 配置不会随 clone 传播。每个新工作区需要执行一次：

```sh
git remote add upstream https://github.com/fatedier/frp.git
git fetch upstream --tags
```

## 合并官方修复

工作区必须先保持干净。在独立分支合并、检查差异和解决冲突：

```sh
git switch main
git pull --ff-only origin main
git fetch upstream --tags
git switch -c sync/frp-update
git merge --no-ff upstream/dev
```

若仅需要指定修复，可将最后一步改为 `git cherry-pick <fix-commit>`；同时检查该提交依赖的其他修复。同步稳定版本时，将 `upstream/dev` 替换为确认过的官方 tag。

发生冲突时保留 aissh 品牌、独立构建入口及自定义功能，结合上游修改逐项解决。合并应保留上游提交历史，不使用 squash。

## 验证与交付

```sh
make -f Makefile.aissh build
make -f Makefile.aissh test
make -f Makefile web-ci
make -f Makefile e2e
```

涉及传输协议时还应执行上游兼容性测试，并验证 STCP SSH 登录、文件传输、重连，以及后续增加的设备授权逻辑。验证通过后推送同步分支并创建 PR，审查后合入 main。

```sh
git push -u origin sync/frp-update
```

## 维护边界

- 不批量重命名上游 Go module、内部目录和协议字段。
- 新功能优先写在独立目录，通过小范围改动接入上游。
- 保留 LICENSE、原作者版权头和上游文档。
- 官方镜像及发布流程带有 fatedier 的目标地址和专用 secrets；aissh 不直接使用这些发布流程。
- 迁移时仅添加构建 CI；后续管理后台的部署、域名、证书及认证需要单独实现与配置。
