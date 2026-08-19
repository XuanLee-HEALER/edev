# edev

`edev` = **e**rase **dev** ports —— 诊断并清理占用本机开发端口的服务。

## 项目目标

给"到底是什么占着我的端口"一个能直接行动的答案,然后把它清掉。

下面几条是这个项目的立身之本,改代码时不要破坏:

- **判定依据是进程的启动现场,不是端口号。** argv、envp、cwd、父进程、端口上的活跃连接。
  端口号几乎不携带信息 —— `8080` 可以是任何东西,正经后端也可能跑在 `3800`。
  **不要再引入端口白名单做预过滤**,全量扫 65535 个端口和扫白名单一样快,白名单只会漏。
- **被动。** 绝不主动连接任何端口。不发探测流量,不进别人的访问日志,不触发限流。
  要加主动探测必须是显式 opt-in 的开关,默认关,且只探回环。
- **快。** 全量遍历约 900 个进程约 3 ms。直接走 `libproc` 和 `sysctl`,**不 fork `lsof`**。
  重的系统调用(`pidpath`、`getpwuid`、`KERN_PROCARGS2`、`PROC_PIDVNODEPATHINFO`)
  只对筛出来的候选进程做,不进全量扫描路径。
- **可解释。** 每条判定都带着产生它的证据一起输出,`-l` 能把推理过程全摊开。
  判错了要让用户一眼看得出来,而不是给一个不可质疑的结论。
- **克制。** 这是清理开发端口的工具,**不是通用的杀进程工具**。
  系统组件和 edev 自身的祖先进程绝对保护,不提供任何放行开关 ——
  曾经有过 `--include-system`,因为它能让 `clean --all` 杀掉用户自己的终端而被移除。
- **隐私。** 环境变量只参与判定,之后立即丢弃,不保存不打印,连 key 都不进 JSON。
  argv 在存进 `Verdict` 之前先脱敏。
- **`src/platform/` 是后端接缝。** 平台专有的东西(系统服务名、系统路径前缀、
  supervisor 进程名、libc 调用)一律留在后端里,不许泄漏到共享层,
  否则将来接 Linux 后端时保护策略会静默失效。

## 发版流程

前置:仓库 secret `TAP_TOKEN` 必须是一个对 `XuanLee-HEALER/homebrew-tap`
有 Contents 写权限的 PAT。默认的 `GITHUB_TOKEN` 只能操作本仓库,推不到 tap。

1. 改 `Cargo.toml` 的 `version`。
2. 提交推到 `main`,等 CI 绿。CI 跑在 `macos-latest` 上 ——
   只能这样,别的系统会直接撞上 `src/platform/mod.rs` 的 `compile_error!`。
3. 打 tag 并推:

   ```bash
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```

4. `Release` workflow 自动完成剩下的:

   - 校验 tag 是 `main` 的祖先,不是就拒绝发版
   - 校验 tag 版本号等于 `Cargo.toml` 里的 version,不一致就拒绝
   - 编 `x86_64-apple-darwin` + `aarch64-apple-darwin`,`lipo` 合成通用二进制,
     `MACOSX_DEPLOYMENT_TARGET=11.0`
   - 打包(含 LICENSE,GPL-2 §3 要求),发 GitHub Release
   - 重写 `homebrew-tap` 里的 `Formula/edev.rb` 并提交

5. crates.io 目前**手动**发,没接进 workflow:

   ```bash
   cargo publish
   ```

   crate 名是 `edev-cli`(`edev` 在 crates.io 已被别人占用),
   装出来的命令仍然是 `edev`,靠 `[[bin]] name = "edev"` 分开。
   需要一个带 `publish-update` scope 的 crates.io token。

### 容易踩的坑

- **tag 版本和 `Cargo.toml` 不一致** —— workflow 会在编译前就失败。先改版本号再打 tag。
- **在非 main 的提交上打 tag** —— 同样会被拒。
- **`main` 有分支保护** —— 外部 PR 需要批准且 CI 必绿;仓库 owner 可以直推。
