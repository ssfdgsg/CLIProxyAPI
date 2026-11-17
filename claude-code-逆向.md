# Claude Code 2.1.220 静态逆向报告

> 样本：`/home/dxy/.nvm/versions/node/v22.22.1/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe`
> 275 MB ELF x86-64, **not stripped**, Bun 打包（SEA）。SHA-256 of `.bun` section body:
> JS bundle offset `0x991b708`, length `21,633,085` bytes (20.6 MB plaintext minified JS).
> 分析方式：静态 only，未启动 claude 进程，未联网。

---

## 1. 打包形态

| 项 | 值 |
|---|---|
| 入口按需加载 | `$bunfs/root/src/entrypoints/cli.js` |
| 内嵌原生 `.node` | `image-processor.node`, `audio-capture.node` |
| 内嵌 JS 资源 | `chart.umd.min.js`, `hljsBundle.generated.min.js`, `mermaid.min.js` |
| Toolchain | Bun 1.97.0-nightly, GCC 13.1 (Ubuntu 24), lld 22.1.4 |
| 运行时 | `node >= 22` 引擎；`bun` SEA（`NODE_SEA_FUSE` 0，有 `bun.sh` 标识 11） |
| 主 JS bundle | 单一 20.6 MB 字符串，minified；明文可读 |

---

## 2. OAuth 协议（**核心**）

### 2.1 常量

| 常量 | 值 |
|---|---|
| `CLIENT_ID` (Claude Code / Pro/Max 订阅) | `9d1c250a-e61b-44d9-88ed-5944d1962f5e` |
| `DESIGN_CLIENT_ID` (Design 子产品) | `59637612-477b-4836-a601-b0589eda7704` |
| `CONSOLE_SUCCESS_URL` | `https://platform.claude.com/buy_credits?returnUrl=/oauth/code/success%3Fapp%3Dclaude-code` |
| `CLAUDEAI_SUCCESS_URL` | `https://platform.claude.com/oauth/code/success?app=claude-code` |
| `MANUAL_REDIRECT_URL` (headless) | `https://platform.claude.com/oauth/code/callback` |
| Loopback redirect (默认) | `http://localhost:${port}/callback` |
| `TOKEN_URL` | `https://platform.claude.com/v1/oauth/token` |
| Authorize URL (订阅) | `https://claude.com/cai/oauth/authorize` |
| Authorize URL (Console) | `https://platform.claude.com/oauth/authorize` |
| `Beta` 标识 |   public: `User Agent`, sdk: `X-Claude-Code-Ide-Authorization`, GitHub: `ccr-byoc-2025-07-29` |

### 2.2 Scopes (`trt`)

```
user:profile
user:inference
user:sessions:claude_code
user:mcp_servers
user:file_upload
```

Console（API 密钥）额外加 `org:create_api_key`。

### 2.3 Authorization URL 拼装（`sno`）

Query 参数：`code=true`, `client_id`, `response_type=code`, `redirect_uri`,
`scope`, **`code_challenge`**, **`code_challenge_method=S256`**, `state`,
(optional) `orgUUID`, `login_hint`, `login_method`.

### 2.4 Token 交换 — **`application/json` body**（**关键差异**）

```js
await Mo.post(TOKEN_URL, {
  grant_type: "authorization_code",
  code, redirect_uri, client_id, code_verifier, state,
  expires_in?                          // optional, caller-supplied
}, {
  headers: { "Content-Type": "application/json" },
  timeout: 30000
})
```

❗ CPA 在 token endpoint 用的是 `application/json body` **正确**（`anthropic_auth.go:223-224`）。  
❗ agy-Antigravity 侧用的是 `application/x-www-form-urlencoded`，CPA 一致，**正确**。

### 2.5 Token 刷新

```js
{
  grant_type: "refresh_token",
  refresh_token,
  client_id,
  scope: trt.join(" "),               // 缺省回到 Claude Code 默认 scopes
  expires_in?
}
```

刷新成功后处理 `access_token`, `refresh_token` 缺省**回退到旧值**,
`expires_in`, **`refresh_token_expires_in`** (CPAn), `scope`, 并回查账户信息。

❗ CPA 的 `refresh_token_expires_in` 处理：`internal/auth/claude/anthropic_auth.go:537`
写回 body 字段，**正确**。

---

## 3. 凭据与设备

### 3.1 凭据存储位置

| 后端 | 路径 | 注释 |
|---|---|---|
| 默认 | `~/.claude/.credentials.json` | 明文 JSON, `Q5i = { name: "plaintext" }` |
| 后选 | OS keychain (`security find-generic-password` on macOS) | 检测 `keychain_locked`/`no_keychain` |
| MCP 服务器级 | 同名 .credentials.json，**每 server 一个**, keychain 凭据 scope 化 | — |

❗ **CPA 不复用 CC 的凭据存储** —— 维护自己独立的 auths/ 目录，
   不会因 agy/Claude Code 文件覆盖或权限问题串扰。

### 3.2 Trusted Device Enrollment（可选/企业特性）

1. 仅当 **org policy** 启用 + **feature gate `urn`** 开启 + 用户 OAuth 登录到订阅账号；
2. `POST /api/auth/trusted_devices` body: `display_name = "Claude Code on ${hostname} · ${os}"`
3. 响应 `device_token` 存 `~/.claude.json` 的 `trustedDeviceToken`；
4. 后续 `yRy()` header builder 偶尔附加 **`X-Trusted-Device-Token: <token>`**：
   - Cloud sessions（`/v1/code/sessions/*`）
   - GitHub PR bridge（`/v1/code/github/*`）

**指纹 UA 默认包含产量消费只有 hostname 与 os 名称 → 不是硬件 hash**。
**CPA 完全没实现这个特性**；这一头缺省不影响封号判定（gate 然后才发）。

### 3.3 User-Agent 拼装（`SS()`）

模板：`claude-code/${VERSION}[ , external][ , sdk-cli/<sdk_ver>][ , client-app/<env>][ , workload/<...>]`

入口 `CLAUDE_CODE_ENTRYPOINT` env 派生：
`claude-vscode`, `remote`, `claude-in-teams`, `sdk-cli`, `sdk-ts`, `sdk-py`, `mcp`,
`claude-code-github-action`, 默认 CLI.

→ UA 形如：
```
claude-code/2.1.220, external, cli
claude-code/2.1.220, external, sdk-cli/0.3.220
```

⚠️ **CPA 用的是 `claude-cli/<ver>` 而不是 `claude-code/<ver>`**，
   例如 `internal/runtime/executor/claude_executor_request.go:1474`。

❗ 对比 Anthropic 上游：`claude-cli` 与 `claude-code` **并不是同一个东西**——
   `claude-cli` 是社区旧 CLI 的包名；Claude Code 是官名。但 real CC 2.x 的 UA 实测
   仍是 `claude-cli/<ver> (external, cli)`（`SS()` 模板里 UA 串首是 `claude-code/...`,
   而 CPA 字符串实际写的是 `claude-cli/` 前缀）。**这俩不一致**——
   CPA 有反向假造 UA 的可能，但因为 Anthropic 用 UA 做分流度取决于灰度，**存疑中风险**。

**`anthropic-client-platform` header**（`cP()`）：
```
claude_vscode | claude_code_remote | claude_code_sdk | claude_code_mcp |
claude_code_github_action | claude_code_cli  (默认)
```

**CPA 完全没发这个 header**——但 CC 在大部分请求依赖 `defaultHeaders`
来自 SDK 默认。看 CC 主线消息请求 `defaultHeaders` 由 `Uqe()` 组装，CPA 检查
`defaultHeaders.x-api-key`，没显式 `anthropic-client-platform`，多半 SDK 自己发给。**待抓包证实**。

### 3.4 其他常规 headers

| header | 出频 | 备注 |
|---|---|---|
| `x-api-key` / `X-Api-Key` | 7+13 | API key fallback |
| `Authorization: Bearer` | — | OAuth access token |
| `anthropic-version: 2023-06-01` | — | 全请求 |
| `anthropic-beta: <list>` | — | context-1m, advisor-tool, claude-code-20250219, ccr-byoc |
| `x-organization-uuid` | 14 | 团体 org 隔离（`Z.zither isUser`） |
| `x-app: cli` | 2 | **硬编码到 CPA test 校验**（`claude_issue_6120_test.go:73`） |
| `x-stainless-*` | — | Anthropic 官方 SDK 默认 steel 头 |
| `X-Claude-Code-Ide-Authorization` | 2 | VSCode IDE, executor 互斥与 main bearer |

---

## 4. 限流与重试

### 4.1 服务端头透传（**Claude Code 听取服务端**）

```
anthropic-ratelimit-unified-status
anthropic-ratelimit-unified-reset
anthropic-ratelimit-unified-overage-status
anthropic-ratelimit-unified-overage-disabled-reason
anthropic-ratelimit-unified-overage-in-use
anthropic-ratelimit-unified-overage-period-monthly-utilization
anthropic-ratelimit-unified-overage-period-channel-utilization
anthropic-ratelimit-unified-overage-reset
anthropic-ratelimit-unified-grace-status               (grace period)
anthropic-ratelimit-unified-fallback
anthropic-ratelimit-unified-upgrade-paths
anthropic-ratelimit-unified-representative-claim
anthropic-ratelimit-7d-status / -7d-reset             (per week)
anthropic-ratelimit-unified- (前缀)
```

→ CC 已有结构化配额判定（`five_hour`/`seven_day`/`seven_day_sonnet`/`seven_day_opus`/
`seven_day_overage_included`）。**CPA 已识别 `unified-status`/`unified-reset`/`unified-7d-status`/**
`unified-7d-reset`**（`claude_executor_ratelimit_test.go:253-255`），**对齐良好**。

### 4.2 默认重试 & 退避配电 (SDK `retryRequest`)

Retry 条件：`status===408 | 409 | 429 | >=500`。

读 `retry-after-ms` header 优先；`retry-after` number 秒或 HTTP-date；否则
`calculateDefaultRetry(maxRetries)`。

CLI-SDK 默认 `maxRetries` 来自 base URL / API key 配置。

**CPA 没有强制 client-side 限流也没有协商过的延迟决策——但 Anthropic
claude_api SDK 已在被 proxy 客户默认插话。不需要 CPA 再造。**

---

## 5. 遥测

- **datasource**：Statsig（feature flag），Datadog RUM/Logs (`browser-intake-us5-datadoghq.com`,
  `http-intake.logs.us5.datadoghq.com`)，Sentry MCP。
- **事件命名**：`tengu_*` 前缀（`tengu_oauth_token_exchange_success`,
  `tengu_oauth_401_recovered_from_keychain`, ...）。
- **采样 gate**：`ca()` "essential traffic only"。

**CPA 不发任何后端遥测**，不会与 Anthropic 服务号策略冲突。✅

---

## 6. 对照 CPA 的潜在风险点清单

| # | 议题 | CPA 现状 | 风险 |
|---|---|---|---|
| 1 | OAuth client_id | 9d1c250a-... 对齐 | ✅ |
| 2 | OAuth scopes | user:inference/sessions:name/... 全对齐 | ✅ |
| 3 | PKCE (S256) | 已实现 (`internal/auth/claude/pkce.go`) | ✅ |
| 4 | exchange body Content-Type | application/json | ✅ |
| 5 | refresh body format | application/json + 字段齐全 | ✅ |
| 6 | Manually 手动 redirect URI headless | 是 `http://localhost:54545/callback` 默认；CC 上游是 `platform.claude.com/oauth/code/callback` | ⚠️ info |
| 7 | User-Agent 默认 | `CLIProxyAPI/<version>` 兜底；如果下游传 claude-cli/... 转发 | ⚠️ 中 |
| 8 | anthropic-client-platform header | 不确定 CPA 默认是否发 | ⚠️ 待抓包 |
| 9 | x-app: cli 默认要写 | 已写 | ✅ |
| 10 | rate-limit headers 解析 | 部分对齐（unified- 默认四个） | ✅ |
| 11 | trusted device enrollment | **完全没实现** | ⚠️ 企业账号 |
| 12 | `.credentials.json` importer | 没有 | ℹ️ design choice |

---

## 7. 结论

CPA **Claude 鉴权协议对齐基本到位**。Antigravity 那边 PKCE 刷新前这就是测序 —
Claude 这边全原本就好。

**剩下两类问题：**

1. **小 header 差异**（user-agent / anthropic-client-platform）——封号 signal 弱；
2. **企业账号特性缺**（`X-Trusted-Device-Token`）——不逃默认上 context，
   在某些 org policy 下会让请求返回 401/403 而不是被风控封号。

**不可能是 CPA Claude 鉴权触发封号的主因。** Antigravity 仍然是主战场
（参见 `agy-风控分析.md` / `CPA-封号风险分析.md`）。
