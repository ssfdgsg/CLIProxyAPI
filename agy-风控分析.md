# agy（Antigravity CLI）认证与风控系统本地分析

> 分析方法：完全本地静态（Go 符号/字符串） + 断网动态（proxy 置错）。**全程未让 agy 联网。**
> agy 版本 1.5.8，`/home/dxy/.local/bin/agy`，281MB Go 静态二进制（stripped）。

## 一、agy 是什么

Antigravity（Google）的 CLI 客户端，Go 编写（符号 `google3/third_party/jetski/...`），与 Claude Code 无关。通过 OAuth 连 Google，调用 `aicode.googleapis.com`（AI Code / Gemini 模型服务）。

## 二、认证体系

### 登录方式：Google OAuth 2.0 + PKCE
- 认证端点：`https://accounts.google.com/o/oauth2/auth`
- 客户端 ID：`1071006060591-...apps.googleusercontent.com`（Antigravity 官方）
- 回调：`https://antigravity.google/oauth-callback`
- PKCE：`code_challenge` / S256
- 令牌端点：`https://oauth2.googleapis.com/token`

### 申请的 scopes（决定访问权限）
```
openid
https://www.googleapis.com/auth/userinfo.email
https://www.googleapis.com/auth/userinfo.profile
https://www.googleapis.com/auth/cloud-platform
https://www.googleapis.com/auth/cclog
https://www.googleapis.com/auth/experimentsandconfigs
https://www.googleapis.com/auth/aicode          ← 核心：AI Code 服务
```

### 凭据存储（本地文件）
```
~/.gemini/antigravity-cli/
├── antigravity-oauth-token   权限 600，JSON：
│     token.access_token   ya29... (260字符, 短期)
│     token.refresh_token  1//0e... (长期, 用于刷新)
│     token.token_type     Bearer
│     token.expiry / expires_in  (3599s ≈ 1小时)
│     auth_method          "consumer"
│     id_token_email       你的 Google 滑箱
├── installation_id         安装UUID（设备指纹之一）
├── settings.json           user 配置、model、permissions
└── jetski_state.pbtxt      installation_uuid、onboarding 状态

~/.gemini/jetski/            jetski sidecar 状态
~/.gemini/config/            mcp_config.json、projects/
```

## 三、风控机制（重点）

### 3.1 令牌生命周期 = 封号关键
- access_token **1 小时**过期 → 靠 refresh_token 自动刷新
- 刷新端点 `https://oauth2.googleapis.com/token`
- 上游拒绝刷新 → 触发登出（见 3.3）

### 3.2 联网触点（= 可能触发风控的地方）
- `accounts.google.com`：登录/OAuth
- `oauth2.googleapis.com/token`：token 刷新（每小时）
- `aicode.googleapis.com`：AI 推理、UserInfo、UserSettings、credits
- `aiplatform.googleapis.com` / `generativelanguage.googleapis.com`：ADC/Vertex 模式

### 3.3 风控/登出触发字符串（从 binary 提取）
| 字符串 | 含义 |
|---|---|
| `Stored OAuth credentials definitively rejected during validation; evicting token and signing out` | **token 被服务端验证拒绝 → 本地清 token + 登出**（封号/吊销的直接表现）|
| `cannot refresh the OAuth token for %s` | refresh 失败 |
| `OAuth refresh after 401 failed` | 401 后刷新仍失败 |
| `sign-out-missing-aicode-scope` | **缺 `aicode` scope → 强制登出**|
| `credential_rejected` / `unauthorized_client` | 客户端被拒 |
| `Account ineligible` | 账号不符合资格 |
| `auth_revoked` | 授权被吊销 |
| `Stored token metadata changed externally; updating in-memory auth session` | 外部改了 token文件 |
| `RATE_LIMIT_EXCEEDED` / `RESOURCE_EXHAUSTED` / `retry-after` | 配额/限流（429 类）|
| `AI Credits not enabled` | 计费/额度 |

### 3.4 客户端身份（风控设备维度）
- `installation_id`、`installation_uuid`（`jetski_state.pbtxt`）→ 设备标识
- OAuth client_id → 应用标识
- `id_token_email` → 账号标识

### 3.5 为什么会“联网可能封号”
agy 每次启动/每次请求会用 refresh_token 换 access_token 并打 `aicode` API。若你当前账号处于**资格受限 / scope 不全 / token 被标记**状态，联网验证会立刻 `Stored OAuth credentials definitively rejected` → 本地登出，且服务端记录异常。断网则不会触发刷新验证，故无风险。

## 四、结论与建议
1. 认证 = **Google OAuth（consumer），refresh_token 长效存于 `~/.gemini/antigravity-cli/antigravity-oauth-token`（600）**。
2. 风控核心是**服务端 token 验证**（`aicode` scope + 资格校验），客户端层面无本地“检测/加固”。封号与否由 Google 服务端决定。
3. 保护建议：
   - **备份** `antigravity-oauth-token` 与 `installation_id`（refresh_token 可复用）。
   - token 文件务必保持 600。
   - 不确定账号状态时**先断网运行**，避免触发 `evicting token and signing out` 式登出。
   - 若 expired 只需联网刷新一次即可；用 `AGY_ADC_AUTH`（Google Cloud ADC）可走企业/按量付费，绕开 consumer 配额风控。
