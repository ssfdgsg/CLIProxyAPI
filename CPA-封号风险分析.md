# 为什么用 CPA 容易封号（agy/Antigravity 视角）

对比 agy 原生 CLI vs CPA 复用同一 Google OAuth client 的行为差异，找出高概率封号触发点。

## 差异一：OAuth 握手 · CPA 没用 PKCE（🔴 高）

agy 原生（前面断网 print 验证）：
```
https://accounts.google.com/o/oauth2/auth?
  ...&code_challenge=...&code_challenge_method=S256
  &redirect_uri=https%3A%2F%2Fantigravity.google%2Foauth-callback
```

CPA `internal/auth/antigravity/auth.go:148-150` 的 auth URL 参数：
- ✅ 同 client_id（`1071006060591-...`）
- ❌ **没有 code_challenge / PKCE**
- ❌ redirect_uri 不是 `antigravity.google/oauth-callback` 而是本地 `localhost:51121`（CallbackPort 常量）

**含义**：CPA 重新发明了一个 OAuth 流程（本机 HTTP 回调、无 PKCE、共用 client_secret 常量 `GOCSPX-K58...`）。
Google 风控看到的是：同一个 client_id 但走"不那么标准"的握手、不同 redirect URI、Bearer 直接从 code 换。**如果风控规则检测 client_id + redirect 不匹配 / 缺少 PKCE → 可能标记为异常登录来源 → 触发 verify challenge 或吊销 refresh_token**。

## 差异二：CPA 多拿一个不该暴露的 client_secret（🟡）

`constants.go:6`：`ClientSecret = "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"` 硬编码在源码里——OAuth client_secret 设计上是**不应随 CLI 客户端分发**的（CLI 是 public client）。agy 原生走 PKCE 就是为了避免 client_secret 落地。CPA 把它当私密用，**这与 Google 对"原生应用应走 PKCE"的预期不一致**，长跑会增加风险。

## 差异三：元数据瘦身（🟡 中）

agy 原生 token JSON 含：`access_token / refresh_token / expires_in / token_type` + **`id_token_email / auth_method / installation_id / 完整的 expiry 时间戳`** 等。

CPA `TokenResponse`（`auth.go:20-25`）**只存 4 个字段**。
- 没有 `installation_id` 记录 → Google 风控看不到稳定的"设备指纹"。每次刷新在 Google 看来像来自"新设备"。
- 没有 `id_token` → CPA 不能校验 aud/azp、拿 email 做安装绑定。
- 多账号并存时（`filename.go:fmt.Sprintf("antigravity-%s.json", email)`）账号隔离依赖 email，但 email 通过额外一次 `oauth2/v2/userinfo` 拿 —— 多了一次 HTTP 调用 = 多了一次风控机会。

## 差异四：额度/限流逻辑（🟡 中）

CPA `antigravity_executor_credits.go` 定义了详尽的 429 分类：
- `antigravity429RateLimited / QuotaExhausted / SoftRateLimit`
- 决策：soft_retry / instant_retry_same_auth / short_cooldown_switch_auth / full_quota_exhausted

好处：遇到 429 知道区分退避、切下一个账号。
**但**：CPA 的"切下一个账号"会**并行疯狂打 aicode.googleapis.com**——如果配额临近上限、switch 触发频繁，Google 侧看到的是短时间内来自不同 client 的并发调用，比 agy 原生（自家串行）压力大 → **更易触发全局 resource_exhausted → 反噬到账号风控**。

## 差异五：环境/指纹差异（🟢 小）

agy 原生有 `installation_id`、`installation_uuid`、本机平台 header；CPA 默认只是个 Go http client，浏览器、UA、设备 ID 都不同，**风控画像与原生 agy 不在同一个轨道**——单用没问题，**混用 agy + CPA 在同一账号** 时会出现"同一账号在两套设备画像间反复横跳"，长期累积异常。

## 总结：CPA 封号概率高的根因

| 优先级 | 问题 | 影响 |
|---|---|---|
| 🔴 1 | OAuth 无 PKCE + redirect_uri 与官方不同 + client_secret 硬编码 | Google 风控认为非预期客户端 |
| 🟡 2 | token 元数据丢失（no installation_id、no id_token） | 刷新指纹不稳定 |
| 🟡 3 | 多凭据切换导致短时间内 aicode 调用频次激增 | 429 → 账号级风险 |
| 🟢 4 | 与官方 agy 不同的客户端画像 | 与 agy 混用时异常 |

## 修复建议

1. **改用 PKCE + 官方 redirect**（`https://antigravity.google/oauth-callback`），去掉 ClientSecret 常量。
2. **Token 存储加 `installation_id`**（CPA 自己生成 UUID 一次，随 refresh 写回）。
3. **429 退避改保守**：单账号串行 + 指数退避，把"切账号 cooldown"默认值延长。
4. **文档提醒**：同一账号别在 agy 和 CPA 之间交替用，要么二选一，要么用 agy 的 `AGY_ADC_AUTH`(Google Cloud ADC) + CPA 业务服务账号分流。
