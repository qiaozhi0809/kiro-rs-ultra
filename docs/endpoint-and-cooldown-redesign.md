# 端点路由 + 凭据并发 + 错误冷却 重构设计

> 起草于 2026-06-24，基于圣何塞生产环境（`kiro-rs-v059`，commit `307d005` "feat(endpoint)" 之后）的实测数据。
>
> 本文记录三件事：
> 1. 当前实测到的问题与数据
> 2. 两层端点路由（全局 + 凭据级覆盖）的目标架构
> 3. 错误冷却（计数+窗口）的目标策略
>
> 实施清单见末尾「Implementation TODO」。

---

## 1. 现状与问题

### 1.1 端点策略当前实现（commit 307d005）

- 全局两个开关：
  - `Config.default_endpoint`（"ide" / "runtime"，默认 "ide"）
  - `Config.runtime_fallback_enabled`（默认 true）
- 路由逻辑（`kiro/provider.rs::endpoint_for`）：所有请求第一次尝试都走 `token_manager.get_default_endpoint()`；失败时若 `runtime_fallback_enabled=true` 则尝试另一端点。
- 凭据 schema 已有 `endpoint: String` 字段，但**当前只用于"分布统计徽章"显示**（`endpoint_distribution()`），**不参与路由决策**。
- Admin API：`GET/PUT /api/admin/config/endpoint-policy`，写 config.json 后立即生效，不重启容器。

### 1.2 实测到的问题

**问题 1：前端切换按钮在某些场景下行为不符合预期**

数据（traces.db，最近 60 分钟）：

```
window      endpoint  attempt0_count  ttft_avg_ms
30-60m_ago  runtime   1258 (98%)
30-60m_ago  ide         23 (1.8%)
last_30m    ide       1012 (76%)
last_30m    runtime    325 (24%)        ← 这部分是 IDE 失败后 fallback
```

切换按钮**确实把全局起点切换了**（attempt=0 端点比例从 runtime 98% → ide 76%），但用户主观感受"按钮失效"——猜测原因：

- 切换瞬间 fallback 仍在工作，剩余 24% 的 runtime 流量来自 IDE 失败回退，用户看 traces 仍以为没切干净
- 或：切换 PUT 请求成功但 UI 无视觉确认（无 toast / 无端点 badge 立刻刷新）

**问题 2：单凭据成为热点，全局切换无法定向规避**

最近 30 分钟，IDE 端 attempt=0 失败（共 178 次）按凭据分布：

```
credential_id  attempt0_total  http_429  e429_pct  success
50             257             111       43.2%     144
52             239              29       12.1%     210
51             183              20       10.9%     161
64             190              12        6.3%     178
48             175               1        0.6%     171
```

凭据 #50 在 IDE 端 **43% 触发 429**（`USER_REQUEST_RATE_EXCEEDED`），单号一已经拖累整体成功率与 TTFT。当前只能"全局切换" / "整号 disable"，**无法做"#50 走 runtime、其他号走 ide"这种定向调度**。

**问题 3：凭据并发数显示与实际不符**

Admin API 返回的 `inFlight` 字段（凭据卡片"实时并发"）跟 traces 复盘出来的真实并发**对不上**。例：

```
credential 65: limit=10, recentDispatch60s=16, traces 5min 峰值=10
                admin api 5次连续抓 inFlight= 2,3,3,2,2

credential 51: limit=50, recentDispatch60s=13, traces 5min 峰值=8
                admin api 5次连续抓 inFlight= 1,0,0,0,0
```

`recent60s=13` 表示一分钟派出 13 次请求，每次跑十几秒，瞬时并发**应该**在 2-4，但 `inFlight` 长期 0-1。

**怀疑根因**：`inFlight` 计数器递增/递减不平衡——
- 请求开始 +1 在某条路径
- 流式正常完成 -1 在另一条路径
- 但流被客户端**断开/取消**或上游 5xx 走了不同的清理路径，**漏减了**（或反之）

后果：
- UI 显示的并发数不可信，运维误判负载
- 实际更严重：如果限流逻辑也读这个计数器（`inFlight < concurrencyLimit` 才放行），**计数偏小会让限流形同虚设**——这正好对应 #65 limit=10 实际打到 10 还在不停接的现象

**修复方向**：
- 用 RAII guard（如 `Arc<Semaphore>` permit drop / 自定义 `InFlightGuard`），保证请求结束（无论成功/失败/取消）一定递减
- 或者改成"按 traces 滚动窗口估算"——`inFlight = traces.where(start <= now AND end >= now).count()`，永远精确（代价是查表）

**问题 4：冷却策略对"长期慢号"无效**

当前 `accountThrottleCooldownSecs: 300`：单次 429 → 冷却 5 分钟。#50 这种**反复触发**的号被拉进 5 分钟冷却 → 解冻 → 再被打 → 再冷却，循环往复，**冷却没有变长**。

需要的是：
- 滑动窗口计数（M 分钟内 N 次错误才算"过载"）
- 累计触发次数升级冷却时长，或自动 disable 整号

### 1.3 重试链对 TTFT 的放大

```
total_attempts  trace_count  ttft_avg_ms
1               4272         10893
2                 56         21601    ← 两次几乎翻倍
3                 67         16351
6                  1        110489    ← 单次 110 秒
```

每多一次重试 ≈ 多一次 TTFT。所以"前置过滤掉问题号"的价值不只是降错误率，还显著降 TTFT 长尾。

---

## 2. 目标架构：两层端点路由

### 2.1 模型

```
endpoint_for(credential):
    if credential.endpointMode != "auto":
        primary = credential.endpointMode      // "ide" | "runtime"
    else:
        primary = global.defaultEndpoint

    if credential.runtimeFallback != null:
        fallback_enabled = credential.runtimeFallback
    else:
        fallback_enabled = global.runtimeFallbackEnabled

    return (primary, fallback_enabled)
```

**凭据级 > 全局**。覆盖字段为 null/"auto" 时继承全局。

### 2.2 数据 schema 变更

`KiroCredentials`（`src/model/credentials.rs` 或同等位置）现有：

```rust
pub endpoint: String,             // 当前只用于分布统计
```

改成（保留向后兼容）：

```rust
/// 路由首选端点。值："ide" / "runtime" / "auto"（=继承全局）
/// 旧版迁移：原值 "ide"/"runtime" 直接保留，其他空值/未知值视为 "auto"
pub endpoint_mode: String,

/// 是否允许 fallback 到另一端点。None = 继承全局；Some(bool) = 强制
pub runtime_fallback: Option<bool>,
```

旧字段 `endpoint` 改成 `endpoint_mode` 时做一次 migration。

### 2.3 路由层改动

`kiro/provider.rs::endpoint_for(credential)` 与 `fallback_endpoint(credential)`：

- 不再无脑 `token_manager.get_default_endpoint()`，而是先查 `credential.endpoint_mode`
- `runtime_fallback_enabled` 短路逻辑同理：先查 `credential.runtime_fallback`，None 时用全局

`endpoint_distribution()` 同时升级：分布按"effective endpoint"（解析后的实际首选）统计，而不是按 raw 字段，否则徽章会失真。

### 2.4 Admin UI 改动

凭据卡片编辑面板加两个字段：

- **端点模式**：单选（auto / ide / runtime）。auto 时显示"跟随全局：ide"灰字提示。
- **降级策略**：三态切换（auto / 强制开 / 强制关）

新 admin API：

- `PATCH /api/admin/credentials/{id}/endpoint-policy` 接 `{ endpointMode?: ..., runtimeFallback?: ... }`

`endpoint-policy-controls.tsx` 主面板的"分布徽章"保留，文案从"凭据级 endpoint 字段的副作用"改成"按生效端点统计"。

---

## 3. 凭据级并发限制

现有字段 `concurrencyLimit` (默认 50) + `concurrencyLimitOverride` 已有，但：

- **inFlight 计数不准**（见问题 3），导致 limit 形同虚设
- **没有 admin UI 编辑入口**让运维针对单凭据收紧并发
- **没有"effective concurrency"概念**——账号级别 + group 级别 + 全局级别需要协同

### 3.1 计数器修复（前置）

`InFlightGuard` 用 RAII 模式包装：

```rust
pub struct InFlightGuard {
    counter: Arc<AtomicUsize>,
}
impl InFlightGuard {
    pub fn acquire(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self { counter }
    }
}
impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}
```

请求开始时 `let _g = InFlightGuard::acquire(...)`，无论后续怎么 panic / cancel / await drop，离开作用域必递减。

或者直接换成 `tokio::sync::Semaphore`，permit 持有时间 = 请求活跃时间，semaphore.available_permits() 反推 inFlight。

### 3.2 数据 schema

`KiroCredentials` 已有 `concurrency_limit` / `concurrency_limit_override`。新增：

```rust
/// 并发限流的窗口语义。"semaphore" = 严格并发数；"rate" = 每秒派发数（QPS）
/// None = 默认 semaphore
pub concurrency_mode: Option<String>,
```

### 3.3 Admin UI

凭据卡片"并发"区显示：

- **当前在飞**: `inFlight` （重写后准确）
- **限额**: `concurrencyLimit`，可点击编辑
- **过去 60s 派发**: `recentDispatch60s`（已有）
- **饱和度**: `inFlight / limit` 进度条

编辑面板加 `concurrencyLimit` 数值输入框。

### 3.4 验证

修复 inFlight 后用 traces 复盘对比：

```sql
-- traces 5 分钟峰值 vs admin api 当前 inFlight
-- 修复后两者应在 ±1 范围
```

---

## 4. 目标策略：错误冷却（计数 + 窗口）

### 4.1 模型

```
凭据触发错误（429 / 5xx）时：
  push (now, errorType) into credential.error_window
  prune entries older than (now - errorWindowSecs)
  if len(error_window) >= errorThreshold:
      cooldown_until = now + cooldownSecs
      tripCount += 1
      if tripCount >= autoDisableAfterTrips within disableWindowSecs:
          credential.disabled = true
          credential.disabledReason = "AutoDisabled: rapid throttle"
          notify admin (UI badge / log)
```

### 4.2 配置 schema

全局（`Config`）：

```rust
pub error_cooldown_policy: ErrorCooldownPolicy {
    error_window_secs: u32,       // 默认 60
    error_threshold: u32,          // 默认 5
    cooldown_secs: u32,            // 默认 600
    auto_disable_after_trips: u32, // 默认 3
    disable_window_secs: u32,      // 默认 3600
}
```

凭据级覆盖（每字段独立 Option，None 继承全局）：

```rust
pub cooldown_policy_override: Option<PartialCooldownPolicy> {
    error_window_secs: Option<u32>,
    error_threshold: Option<u32>,
    cooldown_secs: Option<u32>,
    auto_disable_after_trips: Option<u32>,
    disable_window_secs: Option<u32>,
}
```

读取规则跟端点一致：每字段单独 fallback，未设值取全局。

### 4.3 兼容当前 `accountThrottleCooldownSecs`

旧字段当作"全局 cooldown_secs"的别名，第一次启动时迁移到新结构。`accountThrottleFailover` 字段语义保留（控制要不要在限流后切到下一个号），不动。

### 4.4 错误事件源

**计入窗口的 HTTP 状态**：

- 429 (`USER_REQUEST_RATE_EXCEEDED` 等所有 reason) → 计入
- 500 / 502 / 503 / 504 → 计入（上游瞬态故障）
- 400 → **不计入**（请求体问题，重试也无效，应该直接 fail-fast，不该惩罚号）
- 401 / 403 → 不计入（鉴权问题，单独走"凭据失效"路径）

`trace_attempts` 表已经有 `http_status`、`outcome` 字段，可以直接用。

### 4.5 Admin UI

凭据卡片：

- 显示"近 1 小时错误次数 / 上次冷却 / 累计触发次数"
- 编辑面板加"覆盖冷却策略"折叠区，每字段可填可留空（留空 = 继承全局）

全局：`/api/admin/config/cooldown-policy` GET/PUT，沿用现有 endpoint-policy 模式。

---

## 5. 落地拆分

### Phase 1：诊断与文档（本文档）

- [x] 圣何塞生产环境实测数据落档
- [x] 现状代码定位（commit 307d005 + 当前路由文件）
- [x] 两层架构 + 冷却策略设计

### Phase 2：止血（不改代码）

- [ ] Admin UI 临时禁用 #50（IDE 端 43% 429 的元凶）
- [ ] 观察 30 分钟后 429 率与 TTFT 变化，确认 #50 是主要瓶颈
- [ ] 临时把全局 `accountThrottleCooldownSecs` 从 300 → 900，给"惯犯号"更长冷却

### Phase 3：并发计数器修复（前置基础设施）

- [ ] 引入 `InFlightGuard` RAII 类型（或换 `tokio::sync::Semaphore`）
- [ ] 替换所有 `inFlight.fetch_add/sub` 手工调用，确保 drop 必递减
- [ ] 通过 traces 5 分钟峰值 vs admin api 当前 inFlight 在 ±1 内吻合验证
- [ ] Admin UI 凭据卡片"并发"区显示饱和度进度条 + 编辑 `concurrencyLimit` 入口

### Phase 4：凭据级端点覆盖（架构第 2 件）

- [ ] `KiroCredentials` 加 `endpoint_mode` / `runtime_fallback` 字段 + migration
- [ ] `kiro/provider.rs` 路由层读凭据字段优先
- [ ] `endpoint_distribution()` 按 effective endpoint 统计
- [ ] `PATCH /api/admin/credentials/{id}/endpoint-policy` 后端
- [ ] Admin UI 凭据编辑面板加端点模式 / 降级策略字段
- [ ] 测试：单号强制 runtime、其他全局 ide → 流量分布按预期

### Phase 5：错误冷却策略（架构第 3 件）

- [ ] `Config.error_cooldown_policy` 全局字段 + migration（吃旧 `accountThrottleCooldownSecs`）
- [ ] `KiroCredentials.cooldown_policy_override` 凭据级字段
- [ ] 错误窗口计数器（应放 `token_manager` 或 `provider` 内？设计时需选位置）
- [ ] 触发 trip 时 cooldown_until 写凭据状态、累计 tripCount
- [ ] `auto_disable_after_trips` 达阈值自动 disable + reason
- [ ] `GET/PUT /api/admin/config/cooldown-policy` 全局 admin API
- [ ] `PATCH /api/admin/credentials/{id}/cooldown-policy` 凭据级 admin API
- [ ] Admin UI：全局策略页 + 凭据卡片"近期错误"+ 编辑覆盖
- [ ] 测试：模拟号反复 429 → 累计触发 3 次 → 自动 disable

### Phase 6：切换按钮 UX 修复（架构第 1 件）

- [ ] 切换瞬间 admin UI 调出"已切换至 X，预计 30 秒内全量生效"toast
- [ ] 端点分布徽章 5 秒一刷新（当前需要手动）
- [ ] 切换后立即清空"近期端点分布"窗口起算，避免被切换前流量污染感知
- [ ] 文档说明 fallback 仍可能产生反向端点流量，不是"切换失败"

---

## 6. 验证手册

实施完成后端到端验证：

1. **凭据级端点强制**：把 `#50` 设 `endpointMode="runtime"`，全局保持 `defaultEndpoint="ide"`。30 分钟后看 traces：
   ```sql
   SELECT credential_id, endpoint, COUNT(*) FROM trace_attempts
   WHERE attempt=0 AND ts_epoch > strftime('%s','now')-1800
   GROUP BY credential_id, endpoint;
   ```
   预期：#50 几乎全 runtime，其他凭据几乎全 ide。

2. **错误冷却升级**：模拟单号 1 分钟内被打 6 次 429（threshold=5）：
   - 第 5 次 → 触发冷却，`throttledRemainingSecs > 0`
   - 第 6 次后 1 小时内再触发 2 轮 → 凭据自动 `disabled=true, disabledReason="AutoDisabled"`

3. **fallback 凭据级覆盖**：把 `#48`（健康号）设 `runtimeFallback=false`，全局开 fallback。模拟 #48 IDE 端故障 → 应直接报错给客户端，不打 runtime。

---

## 7. 备注

- 圣何塞生产 commit hash 与本仓 main 的差距：服务器跑 `ghcr.io/daniellee2015/kiro-rs-ultra:latest`，每次本仓 push main 触发 CI 构建镜像 → 服务器 `docker compose pull` 即可。改动在本仓做完即可发布。
- 改动会改 `KiroCredentials` schema，需写一次 credentials.json 的 in-place migration（启动时检测旧字段、补默认值），避免线上文件不兼容。
- Admin UI 是 Bun + React，开发命令 `cd admin-ui && bun run dev`。
