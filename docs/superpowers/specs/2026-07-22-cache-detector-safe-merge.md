# 缓存计费口径迁移:超报 → 检测安全(B1 保留哈希链)

- 日期:2026-07-22
- 范围:仅 `cache_metering.rs` 计费口径层 + 其 per-key 配置波及面
- 上游来源:`aosika3324/kiro.rs` 分支 `feat/cache-metering-detector-safe`(commit `db2e1423d`/`0c2be77d1`/`868ac5bab`)
- 不含:TLS 指纹(#5)、断流 error(#4)、SOCKS 回退(#6)、http_client 超时重构

## 背景

本 fork 之前从上游旧版 cherry-pick 了"超报式"计费(commit 2a01974):`split_anthropic_standard` 通过 `read_final = read0 × (1+p)` 多报 cache_read token 赚差价,上报总量 > 真实 total。线上 ns-1~ns-5 五个组开着此模式。

上游随后(7-14→7-21)**主动废弃超报**,理由是超报使 `weighted/baseline`(检测方看到的 multiplier)飙到 7~20x,远超真实 Anthropic 自然上限(~1.25x),极易被计费检测判 Abnormal/封号。上游改为"检测安全"口径:上报恒 == 真实,multiplier 由护栏钳在 1.25 内。

## 决策(已与用户确认)

1. **弃超报,跟检测安全**——不再多报,`input + creation + read == total_real` 恒成立。
2. **B1 保留哈希链**——read/creation 的比例基准仍来自本地哈希链命中量(`compute_cache_usage` + CacheMeter 段表),只替换计费**口径**。不采用上游的纯结构化估算(B2),因为本地哈希链(尤其 seed3 对话隔离)比上游结构估算更准,且 TTL/grace 是本 fork 独有价值。
3. **保留 R 旋钮**——per-key `read_ratio`(R)作为**安全**赚头替代:R<1 把便宜的 read(0.1x)挪回 input(1.0x),`sum==total` 不变(非超报),护栏保证 multiplier 永不超 1.25。给 ns 组补 margin。

## 不变量(本次迁移必须守住)

- **正交保留:** TTL(5min,刚由 15min 改回)、grace(30min)、DEFAULT_CAPACITY(65536)、`isolation_seed` 分支3(`key:root:hash`)——一行不动。
- **seed 双用途:** `isolation_seed` 不只喂计费,还喂 response_cache 命中回放(response_cache.rs:98),必须保留。
- **恒等式:** 所有分摊路径 `input + creation + read == total_real`。
- **零 panic 迁移:** 删 ClientKey 字段后,老 config.json 里残留的 `anthropicBillingMode` 等被 serde 静默忽略,不崩。

## cache_metering.rs 字段级改动

### CacheUsage 结构

保留哈希链三字段,删超报四件套,加检测安全三字段:

| 字段 | 动作 | 说明 |
|---|---|---|
| `cache_read` | 保留 | 哈希链命中的 read estimate |
| `cache_covered_est` | 保留 | 被缓存覆盖前缀 estimate(read+creation) |
| `prompt_total_est` | 保留 | 分摊分母 |
| `billing_mode` | **删** | 超报开关 |
| `read_inflation` | **删** | 超报系数 p |
| `creation_ratio` | **删** | 超报专用 creation 占比 |
| `pinned_input` | **删** | 超报专用钉 input |
| `multiplier_cap` | **加** | 护栏上限,默认 `DEFAULT_MULTIPLIER_CAP`=1.25 |
| `read_ratio` | **加** | R 阻尼 ∈[0,1],默认 1.0(不挪) |
| `creation_is_1h` | **加** | creation 归 1h 桶,默认 false;影响计价权重不改 token 总数 |

### 常量(新增/保留)

```rust
pub const WEIGHT_INPUT: f64 = 1.0;
pub const WEIGHT_CREATION: f64 = 1.25;
pub const WEIGHT_CREATION_1H: f64 = 2.0;
pub const WEIGHT_READ: f64 = 0.1;
pub const DEFAULT_MULTIPLIER_CAP: f64 = 1.25;
// 删:DEFAULT_PINNED_INPUT / MAX_READ_INFLATION / DEFAULT_READ_INFLATION / DEFAULT_CREATION_RATIO
```

### 函数

- **删** `split_anthropic_standard`(超报)、`apply_billing`(注入超报参数)、`split_final`(口径开关)。
- **改造** `split_against_total(total_real)`:前半段照旧用哈希链比例(`cache_covered_est/prompt_total_est` → cache_total,再按 `cache_read/cache_covered_est` 拆 read/creation)算出三桶;**末尾新增两步**:
  1. **R 阻尼**:`read_kept = read × R`,`input += read − read_kept`(被砍的 read 推回 input,creation 不动)。
  2. **护栏** `apply_multiplier_cap(total, input, creation, read)`:移植上游实现——`weighted = input×1.0 + creation×creation_weight() + read×0.1`;若 `weighted > cap×total`,把 `mv = ceil((weighted − cap×total)/0.9)` 个 token 从 input 挪到 read,钳 `[0,input]`,creation 绝不动。
- **移植** `apply_multiplier_cap` + `creation_weight`(1h→2.0 / 5m→1.25)。
- **新增** `request_marks_1h_cache` + `json_has_1h_cache_control`(从上游移植,给 `compute_cache_usage` 赋 `creation_is_1h`)。

### compute_cache_usage

保持哈希链逻辑不变,仅在构造 CacheUsage 时补:`read_ratio`(从 per-key 传入)、`multiplier_cap`(per-key 覆盖或默认)、`creation_is_1h = request_marks_1h_cache(req)`。

## 波及文件(删字段 + 改调用)

| 文件 | 改动 |
|---|---|
| `handlers.rs:954`、`:1832` | 删 `apply_billing(...)` 调用块;改为注入 `read_ratio`/`multiplier_cap`(见下) |
| `handlers.rs:1505`、`stream.rs:1430` | `split_final(x)` → `split_against_total(x)` |
| `admin/client_keys.rs` | 删超报三字段 `anthropic_billing_mode`/`cache_read_inflation`/`cache_pinned_input` + 其 accessor + upsert 分支;**净新增** `cache_read_ratio`/`cache_multiplier_cap`(本地此前无此二字段)+ accessor + upsert(clamp:R∈[0,1]、cap∈[0.1,1.25]) |
| `admin/types.rs:933/996` | 删对应 API 字段(view + update) |
| `admin/handlers.rs:1081/1186-1193` | 删 billing_touched 分支,改走 read_ratio/multiplier_cap 更新 |
| `anthropic/middleware.rs:32-36/159-161` | KeyContext 删超报三字段(`anthropic_billing_mode`/`cache_read_inflation`/`cache_pinned_input`),净新增 `cache_read_ratio`/`cache_multiplier_cap` 注入 |
| ~~`src/model/config.rs`~~ | **实现时省略**:`CacheUsage::default()` 已内置 R=1.0/cap=1.25,per-key None 直接落默认,全局字段冗余(YAGNI) |
| `anthropic/prompt_filter.rs:169` | 构造默认删超报字段 |
| admin-ui | 编辑弹窗"标准计费"区块:删超报输入(inflation/pinned),留/加 R + cap 两个安全旋钮 |

## ns-1~ns-5 迁移行为

删 ClientKey 超报字段后,serde 静默忽略 config.json 里的 `anthropicBillingMode:true`/`cacheReadInflation` 残留(不崩)。这 5 组自动从"超报"回落到"哈希链真实命中 + 1.25 护栏"。

**计费形状变化(需预期):** 不再凭空多报,cache_read 数字回归真实命中量,per-key 上报总量从 >total 降到 ==total。若要保留 margin,给 ns 组设 `cacheReadRatio`(如 0.7),在护栏内换取有界差价。这一步是**运行时配置**(admin-ui 或 config.json 改 per-key),不走代码。

## R 旋钮数学(安全性论证)

- R=1.0(默认):read 全留,input 不增 → multiplier 最低,纯真实形状。
- R<1.0:每挪 1 token read→input,weighted 升 0.9(input 1.0x − read 0.1x)。R 越低 margin 越高、命中率显示越低。
- **护栏兜底:** 无论 R 设多低,`apply_multiplier_cap` 保证 `weighted/total ≤ 1.25`。超了自动把 input 挪回 read。故 R 是"在 1.25 天花板内尽量榨 margin"的旋钮,**不可能越过检测线**。
- 建议 ns 组 R∈[0.6,0.8]:有可观 margin,又离 1.25 天花板有余量。

## 测试策略

- 保留/更新现有 `split_against_total_*` 测试(恒等式 + 无缓存全 input)。
- 删除 `std_shape_*`/`split_final_*`(超报专用)测试。
- 新增:
  - `read_ratio_moves_read_to_input`:R=0.5 时 read 减半、input 增等量、sum==total。
  - `multiplier_cap_never_exceeds`:构造高 read 命中 + 低 R,断言 `weighted/total ≤ 1.25`。
  - `multiplier_cap_never_touches_creation`:护栏触发时 creation 不变。
  - `creation_is_1h_weight`:1h 标记时 creation_weight()==2.0。
  - `request_marks_1h_cache`:system/tools/message JSON 三处 ttl="1h" 各命中。
- 全量 `cargo test`(本机可跑逻辑测试;完整构建靠 CI)。

## 交付与上线

1. 分支 `feat/cache-detector-safe`,改完本机 `cargo test` + admin-ui `tsc -b`。
2. TTL 5min 改动(已在工作区)并入本分支一起走 CI,不单独推。
3. 推 `myfork master` → CI(见 upgrade-procedure)→ 服务器 pull+up。
4. 上线后 ns-1~ns-5 按需设 `cacheReadRatio` 补 margin(运行时,不停机)。
5. 回滚:打 tag `rollback-20260722`,备份 config + traces.db。

