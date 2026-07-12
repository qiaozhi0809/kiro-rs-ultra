# v0.6.10 / v0.6.11 Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将上游 v0.6.10 / v0.6.11 的限流传播修复整合进当前 fork，同时保留本地三桶 fallback、空响应重试、分组隔离和 admin 自定义能力。

**Architecture:** 先在聊天主链路里引入类型化 429（provider → handlers），再把同一错误语义扩展到 admin 余额/模型/overage 和 MCP/websearch。整合时不直接套 upstream 原版，而是按当前 fork 的调用路径做最小兼容移植，避免破坏本地 error-driven fallback 与运行时指标逻辑。

**Tech Stack:** Rust, axum, reqwest, anyhow, thiserror, tokio, SSE, Admin API

## Global Constraints

- 保留本地 `runtime -> ide -> codewhisperer` 的**错误驱动链式 fallback**，不要改成 upstream 的其他调度语义。
- 保留本地 buffered 空响应透明重试和 `zzz_probe` 0 字节 `tool_use` 静默丢弃语义。
- 保留现有分组隔离、凭据级并发上限、EWMA/dispatch 统计、sticky 调度能力。
- 不引入 changelog / version / package metadata 变更；只移植行为修复。
- 优先编辑现有文件；只有在错误类型需要复用时才新增 `src/kiro/error.rs`。
- 每个任务都必须能单独 review；不要把聊天链路、admin 链路、websearch 链路混成一个大 commit。

---

### Task 1: Port typed 429 propagation into the chat request path

**Files:**
- Modify: `src/kiro/provider.rs:20-32`
- Modify: `src/kiro/provider.rs:300-510`
- Modify: `src/kiro/provider.rs:518-985`
- Modify: `src/kiro/token_manager.rs:1506-1525`
- Modify: `src/kiro/token_manager.rs:2675-2763`
- Modify: `src/kiro/token_manager.rs:5472-5550`
- Modify: `src/anthropic/handlers.rs:429-491`
- Modify: `src/anthropic/handlers.rs:2109-2143`

**Interfaces:**
- Consumes: existing `MultiTokenManager::report_account_throttled(id, cooldown)` and `KiroProvider::call_api*`
- Produces: `crate::kiro::provider::UpstreamRateLimitError { retry_after: Option<String> }`
- Produces: `MultiTokenManager::available_count_for_request(model: Option<&str>, group: Option<&str>) -> usize`
- Produces: `map_provider_error()` returning HTTP `429` with optional `Retry-After`

- [ ] **Step 1: Add the failing handler mapping test**

```rust
#[test]
fn upstream_rate_limit_maps_to_429_with_retry_after() {
    let err = crate::kiro::provider::UpstreamRateLimitError::new(Some("1800".to_string()));
    let resp = map_provider_error(err.into());

    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(resp.headers().get(header::RETRY_AFTER).unwrap(), "1800");
}
```

- [ ] **Step 2: Add request-scoped available-count helper to token manager**

```rust
pub fn available_count_for_request(
    &self,
    model: Option<&str>,
    group: Option<&str>,
) -> usize {
    let now = Instant::now();
    self.entries
        .lock()
        .iter()
        .filter(|entry| {
            !entry.disabled
                && !entry
                    .throttled_until
                    .map(|until| until > now)
                    .unwrap_or(false)
                && credential_matches_request(&entry.credentials, model, group)
        })
        .count()
}
```

- [ ] **Step 3: Add the token-manager regression test for group-aware throttling**

```rust
#[test]
fn test_available_count_for_request_respects_group_throttle() {
    let manager = MultiTokenManager::new(
        Config::default(),
        vec![grouped_cred("a", &["g1"]), grouped_cred("b", &["g2"])],
        None,
        None,
        false,
    )
    .unwrap();

    assert_eq!(manager.available_count_for_request(None, Some("g1")), 1);
    assert_eq!(manager.report_account_throttled(1, StdDuration::from_secs(60)), 1);
    assert_eq!(manager.available_count_for_request(None, Some("g1")), 0);
    assert_eq!(manager.available_count_for_request(None, Some("g2")), 1);
}
```

- [ ] **Step 4: Add typed 429 in provider without changing local fallback semantics**

```rust
#[derive(Debug, thiserror::Error)]
#[error("upstream rate limited")]
pub struct UpstreamRateLimitError {
    retry_after: Option<String>,
}

impl UpstreamRateLimitError {
    pub(crate) fn new(retry_after: Option<String>) -> Self {
        Self { retry_after }
    }

    pub fn retry_after(&self) -> Option<&str> {
        self.retry_after.as_deref()
    }
}
```

```rust
let retry_after = response
    .headers()
    .get(reqwest::header::RETRY_AFTER)
    .and_then(|value| value.to_str().ok())
    .map(str::to_owned);
```

```rust
let rate_limit_error = UpstreamRateLimitError::new(
    retry_after.clone().or_else(|| Some(cooldown_secs.to_string())),
);

if remaining == 0 {
    return Err(rate_limit_error.into());
}
last_error = Some(rate_limit_error.into());
```

- [ ] **Step 5: Map typed 429 to Anthropic-compatible 429 response**

```rust
if let Some(rate_limit) = err.downcast_ref::<crate::kiro::provider::UpstreamRateLimitError>() {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(ErrorResponse::new(
            "rate_limit_error",
            "Upstream rate limit exceeded. Retry later.",
        )),
    )
        .into_response();
    if let Some(value) = rate_limit
        .retry_after()
        .and_then(|value| value.parse::<header::HeaderValue>().ok())
    {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    return response;
}
```

- [ ] **Step 6: Run focused tests**

Run: `cargo test upstream_rate_limit_maps_to_429_with_retry_after test_available_count_for_request_respects_group_throttle -- --nocapture`
Expected: both tests PASS

- [ ] **Step 7: Commit**

```bash
git add src/kiro/provider.rs src/kiro/token_manager.rs src/anthropic/handlers.rs
git commit -m "fix: propagate upstream 429s through chat responses"
```

---

### Task 2: Extend typed 429 propagation through admin and MCP/websearch

**Files:**
- Create: `src/kiro/error.rs`
- Modify: `src/kiro/mod.rs:1-10`
- Modify: `src/kiro/provider.rs:20-985`
- Modify: `src/kiro/token_manager.rs:452-862`
- Modify: `src/admin/error.rs:1-64`
- Modify: `src/admin/service.rs:2393-2463`
- Modify: `src/admin/handlers.rs:73-415`
- Modify: `src/admin/types.rs:1016-1030`
- Modify: `src/anthropic/websearch.rs:12-628`
- Modify: `src/anthropic/websearch_loop.rs:556-689`

**Interfaces:**
- Consumes: `Retry-After` headers from upstream REST/MCP/API responses
- Produces: shared `crate::kiro::error::UpstreamRateLimitError`
- Produces: `AdminServiceError::RateLimited { retry_after: Option<String> }`
- Produces: `AdminServiceError::into_http_response() -> Response`
- Produces: `call_mcp(&self, request_body: &str, group: Option<&str>)`

- [ ] **Step 1: Extract the shared Kiro typed error**

```rust
#[derive(Debug, Clone, thiserror::Error)]
#[error("upstream rate limited")]
pub struct UpstreamRateLimitError {
    retry_after: Option<String>,
}
```

```rust
fn normalize_retry_after(value: String) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.parse::<u64>().is_ok() || httpdate::parse_http_date(value).is_ok() {
        Some(value.to_string())
    } else {
        None
    }
}
```

- [ ] **Step 2: Make REST admin-side Kiro helpers return typed 429s**

```rust
if status.as_u16() == 429 {
    return Err(crate::kiro::error::UpstreamRateLimitError::from_headers(response.headers()).into());
}
```

Apply this to:
- `get_usage_limits()`
- `get_available_models()`
- `set_user_preference()`

- [ ] **Step 3: Add admin-facing rate-limit response path**

```rust
pub enum AdminServiceError {
    NotFound { id: u64 },
    UpstreamError(String),
    RateLimited { retry_after: Option<String> },
    InternalError(String),
    InvalidCredential(String),
}
```

```rust
pub fn into_http_response(self) -> Response {
    let retry_after = match &self {
        AdminServiceError::RateLimited { retry_after } => retry_after.clone(),
        _ => None,
    };
    let status = self.status_code();
    let mut response = (status, Json(self.into_response())).into_response();
    if let Some(value) = retry_after.and_then(|value| value.parse().ok()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}
```

- [ ] **Step 4: Stop swallowing MCP/websearch 429s as empty search results**

```rust
fn finish_mcp_call(result: anyhow::Result<McpResponse>) -> Result<Option<WebSearchResults>, Response> {
    match result {
        Ok(response) => Ok(parse_search_results(&response)),
        Err(error) => Err(super::handlers::map_provider_error(error)),
    }
}
```

```rust
let response = provider.call_mcp(&request_body, group).await?;
```

- [ ] **Step 5: Preserve existing mixed-tool loop behavior while threading group through MCP calls**

```rust
match websearch::call_mcp_api(&provider, &mcp_request, group.as_deref()).await {
    Ok(resp) => searched.push(websearch::parse_search_results(&resp)),
    Err(e) => { ... }
}
```

- [ ] **Step 6: Add focused regression tests**

```rust
#[tokio::test]
async fn rate_limit_response_has_status_header_and_stable_body() { ... }
```

```rust
#[test]
fn test_mcp_rate_limit_is_not_converted_to_empty_results() { ... }
```

- [ ] **Step 7: Run focused tests**

Run: `cargo test rate_limit_response_has_status_header_and_stable_body test_mcp_rate_limit_is_not_converted_to_empty_results -- --nocapture`
Expected: both tests PASS

- [ ] **Step 8: Commit**

```bash
git add src/kiro/error.rs src/kiro/mod.rs src/kiro/provider.rs src/kiro/token_manager.rs src/admin/error.rs src/admin/service.rs src/admin/handlers.rs src/admin/types.rs src/anthropic/websearch.rs src/anthropic/websearch_loop.rs
git commit -m "fix: extend upstream 429 propagation to admin and mcp flows"
```

---

### Task 3: Validate branch state, push CI, and deploy

**Files:**
- Modify: none required unless CI reveals conflicts
- Check: `src/kiro/provider.rs`
- Check: `src/kiro/token_manager.rs`
- Check: `src/anthropic/handlers.rs`
- Check: `src/admin/error.rs`
- Check: `src/anthropic/websearch.rs`

**Interfaces:**
- Consumes: branch commits from Task 1 and Task 2
- Produces: pushed branch and deployment candidate image

- [ ] **Step 1: Inspect branch diff before push**

Run: `git status --short && git log --oneline --decorate -5 && git diff --stat master..HEAD`
Expected: only intended merge files changed

- [ ] **Step 2: Push to fork**

Run: `git push myfork master`
Expected: push succeeds and GitHub Actions starts

- [ ] **Step 3: Watch CI**

Run: `gh run list --limit 5`
Expected: the branch build appears with in-progress / success status

- [ ] **Step 4: Deploy after CI passes**

Run: `ssh ubuntu@147.224.33.164 "cd /home/ubuntu/kiro-rs && docker compose pull && docker compose up -d"`
Expected: service restarts onto the new image

- [ ] **Step 5: Check post-deploy logs**

Run: `ssh ubuntu@147.224.33.164 "cd /home/ubuntu/kiro-rs && docker compose logs --since=10m --tail=300"`
Expected: no new tool JSON regressions, no immediate 429 storm amplification, service healthy

- [ ] **Step 6: Commit follow-up only if CI/deploy reveals a real bug**

```bash
git add <fixed-files>
git commit -m "fix: address post-merge regression"
```

---

## Self-Review

- **Spec coverage:**
  - `9230934` chat-path 429 propagation: Task 1
  - `326a2c7` admin / MCP / websearch propagation: Task 2
  - push / CI / deploy: Task 3
- **Placeholder scan:** no TODO / TBD / “similar to above” placeholders remain
- **Type consistency:** `UpstreamRateLimitError`, `available_count_for_request`, `into_http_response`, and grouped `call_mcp` signature are defined where later tasks consume them
